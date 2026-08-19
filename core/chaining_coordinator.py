"""Chaining Coordinator — conditional edge routing for 3-surface architecture.

Chain preconditions are evaluated against both proved vulnerability nodes and
proved enabling outcomes. Outcomes may unlock a later workflow, but they never
stand in for confirmation of that later method's vulnerability node.
"""

from __future__ import annotations

import logging

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE, MODULE_TO_KG_NODE

_KG_SINGLETON: AttackKnowledgeGraph | None = None


def _get_kg() -> AttackKnowledgeGraph:
    global _KG_SINGLETON
    if _KG_SINGLETON is None:
        _KG_SINGLETON = AttackKnowledgeGraph()
    return _KG_SINGLETON

HIGH_IMPACT_OUTCOMES = set(AttackKnowledgeGraph.HIGH_IMPACT_OUTCOMES)


def confirmed_success_achieved(state: dict) -> bool:
    """Return whether the run has at least one confirmed vulnerability node.

    ``confirmed_vulns`` contains verifier-backed vulnerability confirmations,
    while ``achieved_outcomes`` contains follow-up outcomes that may enable a
    chain.  Keep these concepts separate: an enabling outcome such as
    ``authenticated_session`` must not turn an otherwise unsuccessful run into
    a confirmed exploit.
    """
    return any(
        isinstance(node, str) and node.strip()
        for node in state.get("confirmed_vulns", [])
    )


def critical_outcome_achieved(state: dict) -> bool:
    """Checks whether achieved outcomes contain a high-impact terminal condition."""
    achieved = set(state.get("achieved_outcomes", []))
    confirmed = set(state.get("confirmed_vulns", []))
    return bool((achieved | confirmed) & HIGH_IMPACT_OUTCOMES)


def _find_next_unvisited(viable: list[str], attempted: list[str], blocked: list[str]) -> str | None:
    blocked_set = set(blocked)
    for method in viable:
        if method not in attempted and method not in blocked_set:
            return method
    return None


def _derive_surface_confirmed(confirmed: set[str]) -> set[str]:
    """Map method-confirmed nodes to surface-confirmed nodes for chain precondition checks."""
    surface_confirmed = set()
    for node in confirmed:
        mapped = MODULE_TO_KG_NODE.get(node, node)
        # Method agents append nodes like "sqli_union_confirmed";
        # MODULE_TO_KG_NODE maps the base name ("sqli_union"), so fall
        # back to stripping the _confirmed suffix when needed.
        if mapped == node and node.endswith("_confirmed"):
            base = node[: -len("_confirmed")]
            mapped = MODULE_TO_KG_NODE.get(base, node)
        surface_confirmed.add(mapped)
    return surface_confirmed


def route_after_agent(state: dict) -> str:
    """Evaluates the current state and returns the next graph route after an agent."""
    next_agent, _ = evaluate_chain_route(state)
    return next_agent


def evaluate_chain_route(state: dict) -> tuple[str, dict]:
    """Evaluates chain continuation, fallback, stop, and scoring decisions.

    Reads:
        Confirmed vulnerabilities, achieved outcomes, attempted agents, blocked
        agents, failure agents, iteration counters, selected method, and surface.

    Writes:
        Routing hints, selected method changes, task result, incomplete reason, and
        telemetry events as partial state updates.

    Returns:
        Partial state update consumed by the chaining router node."""
    iteration_count = state.get("iteration_count", 0)
    max_iterations = state.get("max_iterations", 30)
    confirmed = set(state.get("confirmed_vulns", []))
    achieved = set(state.get("achieved_outcomes", []))
    known = confirmed | achieved
    current_surface = state.get("current_surface", "sqli")
    # Deduplicate attempted_agents because Annotated[list[str], add]
    # reducer can accumulate duplicates when agents return the full list.
    attempted = list(dict.fromkeys(state.get("attempted_agents", [])))
    blocked = state.get("blocked_agents", [])
    failure_agents = state.get("failure_agents", [])
    kg = _get_kg()

    if iteration_count >= max_iterations:
        return "scorer", {
            "node": "chaining_router",
            "iteration": iteration_count,
            "event": "akg.route.selected",
            "next_agent": "scorer",
            "reason": "budget_exhausted",
        }

    target_method = state.get("target_method")
    if target_method and target_method in attempted:
        return "scorer", {
            "node": "chaining_router",
            "iteration": iteration_count,
            "event": "akg.route.selected",
            "next_agent": "scorer",
            "reason": "target_method_complete",
            "target_method": target_method,
        }

    # Derive surface-level confirmed nodes for chain precondition checks
    confirmed_for_chains = confirmed | _derive_surface_confirmed(confirmed)
    known_for_chains = known | confirmed_for_chains

    # 1. AKG-guided runs may use cross-surface chains. Both confirmed nodes
    # and separately proved enabling outcomes can satisfy a precondition.
    if state.get("experiment_condition", "linear_hybrid") == "akg_guided_hybrid":
        for node in sorted(known_for_chains):
            for edge in kg.get_next_actions(node):
                if edge.get("is_chain") and all(p in known_for_chains for p in edge.get("preconditions", [])):
                    target_agent = edge.get("target_agent")
                    if target_agent and target_agent not in attempted and target_agent not in blocked:
                        return target_agent, {
                            "node": "chaining_router",
                            "iteration": iteration_count,
                            "event": "akg.route.selected",
                            "next_agent": target_agent,
                            "reason": "chain_ready",
                            "source": node,
                            "target": edge.get("target"),
                        }

    # 2. Critical outcome check — route to scorer immediately if high-impact outcome achieved
    if critical_outcome_achieved(state):
        return "scorer", {
            "node": "chaining_router",
            "iteration": iteration_count,
            "event": "akg.route.selected",
            "next_agent": "scorer",
            "reason": "critical_outcome",
        }

    # 3. Fallback loop: if last agent was blocked or failed, try next unexplored method
    attempted_set = set(attempted)
    last_agent = attempted[-1] if attempted else None
    last_status = None
    if last_agent in blocked:
        last_status = "BLOCKED"
    elif last_agent in failure_agents:
        last_status = "EXECUTION_FAILURE"
    if last_status in ("BLOCKED", "EXECUTION_FAILURE"):
        viable = kg.get_viable_methods(current_surface, state.get("observations", {}))
        next_method = _find_next_unvisited(viable, attempted, blocked)
        if next_method:
            return next_method, {
                "node": "chaining_router",
                "iteration": iteration_count,
                "event": "akg.route.selected",
                "next_agent": next_method,
                "reason": "fallback_next_method",
            }
        if confirmed_success_achieved(state):
            return "scorer", {
                "node": "chaining_router",
                "iteration": iteration_count,
                "event": "akg.route.selected",
                "next_agent": "scorer",
                "reason": "confirmed_success",
                "task_result": "SUCCESS",
            }
        return "scorer", {
            "node": "chaining_router",
            "iteration": iteration_count,
            "event": "akg.route.selected",
            "next_agent": "scorer",
            "reason": "all_methods_exhausted",
            "incomplete_reason": "ALL_METHODS_FAILED",
        }

    # 3. Exhaustion check: if every method on this surface has been attempted
    # or blocked, stop instead of looping back to orchestrator forever.
    all_methods = set(METHODS_BY_SURFACE.get(current_surface, []))
    attempted_set = set(attempted)
    blocked_set = set(blocked)
    if all_methods and all_methods.issubset(attempted_set | blocked_set):
        if confirmed_success_achieved(state):
            return "scorer", {
                "node": "chaining_router",
                "iteration": iteration_count,
                "event": "akg.route.selected",
                "next_agent": "scorer",
                "reason": "confirmed_success",
                "task_result": "SUCCESS",
            }
        return "scorer", {
            "node": "chaining_router",
            "iteration": iteration_count,
            "event": "akg.route.selected",
            "next_agent": "scorer",
            "reason": "all_methods_exhausted",
            "incomplete_reason": "ALL_METHODS_FAILED",
        }

    return "orchestrator", {
        "node": "chaining_router",
        "iteration": iteration_count,
        "event": "akg.route.selected",
        "next_agent": "orchestrator",
        "reason": "no_chain",
    }


def chaining_router_node(state: dict) -> dict:
    """Executes the chaining-router stage of the LangGraph workflow.

    Reads:
        Current method results, chain history, confirmed vulnerabilities, outcomes,
        iteration count, and method-attempt tracking fields.

    Writes:
        Next-agent routing hints, selected method updates, completion status,
        incomplete reason, and telemetry events.

    Routing:
        The graph maps `next_agent` to orchestrator, payload candidate builder,
        scorer, or termination.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update merged into the LangGraph state."""
    next_agent, event = evaluate_chain_route(state)
    updates: dict = {"next_agent": next_agent, "telemetry_events": [event]}
    if next_agent in {method for methods in METHODS_BY_SURFACE.values() for method in methods}:
        updates["selected_method"] = next_agent
    if event.get("reason") == "chain_ready":
        source = str(event.get("source") or "")
        target = str(event.get("target") or next_agent)
        existing_path = list(state.get("akg_path", []))
        additions = [item for item in (source, target) if item and item not in existing_path]
        if additions:
            updates["akg_path"] = additions
        updates["current_chain"] = [*existing_path, *additions]
        updates["chain_history"] = [{
            "chain": [*existing_path, *additions],
            "status": "routed",
            "source": source,
            "target": target,
            "target_agent": next_agent,
        }]
    if event.get("reason") == "all_methods_exhausted":
        updates["task_result"] = "INCOMPLETE"
        updates["incomplete_reason"] = event.get("incomplete_reason", "ALL_METHODS_FAILED")
    elif event.get("reason") == "confirmed_success":
        # A confirmed finding remains a successful run even when a later
        # cross-surface chain was attempted but could not continue.  Clear a
        # stale incomplete marker from the exhausted-surface path so scorer and
        # the persisted artifact agree with the verifier-backed finding.
        updates["task_result"] = "SUCCESS"
        updates["incomplete_reason"] = None
    return updates
