"""Chaining Coordinator — conditional edge routing for 3-surface architecture."""

from __future__ import annotations

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE, MODULE_TO_KG_NODE

HIGH_IMPACT_OUTCOMES = set(AttackKnowledgeGraph.HIGH_IMPACT_OUTCOMES)


def critical_outcome_achieved(state: dict) -> bool:
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
    next_agent, _ = evaluate_chain_route(state)
    return next_agent


def evaluate_chain_route(state: dict) -> tuple[str, dict]:
    iteration_count = state.get("iteration_count", 0)
    max_iterations = state.get("max_iterations", 30)
    confirmed = set(state.get("confirmed_vulns", []))
    achieved = set(state.get("achieved_outcomes", []))
    known = confirmed  # chain preconditions must be confirmed_vulns only, not achieved_outcomes
    current_surface = state.get("current_surface", "sqli")
    # Deduplicate attempted_agents because Annotated[list[str], add]
    # reducer can accumulate duplicates when agents return the full list.
    attempted = list(dict.fromkeys(state.get("attempted_agents", [])))
    blocked = state.get("blocked_agents", [])
    failure_agents = state.get("failure_agents", [])
    kg = AttackKnowledgeGraph()

    if iteration_count >= max_iterations:
        return "scorer", {
            "node": "chaining_router",
            "iteration": iteration_count,
            "event": "akg.route.selected",
            "next_agent": "scorer",
            "reason": "budget_exhausted",
        }

    # Derive surface-level confirmed nodes for chain precondition checks
    confirmed_for_chains = confirmed | _derive_surface_confirmed(confirmed)

    # 1. Check cross-surface chains from confirmed nodes
    for vuln in sorted(confirmed_for_chains):
        for edge in kg.get_next_actions(vuln):
            if edge.get("is_chain") and all(p in known for p in edge.get("preconditions", [])):
                target_agent = edge.get("target_agent")
                if target_agent and target_agent not in attempted and target_agent not in blocked:
                    return target_agent, {
                        "node": "chaining_router",
                        "iteration": iteration_count,
                        "event": "akg.route.selected",
                        "next_agent": target_agent,
                        "reason": "chain_ready",
                        "source": vuln,
                        "target": edge.get("target"),
                    }

    # 2. Fallback loop: if last agent was blocked or failed, try next unexplored method
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
        # Second pass: any unattempted method on this surface
        for method in METHODS_BY_SURFACE.get(current_surface, []):
            if method not in attempted_set and method not in blocked:
                return method, {
                    "node": "chaining_router",
                    "iteration": iteration_count,
                    "event": "akg.route.selected",
                    "next_agent": method,
                    "reason": "fallback_next_method",
                }
        return "scorer", {
            "node": "chaining_router",
            "iteration": iteration_count,
            "event": "akg.route.selected",
            "next_agent": "scorer",
            "reason": "all_methods_exhausted",
            "incomplete_reason": "ALL_METHODS_FAILED",
        }

    if critical_outcome_achieved(state):
        return "scorer", {
            "node": "chaining_router",
            "iteration": iteration_count,
            "event": "akg.route.selected",
            "next_agent": "scorer",
            "reason": "critical_outcome",
        }

    # 3. Exhaustion check: if every method on this surface has been attempted
    # or blocked, stop instead of looping back to orchestrator forever.
    all_methods = set(METHODS_BY_SURFACE.get(current_surface, []))
    attempted_set = set(attempted)
    blocked_set = set(blocked)
    if all_methods and all_methods.issubset(attempted_set | blocked_set):
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
    next_agent, event = evaluate_chain_route(state)
    updates: dict = {"next_agent": next_agent, "telemetry_events": [event]}
    if event.get("reason") == "all_methods_exhausted":
        updates["task_result"] = "INCOMPLETE"
        updates["incomplete_reason"] = event.get("incomplete_reason", "ALL_METHODS_FAILED")
    return updates
