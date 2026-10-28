"""Chaining Coordinator — conditional edge routing for 3-surface architecture.

Chain preconditions are evaluated against both proved vulnerability nodes and
proved enabling outcomes. Outcomes may unlock a later workflow, but they never
stand in for confirmation of that later method's vulnerability node.
"""

from __future__ import annotations

from core.run_status import terminal_status

import logging

from core.knowledge_graph import AttackKnowledgeGraph, get_attack_knowledge_graph
from core.workflow_policy import eligible_methods, stop_reason
from core.state import METHODS_BY_SURFACE, MODULE_TO_KG_NODE
from core.state import score_decision
from agents.state_utils import method_selection_update

def _get_kg() -> AttackKnowledgeGraph:
    return get_attack_knowledge_graph()

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


CHAIN_ASSESSMENT_POLICY_VERSION = "chain-assessment.v1"


def _derive_surface_confirmed(confirmed: set[str]) -> set[str]:
    """Map method-confirmed nodes to surface-confirmed nodes for chain precondition checks."""
    return {f"{surface}_confirmed" for surface, methods in METHODS_BY_SURFACE.items()
        if any(MODULE_TO_KG_NODE[method] in confirmed for method in methods)}


def _known_chain_nodes(state: dict) -> set[str]:
    confirmed = set(state.get("confirmed_vulns", []))
    return confirmed | set(state.get("achieved_outcomes", [])) | _derive_surface_confirmed(confirmed)


def _route_receipts(state: dict) -> list[dict]:
    rows: list[dict] = []
    for row in state.get("chain_history", []) or []:
        if isinstance(row, dict) and row.get("route_id"):
            rows.append(row)
    return rows


def _chain_source_assessed(state: dict) -> bool:
    """Require current candidate proof before claiming an assessed absence."""
    from evaluation.scoring_evidence import candidate_base, candidate_execution_rows

    method = state.get("selected_method")
    visit_id = state.get("selected_visit_id")
    if not method or not visit_id:
        return False
    artifact = {
        "config": {"scoring_oracles": state.get("scoring_oracles", [])},
        "final_state": state,
    }
    proofs = []
    for candidate in state.get("payload_candidates", {}).get(method, []):
        if candidate.get("stage") not in {"exploit", "bypass"} or candidate.get("visit_id") != visit_id:
            continue
        candidate_id = candidate.get("candidate_id")
        refs = [
            f"#/final_state/response_evidence/{index}"
            for index, row in candidate_execution_rows(artifact, candidate_id, method)
            if row.get("visit_id") == visit_id
        ]
        proofs.append(candidate_base(artifact, candidate_id, method, refs))
    return any(proof is not None and proof > 0 for proof in proofs) or (
        bool(proofs) and all(proof == 0 for proof in proofs)
    )


def build_chain_assessment(
    state: dict,
    *,
    status: str,
    reason: str,
    evaluated_edges: int = 0,
) -> dict:
    """Record the edge-by-edge chain opportunity assessment for v4 consumers.

    ``assessed`` requires an actual source-proof and static-edge assessment.
    A completed scan may prove absence; an empty default list cannot.
    """
    known = _known_chain_nodes(state)
    edges: list[dict] = []
    for source in sorted(known):
        for edge in _get_kg().get_next_actions(source):
            if not edge.get("is_chain") or not edge.get("target_agent"):
                continue
            infeasible = _chain_infeasibility(state, edge)
            route = next((row for row in reversed(_route_receipts(state))
                          if row.get("source") == source and row.get("target_agent") == edge.get("target_agent")), None)
            if route and route.get("status") in {"completed", "failed", "unverified", "executed"}:
                edge_status = "confirmed" if route.get("status") == "completed" else "executed"
                edge_reason = str(route.get("reason") or edge_status)
            elif infeasible:
                edge_status, edge_reason = "infeasible", infeasible
            else:
                edge_status, edge_reason = "available", "route_available"
            edges.append({
                "source": source,
                "target": edge.get("target"),
                "target_agent": edge.get("target_agent"),
                "status": edge_status,
                "reason": edge_reason,
                "evidence_refs": list((route or {}).get("source_evidence_refs", [])),
                "prerequisite_status": {
                    key: ("proved" if key in known else "unproved")
                    for key in edge.get("preconditions", [])
                },
            })
    return {
        "assessed": status == "assessed",
        "status": status,
        "reason": reason,
        "edges": edges,
        "routes_evaluated": int(evaluated_edges),
        "policy_version": CHAIN_ASSESSMENT_POLICY_VERSION,
        "routes": _route_receipts(state),
    }


def route_after_agent(state: dict) -> str:
    """Evaluates the current state and returns the next graph route after an agent."""
    next_agent, _ = evaluate_chain_route(state)
    return next_agent


def _chain_candidates(state: dict) -> list[dict]:
    """Return unvisited static routes whose enabling outcomes are proved."""
    if state.get("experiment_condition", "linear_hybrid") != "akg_guided_hybrid":
        return []
    confirmed = set(state.get("confirmed_vulns", []))
    known = confirmed | set(state.get("achieved_outcomes", [])) | _derive_surface_confirmed(confirmed)
    excluded = set(state.get("attempted_agents", [])) | set(state.get("blocked_agents", [])) | set(state.get("failure_agents", []))
    excluded.update(row.get("method") for row in state.get("preparation_failures", []))
    candidates = [dict(edge, source=node) for node in sorted(known)
        for edge in _get_kg().get_next_actions(node) if edge.get("is_chain")
        and edge.get("target_agent") and edge["target_agent"] not in excluded
        and all(p in known for p in edge.get("preconditions", []))]
    return sorted(candidates, key=lambda row: (row.get("priority", 100), row["source"], row["target"]))


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
    current_surface = state.get("current_surface", "sqli")
    # Deduplicate attempted_agents because Annotated[list[str], add]
    # reducer can accumulate duplicates when agents return the full list.
    attempted = list(dict.fromkeys(state.get("attempted_agents", [])))
    blocked = state.get("blocked_agents", [])
    failure_agents = state.get("failure_agents", [])

    stopping = stop_reason(state)
    if stopping:
        return "scorer", {"node": "chaining_router", "iteration": iteration_count,
            "event": "akg.route.selected", "next_agent": "scorer", "reason": stopping}

    rejected_routes = []
    if state.get("experiment_condition", "linear_hybrid") == "akg_guided_hybrid":
        for edge in _chain_candidates(state):
            target_agent = edge.get("target_agent")
            unavailable = _chain_infeasibility(state, edge)
            if unavailable:
                rejected_routes.append({"source": edge["source"], "target": edge["target"],
                    "target_agent": target_agent, "reason": unavailable,
                    "preconditions": edge.get("preconditions", []), "status": "infeasible"})
                continue
            return target_agent, {"node": "chaining_router", "iteration": iteration_count,
                "event": "akg.route.selected", "next_agent": target_agent, "reason": "chain_ready",
                "source": edge["source"], "target": edge["target"],
                "preconditions": list(edge.get("preconditions", [])), "infeasible_routes": rejected_routes}

    # 3. Fallback loop: if last agent was blocked or failed, try next unexplored method
    last_agent = attempted[-1] if attempted else None
    last_status = None
    if last_agent in blocked:
        last_status = "BLOCKED"
    elif last_agent in failure_agents:
        last_status = "EXECUTION_FAILURE"
    if last_status in ("BLOCKED", "EXECUTION_FAILURE"):
        viable = eligible_methods(state)
        next_method = _find_next_unvisited(viable, attempted, blocked)
        if next_method:
            return next_method, {
                "node": "chaining_router",
                "infeasible_routes": rejected_routes,
                "iteration": iteration_count,
                "event": "akg.route.selected",
                "next_agent": next_method,
                "reason": "fallback_next_method",
            }
        if confirmed_success_achieved(state):
            return "scorer", {
                "node": "chaining_router",
                "infeasible_routes": rejected_routes,
                "iteration": iteration_count,
                "event": "akg.route.selected",
                "next_agent": "scorer",
                "reason": "confirmed_success",
                "task_result": "SUCCESS",
            }
        return "scorer", {
            "node": "chaining_router",
            "infeasible_routes": rejected_routes,
            "iteration": iteration_count,
            "event": "akg.route.selected",
            "next_agent": "scorer",
            "reason": "all_methods_exhausted",
            "incomplete_reason": "ALL_METHODS_FAILED",
        }

    # 3. Exhaustion check: if every method on this surface has been attempted
    # or blocked, stop instead of looping back to orchestrator forever.
    all_methods = set(METHODS_BY_SURFACE.get(current_surface, []))
    if all_methods and not eligible_methods(state):
        if confirmed_success_achieved(state):
            return "scorer", {
                "node": "chaining_router",
                "infeasible_routes": rejected_routes,
                "iteration": iteration_count,
                "event": "akg.route.selected",
                "next_agent": "scorer",
                "reason": "confirmed_success",
                "task_result": "SUCCESS",
            }
        return "scorer", {
            "node": "chaining_router",
            "infeasible_routes": rejected_routes,
            "iteration": iteration_count,
            "event": "akg.route.selected",
            "next_agent": "scorer",
            "reason": "all_methods_exhausted",
            "incomplete_reason": "ALL_METHODS_FAILED",
        }

    return "orchestrator", {
        "node": "chaining_router",
        "infeasible_routes": rejected_routes,
        "iteration": iteration_count,
        "event": "akg.route.selected",
        "next_agent": "orchestrator",
        "reason": "no_chain",
    }


def _source_decisions(state: dict, source: str) -> list[dict]:
    return [decision for decision in state.get("verifier_history", [])
        if decision.get("decision") == "confirmed" and source in
        (set(decision.get("achieved_outcomes", [])) | set(decision.get("confirmed_vulns", []))
            | _derive_surface_confirmed(set(decision.get("confirmed_vulns", []))))]


def _chain_infeasibility(state: dict, edge: dict, *, check_destination: bool = True) -> str | None:
    """Only schedule dependencies supported by the current destination adapter."""
    method, source = edge["target_agent"], edge["source"]
    if check_destination:
        from foundation.preconditions import statuses_snapshot
        statuses = statuses_snapshot(state, method)
        if any(value != "true" for value in statuses.values()):
            return "destination_preconditions_not_proved"
    if not ((source == "authenticated_session" and method in {"ac_idor", "ac_force_browse"})
            or (source == "credentials_extracted" and method == "bf_dictionary")):
        return "source_consumption_adapter_unavailable"
    decisions = _source_decisions(state, source)
    refs = {ref for decision in decisions for ref in decision.get("evidence_refs", [])}
    rows = state.get("response_evidence", [])
    source_ids = {row.get("evidence_id") for i, row in enumerate(rows)
        if f"#/final_state/response_evidence/{i}" in refs and row.get("candidate_id") and row.get("evidence_id")}
    if not source_ids:
        return "source_evidence_unavailable"
    credentials = [credential for credential in state.get("found_credentials", [])
        if credential.get("source_evidence_id") in source_ids and credential.get("source_candidate_id")
        and any(row.get("evidence_id") == credential["source_evidence_id"]
            and row.get("candidate_id") == credential["source_candidate_id"]
            and row.get("visit_id") and row["visit_id"] == credential.get("source_visit_id") for row in rows)
        and credential.get("username") and credential.get("password")]
    if source == "credentials_extracted":
        if not any(c.get("representation") == "plaintext" for c in credentials):
            return "plaintext_source_credentials_unavailable"
    elif not credentials:
        return "route_bound_session_material_unavailable"
    elif not any(c["username"].lower() != "admin" for c in credentials):
        return "nonadmin_source_principal_unavailable"
    return None


def _complete_routed_visit(state: dict) -> dict:
    """Credit only a recorded route whose own destination consumed proved source data."""
    route = state.get("active_chain_route") or {}
    decision = state.get("verifier_decision") or {}
    if route and any(row.get("visit_id") == route.get("target_visit_id") for row in state.get("preparation_failures", [])):
        return {"active_chain_route": None, "chain_scores": {route["target_agent"]: 0},
            "chain_history": [{**route, "status": "failed", "reason": "NO_VALID_PAYLOADS", "score": 0}]}
    if not route or decision.get("visit_id") != route.get("target_visit_id"):
        return {}
    if any(h.get("route_id") == route["route_id"] and h.get("status") in {"completed", "failed", "unverified"}
           for h in state.get("chain_history", [])):
        return {}
    method = route["target_agent"]
    consumption = [c for c in state.get("chain_consumption", [])
        if c.get("route_id") == route["route_id"] and c.get("visit_id") == decision["visit_id"]]
    source_ids = set(route.get("source_evidence_ids", []))
    source_proved = bool(route.get("source_verifier_ids")) and route.get("prerequisites_proved") is True
    destination_rows = [r for i, r in enumerate(state.get("response_evidence", []))
        if r.get("visit_id") == decision["visit_id"] and r.get("verified_grade") == 3
        and r.get("agent_id") == method
        and f"#/final_state/response_evidence/{i}" in decision.get("evidence_refs", [])]
    destination_ids = {r["evidence_id"] for r in destination_rows}
    dependency = any(c.get("source_evidence_id") in source_ids and c.get("destination_evidence_id") in destination_ids
        and any(r.get("evidence_id") == c.get("destination_evidence_id")
            and r.get("candidate_id") == c.get("candidate_id")
            and r.get("consumed_source_evidence_id") == c.get("source_evidence_id") for r in destination_rows)
        for c in consumption)
    downstream = decision.get("decision") == "confirmed" and MODULE_TO_KG_NODE[method] in decision.get("confirmed_vulns", [])
    completed = source_proved and dependency and downstream
    if completed:
        status, reason = "completed", "source_consumed_and_downstream_verified"
    elif decision.get("decision") == "unverified":
        status, reason = "unverified", decision.get("reason", "downstream_unverified")
    elif not downstream:
        status, reason = "failed", "downstream_not_confirmed"
    else:
        status, reason = "unverified", "source_consumption_not_proved"
        if route.get("source") == "credentials_extracted" and any(c.get("representation") == "password_hash" for c in state.get("found_credentials", [])):
            reason = "extracted_password_hash_not_consumable_as_plaintext"
    grade = 4 if completed else 0
    receipt = {**route, "status": status, "reason": reason, "consumption": consumption,
        "destination_verifier_id": decision.get("verifier_id"),
        "destination_evidence_refs": list(decision.get("evidence_refs", [])),
        "credited_method": method if completed else None, "score": grade}
    update = {"chain_history": [{**route, "status": "executed", "destination_verifier_id": decision.get("verifier_id")}, receipt],
        "chain_scores": {method: grade}, "active_chain_route": None,
        "scoring_decisions": [score_decision(state, "Schain", method, grade, reason,
            aggregation="destination_visit", route_id=route["route_id"],
            evidence_refs=[*route.get("source_evidence_refs", []), *decision.get("evidence_refs", [])],
            verifier_id=decision.get("verifier_id"), consumption=consumption)]}
    if completed:
        update["scores"] = {method: 4}
    return update


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
    from foundation.control_catalog import quarantine_gate
    from foundation.readiness import readiness_block_update, readiness_gate

    readiness = readiness_gate(state)
    if readiness["decision"] == "block":
        update = readiness_block_update(readiness)
        update["chain_assessment"] = build_chain_assessment(
            state, status="not_run", reason="readiness_blocked")
        update["next_agent"] = "scorer"
        return update
    quarantine = quarantine_gate(state)
    if quarantine.get("blocked"):
        from core.run_status import reason as status_reason
        code = "CONTROL_CONTAMINATION"
        return {
            "next_agent": "scorer", "selected_method": None,
            "task_result": "INCOMPLETE", "incomplete_reason": code,
            "workflow_stop_reason": "control_quarantine",
            "execution_status": "failed",
            "execution_reason": status_reason(code, str(quarantine.get("reason") or ""),
                                              list(quarantine.get("evidence_refs") or [])),
            "security_outcome": "fixture_limited",
            "security_outcome_reason": status_reason(code, str(quarantine.get("reason") or ""),
                                                     list(quarantine.get("evidence_refs") or [])),
            "chain_assessment": build_chain_assessment(
                state, status="not_run", reason="run_quarantined"),
        }

    destination_update = {}
    if not stop_reason(state):
        from foundation.preconditions import precondition_keys_for_method, statuses_snapshot

        for edge in _chain_candidates(state):
            if _chain_infeasibility(state, edge) is None:
                break
            if _chain_infeasibility(state, edge, check_destination=False) is not None:
                continue
            target_agent = str(edge["target_agent"])
            required_keys = precondition_keys_for_method(target_agent)
            statuses = statuses_snapshot(state, target_agent)
            if any(statuses.get(key) == "false" for key in required_keys):
                # Measured negative evidence is a rejection, not a reason to probe.
                continue
            measured = {}
            if target_agent == "bf_dictionary":
                if all(statuses.get(key) == "true" for key in required_keys):
                    continue
                from foundation.recon import probe_brute_force_destination
                measured = probe_brute_force_destination(state)
            elif target_agent in {"ac_idor", "ac_force_browse"}:
                if all(statuses.get(key) == "true" for key in required_keys):
                    continue
                from foundation.recon import probe_access_control_destination
                refs = {ref for decision in _source_decisions(state, edge["source"]) for ref in decision.get("evidence_refs", [])}
                source_ids = [row["evidence_id"] for i, row in enumerate(state.get("response_evidence", []))
                    if f"#/final_state/response_evidence/{i}" in refs and row.get("evidence_id")]
                measured = probe_access_control_destination(state, target_agent, source_ids)
            for key, value in measured.items():
                if key == "observations":
                    destination_update[key] = {**destination_update.get(key, {}), **value}
                elif isinstance(value, dict):
                    destination_update[key] = {**destination_update.get(key, {}), **value}
                else:
                    destination_update[key] = [*destination_update.get(key, []), *value]
            measured_state = {**state, **destination_update,
                "observations": {**state.get("observations", {}), **destination_update.get("observations", {})},
                "precondition_status": {**state.get("precondition_status", {}), **destination_update.get("precondition_status", {})}}
            measured_statuses = statuses_snapshot(measured_state, target_agent)
            if any(measured_statuses.get(key) == "false" for key in required_keys):
                continue
            if not all(measured_statuses.get(key) == "true" for key in required_keys):
                # An attempted but inconclusive control cannot authorize the
                # destination visit; retain the limitation explicitly.
                destination_update.setdefault("preparation_failures", []).append({
                    "method": target_agent,
                    "visit_id": f"{target_agent}:destination_probe",
                    "reason": "destination_precondition_unknown",
                    "detail": "bounded destination control did not establish the prerequisite",
                })
                continue
            if _chain_infeasibility(measured_state, edge) is None:
                break
    routing_state = {**state, **destination_update, "observations": {
        **state.get("observations", {}), **destination_update.get("observations", {}),
    }}
    next_agent, event = evaluate_chain_route(routing_state)
    updates: dict = {**destination_update, **_complete_routed_visit(state), "next_agent": next_agent}
    prior_routes = [row for row in _route_receipts(state)
                    if row.get("status") in {"completed", "failed", "unverified", "executed", "ready", "routed"}]
    candidates = _chain_candidates(routing_state) if state.get("experiment_condition") == "akg_guided_hybrid" else []
    evaluated = len(candidates) + (1 if prior_routes and not candidates else 0)
    if _chain_source_assessed(routing_state):
        assessment_status, assessment_reason = "assessed", "source_and_chain_edges_assessed"
    elif stop_reason(state):
        assessment_status, assessment_reason = "not_run", str(stop_reason(state))
    elif evaluated:
        assessment_status, assessment_reason = "assessed", "chain_opportunity_evaluated"
    else:
        assessment_status, assessment_reason = "insufficient_evidence", "no_proved_enabling_outcome"
    updates["chain_assessment"] = build_chain_assessment(
        routing_state, status=assessment_status, reason=assessment_reason,
        evaluated_edges=evaluated)
    updates["chain_assessment"]["routes_evaluated"] = max(
        evaluated, len(updates["chain_assessment"]["edges"]))
    if next_agent == "scorer":
        updates["workflow_stop_reason"] = event.get("reason")
    rejected = event.pop("infeasible_routes", [])
    existing = {(row.get("source"), row.get("target"), row.get("target_agent"), row.get("reason"))
        for row in state.get("chain_history", []) if row.get("status") == "infeasible"}
    rejected = [row for row in rejected if (row["source"], row["target"], row["target_agent"], row["reason"]) not in existing]
    if state.get('scoring_rubric_version') == 'scoring.v4':
        from evaluation.scoring_evidence import weak_opportunity_update
        updates.update(weak_opportunity_update(state))
    decision = state.get("verifier_decision") or {}
    if decision.get("visit_id") and decision.get("visit_id") == state.get("selected_visit_id"):
        from core.scorer import output_decision_update
        output = output_decision_update(state, decision["agent_id"])
        updates["output_scores"] = output["output_scores"]
        updates["scoring_decisions"] = [*updates.get("scoring_decisions", []), *output["scoring_decisions"]]
    if next_agent in {method for methods in METHODS_BY_SURFACE.values() for method in methods}:
        selection = method_selection_update(routing_state, next_agent,
            "akg_route" if event.get("reason") == "chain_ready" else "deterministic_fallback",
            preconditions=event.get("preconditions", []))
        updates["scoring_decisions"] = [*updates.get("scoring_decisions", []), *selection.pop("scoring_decisions")]
        updates.update(selection)
    if event.get("reason") == "chain_ready":
        source = str(event.get("source") or "")
        target = str(event.get("target") or next_agent)
        existing_path = list(state.get("akg_path", []))
        additions = []
        connected = not existing_path or existing_path[-1] == source or _get_kg().graph.has_edge(existing_path[-1], source)
        if connected:
            for item in (source, target):
                previous = (additions or existing_path or [None])[-1]
                if item and item != previous:
                    additions.append(item)
        if additions:
            updates["akg_path"] = additions
        route_path = [*existing_path, *additions] if connected else [source, target]
        updates["current_chain"] = route_path
        source_decisions = _source_decisions(state, source)
        recorded_refs = {ref for d in source_decisions for ref in d.get("evidence_refs", [])}
        source_refs = [f"#/final_state/response_evidence/{i}" for i, row in enumerate(state.get("response_evidence", []))
            if f"#/final_state/response_evidence/{i}" in recorded_refs and row.get("candidate_id") and row.get("evidence_id")]
        source_rows = [row for i, row in enumerate(state.get("response_evidence", []))
            if f"#/final_state/response_evidence/{i}" in source_refs]
        route = {
            "chain": route_path,
            "route_id": f"route:{len(state.get('chain_history', []))}",
            "source": source,
            "target": target,
            "target_agent": next_agent,
            "target_visit_id": updates["selected_visit_id"],
            "preconditions": list(event.get("preconditions", [])),
            "prerequisites_proved": True,
            "source_verifier_ids": [d["verifier_id"] for d in source_decisions],
            "source_evidence_refs": source_refs,
            "source_evidence_ids": [r["evidence_id"] for r in source_rows],
            "prerequisite_evidence_refs": {p: [f'#/final_state/verifier_history/{i}'
                for i,d in enumerate(state.get('verifier_history', [])) if p in
                set(d.get('achieved_outcomes', [])) | set(d.get('confirmed_vulns', [])) |
                _derive_surface_confirmed(set(d.get('confirmed_vulns', [])))]
                for p in event.get('preconditions', [])},
        }
        updates["active_chain_route"] = route
        updates["chain_history"] = [*updates.get("chain_history", []),
            {**route, "status": "ready"}, {**route, "status": "routed"}]
        event.update(route)
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
    if event.get("reason") in {"all_methods_exhausted", "confirmed_success"}:
        updates.update(terminal_status({**state, **updates}, classify=True))
    event["payload"] = {k: v for k, v in event.items() if k not in {"node", "event", "iteration", "payload"}}
    if rejected:
        updates["chain_history"] = [*updates.get("chain_history", []), *rejected]
    updates["telemetry_events"] = [
        *destination_update.get("telemetry_events", []),
        *({"node": "chaining_router", "event": "akg.route.infeasible",
           "iteration": state.get("iteration_count", 0), "payload": row} for row in rejected),
        event,
    ]
    return updates
