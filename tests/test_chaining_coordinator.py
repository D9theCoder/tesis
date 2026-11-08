"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""

from copy import deepcopy
from importlib import import_module
from unittest.mock import MagicMock


from core.chaining_coordinator import chaining_router_node, evaluate_chain_route
from core.state import new_default_state
from foundation.http_client import ContainmentError
from tests.support import READY_RECEIPT

def proved_chain_source(source):
    return {"readiness": deepcopy(READY_RECEIPT),
        "response_evidence": [{"evidence_id": "source-evidence", "candidate_id": "source-candidate", "visit_id": "source-visit"}],
        "verifier_history": [{"decision": "confirmed", "verifier_id": "source-verifier",
            "confirmed_vulns": ["bf_dictionary_confirmed"], "achieved_outcomes": [source],
            "evidence_refs": ["#/final_state/response_evidence/0"]}],
        "found_credentials": [{"username": "fixture-user", "password": "fixture-value", "representation": "plaintext",
            "source_evidence_id": "source-evidence", "source_candidate_id": "source-candidate", "source_visit_id": "source-visit"}]}


def fresh_sqli_chain_state():
    source = proved_chain_source("credentials_extracted")
    source["verifier_history"][0]["confirmed_vulns"] = ["sqli_union_confirmed"]
    return {**new_default_state(), **source,
        "target_url": "http://localhost/dvwa", "current_surface": "sqli",
        "experiment_condition": "akg_guided_hybrid", "stop_policy": "coverage",
        "confirmed_vulns": ["sqli_union_confirmed"], "achieved_outcomes": ["credentials_extracted"],
        "iteration_count": 1, "max_iterations": 4, "attempted_agents": ["sqli_union"],
        "observations": {"union_select_possible": True, "error_messages_enabled": True},
        "endpoints": [{"module_name": "brute", "url": "http://localhost/dvwa/vulnerabilities/brute/"}]}


def test_destination_recon_records_containment_failure_and_closes_session(monkeypatch):
    state = fresh_sqli_chain_state()
    session = MagicMock()
    session.login.side_effect = ContainmentError(
        "external redirect rejected", url="https://external.invalid/", allowed_host="localhost")
    monkeypatch.setattr(import_module("foundation.recon"), "DVWASession", lambda target: session)

    update = chaining_router_node(state)

    assert update["next_agent"] != "bf_dictionary"
    assert update["observations"] == {}
    assert update["containment_events"][0]["classification"] == "scope_violation"
    assert update["containment_events"][0]["blocked_url"] == "https://external.invalid/"
    session.close.assert_called_once()
    session.get.assert_not_called()


def test_proved_enabling_outcome_triggers_akg_chain():
    """A proved enabling outcome may route its explicitly linked next method."""
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": ["credentials_extracted"],
        **proved_chain_source("credentials_extracted"),
        "iteration_count": 1,
        "max_iterations": 30,
        "current_surface": "brute_force",
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "observations": {"no_rate_limit": True, "force_browse_endpoints_visible": True},
        "experiment_condition": "akg_guided_hybrid",
    }
    next_agent, event = evaluate_chain_route(state)
    assert next_agent == "bf_dictionary"
    assert event["reason"] == "chain_ready"


def test_same_source_destination_probe_runs_once_per_router_pass(monkeypatch):
    """A completion recorded earlier in one pass must stop the next same edge."""
    from core import chaining_coordinator as coordinator
    state = {
        **new_default_state(),
        **proved_chain_source("authenticated_session"),
        "target_url": "http://fixture.invalid/dvwa",
        "experiment_condition": "akg_guided_hybrid",
        "current_surface": "brute_force",
        "stop_policy": "coverage",
        "coverage_target": 1.0,
        "achieved_outcomes": ["authenticated_session"],
        "attempted_agents": ["bf_dictionary", "ac_force_browse"],
        "observations": {"no_rate_limit": True},
    }
    edges = coordinator._chain_candidates(state)
    edge = next(row for row in edges if row["target_agent"] == "ac_idor")
    monkeypatch.setattr(coordinator, "_chain_candidates",
                        lambda _state: [dict(edge), dict(edge)])
    calls: list[tuple[str, list[str]]] = []

    def fake_probe(probe_state, method, source_ids):
        if any(
            event.get("event") == "recon.destination.completed"
            and (event.get("payload") or {}).get("method") == method
            and (event.get("payload") or {}).get("source_evidence_ids") == source_ids
            for event in probe_state.get("telemetry_events", [])
        ):
            return {}
        calls.append((method, list(source_ids)))

        return {
            "telemetry_events": [{
                "node": "chaining_router", "event": "recon.destination.completed",
                "payload": {"method": method, "source_evidence_ids": list(source_ids),
                            "reason": "probe_evidence_unavailable", "observations": {}},
            }]
        }

    recon_module = import_module("foundation.recon")
    monkeypatch.setattr(recon_module, "probe_access_control_destination", fake_probe)
    before = deepcopy(state)
    coordinator.chaining_router_node(state)
    assert calls == [("ac_idor", ["source-evidence"])]
    assert state == before, "the router must not mutate its input state"


def test_distinct_sources_probe_independently(monkeypatch):
    """A completion for one source must not suppress a different source edge."""
    from core import chaining_coordinator as coordinator
    state = {
        **new_default_state(),
        **proved_chain_source("authenticated_session"),
        "target_url": "http://fixture.invalid/dvwa",
        "experiment_condition": "akg_guided_hybrid",
        "current_surface": "brute_force",
        "stop_policy": "coverage",
        "coverage_target": 1.0,
        "response_evidence": [
            {"evidence_id": "source-evidence-1"},
            {"evidence_id": "source-evidence-2"},
        ],
        "verifier_history": [
            {"decision": "confirmed", "achieved_outcomes": ["authenticated_session"],
             "evidence_refs": ["#/final_state/response_evidence/0"]},
            {"decision": "confirmed", "achieved_outcomes": ["brute_force_confirmed"],
             "evidence_refs": ["#/final_state/response_evidence/1"]},
        ],
        "attempted_agents": ["bf_dictionary", "ac_force_browse"],
        "observations": {"no_rate_limit": True},
    }
    edges = [
        {"source": "authenticated_session", "target": "ac_idor",
         "target_agent": "ac_idor"},
        {"source": "brute_force_confirmed", "target": "ac_idor",
         "target_agent": "ac_idor"},
    ]
    monkeypatch.setattr(coordinator, "_chain_candidates", lambda _state: edges)
    monkeypatch.setattr(coordinator, "_chain_infeasibility",
                        lambda _state, _edge: "offline_unknown")
    calls: list[tuple[str, list[str]]] = []

    def fake_probe(probe_state, method, source_ids):
        if any(
            event.get("event") == "recon.destination.completed"
            and (event.get("payload") or {}).get("method") == method
            and (event.get("payload") or {}).get("source_evidence_ids") == source_ids
            for event in probe_state.get("telemetry_events", [])
        ):
            return {}
        calls.append((method, list(source_ids)))
        return {
            "telemetry_events": [{
                "node": "chaining_router", "event": "recon.destination.completed",
                "payload": {"method": method, "source_evidence_ids": list(source_ids),
                            "reason": "probe_evidence_unavailable", "observations": {}},
            }]
        }

    recon_module = import_module("foundation.recon")
    monkeypatch.setattr(recon_module, "probe_access_control_destination", fake_probe)
    before = deepcopy(state)
    coordinator.chaining_router_node(state)
    assert calls == [
        ("ac_idor", ["source-evidence-1"]),
        ("ac_idor", ["source-evidence-2"]),
    ]
    assert state == before, "the router must not mutate its input state"


def test_linear_condition_does_not_take_cross_surface_chain():
    """The baseline condition must not receive AKG-guided chain routing."""
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": ["credentials_extracted"],
        "iteration_count": 1,
        "max_iterations": 30,
        "current_surface": "sqli",
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "observations": {},
        "experiment_condition": "linear_hybrid",
    }
    next_agent, event = evaluate_chain_route(state)
    assert next_agent == "orchestrator"
    assert event["reason"] == "no_chain"


def test_routed_selection_grades_destination_method_preconditions():
    """G16: AKG edge prerequisites must not replace the destination's own keys."""
    from foundation.preconditions import precondition_keys_for_method

    state = fresh_sqli_chain_state()
    state["observations"] = {**state["observations"], "no_rate_limit": True}

    update = chaining_router_node(state)

    assert update["next_agent"] == "bf_dictionary"
    decision = next(row for row in update["scoring_decisions"]
        if row.get("dimension") == "Smethod" and row.get("method") == "bf_dictionary")
    assert decision["preconditions"] == precondition_keys_for_method("bf_dictionary") == ["no_rate_limit"]
    assert decision["viable"] is True
    assert decision["score"] == 3
    route = update["active_chain_route"]
    assert route["preconditions"] == ["credentials_extracted"]
    assert route["route_preconditions"] == ["credentials_extracted"]
    assert [row["preconditions"] for row in update["chain_history"]] == [
        ["credentials_extracted"], ["credentials_extracted"]]
