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
