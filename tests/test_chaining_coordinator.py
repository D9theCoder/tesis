"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""

from copy import deepcopy
from importlib import import_module
from unittest.mock import MagicMock

import pytest

from core.chaining_coordinator import chaining_router_node, evaluate_chain_route, route_after_agent
from core.state import new_default_state
from foundation.http_client import ContainmentError

def proved_chain_source(source):
    return {"response_evidence": [{"evidence_id": "source-evidence", "candidate_id": "source-candidate", "visit_id": "source-visit"}],
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


@pytest.mark.parametrize("status_code,expected", [(200, True), (429, False), (503, None)])
def test_sqli_chain_measures_missing_destination_preconditions(monkeypatch, status_code, expected):
    state = fresh_sqli_chain_state()
    before = deepcopy(state)
    session = MagicMock()
    session.login.return_value = True
    response = MagicMock(status_code=status_code, text="Incorrect", headers={}, elapsed_ms=10.0)
    session.get.return_value = response
    monkeypatch.setattr(import_module("foundation.recon"), "DVWASession", lambda target: session)

    update = chaining_router_node(state)

    assert state == before
    assert session.get.call_count == 2
    assert {call.kwargs["params"]["username"] for call in session.get.call_args_list} == {"rate_test", "probe"}
    session.close.assert_called_once()
    assert update["observations"].get("no_rate_limit") is expected
    assert update["next_agent"] == ("bf_dictionary" if expected is True else "orchestrator")
    if expected is True:
        assert update["iteration_count"] == 2
        selection = next(row for row in update["scoring_decisions"] if row["dimension"] == "Smethod")
        assert selection["observations"]["no_rate_limit"] is True
        assert not any(row.get("target_agent") == "bf_dictionary" and row.get("status") == "infeasible"
                       for row in update.get("chain_history", []))
    else:
        assert "selected_visit_id" not in update
    # Even inconclusive transport must not trigger another probe on each router visit.
    if expected is None:
        chaining_router_node({**state, **update})
        assert session.get.call_count == 2


@pytest.mark.parametrize("case", ["known", "budget", "hash", "linear", "attempted"])
def test_destination_recon_does_not_run_without_a_pending_consumable_chain(monkeypatch, case):
    state = fresh_sqli_chain_state()
    if case == "known":
        state["observations"]["no_rate_limit"] = False
    elif case == "budget":
        state["max_iterations"] = 1
    elif case == "hash":
        state["found_credentials"][0]["representation"] = "password_hash"
    elif case == "linear":
        state["experiment_condition"] = "linear_hybrid"
    else:
        state["attempted_agents"].append("bf_dictionary")
    factory = MagicMock(side_effect=AssertionError("unexpected destination HTTP"))
    monkeypatch.setattr(import_module("foundation.recon"), "DVWASession", factory)

    update = chaining_router_node(state)

    factory.assert_not_called()
    assert update["next_agent"] != "bf_dictionary"


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


def test_route_after_agent_budget_exhausted():
    """Verifies route after agent budget exhausted behavior."""
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "iteration_count": 30,
        "max_iterations": 30,
        "current_surface": "sqli",
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "observations": {},
    }
    assert route_after_agent(state) == "scorer"

def test_route_after_agent_fallback_orchestrator():
    """Verifies route after agent fallback orchestrator behavior."""
    state = {
        "confirmed_vulns": ["sqli_union_confirmed"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
        "current_surface": "sqli",
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "observations": {},
        "agent_results": [],
    }
    assert route_after_agent(state) == "orchestrator"

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

def test_authenticated_outcome_triggers_access_control_chain():
    """An authenticated-session outcome selects the first registered AC route."""
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": ["authenticated_session"],
        **proved_chain_source("authenticated_session"),
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
    assert next_agent == "ac_force_browse"
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
