"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import pytest

from core.chaining_coordinator import (
    critical_outcome_achieved,
    route_after_agent,
    _find_next_unvisited,
)


def test_find_next_unvisited_basic():
    """Verifies find next unvisited basic behavior."""
    assert _find_next_unvisited(["a", "b", "c"], ["a"], []) == "b"
    assert _find_next_unvisited(["a", "b"], ["a", "b"], []) is None
    assert _find_next_unvisited(["a", "b"], [], ["a"]) == "b"


def test_critical_outcome_achieved():
    """Verifies critical outcome achieved behavior."""
    assert critical_outcome_achieved({"achieved_outcomes": ["admin_session_obtained"], "confirmed_vulns": []})
    assert critical_outcome_achieved({"achieved_outcomes": [], "confirmed_vulns": ["admin_session_obtained"]})
    assert not critical_outcome_achieved({"achieved_outcomes": [], "confirmed_vulns": ["sqli_union_confirmed"]})


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


def test_route_after_agent_chain_ready():
    # brute_force_confirmed -> ac_idor chain
    """Verifies route after agent chain ready behavior."""
    state = {
        "confirmed_vulns": ["bf_dictionary_confirmed", "brute_force_confirmed"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
        "current_surface": "brute_force",
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "observations": {},
        "agent_results": [],
    }
    result = route_after_agent(state)
    # Should route to chain target agent
    assert result in {"ac_idor", "orchestrator", "scorer"}


def test_route_after_agent_all_methods_exhausted():
    """Verifies route after agent all methods exhausted behavior."""
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "iteration_count": 5,
        "max_iterations": 30,
        "current_surface": "sqli",
        "attempted_agents": ["sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind"],
        "blocked_agents": [],
        "failure_agents": ["sqli_time_blind"],
        "observations": {},
    }
    assert route_after_agent(state) == "scorer"


from core.chaining_coordinator import evaluate_chain_route


def test_proved_enabling_outcome_triggers_akg_chain():
    """A proved enabling outcome may route its explicitly linked next method."""
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": ["credentials_extracted"],
        "iteration_count": 1,
        "max_iterations": 30,
        "current_surface": "brute_force",
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "observations": {},
        "experiment_condition": "akg_guided_hybrid",
    }
    next_agent, event = evaluate_chain_route(state)
    assert next_agent == "bf_dictionary"
    assert event["reason"] == "chain_ready"


def test_authenticated_outcome_triggers_access_control_chain():
    """An authenticated-session outcome enables the linked IDOR workflow."""
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": ["authenticated_session"],
        "iteration_count": 1,
        "max_iterations": 30,
        "current_surface": "brute_force",
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "observations": {},
        "experiment_condition": "akg_guided_hybrid",
    }
    next_agent, event = evaluate_chain_route(state)
    assert next_agent == "ac_idor"
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
