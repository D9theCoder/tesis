"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""

from core.chaining_coordinator import evaluate_chain_route, route_after_agent

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
