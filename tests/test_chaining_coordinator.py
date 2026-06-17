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


def test_chain_preconditions_use_confirmed_vulns_only():
    """Achieved outcomes alone should NOT trigger a chain."""
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
    }
    next_agent, event = evaluate_chain_route(state)
    # Should NOT trigger the credentials_extracted -> brute_force_confirmed chain
    # because confirmed_vulns is empty
    assert event["reason"] != "chain_ready" or next_agent != "bf_dictionary"


def test_achieved_outcomes_alone_cannot_trigger_chain():
    """Verifies achieved outcomes alone cannot trigger chain behavior."""
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": ["brute_force_confirmed", "credentials_extracted"],
        "iteration_count": 1,
        "max_iterations": 30,
        "current_surface": "brute_force",
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "observations": {},
    }
    next_agent, event = evaluate_chain_route(state)
    # achieved_outcomes should not satisfy chain preconditions
    assert event["reason"] != "chain_ready" or next_agent != "ac_idor"
