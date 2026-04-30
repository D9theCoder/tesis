import pytest
from core.chaining_coordinator import evaluate_chain_route, _find_next_unvisited


def test_find_next_unvisited():
    assert _find_next_unvisited(["a", "b", "c"], ["a"], []) == "b"
    assert _find_next_unvisited(["a", "b"], ["a", "b"], []) is None


def test_all_exhausted_returns_scorer():
    state = {
        "iteration_count": 5,
        "max_iterations": 30,
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "current_surface": "sqli",
        "attempted_agents": ["sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind"],
        "blocked_agents": [],
        "failure_agents": ["sqli_time_blind"],
        "observations": {},
    }
    next_agent, event = evaluate_chain_route(state)
    assert next_agent == "scorer"
    assert event["reason"] == "all_methods_exhausted"
