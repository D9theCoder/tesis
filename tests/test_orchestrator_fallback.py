"""Tests for orchestrator fallback diversification (3-surface refactor)."""

from __future__ import annotations

from agents.orchestrator import _fallback_next_agent


def test_fallback_returns_starter_when_nothing_confirmed():
    state = {
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
    }
    agent = _fallback_next_agent(state)
    assert agent in {"sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind", "scorer"}


def test_fallback_cycles_starters_when_all_attempted():
    state = {
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": ["sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind"],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
    }
    agent = _fallback_next_agent(state)
    assert agent == "scorer"


def test_fallback_prioritizes_unexplored_method():
    state = {
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": ["sqli_union"],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {"sqli_union": 4, "sqli_error": 0},
    }
    agent = _fallback_next_agent(state)
    assert agent != "sqli_union"
    assert agent in {"sqli_error", "sqli_boolean_blind", "sqli_time_blind", "scorer"}


def test_fallback_prioritizes_lowest_score():
    state = {
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": ["sqli_union"],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {"sqli_union": 4, "sqli_error": 0, "sqli_boolean_blind": 1},
    }
    agent = _fallback_next_agent(state)
    # sqli_error has score 0, should be prioritized
    assert agent == "sqli_error"


def test_fallback_returns_scorer_for_exhausted_surface():
    state = {
        "current_surface": "access_control",
        "observations": {},
        "attempted_agents": ["ac_idor", "ac_vertical_escalation", "ac_force_browse"],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {"ac_idor": 4},
    }
    agent = _fallback_next_agent(state)
    assert agent == "scorer"


def test_fallback_does_not_repeat_blocked_agent():
    state = {
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": ["sqli_union"],
        "blocked_agents": ["sqli_error"],
        "failure_agents": [],
        "scores": {"sqli_union": 4, "sqli_error": 0},
    }
    agent = _fallback_next_agent(state)
    assert agent != "sqli_error"
    assert agent in {"sqli_boolean_blind", "sqli_time_blind", "scorer"}


def test_fallback_all_attempted_returns_scorer():
    state = {
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": ["sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind"],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {"sqli_union": 4, "sqli_error": 0, "sqli_boolean_blind": 2},
    }
    agent = _fallback_next_agent(state)
    # All attempted, should return scorer
    assert agent == "scorer"
