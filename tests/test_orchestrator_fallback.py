"""Tests for orchestrator fallback diversification (3-surface refactor)."""

from __future__ import annotations

from agents.orchestrator import _fallback_next_agent

def test_fallback_prioritizes_lowest_score():
    """Verifies fallback prioritizes lowest score behavior."""
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

def test_fallback_exhausts_surface_methods_before_scorer():
    """Verifies fallback exhausts surface methods before scorer behavior."""
    state = {
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": ["sqli_union", "sqli_error", "sqli_boolean_blind"],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
    }
    agent = _fallback_next_agent(state)
    assert agent == "sqli_time_blind"

def test_fallback_does_not_repeat_blocked_agent():
    """Verifies fallback does not repeat blocked agent behavior."""
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
