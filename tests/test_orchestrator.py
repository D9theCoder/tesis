"""Tests for 3-surface orchestrator."""

import pytest

from agents.orchestrator import orchestrator, _fallback_next_agent


def test_orchestrator_stops_when_budget_exhausted():
    state = {
        "target_url": "http://localhost/dvwa",
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "iteration_count": 30,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
        "evasion_enabled": False,
        "evasion_mode": "reactive",
        "evasion_max_retries": 3,
        "consecutive_clean_responses": 0,
    }
    update = orchestrator(state)
    assert update["next_agent"] == "scorer"


def test_orchestrator_critical_outcome_routes_to_scorer():
    state = {
        "target_url": "http://localhost/dvwa",
        "confirmed_vulns": [],
        "achieved_outcomes": ["rce_achieved"],
        "iteration_count": 1,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
        "evasion_enabled": False,
        "evasion_mode": "reactive",
        "evasion_max_retries": 3,
        "consecutive_clean_responses": 0,
    }
    update = orchestrator(state)
    assert update["next_agent"] == "scorer"


def test_fallback_next_agent_returns_viable_method():
    state = {
        "current_surface": "sqli",
        "observations": {"error_messages_enabled": True, "union_select_possible": True},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
    }
    result = _fallback_next_agent(state)
    assert result in {"sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind", "scorer"}


def test_fallback_next_agent_all_exhausted():
    state = {
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": ["sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind"],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
    }
    result = _fallback_next_agent(state)
    assert result == "scorer"
