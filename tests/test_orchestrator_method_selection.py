"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import pytest
from agents.orchestrator import orchestrator, _fallback_next_agent


def test_fallback_next_agent_returns_viable_method():
    """Verifies fallback next agent returns viable method behavior."""
    state = {
        "current_surface": "sqli",
        "observations": {"error_messages_enabled": True},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
    }
    result = _fallback_next_agent(state)
    assert result in {"sqli_error", "sqli_union", "sqli_boolean_blind", "sqli_time_blind", "scorer"}


def test_orchestrator_returns_dict():
    """Verifies orchestrator returns dict behavior."""
    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "llm_provider": "gemini",
        "current_surface": "sqli",
        "observations": {},
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
        "iteration_count": 0,
        "max_iterations": 30,
        "evasion_enabled": False,
        "evasion_mode": "reactive",
        "evasion_max_retries": 3,
        "consecutive_clean_responses": 0,
    }
    # This may try to call LLM; just verify it returns a dict structure
    # We can't fully test without mocking LLM
    result = orchestrator(state)
    assert isinstance(result, dict)
