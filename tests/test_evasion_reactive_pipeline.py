"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import pytest
from unittest.mock import MagicMock, patch


def test_clean_response_skips_evasion():
    """Verifies clean response skips evasion behavior."""
    from agents.orchestrator import orchestrator
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
        "evasion_enabled": True,
        "evasion_mode": "reactive",
        "evasion_max_retries": 3,
        "consecutive_clean_responses": 0,
    }
    with patch("agents.orchestrator.get_llm") as mock_get_llm:
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content='{"next_agent": "sqli_union"}')
        mock_get_llm.return_value = mock_llm
        result = orchestrator(state)
        events = result.get("telemetry_events", [])
        skipped_events = [e for e in events if e.get("event") == "orchestrator.evasion.skipped"]
        assert len(skipped_events) > 0
