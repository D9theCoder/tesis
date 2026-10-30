"""Tests for orchestrator loop prevention and telemetry accuracy."""

from __future__ import annotations
from tests.support import READY_RECEIPT

from unittest.mock import patch

from agents.orchestrator import orchestrator

class TestUsedFallbackAccuracy:
    """Verify used_fallback is true ONLY when LLM parsing fails."""


    def test_provider_exception_marks_fallback_as_incomplete(self):
        """A deterministic fallback cannot turn a failed model runtime into success."""
        state = {
            "iteration_count": 0,
            "max_iterations": 30,
            "confirmed_vulns": [],
            "achieved_outcomes": [],
            "attempted_agents": [],
            "blocked_agents": [],
            "failure_agents": [],
            "current_surface": "sqli",
            # Keep one method viable so the provider exception path is
            # exercised; an empty AKG viable set now intentionally skips LLM.
            "observations": {"union_select_possible": True},
            "scores": {},
            "consecutive_clean_responses": 0,
            "llm_provider": "openai_compatible",
            "security_level": "low",
            "evasion_enabled": False,
            "readiness": dict(READY_RECEIPT),
            "experiment_condition": "akg_guided_hybrid",
        }

        with patch("agents.orchestrator.get_llm", side_effect=RuntimeError("provider unavailable")):
            result = orchestrator(state)

        assert result["task_result"] == "INCOMPLETE"
        assert result["incomplete_reason"] == "LLM_RUNTIME_FAILURE"
        assert result["fallback_events"] == [{
            "event": "orchestrator.llm_failure",
            "error_type": "RuntimeError",
            "next_agent": "sqli_union",
            "method": "sqli_union", "visit_id": "sqli_union:visit:1",
            "origin": "orchestrator", "scope": "method",
        }]
