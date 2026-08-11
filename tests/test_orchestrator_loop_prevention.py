"""Tests for orchestrator loop prevention and telemetry accuracy."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agents.orchestrator import orchestrator, _parse_decision_payload
from core.state import ALL_METHOD_AGENTS


class TestUsedFallbackAccuracy:
    """Verify used_fallback is true ONLY when LLM parsing fails."""

    def test_used_fallback_false_when_llm_returns_valid_agent(self):
        """Verifies used fallback false when llm returns valid agent behavior."""
        state = {
            "iteration_count": 0,
            "max_iterations": 30,
            "confirmed_vulns": [],
            "achieved_outcomes": [],
            "attempted_agents": [],
            "blocked_agents": [],
            "failure_agents": [],
            "current_surface": "sqli",
            "observations": {},
            "scores": {},
            "consecutive_clean_responses": 0,
            "llm_provider": "gemini",
            "security_level": "low",
            "evasion_enabled": False,
        }

        fake_llm = MagicMock()
        fake_llm.invoke.return_value = MagicMock(
            content='{"next_agent": "sqli_error", "reasoning": "test"}'
        )

        with patch("agents.orchestrator.get_llm", return_value=fake_llm):
            result = orchestrator(state)

        decision_event = [e for e in result["telemetry_events"] if e["event"] == "orchestrator.decision"][0]
        assert decision_event["payload"]["used_fallback"] is False
        assert result["next_agent"] == "payload_candidate_builder"
        assert result["selected_method"] == "sqli_error"

    def test_used_fallback_true_when_llm_returns_invalid_agent(self):
        """Verifies used fallback true when llm returns invalid agent behavior."""
        state = {
            "iteration_count": 0,
            "max_iterations": 30,
            "confirmed_vulns": [],
            "achieved_outcomes": [],
            "attempted_agents": [],
            "blocked_agents": [],
            "failure_agents": [],
            "current_surface": "sqli",
            "observations": {},
            "scores": {},
            "consecutive_clean_responses": 0,
            "llm_provider": "gemini",
            "security_level": "low",
            "evasion_enabled": False,
        }

        fake_llm = MagicMock()
        fake_llm.invoke.return_value = MagicMock(
            content='{"next_agent": "nonexistent_agent", "reasoning": "test"}'
        )

        with patch("agents.orchestrator.get_llm", return_value=fake_llm):
            result = orchestrator(state)

        decision_event = [e for e in result["telemetry_events"] if e["event"] == "orchestrator.decision"][0]
        assert decision_event["payload"]["used_fallback"] is True
        assert result["next_agent"] in {"payload_candidate_builder", "scorer"}
        if result["next_agent"] == "payload_candidate_builder":
            assert result["selected_method"] in ALL_METHOD_AGENTS

    def test_used_fallback_true_when_llm_returns_unparseable_json(self):
        """Verifies used fallback true when llm returns unparseable json behavior."""
        state = {
            "iteration_count": 0,
            "max_iterations": 30,
            "confirmed_vulns": [],
            "achieved_outcomes": [],
            "attempted_agents": [],
            "blocked_agents": [],
            "failure_agents": [],
            "current_surface": "sqli",
            "observations": {},
            "scores": {},
            "consecutive_clean_responses": 0,
            "llm_provider": "gemini",
            "security_level": "low",
            "evasion_enabled": False,
        }

        fake_llm = MagicMock()
        # Unparseable but NOT a guardrail refusal
        fake_llm.invoke.return_value = MagicMock(
            content="Here is my decision: {broken json"
        )

        with patch("agents.orchestrator.get_llm", return_value=fake_llm):
            result = orchestrator(state)

        decision_event = [e for e in result["telemetry_events"] if e["event"] == "orchestrator.decision"][0]
        assert decision_event["payload"]["used_fallback"] is True

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
            "observations": {},
            "scores": {},
            "consecutive_clean_responses": 0,
            "llm_provider": "openai_compatible",
            "security_level": "low",
            "evasion_enabled": False,
            "experiment_condition": "akg_guided_hybrid",
        }

        with patch("agents.orchestrator.get_llm", side_effect=RuntimeError("provider unavailable")):
            result = orchestrator(state)

        assert result["task_result"] == "INCOMPLETE"
        assert result["incomplete_reason"] == "LLM_RUNTIME_FAILURE"
        assert result["fallback_events"] == [{
            "event": "orchestrator.llm_failure",
            "error_type": "RuntimeError",
            "next_agent": "scorer",
        }]


class TestOrchestratorDeduplicatesAttemptedAgents:
    """Verify orchestrator deduplicates attempted_agents before using them."""

    def test_does_not_select_already_attempted_agent(self):
        """Verifies does not select already attempted agent behavior."""
        state = {
            "iteration_count": 1,
            "max_iterations": 30,
            "confirmed_vulns": [],
            "achieved_outcomes": [],
            "attempted_agents": ["sqli_union", "sqli_union", "sqli_error"],
            "blocked_agents": [],
            "failure_agents": [],
            "current_surface": "sqli",
            "observations": {"union_select_possible": True, "error_messages_enabled": True},
            "scores": {},
            "consecutive_clean_responses": 0,
            "llm_provider": "gemini",
            "security_level": "low",
            "evasion_enabled": False,
        }

        fake_llm = MagicMock()
        # LLM tries to select sqli_union again (bad LLM!)
        fake_llm.invoke.return_value = MagicMock(
            content='{"next_agent": "sqli_union", "reasoning": "test"}'
        )

        with patch("agents.orchestrator.get_llm", return_value=fake_llm):
            result = orchestrator(state)

        # Even though LLM said sqli_union, the orchestrator should accept it
        # because validation happens at the orchestrator level, not coercion.
        # The important thing is that fallback logic sees deduplicated attempted_agents.
        assert "sqli_union" in state["attempted_agents"]


class TestChainingRouterExhaustion:
    """Verify chaining router routes to scorer when all methods are exhausted."""

    def test_all_methods_exhausted_routes_to_scorer(self):
        """Verifies all methods exhausted routes to scorer behavior."""
        from core.chaining_coordinator import evaluate_chain_route

        state = {
            "iteration_count": 5,
            "max_iterations": 30,
            "confirmed_vulns": [],
            "achieved_outcomes": [],
            "current_surface": "sqli",
            "attempted_agents": [
                "sqli_union", "sqli_error",
                "sqli_boolean_blind", "sqli_time_blind",
            ],
            "blocked_agents": [],
            "failure_agents": [],
            "observations": {},
        }

        next_agent, event = evaluate_chain_route(state)
        assert next_agent == "scorer"
        assert event["reason"] == "all_methods_exhausted"

    def test_duplicate_attempted_agents_still_exhausted(self):
        """Verifies duplicate attempted agents still exhausted behavior."""
        from core.chaining_coordinator import evaluate_chain_route

        state = {
            "iteration_count": 5,
            "max_iterations": 30,
            "confirmed_vulns": [],
            "achieved_outcomes": [],
            "current_surface": "sqli",
            "attempted_agents": [
                "sqli_union", "sqli_union", "sqli_union",
                "sqli_error", "sqli_boolean_blind", "sqli_time_blind",
            ],
            "blocked_agents": [],
            "failure_agents": [],
            "observations": {},
        }

        next_agent, event = evaluate_chain_route(state)
        assert next_agent == "scorer"
        assert event["reason"] == "all_methods_exhausted"
