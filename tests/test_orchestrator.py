"""Tests for 3-surface orchestrator."""

import pytest

from agents.orchestrator import orchestrator, _fallback_next_agent


def test_orchestrator_stops_when_budget_exhausted():
    """Verifies orchestrator stops when budget exhausted behavior."""
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
    assert update["task_result"] == "INCOMPLETE"
    assert update["incomplete_reason"] == "ITERATION_LIMIT"
    assert update["telemetry_events"] == [{
        "node": "orchestrator",
        "iteration": 30,
        "event": "orchestrator.stop",
        "status": "incomplete",
        "payload": {"reason": "ITERATION_LIMIT"},
    }]


def test_orchestrator_critical_outcome_routes_to_scorer():
    """Verifies orchestrator critical outcome routes to scorer behavior."""
    state = {
        "target_url": "http://localhost/dvwa",
        "confirmed_vulns": [],
        "achieved_outcomes": ["admin_session_obtained"],
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


def test_orchestrator_labels_model_scorer_stop_after_method_exhaustion(monkeypatch):
    """A scorer stop after an exhausted viable set must retain a terminal reason."""
    class FakeKnowledgeGraph:
        def get_viable_methods(self, surface, observations):
            return ["ac_force_browse"]

    class FakeLLM:
        def invoke(self, messages):
            return type("Response", (), {
                "content": '{"next_agent":"scorer","reason_code":"best_viable"}',
            })()

    monkeypatch.setattr("agents.orchestrator.AttackKnowledgeGraph", FakeKnowledgeGraph)
    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: FakeLLM())
    result = orchestrator({
        "target_url": "http://localhost/dvwa",
        "security_level": "high",
        "llm_provider": "openai_compatible",
        "current_surface": "access_control",
        "observations": {},
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "attempted_agents": ["ac_force_browse"],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
        "method_scores": {},
        "iteration_count": 2,
        "max_iterations": 30,
        "payload_mode": "llm_mutation_only",
        "experiment_condition": "akg_guided_hybrid",
        "evasion_enabled": False,
        "evasion_mode": "reactive",
        "evasion_max_retries": 3,
        "evasion_cooldown_threshold": 5,
        "consecutive_clean_responses": 0,
    })

    assert result["next_agent"] == "scorer"
    assert result["task_result"] == "INCOMPLETE"
    assert result["incomplete_reason"] == "ALL_METHODS_FAILED"
    assert any(
        event["event"] == "orchestrator.stop"
        and event["payload"] == {"reason": "ALL_METHODS_FAILED"}
        for event in result["telemetry_events"]
    )


def test_orchestrator_distinguishes_model_scorer_stop_before_exhaustion(monkeypatch):
    """A semantic scorer stop before method exhaustion is not all-methods failure."""
    class FakeKnowledgeGraph:
        def get_viable_methods(self, surface, observations):
            return ["ac_force_browse", "ac_idor"]

    class FakeLLM:
        def invoke(self, messages):
            return type("Response", (), {
                "content": '{"next_agent":"scorer","reason_code":"best_viable"}',
            })()

    monkeypatch.setattr("agents.orchestrator.AttackKnowledgeGraph", FakeKnowledgeGraph)
    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: FakeLLM())
    result = orchestrator({
        "target_url": "http://localhost/dvwa",
        "security_level": "high",
        "llm_provider": "openai_compatible",
        "current_surface": "access_control",
        "observations": {},
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "attempted_agents": ["ac_force_browse"],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
        "method_scores": {},
        "iteration_count": 2,
        "max_iterations": 30,
        "payload_mode": "llm_mutation_only",
        "experiment_condition": "akg_guided_hybrid",
        "evasion_enabled": False,
        "evasion_mode": "reactive",
        "evasion_max_retries": 3,
        "evasion_cooldown_threshold": 5,
        "consecutive_clean_responses": 0,
    })

    assert result["next_agent"] == "scorer"
    assert result["task_result"] == "INCOMPLETE"
    assert result["incomplete_reason"] == "MODEL_STOPPED_WITHOUT_FINDING"


def test_orchestrator_counts_execution_failure_as_attempted_for_terminal_reason(monkeypatch):
    """A recorded agent failure must not degrade an exhausted stop to unspecified."""
    class FakeKnowledgeGraph:
        def get_viable_methods(self, surface, observations):
            return ["ac_force_browse"]

    class FakeLLM:
        def invoke(self, messages):
            return type("Response", (), {
                "content": '{"next_agent":"scorer","reason_code":"best_viable"}',
            })()

    monkeypatch.setattr("agents.orchestrator.AttackKnowledgeGraph", FakeKnowledgeGraph)
    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: FakeLLM())
    result = orchestrator({
        "target_url": "http://localhost/dvwa",
        "security_level": "high",
        "llm_provider": "openai_compatible",
        "current_surface": "access_control",
        "observations": {},
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": ["ac_force_browse"],
        "scores": {},
        "method_scores": {},
        "iteration_count": 2,
        "max_iterations": 30,
        "payload_mode": "llm_mutation_only",
        "experiment_condition": "akg_guided_hybrid",
        "evasion_enabled": False,
        "evasion_mode": "reactive",
        "evasion_max_retries": 3,
        "evasion_cooldown_threshold": 5,
        "consecutive_clean_responses": 0,
    })

    assert result["incomplete_reason"] == "ALL_METHODS_FAILED"


def test_fallback_next_agent_returns_viable_method():
    """Verifies fallback next agent returns viable method behavior."""
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
    """Verifies fallback next agent all exhausted behavior."""
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
