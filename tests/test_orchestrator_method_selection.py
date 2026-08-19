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


def test_experiment_condition_changes_deterministic_selection(monkeypatch):
    class FakeKnowledgeGraph:
        def get_viable_methods(self, surface, observations):
            return ["sqli_time_blind"]

    monkeypatch.setattr("agents.orchestrator.AttackKnowledgeGraph", FakeKnowledgeGraph)
    base = {
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
    }

    assert _fallback_next_agent({**base, "experiment_condition": "linear_hybrid"}) == "sqli_union"
    assert _fallback_next_agent({**base, "experiment_condition": "akg_guided_hybrid"}) == "sqli_time_blind"


def test_akg_fallback_does_not_execute_unviable_method(monkeypatch):
    class FakeKnowledgeGraph:
        def get_viable_methods(self, surface, observations):
            return []

    monkeypatch.setattr("agents.orchestrator.AttackKnowledgeGraph", FakeKnowledgeGraph)
    assert _fallback_next_agent({
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "experiment_condition": "akg_guided_hybrid",
    }) == "scorer"


def test_akg_fallback_filters_cross_surface_methods(monkeypatch):
    class FakeKnowledgeGraph:
        def get_viable_methods(self, surface, observations):
            return ["ac_force_browse", "sqli_error"]

    monkeypatch.setattr("agents.orchestrator.AttackKnowledgeGraph", FakeKnowledgeGraph)
    assert _fallback_next_agent({
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "experiment_condition": "akg_guided_hybrid",
    }) == "sqli_error"


def test_akg_orchestrator_rejects_cross_surface_llm_choice(monkeypatch):
    class FakeKnowledgeGraph:
        def get_viable_methods(self, surface, observations):
            return ["sqli_error"]

    class FakeLLM:
        def invoke(self, messages):
            return type("Response", (), {"content": '{"next_agent": "ac_idor"}'})()

    monkeypatch.setattr("agents.orchestrator.AttackKnowledgeGraph", FakeKnowledgeGraph)
    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: FakeLLM())
    result = orchestrator({
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
        "evasion_cooldown_threshold": 5,
        "consecutive_clean_responses": 0,
        "experiment_condition": "akg_guided_hybrid",
    })

    assert result["selected_method"] == "sqli_error"
    assert result["next_agent"] == "payload_candidate_builder"


def test_akg_orchestrator_does_not_route_cross_surface_choice_when_none_viable(monkeypatch):
    """A cross-surface model choice must not become an executable method."""
    class FakeKnowledgeGraph:
        def get_viable_methods(self, surface, observations):
            return []

    class FakeLLM:
        def invoke(self, messages):
            return type("Response", (), {"content": '{"next_agent": "ac_force_browse", "selected_method": "ac_force_browse"}'})()

    monkeypatch.setattr("agents.orchestrator.AttackKnowledgeGraph", FakeKnowledgeGraph)
    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: FakeLLM())
    result = orchestrator({
        "target_url": "http://localhost/dvwa",
        "security_level": "high",
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
        "evasion_cooldown_threshold": 5,
        "consecutive_clean_responses": 0,
        "experiment_condition": "akg_guided_hybrid",
    })

    assert result["viable_methods"] == []
    assert result["selected_method"] is None
    assert result["next_agent"] == "scorer"
    decision = next(event for event in result["telemetry_events"] if event["event"] == "orchestrator.decision")
    assert decision["payload"] == {"next_agent": "scorer", "used_fallback": True}


def test_akg_viable_methods_are_filtered_to_active_surface(monkeypatch):
    """AKG output cannot widen the active surface's canonical allow-list."""
    class FakeKnowledgeGraph:
        def get_viable_methods(self, surface, observations):
            return ["ac_force_browse", "sqli_error"]

    class FakeLLM:
        def invoke(self, messages):
            return type("Response", (), {"content": '{"next_agent": "sqli_error"}'})()

    monkeypatch.setattr("agents.orchestrator.AttackKnowledgeGraph", FakeKnowledgeGraph)
    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: FakeLLM())
    result = orchestrator({
        "target_url": "http://localhost/dvwa",
        "security_level": "high",
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
        "evasion_cooldown_threshold": 5,
        "consecutive_clean_responses": 0,
        "experiment_condition": "akg_guided_hybrid",
    })

    assert result["viable_methods"] == ["sqli_error"]
    assert result["selected_method"] == "sqli_error"
    assert result["next_agent"] == "payload_candidate_builder"


def test_target_method_explicit_selection_preserves_target_events(monkeypatch):
    """An explicit in-surface target remains selectable despite AKG viability."""
    class FakeKnowledgeGraph:
        def get_viable_methods(self, surface, observations):
            return []

    monkeypatch.setattr("agents.orchestrator.AttackKnowledgeGraph", FakeKnowledgeGraph)
    result = orchestrator({
        "target_url": "http://localhost/dvwa",
        "security_level": "high",
        "llm_provider": "gemini",
        "current_surface": "sqli",
        "target_method": "sqli_time_blind",
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
        "evasion_cooldown_threshold": 5,
        "consecutive_clean_responses": 0,
        "experiment_condition": "akg_guided_hybrid",
    })

    assert result["selected_method"] == "sqli_time_blind"
    assert result["next_agent"] == "payload_candidate_builder"
    assert result["telemetry_events"][0]["event"] == "orchestrator.target_method.selected"
    assert result["telemetry_events"][0]["payload"] == {
        "target_method": "sqli_time_blind",
        "viable": False,
    }


def test_target_method_cross_surface_stops_with_infeasible_event():
    """An explicit target from another surface cannot override containment."""
    result = orchestrator({
        "target_url": "http://localhost/dvwa",
        "security_level": "high",
        "llm_provider": "gemini",
        "current_surface": "sqli",
        "target_method": "ac_force_browse",
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
        "evasion_cooldown_threshold": 5,
        "consecutive_clean_responses": 0,
        "experiment_condition": "akg_guided_hybrid",
    })

    assert result["selected_method"] is None
    assert result["next_agent"] == "scorer"
    assert result["fallback_events"] == [{
        "event": "target_method.infeasible",
        "target_method": "ac_force_browse",
        "surface": "sqli",
    }]
    assert result["telemetry_events"][0]["event"] == "orchestrator.target_method.infeasible"


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
