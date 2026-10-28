"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import pytest
from tests.support import READY_RECEIPT
from agents.orchestrator import orchestrator, _fallback_next_agent

def test_experiment_condition_changes_deterministic_selection(monkeypatch):
    base = {
        "current_surface": "sqli",
        "observations": {"response_delay_measurable": True},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
    }

    assert _fallback_next_agent({**base, "experiment_condition": "linear_hybrid"}) == "sqli_union"
    assert _fallback_next_agent({**base, "experiment_condition": "akg_guided_hybrid"}) == "sqli_time_blind"

def test_akg_fallback_does_not_execute_unviable_method(monkeypatch):
    assert _fallback_next_agent({
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "experiment_condition": "akg_guided_hybrid",
    }) == "scorer"

def test_akg_fallback_filters_cross_surface_methods(monkeypatch):
    assert _fallback_next_agent({
        "current_surface": "sqli",
        "observations": {"error_messages_enabled": True, "force_browse_endpoints_visible": True},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "experiment_condition": "akg_guided_hybrid",
    }) == "sqli_error"

def test_akg_orchestrator_rejects_cross_surface_llm_choice(monkeypatch):
    class FakeLLM:
        def invoke(self, messages):
            return type("Response", (), {"content": '{"next_agent": "ac_idor"}'})()

    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: FakeLLM())
    result = orchestrator({
        "target_url": "http://localhost/dvwa",
        "readiness": READY_RECEIPT,
        "security_level": "low",
        "llm_provider": "openai_compatible",
        "current_surface": "sqli",
        "observations": {"error_messages_enabled": True},
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
    """No viable AKG method stops cleanly without an LLM selection call."""
    monkeypatch.setattr(
        "agents.orchestrator.get_llm",
        lambda *args, **kwargs: pytest.fail("orchestrator LLM must not be called"),
    )
    result = orchestrator({
        "target_url": "http://localhost/dvwa",
        "readiness": READY_RECEIPT,
        "security_level": "high",
        "llm_provider": "openai_compatible",
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
    assert result["task_result"] == "INCOMPLETE"
    assert result["incomplete_reason"] == "NO_VIABLE_METHODS"

def test_akg_viable_methods_are_filtered_to_active_surface(monkeypatch):
    """AKG output cannot widen the active surface's canonical allow-list."""
    class FakeLLM:
        def invoke(self, messages):
            return type("Response", (), {"content": '{"next_agent": "sqli_error"}'})()

    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: FakeLLM())
    result = orchestrator({
        "target_url": "http://localhost/dvwa",
        "readiness": READY_RECEIPT,
        "security_level": "high",
        "llm_provider": "openai_compatible",
        "current_surface": "sqli",
        "observations": {"error_messages_enabled": True, "force_browse_endpoints_visible": True},
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
    result = orchestrator({
        "target_url": "http://localhost/dvwa",
        "readiness": READY_RECEIPT,
        "security_level": "high",
        "llm_provider": "openai_compatible",
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
        "readiness": READY_RECEIPT,
        "security_level": "high",
        "llm_provider": "openai_compatible",
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
        "method": None, "visit_id": None, "origin": "orchestrator", "scope": "run",
    }]
    assert result["telemetry_events"][0]["event"] == "orchestrator.target_method.infeasible"
