"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from tests.support import READY_RECEIPT
from agents.orchestrator import orchestrator, _fallback_next_agent


def test_akg_fallback_does_not_execute_unviable_method(monkeypatch):
    assert _fallback_next_agent({
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "experiment_condition": "akg_guided_hybrid",
    }) == "scorer"


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
