"""Behavior controls for readiness, scoped evidence, and bounded detection.

These tests cover the runtime contract implemented by slice B.  They do not
perform live DVWA or provider calls; every HTTP interaction is a fake session.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.state import new_default_state
from foundation.preconditions import (
    derive_precondition_status,
    make_observation_fact,
    observation_update,
)
from foundation.readiness import build_readiness, readiness_gate
from foundation.session_manager import DVWASession
from tests.support import ready_state


def _fact(key, value, **overrides):
    payload = {"source": "detection_control", "method": "sqli_error",
               "security_level": "low", "visit_id": "sqli_error:visit:1"}
    payload.update(overrides)
    return make_observation_fact(key, value, **payload)


def _state_with_fact(key, value, **overrides):
    state = ready_state()
    fact = _fact(key, value, **overrides)
    state.update(observation_update(state, [fact], method="sqli_error"))
    state["observation_facts"] = [fact]
    return state


def _fake_llm(decisions):
    class FakeLLM:
        def __init__(self):
            self.calls = 0

        def invoke(self, messages):
            decision = decisions[min(self.calls, len(decisions) - 1)]
            self.calls += 1
            return SimpleNamespace(content=json.dumps(decision))

    return FakeLLM()


# ---------------------------------------------------------------- evidence


def test_transport_unknown_does_not_become_false():
    unknown = _fact("response_delay_measurable", None, method="sqli_time_blind",
                    detail="baseline unavailable")
    state = new_default_state()
    state["observation_facts"] = [unknown]
    status = derive_precondition_status(state)
    assert status["response_delay_measurable"] == "unknown"


# ---------------------------------------------------------------- readiness


def test_readiness_fails_closed_on_level_mismatch_and_preserves_coordinate():
    receipt = build_readiness(
        state={"current_surface": "sqli", "security_level": "high"},
        login_ok=True, requested_level="high", observed_level="low",
        endpoints=[{"url": "http://x/vulnerabilities/sqli/"},
                   {"url": "http://x/vulnerabilities/sqli_blind/"}],
        requested_principal="admin", observed_principal="admin",
        token_present=None, setup_state="authenticated_crawl")
    assert receipt["requested_level"] == "high"
    assert receipt["observed_level"] == "low"
    gate = readiness_gate(receipt)
    assert receipt["status"] == "failed"
    assert gate["decision"] == "block"
    assert gate["code"] == "security_level_mismatch"


def test_brute_force_token_requirement_is_observed_not_assumed():
    """Only a level whose form declares ``user_token`` requires a token."""
    medium = build_readiness(
        state={"current_surface": "brute_force", "security_level": "medium"},
        login_ok=True, requested_level="medium", observed_level="medium",
        endpoints=[{"url": "http://x/vulnerabilities/brute/",
                    "method": "get", "params": ["username", "password", "Login"]}],
        requested_principal="admin", observed_principal="admin",
        token_present=False, setup_state="authenticated_crawl")
    assert medium["token"]["required"] is False
    assert medium["status"] == "ready"

    declared_but_absent = build_readiness(
        state={"current_surface": "brute_force", "security_level": "high"},
        login_ok=True, requested_level="high", observed_level="high",
        endpoints=[{"url": "http://x/vulnerabilities/brute/",
                    "method": "get", "params": ["username", "password", "user_token"],
                    "csrf_token": "tok"}],
        requested_principal="admin", observed_principal="admin",
        token_present=False, setup_state="authenticated_crawl")
    assert declared_but_absent["token"]["required"] is True
    assert declared_but_absent["status"] == "failed"
    assert readiness_gate(declared_but_absent)["code"] == "required_token_missing"

    declared_and_present = build_readiness(
        state={"current_surface": "brute_force", "security_level": "high"},
        login_ok=True, requested_level="high", observed_level="high",
        endpoints=[{"url": "http://x/vulnerabilities/brute/",
                    "method": "get", "params": ["username", "password", "user_token"],
                    "csrf_token": "tok"}],
        requested_principal="admin", observed_principal="admin",
        token_present=True, setup_state="authenticated_crawl")
    assert declared_and_present["status"] == "ready"


# --------------------------------------------------------------- catalog


def test_empty_brute_force_control_list_sends_zero_requests():
    from agents.brute_force.bf_dictionary_agent import _probe_preconditions

    session = MagicMock()
    ok, tried, observations, events = _probe_preconditions(
        session, [], set(), security_level="low")
    assert ok is False and tried == [] and observations == {} and events == []
    session.get.assert_not_called()
    session.post.assert_not_called()


# ------------------------------------------------------------- selection


def test_rejected_model_selection_records_and_stops_without_retry(monkeypatch):
    from agents.orchestrator import orchestrator

    fake = _fake_llm([{"next_agent": "sqli_error", "reason_code": "first"}])
    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: fake)
    state = _state_with_fact("error_messages_enabled", False)
    state.update({"target_url": "http://localhost/dvwa", "current_surface": "sqli",
                  "experiment_condition": "linear_hybrid", "security_level": "low"})
    update = orchestrator(state)
    assert update["next_agent"] == "scorer"
    assert update["task_result"] == "INCOMPLETE"
    assert update["incomplete_reason"] == "SELECTION_REJECTED"
    assert update["selection_rejections"][0]["method"] == "sqli_error"
    assert update["selection_rejections"][0]["decision_origin"] == "model"
    assert update["selection_rejections"][0]["observations"]["error_messages_enabled"] is False
    assert update["model_call_requirements"][0]["status"] == "completed"
    assert "selection_rejected" in update["model_call_requirements"][0]["reason"]
    assert fake.calls == 1


# ------------------------------------------------------- execution identity


# -------------------------------------------------------------- quarantine


def test_quarantined_run_blocks_orchestrator_without_model_call(monkeypatch):
    from agents.orchestrator import orchestrator

    calls = []
    monkeypatch.setattr("agents.orchestrator.get_llm",
                        lambda *args, **kwargs: calls.append(1))
    state = ready_state()
    state.update({
        "target_url": "http://localhost/dvwa", "current_surface": "sqli",
        "quarantined_visits": [{
            "visit_id": "sqli_error:visit:1", "method": "sqli_error",
            "control_id": "control:1", "control_class": "detection",
            "reason": "unexpected_sensitive_disclosure", "detail": "restricted data",
            "evidence_refs": ["control:1"],
            "restoration": {"status": "not-established", "evidence_refs": []}}],
    })
    update = orchestrator(state)
    assert calls == []
    assert update["next_agent"] == "scorer"
    assert update["incomplete_reason"] == "CONTROL_CONTAMINATION"
    assert update["security_outcome"] == "fixture_limited"


# ------------------------------------------------------------ chain trace


# ------------------------------------------------------- method selection


# --------------------------------------------------- correction regressions


def test_unverified_security_level_is_a_setup_failure(monkeypatch):
    session = DVWASession("http://localhost/dvwa")
    try:
        monkeypatch.setattr(session, "_submit_security_form", lambda level: False)
        with pytest.raises(RuntimeError, match="not verified server-side"):
            session.set_security_level("high")
    finally:
        session.close()
