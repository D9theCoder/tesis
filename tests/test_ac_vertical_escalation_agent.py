"""Tests for ac_vertical_escalation_agent — PROBE, EXPLOIT, CHAIN CHECK stages."""

import pytest
import importlib
from types import SimpleNamespace
from unittest.mock import MagicMock

vertical = importlib.import_module("agents.access_control.ac_vertical_escalation_agent")
from agents.access_control.ac_vertical_escalation_agent import ac_vertical_escalation_agent
from core.state import new_default_state

@pytest.fixture
def base_state():
    """Supports regression tests for test ac vertical escalation agent."""
    state = new_default_state()
    state["target_url"] = "http://localhost/dvwa"
    state["security_level"] = "low"
    return state

def _make_mock_session(login_ok=True):
    """Supports regression tests for test ac vertical escalation agent."""
    session = MagicMock()
    session.login.return_value = login_ok
    session.set_security_level.return_value = None
    return session

def _make_response(status_code=200, text="No data"):
    """Supports regression tests for test ac vertical escalation agent."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp

def _use_documented_nonadmin_session(monkeypatch, session):
    session.http = SimpleNamespace(cookies={"PHPSESSID": "fixture-nonadmin"})
    monkeypatch.setattr(vertical, "open_access_control_session",
        lambda *args: (session, "gordonb", "initial-session-fingerprint", None))

def test_probe_no_admin_access(base_state, monkeypatch):
    """When admin access is not possible, score 0."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(200, "Access denied")

    _use_documented_nonadmin_session(monkeypatch, mock_session)
    result = ac_vertical_escalation_agent(base_state)

    assert result["scores"]["ac_vertical_escalation"] == 0

def test_admin_looking_html_without_record_oracle_does_not_confirm(base_state, monkeypatch):
    """HTML resembling admin data is not a structured candidate-owned record."""
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        """Supports regression tests for test ac vertical escalation agent."""
        return _make_response(200, "First name: admin<br>Surname: admin<br>User ID: 1")

    mock_session.get.side_effect = mock_get

    _use_documented_nonadmin_session(monkeypatch, mock_session)
    result = ac_vertical_escalation_agent(base_state)

    assert result["scores"]["ac_vertical_escalation"] == 0
    assert not result.get("confirmed_vulns")
    assert result["verifier_decision"]["decision"] == "not_confirmed"

def test_missing_documented_nonadmin_session_fails_closed(base_state, monkeypatch):
    """Session setup failure does not perform unbound privilege probes."""
    def fail_session(*args):
        raise ValueError("fixture lacks documented non-admin identity")

    monkeypatch.setattr(vertical, "open_access_control_session", fail_session)
    result = ac_vertical_escalation_agent(base_state)
    assert result["scores"]["ac_vertical_escalation"] == 0
