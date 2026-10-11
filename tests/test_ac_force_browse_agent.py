"""Tests for ac_force_browse_agent — PROBE, EXPLOIT, CHAIN CHECK stages."""

import pytest
import importlib
from types import SimpleNamespace
from unittest.mock import MagicMock

force_browse = importlib.import_module("agents.access_control.ac_force_browse_agent")
from agents.access_control.ac_force_browse_agent import ac_force_browse_agent
from core.state import new_default_state

@pytest.fixture
def base_state():
    """Supports regression tests for test ac force browse agent."""
    state = new_default_state()
    state["target_url"] = "http://localhost/dvwa"
    state["security_level"] = "low"
    return state

def _make_mock_session(login_ok=True):
    """Supports regression tests for test ac force browse agent."""
    session = MagicMock()
    session.login.return_value = login_ok
    session.set_security_level.return_value = None
    return session

def _make_response(status_code=200, text="Not found"):
    """Supports regression tests for test ac force browse agent."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp

def _use_documented_nonadmin_session(monkeypatch, session):
    session.http = SimpleNamespace(cookies={"PHPSESSID": "fixture-nonadmin"})
    monkeypatch.setattr(force_browse, "open_access_control_session",
        lambda *args: (session, "gordonb", "initial-session-fingerprint", None))

def test_probe_no_accessible_pages(base_state, monkeypatch):
    """When all pages redirect or 403, score 0."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(403, "Forbidden")

    _use_documented_nonadmin_session(monkeypatch, mock_session)
    result = ac_force_browse_agent(base_state)

    assert result["scores"]["ac_force_browse"] == 0

def test_visible_content_without_permission_control_is_probe_only(base_state, monkeypatch):
    """Page visibility alone must not confirm unauthorized access."""
    mock_session = _make_mock_session()

    def mock_get(path, **kwargs):
        """Supports regression tests for test ac force browse agent."""
        if "setup" in path or "view_source" in path:
            return _make_response(200, "Database Setup<br>source code visible")
        return _make_response(200, "DVWA Security Level")

    mock_session.get.side_effect = mock_get

    _use_documented_nonadmin_session(monkeypatch, mock_session)
    result = ac_force_browse_agent(base_state)

    assert result["scores"]["ac_force_browse"] == 1
    assert not result.get("confirmed_vulns")
    assert result["verifier_decision"]["decision"] == "not_confirmed"
def test_missing_documented_nonadmin_session_fails_closed(base_state, monkeypatch):
    """Session setup failure does not perform unbound permission probes."""
    def fail_session(*args):
        raise ValueError("fixture lacks documented non-admin identity")

    monkeypatch.setattr(force_browse, "open_access_control_session", fail_session)
    result = ac_force_browse_agent(base_state)
    assert result["scores"]["ac_force_browse"] == 0
