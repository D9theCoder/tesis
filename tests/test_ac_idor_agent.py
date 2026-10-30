"""Tests for ac_idor_agent — PROBE, EXPLOIT, CHAIN CHECK stages."""

import pytest
import importlib
from types import SimpleNamespace
from unittest.mock import MagicMock

idor = importlib.import_module("agents.access_control.ac_idor_agent")
from agents.access_control.ac_idor_agent import ac_idor_agent
from tests.support import ready_state
from foundation.session_manager import session_fingerprint

@pytest.fixture
def base_state():
    """Supports regression tests for test ac idor agent."""
    state = ready_state("ac_idor")
    state["target_url"] = "http://localhost/dvwa"
    state["security_level"] = "low"
    return state

def _make_mock_session(login_ok=True):
    """Supports regression tests for test ac idor agent."""
    session = MagicMock()
    session.login.return_value = login_ok
    session.set_security_level.return_value = None
    return session

def _make_response(status_code=200, text="No data"):
    """Supports regression tests for test ac idor agent."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp

def _use_documented_nonadmin_session(monkeypatch, session):
    session.http = SimpleNamespace(cookies={"PHPSESSID": "fixture-nonadmin"})
    monkeypatch.setattr(idor, "open_access_control_session",
        lambda *args: (session, "gordonb", session_fingerprint(session), None))

def test_probe_no_idor(base_state, monkeypatch):
    """When same response for all IDs, score 0."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(200, "Same response for all")

    _use_documented_nonadmin_session(monkeypatch, mock_session)
    result = ac_idor_agent(base_state)

    assert result["scores"]["ac_idor"] == 0
    assert result["observations"].get("object_ids_enumerable") is False

def test_visible_object_data_without_permission_control_is_probe_only(base_state, monkeypatch):
    """Generic object data does not confirm an IDOR without a permission oracle."""
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        """Supports regression tests for test ac idor agent."""
        uid = (params or {}).get("userId", "1")
        if uid == "1":
            return _make_response(200, "First name: admin<br>Surname: admin")
        return _make_response(200, f"First name: Gordon<br>Surname: Brown<br>User ID: {uid}")

    mock_session.get.side_effect = mock_get

    _use_documented_nonadmin_session(monkeypatch, mock_session)
    result = ac_idor_agent(base_state)

    assert result["scores"]["ac_idor"] == 1
    assert not result.get("confirmed_vulns")
    assert result["verifier_decision"]["decision"] == "not_confirmed"
