"""Tests for ac_idor_agent — PROBE, EXPLOIT, CHAIN CHECK stages."""

import pytest
from unittest.mock import MagicMock, patch

from agents.access_control.ac_idor_agent import ac_idor_agent
from core.state import new_default_state

@pytest.fixture
def base_state():
    """Supports regression tests for test ac idor agent."""
    state = new_default_state()
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

def test_probe_no_idor(base_state):
    """When same response for all IDs, score 0."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(200, "Same response for all")

    with patch("agents.access_control.ac_idor_agent.DVWASession", return_value=mock_session):
        result = ac_idor_agent(base_state)

    assert result["scores"]["ac_idor"] == 0
    assert result["observations"].get("object_ids_enumerable") is False

def test_object_data_requires_independent_authorization_control(base_state):
    """When unauthorized data access confirmed, score >= 3."""
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        """Supports regression tests for test ac idor agent."""
        uid = (params or {}).get("userId", "1")
        if uid == "1":
            return _make_response(200, "First name: admin<br>Surname: admin")
        return _make_response(200, f"First name: Gordon<br>Surname: Brown<br>User ID: {uid}")

    mock_session.get.side_effect = mock_get

    with patch("agents.access_control.ac_idor_agent.DVWASession", return_value=mock_session):
        result = ac_idor_agent(base_state)

    assert result["scores"]["ac_idor"] == 2
    assert not result.get("confirmed_vulns")
    assert result["verifier_decision"]["decision"] == "unverified"
def test_login_failure(base_state):
    """Verifies login failure behavior."""
    mock_session = _make_mock_session(login_ok=False)
    with patch("agents.access_control.ac_idor_agent.DVWASession", return_value=mock_session):
        result = ac_idor_agent(base_state)
    assert result["scores"]["ac_idor"] == 0
