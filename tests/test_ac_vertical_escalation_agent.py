"""Tests for ac_vertical_escalation_agent — PROBE, EXPLOIT, CHAIN CHECK stages."""

import pytest
from unittest.mock import MagicMock, patch

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


def test_probe_detects_admin_access(base_state):
    """When admin user data is accessible, precondition met."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(
        200, "First name: admin<br>Surname: admin<br>User ID: 1"
    )

    with patch("agents.access_control.ac_vertical_escalation_agent.DVWASession", return_value=mock_session):
        result = ac_vertical_escalation_agent(base_state)

    assert result["scores"]["ac_vertical_escalation"] >= 1
    assert result["observations"].get("role_based_access_present") is True


def test_probe_no_admin_access(base_state):
    """When admin access is not possible, score 0."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(200, "Access denied")

    with patch("agents.access_control.ac_vertical_escalation_agent.DVWASession", return_value=mock_session):
        result = ac_vertical_escalation_agent(base_state)

    assert result["scores"]["ac_vertical_escalation"] == 0


def test_exploit_confirms_escalation(base_state):
    """When admin-level data accessed, score >= 3."""
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        """Supports regression tests for test ac vertical escalation agent."""
        return _make_response(200, "First name: admin<br>Surname: admin<br>User ID: 1")

    mock_session.get.side_effect = mock_get

    with patch("agents.access_control.ac_vertical_escalation_agent.DVWASession", return_value=mock_session):
        result = ac_vertical_escalation_agent(base_state)

    assert result["scores"]["ac_vertical_escalation"] >= 1


def test_login_failure(base_state):
    """Verifies login failure behavior."""
    mock_session = _make_mock_session(login_ok=False)
    with patch("agents.access_control.ac_vertical_escalation_agent.DVWASession", return_value=mock_session):
        result = ac_vertical_escalation_agent(base_state)
    assert result["scores"]["ac_vertical_escalation"] == 0
