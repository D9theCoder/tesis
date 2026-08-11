"""Tests for ac_force_browse_agent — PROBE, EXPLOIT, CHAIN CHECK stages."""

import pytest
from unittest.mock import MagicMock, patch

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


def test_probe_detects_accessible_pages(base_state):
    """When protected page is accessible without proper auth, precondition met."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(
        200, "Database Setup<br>DVWA Security"
    )

    with patch("agents.access_control.ac_force_browse_agent.DVWASession", return_value=mock_session):
        result = ac_force_browse_agent(base_state)

    assert result["scores"]["ac_force_browse"] >= 1
    assert result["observations"].get("force_browse_endpoints_visible") is True


def test_probe_no_accessible_pages(base_state):
    """When all pages redirect or 403, score 0."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(403, "Forbidden")

    with patch("agents.access_control.ac_force_browse_agent.DVWASession", return_value=mock_session):
        result = ac_force_browse_agent(base_state)

    assert result["scores"]["ac_force_browse"] == 0


def test_exploit_confirms_force_browse(base_state):
    """When source code or setup page accessed, score >= 3."""
    mock_session = _make_mock_session()

    def mock_get(path, **kwargs):
        """Supports regression tests for test ac force browse agent."""
        if "setup" in path or "view_source" in path:
            return _make_response(200, "Database Setup<br>source code visible")
        return _make_response(200, "DVWA Security Level")

    mock_session.get.side_effect = mock_get

    with patch("agents.access_control.ac_force_browse_agent.DVWASession", return_value=mock_session):
        result = ac_force_browse_agent(base_state)

    assert result["scores"]["ac_force_browse"] >= 3
    assert "ac_force_browse_confirmed" in result.get("confirmed_vulns", [])


def test_login_failure(base_state):
    """Verifies login failure behavior."""
    mock_session = _make_mock_session(login_ok=False)
    with patch("agents.access_control.ac_force_browse_agent.DVWASession", return_value=mock_session):
        result = ac_force_browse_agent(base_state)
    assert result["scores"]["ac_force_browse"] == 0
