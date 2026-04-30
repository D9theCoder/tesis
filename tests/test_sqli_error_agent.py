"""Tests for sqli_error_agent — PROBE, EXPLOIT, CHAIN CHECK stages."""

import pytest
from unittest.mock import MagicMock, patch

from agents.sqli.sqli_error_agent import sqli_error_agent
from core.state import new_default_state


@pytest.fixture
def base_state():
    state = new_default_state()
    state["target_url"] = "http://localhost/dvwa"
    state["security_level"] = "low"
    return state


def _make_mock_session(login_ok=True):
    session = MagicMock()
    session.login.return_value = login_ok
    session.set_security_level.return_value = None
    return session


def _make_response(status_code=200, text="No results"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def test_probe_detects_error_messages(base_state):
    """When SQL syntax error appears in response, precondition met."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(
        200, "You have an error in your SQL syntax near ''1'''"
    )

    with patch("agents.sqli.sqli_error_agent.DVWASession", return_value=mock_session):
        result = sqli_error_agent(base_state)

    assert result["scores"]["sqli_error"] >= 1
    assert result["observations"].get("error_messages_enabled") is True


def test_probe_no_error_returns_zero(base_state):
    """When no error message appears, score should be 0."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(200, "Normal page")

    with patch("agents.sqli.sqli_error_agent.DVWASession", return_value=mock_session):
        result = sqli_error_agent(base_state)

    assert result["scores"]["sqli_error"] == 0
    assert result["observations"].get("error_messages_enabled") is False


def test_exploit_extracts_data(base_state):
    """When error-based extraction succeeds, score >= 3."""
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        payload = (params or {}).get("id", "")
        if "extractvalue" in payload or "UNION" in payload:
            return _make_response(200, "~dvwa<br>admin:password")
        return _make_response(200, "You have an error in your SQL syntax")

    mock_session.get.side_effect = mock_get

    with patch("agents.sqli.sqli_error_agent.DVWASession", return_value=mock_session):
        result = sqli_error_agent(base_state)

    assert result["scores"]["sqli_error"] >= 3
    assert "sqli_confirmed" in result.get("confirmed_vulns", [])


def test_chain_check_triggers_score_four(base_state):
    """When sqli_confirmed is in state and chain edge is satisfied, score = 4."""
    base_state["confirmed_vulns"] = ["sqli_confirmed"]
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        payload = (params or {}).get("id", "")
        if "extractvalue" in payload or "UNION" in payload:
            return _make_response(200, "~dvwa<br>admin:password")
        return _make_response(200, "You have an error in your SQL syntax")

    mock_session.get.side_effect = mock_get

    with patch("agents.sqli.sqli_error_agent.DVWASession", return_value=mock_session):
        result = sqli_error_agent(base_state)

    assert result["scores"]["sqli_error"] == 4
    assert "credentials_extracted" in result.get("achieved_outcomes", [])


def test_login_failure(base_state):
    """Login failure should return score 0."""
    mock_session = _make_mock_session(login_ok=False)

    with patch("agents.sqli.sqli_error_agent.DVWASession", return_value=mock_session):
        result = sqli_error_agent(base_state)

    assert result["scores"]["sqli_error"] == 0
