"""Tests for bf_dictionary_agent — PROBE, EXPLOIT, CHAIN CHECK stages."""

import pytest
from unittest.mock import MagicMock, patch

from agents.brute_force.bf_dictionary_agent import bf_dictionary_agent
from core.state import new_default_state


@pytest.fixture
def base_state():
    """Supports regression tests for test bf dictionary agent."""
    state = new_default_state()
    state["target_url"] = "http://localhost/dvwa"
    state["security_level"] = "low"
    return state


def _make_mock_session(login_ok=True):
    """Supports regression tests for test bf dictionary agent."""
    session = MagicMock()
    session.login.return_value = login_ok
    session.set_security_level.return_value = None
    return session


def _make_response(status_code=200, text="Incorrect"):
    """Supports regression tests for test bf dictionary agent."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.elapsed_ms = 0.0
    return resp


def test_probe_detects_no_rate_limit(base_state):
    """When requests complete quickly, no_rate_limit = True."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(200, "Username and/or password incorrect.")

    with patch("agents.brute_force.bf_dictionary_agent.DVWASession", return_value=mock_session):
        result = bf_dictionary_agent(base_state)

    assert result["scores"]["bf_dictionary"] >= 1
    assert result["observations"].get("no_rate_limit") is True


def test_exploit_finds_credentials(base_state):
    """When valid credentials found, score >= 3."""
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        """Supports regression tests for test bf dictionary agent."""
        username = (params or {}).get("username", "")
        password = (params or {}).get("password", "")
        if username == "admin" and password == "password":
            return _make_response(200, "Welcome to the password protected area admin!<br>")
        return _make_response(200, "Username and/or password incorrect.")

    mock_session.get.side_effect = mock_get

    with patch("agents.brute_force.bf_dictionary_agent.DVWASession", return_value=mock_session):
        result = bf_dictionary_agent(base_state)

    assert result["scores"]["bf_dictionary"] >= 3
    assert "bf_dictionary_confirmed" in result.get("confirmed_vulns", [])
    assert "authenticated_session" in result.get("achieved_outcomes", [])
    creds = result.get("found_credentials", [])
    assert any(c.get("username") == "admin" for c in creds)


def test_chain_check_triggers_score_four(base_state):
    """When brute_force_confirmed in state, chain check may trigger score 4."""
    base_state["confirmed_vulns"] = ["brute_force_confirmed"]
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        """Supports regression tests for test bf dictionary agent."""
        username = (params or {}).get("username", "")
        password = (params or {}).get("password", "")
        if username == "admin" and password == "password":
            return _make_response(200, "Welcome to the password protected area admin!")
        return _make_response(200, "Username and/or password incorrect.")

    mock_session.get.side_effect = mock_get

    with patch("agents.brute_force.bf_dictionary_agent.DVWASession", return_value=mock_session):
        result = bf_dictionary_agent(base_state)

    assert result["scores"]["bf_dictionary"] == 3
    # AKG chain: brute_force_confirmed -> ac_idor (target_agent)
    achieved = result.get("achieved_outcomes", [])
    assert len(achieved) > 0


def test_login_failure(base_state):
    """Verifies login failure behavior."""
    mock_session = _make_mock_session(login_ok=False)
    with patch("agents.brute_force.bf_dictionary_agent.DVWASession", return_value=mock_session):
        result = bf_dictionary_agent(base_state)
    assert result["scores"]["bf_dictionary"] == 0


def test_missing_target_url():
    """Verifies missing target url behavior."""
    state = new_default_state()
    state["security_level"] = "low"
    result = bf_dictionary_agent(state)
    assert result["scores"]["bf_dictionary"] == 0
