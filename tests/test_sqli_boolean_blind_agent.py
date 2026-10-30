"""Tests for sqli_boolean_blind_agent — PROBE, EXPLOIT, CHAIN CHECK stages."""

import pytest
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

from agents.sqli.sqli_boolean_blind_agent import sqli_boolean_blind_agent
from tests.support import ready_state

@pytest.fixture
def base_state():
    """Supports regression tests for test sqli boolean blind agent."""
    state = ready_state("sqli_boolean_blind")
    state["target_url"] = "http://localhost/dvwa"
    state["security_level"] = "low"
    return state

def _make_mock_session(login_ok=True):
    """Supports regression tests for test sqli boolean blind agent."""
    session = MagicMock()
    session.http = SimpleNamespace(cookies={"PHPSESSID": "fixture-admin"})
    session._principal_id = "admin"
    session.login.return_value = login_ok
    session.set_security_level.return_value = None
    return session

def _make_response(status_code=200, text="No results"):
    """Supports regression tests for test sqli boolean blind agent."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp

def test_probe_no_difference_returns_zero(base_state):
    """When truthy and falsy responses are identical, score 0."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(200, "Same response always")

    with patch("agents.sqli.sqli_boolean_blind_agent.DVWASession", return_value=mock_session):
        result = sqli_boolean_blind_agent(base_state)

    assert result["scores"]["sqli_boolean_blind"] == 0

def test_exploit_confirmed(base_state):
    """When boolean condition true signal in response, score >= 3."""
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        """Supports regression tests for test sqli boolean blind agent."""
        payload = (params or {}).get("id", "")
        # Probe payloads need differentiated responses
        if "1=1" in payload:
            return _make_response(200, "User ID exists in the database")
        if "1=2" in payload:
            return _make_response(200, "User ID is missing from the database")
        # Exploit payloads return truthy signal
        return _make_response(200, "User ID exists in the database")

    mock_session.get.side_effect = mock_get

    with patch("agents.sqli.sqli_boolean_blind_agent.DVWASession", return_value=mock_session):
        result = sqli_boolean_blind_agent(base_state)

    assert result["scores"]["sqli_boolean_blind"] >= 3
    assert "sqli_boolean_blind_confirmed" in result.get("confirmed_vulns", [])
