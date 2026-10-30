"""Tests for sqli_union_agent — PROBE, EXPLOIT, CHAIN CHECK stages."""

import pytest
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

from agents.sqli.sqli_union_agent import sqli_union_agent
from tests.support import ready_state

@pytest.fixture
def base_state():
    """Supports regression tests for test sqli union agent."""
    state = ready_state("sqli_union")
    state["target_url"] = "http://localhost/dvwa"
    state["security_level"] = "low"
    return state

def _make_mock_session(login_ok=True):
    """Supports regression tests for test sqli union agent."""
    session = MagicMock()
    session.http = SimpleNamespace(cookies={"PHPSESSID": "fixture-admin"})
    session._principal_id = "admin"
    session.login.return_value = login_ok
    session.set_security_level.return_value = None
    return session

def _make_response(status_code=200, text="No results"):
    """Supports regression tests for test sqli union agent."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def test_probe_success_then_exploit_full(base_state):
    """When probe detects signal and exploit finds credentials, score >= 3."""
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        """Supports regression tests for test sqli union agent."""
        payload = (params or {}).get("id", "")
        if "UNION" in payload and "users" in payload:
            return _make_response(200, "First name: admin<br>Surname: password")
        return _make_response(200, "First name: test<br>Surname: test")

    mock_session.get.side_effect = mock_get

    with patch("agents.sqli.sqli_union_agent.DVWASession", return_value=mock_session):
        result = sqli_union_agent(base_state)

    assert result["scores"]["sqli_union"] >= 3
    assert "sqli_union_confirmed" in result.get("confirmed_vulns", [])
    assert "credentials_extracted" in result.get("achieved_outcomes", [])

def test_login_failure_returns_zero(base_state):
    """When session login fails, score should be 0."""
    mock_session = _make_mock_session(login_ok=False)

    with patch("agents.sqli.sqli_union_agent.DVWASession", return_value=mock_session):
        result = sqli_union_agent(base_state)

    assert result["scores"]["sqli_union"] == 0
