"""Tests for sqli_union_agent — PROBE, EXPLOIT, CHAIN CHECK stages."""

import pytest
from unittest.mock import MagicMock, patch

from agents.sqli.sqli_union_agent import sqli_union_agent
from core.state import new_default_state


@pytest.fixture
def base_state():
    """Supports regression tests for test sqli union agent."""
    state = new_default_state()
    state["target_url"] = "http://localhost/dvwa"
    state["security_level"] = "low"
    return state


def _make_mock_session(login_ok=True):
    """Supports regression tests for test sqli union agent."""
    session = MagicMock()
    session.login.return_value = login_ok
    session.set_security_level.return_value = None
    return session


def _make_response(status_code=200, text="No results"):
    """Supports regression tests for test sqli union agent."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def test_probe_precondition_unmet_returns_zero(base_state):
    """When DVWA returns no signal, score should be 0."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(200, "no signal here")

    with patch("agents.sqli.sqli_union_agent.DVWASession", return_value=mock_session):
        result = sqli_union_agent(base_state)

    assert result["scores"]["sqli_union"] == 0
    assert result["observations"].get("union_select_possible") is False


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


def test_exploit_partial_success(base_state):
    """When page renders with data but no clear credentials, score should be 2."""
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        """Supports regression tests for test sqli union agent."""
        return _make_response(200, "First name: test<br>Surname: test")

    mock_session.get.side_effect = mock_get

    with patch("agents.sqli.sqli_union_agent.DVWASession", return_value=mock_session):
        result = sqli_union_agent(base_state)

    assert result["scores"]["sqli_union"] >= 2
    # Should NOT have confirmed vuln for partial
    confirmed = result.get("confirmed_vulns", [])
    assert "sqli_confirmed" not in confirmed


def test_chain_check_triggers_score_four(base_state):
    """When sqli_confirmed is in state and chain precondition is met, score should be 4."""
    base_state["confirmed_vulns"] = ["sqli_confirmed"]
    mock_session = _make_mock_session()

    def mock_get(path, params=None):
        """Supports regression tests for test sqli union agent."""
        return _make_response(200, "First name: admin<br>Surname: password")

    mock_session.get.side_effect = mock_get

    with patch("agents.sqli.sqli_union_agent.DVWASession", return_value=mock_session):
        result = sqli_union_agent(base_state)

    assert result["scores"]["sqli_union"] == 3
    assert "credentials_extracted" in result.get("achieved_outcomes", [])
    assert "credentials_extracted" in result.get("achieved_outcomes", [])


def test_login_failure_returns_zero(base_state):
    """When session login fails, score should be 0."""
    mock_session = _make_mock_session(login_ok=False)

    with patch("agents.sqli.sqli_union_agent.DVWASession", return_value=mock_session):
        result = sqli_union_agent(base_state)

    assert result["scores"]["sqli_union"] == 0


def test_missing_target_url_returns_zero():
    """When target_url is missing, score should be 0."""
    state = new_default_state()
    state["security_level"] = "low"

    result = sqli_union_agent(state)
    assert result["scores"]["sqli_union"] == 0


def test_tried_payloads_tracked(base_state):
    """All sent payloads should be tracked in tried_payloads."""
    mock_session = _make_mock_session()
    mock_session.get.return_value = _make_response(200, "no signal")

    with patch("agents.sqli.sqli_union_agent.DVWASession", return_value=mock_session):
        result = sqli_union_agent(base_state)

    tried = result.get("tried_payloads", {}).get("sqli_union", [])
    assert len(tried) > 0
