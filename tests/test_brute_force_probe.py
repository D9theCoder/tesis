"""Regression tests for brute-force probe rate-limit classification."""

from unittest.mock import MagicMock, patch
from importlib import import_module

import pytest

from core.state import new_default_state


dictionary_module = import_module("agents.brute_force.bf_dictionary_agent")
spray_module = import_module("agents.brute_force.bf_spray_agent")


PROBE_MODULES = (dictionary_module, spray_module)


def _response(*, status_code: int = 200, text: str = "Incorrect", elapsed_ms: float = 1_200.0):
    response = MagicMock()
    response.status_code = status_code
    response.text = text
    response.headers = {}
    response.elapsed_ms = elapsed_ms
    return response


@pytest.mark.parametrize("module", PROBE_MODULES, ids=["dictionary", "spray"])
def test_uniformly_slow_dvwa_is_not_classified_as_rate_limited(module):
    """A slow baseline must still allow the exploit stage to run."""
    session = MagicMock()
    session.get.return_value = _response(elapsed_ms=1_200.0)

    probe_ok, tried, observations, _events = module._probe_preconditions(
        session,
        ["rate_test:test", "probe:probe"],
        set(),
    )

    assert probe_ok is True
    assert tried == ["rate_test:test", "probe:probe"]
    assert observations["no_rate_limit"] is True


@pytest.mark.parametrize("module", PROBE_MODULES, ids=["dictionary", "spray"])
def test_explicit_rate_limit_response_stops_probe(module):
    """A server-declared throttle remains a failed precondition."""
    session = MagicMock()
    session.get.return_value = _response(
        status_code=429,
        text="Too many requests; try again later.",
        elapsed_ms=1_200.0,
    )

    probe_ok, _tried, observations, events = module._probe_preconditions(
        session,
        ["rate_test:test", "probe:probe"],
        set(),
    )

    assert probe_ok is False
    assert observations["no_rate_limit"] is False
    assert events[0]["payload"]["signal_detected"] is False


@pytest.mark.parametrize("module", PROBE_MODULES, ids=["dictionary", "spray"])
def test_relative_latency_increase_remains_rate_limit_signal(module):
    """A throttle that only delays follow-up responses is still detected."""
    session = MagicMock()
    session.get.side_effect = [
        _response(elapsed_ms=100.0),
        _response(elapsed_ms=400.0),
    ]

    probe_ok, _tried, observations, _events = module._probe_preconditions(
        session,
        ["rate_test:test", "probe:probe"],
        set(),
    )

    assert probe_ok is False
    assert observations["no_rate_limit"] is False


@pytest.mark.parametrize("module", PROBE_MODULES, ids=["dictionary", "spray"])
def test_high_random_latency_is_not_classified_as_rate_limited(module):
    """High DVWA random sleep must not prevent the exploit stage."""
    session = MagicMock()
    session.get.side_effect = [
        _response(
            text='<input name="user_token" value="token-a">',
            elapsed_ms=100.0,
        ),
        _response(elapsed_ms=100.0),
        _response(
            text='<input name="user_token" value="token-b">',
            elapsed_ms=400.0,
        ),
        _response(elapsed_ms=400.0),
    ]
    session._extract_user_token.side_effect = lambda html: (
        html.split('value="', 1)[1].split('"', 1)[0]
    )

    probe_ok, _tried, observations, _events = module._probe_preconditions(
        session,
        ["rate_test:test", "probe:probe"],
        set(),
        security_level="high",
    )

    assert probe_ok is True
    assert observations["no_rate_limit"] is True


@pytest.mark.parametrize(
    ("module", "agent", "agent_id"),
    (
        (dictionary_module, dictionary_module.bf_dictionary_agent, "bf_dictionary"),
        (spray_module, spray_module.bf_spray_agent, "bf_spray"),
    ),
    ids=["dictionary", "spray"],
)
def test_slow_probe_does_not_skip_exploit_stage(module, agent, agent_id):
    """Regression for runs that tried only rate_test/probe on a slow DVWA."""
    state = new_default_state()
    state["target_url"] = "http://localhost/dvwa"
    state["security_level"] = "low"
    state["payload_candidates"] = {
        agent_id: [
            {"stage": "probe", "payload_or_logic": "rate_test:test"},
            {"stage": "probe", "payload_or_logic": "probe:probe"},
            {"stage": "exploit", "payload_or_logic": "admin:password"},
        ]
    }

    session = MagicMock()
    session.login.return_value = True
    session.set_security_level.return_value = None

    def get_response(_path, params=None):
        params = params or {}
        if params.get("username") == "admin" and params.get("password") == "password":
            return _response(text="Welcome to the password protected area admin!")
        return _response(elapsed_ms=1_200.0)

    session.get.side_effect = get_response
    with patch.object(module, "DVWASession", return_value=session):
        result = agent(state)

    assert result["observations"]["no_rate_limit"] is True
    assert result["scores"][agent_id] >= 3
    assert "admin:password" in result["tried_payloads"][agent_id]
    assert any(
        (call.kwargs.get("params") or {}).get("username") == "admin"
        for call in session.get.call_args_list
    )


@pytest.mark.parametrize("module", PROBE_MODULES, ids=["dictionary", "spray"])
def test_invalid_credentials_are_not_reported_as_exploit_success(module):
    """Brute-force telemetry success must represent semantic login confirmation."""
    session = MagicMock()
    session.get.return_value = _response(
        text="Username and/or password incorrect.",
        elapsed_ms=20.0,
    )

    score, _tried, confirmed, events, _credentials, boundary = module._attempt_exploit(
        session,
        ["admin:wrong"],
        set(),
        "low",
    )

    assert score == 0
    assert confirmed == []
    assert boundary is False
    assert [event["payload"]["success"] for event in events] == [False]
    assert [event["status"] for event in events] == ["failed"]
