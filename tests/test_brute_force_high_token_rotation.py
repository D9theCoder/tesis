"""Focused tests for high-security brute-force token rotation and retry."""

from types import SimpleNamespace
from unittest.mock import MagicMock, call

import pytest


BRUTE_AGENT_MODULES = (
    "agents.brute_force.bf_dictionary_agent",
    "agents.brute_force.bf_spray_agent",
)


def _response(text: str, *, status_code: int = 200) -> SimpleNamespace:
    return SimpleNamespace(text=text, status_code=status_code, elapsed_ms=1.0)


def _token_page(token: str) -> SimpleNamespace:
    return _response(f'<input type="hidden" name="user_token" value="{token}">')


def _session(*responses: SimpleNamespace) -> MagicMock:
    session = MagicMock()
    session.get.side_effect = list(responses)
    session._extract_user_token.side_effect = lambda html: html.split('value="', 1)[1].split('"', 1)[0]
    return session


@pytest.mark.parametrize("module_name", BRUTE_AGENT_MODULES)
def test_high_credential_request_refreshes_token_and_retries_csrf_rejection(module_name):
    """A stale token causes exactly one fresh-token retry for high security."""
    module = __import__(module_name, fromlist=["_credential_requests"])
    session = _session(
        _token_page("token-a"),
        _response("CSRF token is incorrect"),
        _token_page("token-b"),
        _response("Welcome to the password protected area"),
    )

    responses = module._credential_requests(
        session,
        "admin",
        "password",
        "high",
        None,
    )

    assert [response.text for response in responses] == [
        "CSRF token is incorrect",
        "Welcome to the password protected area",
    ]
    assert session.get.call_args_list == [
        call(module.MODULE_PATH),
        call(
            module.MODULE_PATH,
            params={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": "token-a",
            },
        ),
        call(module.MODULE_PATH),
        call(
            module.MODULE_PATH,
            params={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": "token-b",
            },
        ),
    ]


@pytest.mark.parametrize("module_name", BRUTE_AGENT_MODULES)
def test_high_credential_request_does_not_retry_more_than_once(module_name):
    """Repeated CSRF rejection is bounded and cannot loop indefinitely."""
    module = __import__(module_name, fromlist=["_credential_requests"])
    session = _session(
        _token_page("token-a"),
        _response("CSRF token is incorrect"),
        _token_page("token-b"),
        _response("CSRF token is incorrect"),
    )

    responses = module._credential_requests(
        session,
        "admin",
        "wrong",
        "high",
        None,
    )

    assert len(responses) == 2
    assert session.get.call_count == 4


@pytest.mark.parametrize("module_name", BRUTE_AGENT_MODULES)
def test_high_retry_telemetry_marks_stale_response_failed(module_name):
    """Intermediate CSRF rejection is visible as failed evidence."""
    module = __import__(module_name, fromlist=["_attempt_exploit"])
    session = _session(
        _token_page("token-a"),
        _response("CSRF token is incorrect"),
        _token_page("token-b"),
        _response("Welcome to the password protected area"),
    )

    score, _tried, confirmed, events, credentials, boundary = module._attempt_exploit(
        session,
        ["admin:password"],
        set(),
        "high",
        user_token=None,
    )

    assert score == 3
    assert confirmed
    assert credentials == [{"username": "admin", "password": "password"}]
    assert boundary is False
    assert [event["status"] for event in events] == ["failed", "ok"]
    assert events[0]["payload"]["success"] is False
    assert events[1]["payload"]["success"] is True


@pytest.mark.parametrize("module_name", BRUTE_AGENT_MODULES)
def test_low_credential_request_keeps_shared_token_without_refresh(module_name):
    """Lower levels retain the existing single-request token behavior."""
    module = __import__(module_name, fromlist=["_credential_requests"])
    response = _response("invalid credentials")
    session = _session(response)

    responses = module._credential_requests(
        session,
        "admin",
        "wrong",
        "medium",
        "shared-token",
    )

    assert responses == [response]
    session.get.assert_called_once_with(
        module.MODULE_PATH,
        params={
            "username": "admin",
            "password": "wrong",
            "Login": "Login",
            "user_token": "shared-token",
        },
    )
