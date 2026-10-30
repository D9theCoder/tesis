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
