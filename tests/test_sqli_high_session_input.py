"""Focused request-path tests for high-level SQLi session-input handling."""

from importlib import import_module
from unittest.mock import MagicMock

import pytest

SQLI_AGENT_MODULES = (
    "agents.sqli.sqli_union_agent",
    "agents.sqli.sqli_error_agent",
    "agents.sqli.sqli_boolean_blind_agent",
    "agents.sqli.sqli_time_blind_agent",
)

@pytest.mark.parametrize("module_name", SQLI_AGENT_MODULES)
def test_high_uses_the_module_specific_transport(module_name):
    """High SQLi requests use the session setter and return its reload response."""
    module = import_module(module_name)
    session = MagicMock()
    post_response = MagicMock(status_code=200, text="session setter response")
    reload_response = MagicMock(text="normal SQLi result")
    session.post.return_value = post_response
    session.get.return_value = reload_response

    result = module._request(session, "high", "1' UNION SELECT user,password FROM users#")

    assert result is reload_response
    if "blind" in module_name:
        session.post.assert_not_called()
        session.http.set_cookie.assert_called_once()
        session.get.assert_called_once_with("/vulnerabilities/sqli_blind/")
    else:
        session.post.assert_called_once_with(
            "/vulnerabilities/sqli/session-input.php",
            data={"id": "1' UNION SELECT user,password FROM users#"},
        )
        session.get.assert_called_once_with("/vulnerabilities/sqli/")
