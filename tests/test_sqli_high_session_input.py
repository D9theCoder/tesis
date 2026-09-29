"""Focused request-path tests for high-level SQLi session-input handling."""

from importlib import import_module
from unittest.mock import MagicMock, call, patch

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

@pytest.mark.parametrize("module_name", SQLI_AGENT_MODULES)
@pytest.mark.parametrize("security_level", ["low", "medium"])
def test_low_and_medium_retain_existing_module_request_paths(module_name, security_level):
    """Only high uses session-input; existing low/medium requests stay unchanged."""
    module = import_module(module_name)
    session = MagicMock()
    response = MagicMock()
    session.get.return_value = response
    session.post.return_value = response
    payload = "1' AND 1=1-- -"

    result = module._request(session, security_level, payload)

    assert result is response
    request_data = {"id": payload, "Submit": "Submit"}
    if security_level == "low":
        session.get.assert_called_once_with(module.MODULE_PATH, params=request_data)
        session.post.assert_not_called()
    else:
        session.post.assert_called_once_with(module.MODULE_PATH, data=request_data)
        session.get.assert_not_called()

def test_high_time_baseline_uses_cookie_for_each_sample():
    """The timing baseline inherits the high POST+reload path for every sample."""
    module = import_module("agents.sqli.sqli_time_blind_agent")
    session = MagicMock()
    session.post.return_value = MagicMock(status_code=200)
    session.get.return_value = MagicMock(status_code=200)
    clock = iter((0.0, 0.1, 1.0, 1.2, 2.0, 2.2))

    with patch.object(module.time, "monotonic", side_effect=lambda: next(clock)):
        elapsed = module._get_baseline_timing(session, samples=3, security_level="high")

    assert elapsed == pytest.approx(0.2)
    session.post.assert_not_called()
    assert session.http.set_cookie.call_count == 3
    assert session.get.call_args_list == [call("/vulnerabilities/sqli_blind/")] * 3
