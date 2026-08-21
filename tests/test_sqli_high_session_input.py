"""Focused request-path tests for high-level SQLi session-input handling."""

from importlib import import_module
from unittest.mock import MagicMock, call, patch

import pytest
from foundation.payload_library import PayloadLibrary


SQLI_AGENT_MODULES = (
    "agents.sqli.sqli_union_agent",
    "agents.sqli.sqli_error_agent",
    "agents.sqli.sqli_boolean_blind_agent",
    "agents.sqli.sqli_time_blind_agent",
)


@pytest.mark.parametrize("module_name", SQLI_AGENT_MODULES)
def test_high_posts_to_session_input_and_verifies_reload_response(module_name):
    """High SQLi requests use the session setter and return its reload response."""
    module = import_module(module_name)
    session = MagicMock()
    post_response = MagicMock(text="session setter response")
    reload_response = MagicMock(text="normal SQLi result")
    session.post.return_value = post_response
    session.get.return_value = reload_response

    result = module._request(session, "high", "1' UNION SELECT user,password FROM users#")

    assert result is reload_response
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


def test_high_time_baseline_uses_session_input_for_each_sample():
    """The timing baseline inherits the high POST+reload path for every sample."""
    module = import_module("agents.sqli.sqli_time_blind_agent")
    session = MagicMock()
    session.post.return_value = MagicMock()
    session.get.return_value = MagicMock()
    clock = iter((0.0, 0.1, 1.0, 1.2, 2.0, 2.2))

    with patch.object(module.time, "monotonic", side_effect=lambda: next(clock)):
        elapsed = module._get_baseline_timing(session, samples=3, security_level="high")

    assert elapsed == pytest.approx(0.2)
    assert session.post.call_args_list == [
        call("/vulnerabilities/sqli/session-input.php", data={"id": "1"}),
    ] * 3
    assert session.get.call_args_list == [call("/vulnerabilities/sqli/")] * 3


def test_high_union_static_seeds_include_hash_comment_fallback():
    """High SQLi keeps both MySQL comment forms available to static mode."""
    payloads = PayloadLibrary().load_seed_candidates("sqli_union", "high")
    values = {candidate["payload_or_logic"] for candidate in payloads}

    assert "1' UNION SELECT user,password FROM users LIMIT 1-- -" in values
    assert "1' UNION SELECT user,password FROM users#" in values
