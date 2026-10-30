"""Regression tests for brute-force probe rate-limit classification."""

from unittest.mock import MagicMock
from importlib import import_module

import pytest


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
