"""Tests for BaseAgent (3-surface deep-method)."""

from typing import Any

from agents.base_agent import BaseAgent, _coerce_bool


class DummyAgent(BaseAgent):
    """Groups regression tests for DummyAgent behavior."""
    agent_id = "sqli_union"
    surface = "sqli"

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        """Supports regression tests for test base agent."""
        return {}


def test_coerce_bool():
    """Verifies coerce bool behavior."""
    assert _coerce_bool(True) is True
    assert _coerce_bool(False) is False
    assert _coerce_bool("true") is True
    assert _coerce_bool("false") is False
    assert _coerce_bool(1) is True
    assert _coerce_bool(0) is False
    assert _coerce_bool(None) is False


def test_enhance_prompt_is_noop():
    """Verifies enhance prompt is noop behavior."""
    agent = DummyAgent()
    result = agent.enhance_prompt({"evasion_enabled": True}, "base prompt")
    assert result == "base prompt"


def test_probe_returns_dict():
    """Verifies probe returns dict behavior."""
    agent = DummyAgent()
    result = agent.probe({})
    assert isinstance(result, dict)
    assert "observations" in result


def test_emit_telemetry():
    """Verifies emit telemetry behavior."""
    agent = DummyAgent()
    result = agent._emit_telemetry({"iteration_count": 5}, "test", {"status": "ok"})
    assert "telemetry_events" in result
    assert result["telemetry_events"][0]["node"] == "sqli_union"
