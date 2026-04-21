"""Tests for BaseAgent Stage 8 evasion helper."""

from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent
import llm.evasion.pipeline as pipeline_module


class DummyAgent(BaseAgent):
    module_name = "dummy"

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        return {}


def test_enhance_prompt_passes_evasion_strategy_to_pipeline(monkeypatch):
    captured: dict[str, Any] = {}

    class FakeGraph:
        def invoke(self, payload):
            captured.update(payload)
            return {"final_prompt": "enhanced"}

    monkeypatch.setattr(pipeline_module, "build_evasion_graph", lambda: FakeGraph())

    agent = DummyAgent()
    result = agent.enhance_prompt(
        {
            "evasion_enabled": True,
            "evasion_strategy": "base64",
        },
        "base prompt",
    )

    assert result == "enhanced"
    assert captured["evasion_strategy"] == "base64"


def test_enhance_prompt_treats_string_false_as_disabled(monkeypatch):
    class FakeGraph:
        def invoke(self, payload):
            raise AssertionError("evasion graph should not be invoked")

    monkeypatch.setattr(pipeline_module, "build_evasion_graph", lambda: FakeGraph())

    agent = DummyAgent()
    result = agent.enhance_prompt(
        {
            "evasion_enabled": "false",
            "evasion_strategy": "base64",
        },
        "base prompt",
    )

    assert result == "base prompt"
