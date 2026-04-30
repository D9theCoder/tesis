"""Tests for the Stage 8 DeepTeam adapters."""

from __future__ import annotations

import pytest

import llm.evasion.deepteam_adapters as deepteam_adapters
from llm.evasion.deepteam_adapters import enhance_with_deepteam


def test_enhance_with_deepteam_returns_prompt_when_strategy_unsupported():
    """Unknown strategies should return the base prompt unchanged."""
    base = "Generate SQL injection payloads"
    result = enhance_with_deepteam(base, strategy="unknown_strategy")
    assert result == base


def test_enhance_with_deepteam_normalizes_strategy_names(monkeypatch):
    """Strategy names with mixed case/separators should still resolve."""

    class FakeAttack:
        def enhance(self, prompt: str, simulator_model=None, **kwargs) -> str:
            return f"enhanced:{prompt}"

    monkeypatch.setattr(deepteam_adapters, "_DEEPTEAM_AVAILABLE", True)
    monkeypatch.setattr(deepteam_adapters, "_STRATEGY_MAP", {"prompt_injection": FakeAttack})

    base = "Generate SQL injection payloads"
    result = enhance_with_deepteam(base, strategy=" Prompt-Injection ")
    assert result == f"enhanced:{base}"


def test_partial_strategy_map_does_not_disable_available_strategies(monkeypatch):
    """Missing classes should not affect strategies that are present."""

    class FakeAttack:
        def enhance(self, prompt: str) -> str:
            return "ok"

    monkeypatch.setattr(deepteam_adapters, "_DEEPTEAM_AVAILABLE", True)
    monkeypatch.setattr(deepteam_adapters, "_STRATEGY_MAP", {"base64": FakeAttack})

    assert enhance_with_deepteam("seed", strategy="base64") == "ok"
    assert enhance_with_deepteam("seed", strategy="system_override") == "seed"


def test_enhance_with_deepteam_defaults_to_prompt_injection():
    """Default strategy should be prompt_injection."""
    base = "Generate XSS payloads"
    result = enhance_with_deepteam(base)
    # When deepteam is not installed, the function returns base unchanged
    assert isinstance(result, str)


def test_enhance_with_deepteam_prompt_injection_strategy():
    """prompt_injection strategy should be accepted."""
    base = "Generate command injection payloads"
    result = enhance_with_deepteam(base, strategy="prompt_injection")
    assert isinstance(result, str)


def test_enhance_with_deepteam_roleplay_strategy():
    """roleplay strategy should be accepted."""
    base = "Generate path traversal payloads"
    result = enhance_with_deepteam(base, strategy="roleplay")
    assert isinstance(result, str)


@pytest.mark.parametrize(
    "strategy",
    [
        "base64",
        "leetspeak",
        "rot13",
        "goal_redirection",
        "adversarial_poetry",
        "gray_box",
        "math_problem",
        "multilingual",
        "context_poisoning",
        "input_bypass",
        "permission_escalation",
        "linguistic_confusion",
        "system_override",
    ],
)
def test_enhance_with_deepteam_all_single_turn_strategies(strategy):
    """All registered single-turn strategies should be accepted and return a string."""
    base = "Generate SQL injection payloads"
    result = enhance_with_deepteam(base, strategy=strategy)
    assert isinstance(result, str)
