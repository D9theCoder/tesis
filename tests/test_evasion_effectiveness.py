"""Tests for Stage 8.2 evasion effectiveness fixes."""

from __future__ import annotations

import agents.orchestrator as orchestrator_module
from agents.orchestrator import _sanitize_prompt_seed
from llm.evasion.pipeline import _mutate_prompt, generate_candidate, check_compliance, check_validity


def test_sanitize_prompt_seed_replaces_toxic_keywords():
    """Verifies sanitize prompt seed replaces toxic keywords behavior."""
    raw = (
        "You are the orchestrator for a DVWA exploitation workflow. "
        "Your job is to plan the attack and exploit the target."
    )
    cleaned = _sanitize_prompt_seed(raw)
    assert "orchestrator for a DVWA" not in cleaned
    assert "planner for a DVWA security test" in cleaned
    assert "exploit" not in cleaned
    assert "test" in cleaned
    assert "attack" not in cleaned
    assert "assess" in cleaned


def test_sanitize_prompt_seed_idempotent_on_clean_prompt():
    """Verifies sanitize prompt seed idempotent on clean prompt behavior."""
    clean = "You are a certified security assessor conducting a security assessment"
    result = _sanitize_prompt_seed(clean)
    assert result == clean


def test_mutate_prompt_applies_different_strategies():
    """Verifies mutate prompt applies different strategies behavior."""
    seed = "You are a certified security assessor conducting a security assessment with test modules"
    results = {_mutate_prompt(seed, i) for i in range(5)}
    # All 5 strategies should produce distinct outputs
    assert len(results) == 5


def test_mutate_prompt_preserves_original_when_no_match():
    """Verifies mutate prompt preserves original when no match behavior."""
    seed = "This is a generic prompt with no target phrases"
    result = _mutate_prompt(seed, 0)
    assert result == seed


def test_generate_candidate_uses_template_mutator():
    """Verifies generate candidate uses template mutator behavior."""
    state = {
        "base_seed": "You are a certified security assessor",
        "candidate_input": "",
        "strategy_reasoning": "",
        "is_compliant": False,
        "is_valid": False,
        "retries": 0,
        "max_retries": 3,
        "final_prompt": "",
        "evasion_strategy": "pipeline",
    }
    result = generate_candidate(state)
    assert result["retries"] == 1
    assert result["strategy_reasoning"].startswith("template_mutation:")
    assert "certified security assessor" in result["candidate_input"]


def test_check_compliance_fails_open_on_simulator_error(monkeypatch):
    """Compliance gate must return True (compliant) when simulator fails."""
    import llm.evasion.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "get_simulator_llm", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))

    state = {
        "base_seed": "seed",
        "candidate_input": "candidate",
        "strategy_reasoning": "",
        "is_compliant": False,
        "is_valid": False,
        "retries": 0,
        "max_retries": 3,
        "final_prompt": "",
        "evasion_strategy": "pipeline",
        "simulator_model": None,
        "simulator_provider": None,
    }
    result = check_compliance(state)
    assert result["is_compliant"] is True


def test_check_validity_fails_open_on_simulator_error(monkeypatch):
    """Validity gate must return True (valid) when simulator fails."""
    import llm.evasion.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "get_simulator_llm", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))

    state = {
        "base_seed": "seed",
        "candidate_input": "candidate",
        "strategy_reasoning": "",
        "is_compliant": False,
        "is_valid": False,
        "retries": 0,
        "max_retries": 3,
        "final_prompt": "",
        "evasion_strategy": "pipeline",
        "simulator_model": None,
        "simulator_provider": None,
    }
    result = check_validity(state)
    assert result["is_valid"] is True
