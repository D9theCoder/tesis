"""Tests for Stage 8.2 evasion effectiveness fixes."""

from __future__ import annotations

import agents.orchestrator as orchestrator_module
from agents.orchestrator import _sanitize_prompt_seed

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

