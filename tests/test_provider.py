"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import pytest


from llm.provider import (
    get_llm,
)


def test_get_llm_invalid():
    """Verifies get llm invalid behavior."""
    with pytest.raises(ValueError, match="Unsupported LLM provider: unknown"):
        get_llm("unknown")
