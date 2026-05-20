"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import pytest
from core.scorer import method_selection_accuracy, adaptation_rate, mean_attempts_to_success


def test_method_selection_accuracy():
    """Verifies method selection accuracy behavior."""
    scores = {"sqli_union": 3, "sqli_error": 1, "ac_idor": 3}
    assert method_selection_accuracy(scores, ["sqli_union", "sqli_error", "ac_idor"]) == 1.0


def test_adaptation_rate():
    """Verifies adaptation rate behavior."""
    scores = {"sqli_union": 3, "sqli_error": 0, "ac_idor": 0, "bf_dictionary": 3}
    assert adaptation_rate(scores, ["sqli_error", "bf_dictionary"]) == 1.0


def test_mean_attempts_to_success():
    """Verifies mean attempts to success behavior."""
    tried = {"sqli_union": ["p1", "p2"], "sqli_error": ["p1"]}
    scores = {"sqli_union": 3, "sqli_error": 1}
    assert mean_attempts_to_success(tried, scores) == 2.0
