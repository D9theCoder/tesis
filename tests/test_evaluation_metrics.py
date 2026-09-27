"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from evaluation.metrics import (
    highest_impact_outcome,
)


def test_highest_impact_outcome_checks_achieved_too():
    """Verifies highest impact outcome checks achieved too behavior."""
    result = highest_impact_outcome([], ["data_exfiltrated"])
    assert result == "data_exfiltrated"
