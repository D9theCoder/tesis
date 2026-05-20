"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from evaluation.metrics import (
    aggregate_runs,
    highest_impact_outcome,
    normalize_method_scores,
    score_distribution,
)
from core.state import ALL_METHOD_AGENTS


def test_normalize_method_scores_has_all_methods():
    """Verifies normalize method scores has all methods behavior."""
    normalized = normalize_method_scores({"sqli_union": 3})
    assert "sqli_union" in normalized
    for agent in ALL_METHOD_AGENTS:
        assert agent in normalized


def test_score_distribution_has_fixed_buckets():
    """Verifies score distribution has fixed buckets behavior."""
    dist = score_distribution({"sqli": 4, "cmdi": 0})
    assert set(dist.keys()) == {0, 1, 2, 3, 4}


def test_aggregate_runs_counts_statuses():
    """Verifies aggregate runs counts statuses behavior."""
    agg = aggregate_runs([
        {"status": "success"},
        {"status": "error"},
        {"status": "skipped"},
    ])
    assert agg["total_runs"] == 3
    assert agg["successful_runs"] == 1


def test_highest_impact_outcome_returns_none_when_empty():
    """Verifies highest impact outcome returns none when empty behavior."""
    assert highest_impact_outcome([], []) is None


def test_highest_impact_outcome_prefers_admin_over_data_exfiltrated():
    """Verifies highest impact outcome prefers admin over data exfiltrated behavior."""
    confirmed = ["data_exfiltrated", "admin_session_obtained"]
    result = highest_impact_outcome(confirmed, [])
    assert result == "admin_session_obtained"


def test_highest_impact_outcome_checks_achieved_too():
    """Verifies highest impact outcome checks achieved too behavior."""
    result = highest_impact_outcome([], ["data_exfiltrated"])
    assert result == "data_exfiltrated"
