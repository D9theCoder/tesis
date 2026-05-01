from evaluation.metrics import (
    aggregate_runs,
    highest_impact_outcome,
    normalize_method_scores,
    score_distribution,
)
from core.state import ALL_METHOD_AGENTS


def test_normalize_method_scores_has_all_methods():
    normalized = normalize_method_scores({"sqli_union": 3})
    assert "sqli_union" in normalized
    for agent in ALL_METHOD_AGENTS:
        assert agent in normalized


def test_score_distribution_has_fixed_buckets():
    dist = score_distribution({"sqli": 4, "cmdi": 0})
    assert set(dist.keys()) == {0, 1, 2, 3, 4}


def test_aggregate_runs_counts_statuses():
    agg = aggregate_runs([
        {"status": "success"},
        {"status": "error"},
        {"status": "skipped"},
    ])
    assert agg["total_runs"] == 3
    assert agg["successful_runs"] == 1


def test_highest_impact_outcome_returns_none_when_empty():
    assert highest_impact_outcome([], []) is None


def test_highest_impact_outcome_prefers_admin_over_data_exfiltrated():
    confirmed = ["data_exfiltrated", "admin_session_obtained"]
    result = highest_impact_outcome(confirmed, [])
    assert result == "admin_session_obtained"


def test_highest_impact_outcome_checks_achieved_too():
    result = highest_impact_outcome([], ["data_exfiltrated"])
    assert result == "data_exfiltrated"
