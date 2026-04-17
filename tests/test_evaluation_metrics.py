from evaluation.metrics import (
    aggregate_runs,
    highest_impact_outcome,
    normalize_module_scores,
    score_distribution,
)


def test_normalize_module_scores_has_all_modules():
    normalized = normalize_module_scores({"sqli": 3})
    assert "sqli" in normalized
    assert "cmdi" in normalized


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


def test_highest_impact_outcome_prefers_rce_over_admin():
    confirmed = ["admin_session_obtained", "rce_achieved"]
    result = highest_impact_outcome(confirmed, [])
    assert result == "rce_achieved"


def test_highest_impact_outcome_checks_achieved_too():
    result = highest_impact_outcome([], ["session_hijack"])
    assert result == "session_hijack"
