"""P1 nullable-metric migration: legacy/new artifacts load, render, aggregate."""

from evaluation.metrics import (
    aggregate_metric,
)

LEGACY = {
    "consistency_score": 0.0,
    "token_cost": 0.0,
    "token_cost_per_success": 0.0,
}
NEW = {
    "consistency_score": None,
    "token_cost": None,
    "token_cost_per_success": None,
    "metric_availability": {
        "consistency_score": False,
        "token_cost": False,
        "token_cost_per_success": False,
    },
    "metric_unavailable_reason": {
        "consistency_score": "not_computed",
        "token_cost": "not_computed",
        "token_cost_per_success": "not_computed",
    },
}


def test_all_unavailable_aggregate_is_none_not_zero():
    agg = aggregate_metric([dict(LEGACY), dict(NEW)], "token_cost")
    assert agg["mean"] is None
    assert agg["n_available"] == 0
