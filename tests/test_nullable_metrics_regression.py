"""P1 nullable-metric migration: legacy/new artifacts load, render, aggregate."""

from evaluation.contracts import ScoreSummary
from evaluation.metrics import (
    UNAVAILABLE_METRICS,
    aggregate_metric,
    aggregate_runs,
    artifact_summary,
    format_metric,
    metric_reading,
)
from evaluation.reporter import build_markdown_summary
from tesis.report_formatters import (
    format_module_scores_table,
    format_provider_comparison_table,
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
AVAILABLE = {
    "consistency_score": 0.9,
    "token_cost": 1.25,
    "token_cost_per_success": 0.5,
    "metric_availability": {
        "consistency_score": True,
        "token_cost": True,
        "token_cost_per_success": True,
    },
    "metric_unavailable_reason": {},
}


def _artifact(summary, provider="gemini"):
    return {
        "run_id": "r-1",
        "status": "success",
        "config": {"provider": provider},
        "report": {
            "summary": summary,
            "module_scores": {"sqli": {"score": 4, "label": "Chain Exploit"}},
        },
    }


def test_legacy_numeric_dual_reads_as_unavailable():
    for name in UNAVAILABLE_METRICS:
        assert metric_reading(dict(LEGACY), name) == (None, False, "legacy_numeric")
        assert format_metric(dict(LEGACY), name) == "N/A"


def test_new_nullable_dual_reads_with_reason():
    for name in UNAVAILABLE_METRICS:
        assert metric_reading(dict(NEW), name) == (None, False, "not_computed")
        assert format_metric(dict(NEW), name) == "N/A"


def test_available_reading_returns_number():
    assert metric_reading(dict(AVAILABLE), "token_cost") == (1.25, True, None)
    assert format_metric(dict(AVAILABLE), "token_cost") == "1.25"


def test_mixed_aggregation_excludes_unavailable():
    agg = aggregate_metric([dict(LEGACY), dict(NEW), dict(AVAILABLE)], "token_cost")
    assert agg == {
        "n_available": 1,
        "n_unavailable": 2,
        "mean": 1.25,
        "unavailable_reasons": {"legacy_numeric": 1, "not_computed": 1},
    }


def test_all_unavailable_aggregate_is_none_not_zero():
    agg = aggregate_metric([dict(LEGACY), dict(NEW)], "token_cost")
    assert agg["mean"] is None
    assert agg["n_available"] == 0


def test_aggregate_runs_carries_metrics_block():
    agg = aggregate_runs([_artifact(LEGACY), _artifact(NEW)])
    assert agg["metrics"]["token_cost"]["mean"] is None
    assert agg["metrics"]["token_cost"]["n_unavailable"] == 2


def test_markdown_summary_renders_na_never_zero_filled():
    text = build_markdown_summary(
        {
            "totals": {
                "total_runs": 2,
                "successful_runs": 2,
                "error_runs": 0,
                "skipped_runs": 0,
                "metrics": {
                    n: aggregate_metric([dict(LEGACY)], n) for n in UNAVAILABLE_METRICS
                },
            }
        }
    )
    assert "token_cost: N/A (0/1 available)" in text
    assert "token_cost: 0" not in text


def test_score_table_renders_na_for_unavailable():
    rendered = format_module_scores_table(_artifact(dict(NEW)))
    assert "consistency_score: N/A" in rendered
    assert "token_cost: N/A" in rendered
    assert "token_cost_per_success: N/A" in rendered


def test_provider_comparison_mixed_old_new():
    rendered = format_provider_comparison_table(
        {"runs": [_artifact(dict(LEGACY), "gemini"), _artifact(dict(AVAILABLE), "claude")]}
    )
    assert "N/A (1 unavail)" in rendered
    assert "1.25 (1 avail)" in rendered


def test_artifact_summary_prefers_nested_report():
    assert artifact_summary(_artifact(dict(NEW))) == dict(NEW)
    flat = {"status": "success", **dict(LEGACY)}
    assert artifact_summary(flat) is flat


def test_score_summary_rejects_availability_mismatch():
    base = dict(
        llm_provider="gemini",
        security_level="low",
        total_modules_tested=1,
        score_distribution={0: 1},
        chain_exploits_achieved=0,
        highest_impact_outcome=None,
        guardrail_activations=0,
        total_iterations_used=0,
        longest_chain=None,
    )
    try:
        ScoreSummary(**base, consistency_score=0.0,
                     metric_availability={"consistency_score": False})
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("unavailable metric carrying 0.0 must fail closed")
    try:
        ScoreSummary(**base, metric_availability={"token_cost": True})
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("available flag with null value must fail closed")
    ok = ScoreSummary(**base, token_cost=1.5, metric_availability={"token_cost": True})
    assert ok.token_cost == 1.5


def test_available_nonfinite_fails_closed():
    for bad in (float("inf"), float("-inf"), float("nan")):
        summary = {
            "token_cost": bad,
            "metric_availability": {"token_cost": True},
            "metric_unavailable_reason": {},
        }
        value, available, reason = metric_reading(summary, "token_cost")
        assert value is None
        assert available is False
        assert reason == "nonfinite"
        assert format_metric(summary, "token_cost") == "N/A"
    agg = aggregate_metric(
        [
            dict(AVAILABLE),
            {
                "token_cost": float("inf"),
                "metric_availability": {"token_cost": True},
                "metric_unavailable_reason": {},
            },
        ],
        "token_cost",
    )
    assert agg["mean"] == 1.25
    assert agg["n_available"] == 1
    assert agg["unavailable_reasons"] == {"nonfinite": 1}
    text = build_markdown_summary(
        {
            "totals": {
                "total_runs": 1,
                "successful_runs": 1,
                "error_runs": 0,
                "skipped_runs": 0,
                "metrics": {
                    "consistency_score": {"mean": None, "n_available": 0, "n_unavailable": 1},
                    "token_cost": {"mean": float("inf"), "n_available": 1, "n_unavailable": 0},
                    "token_cost_per_success": {"mean": None, "n_available": 0, "n_unavailable": 1},
                },
            }
        }
    )
    assert "token_cost: N/A" in text
    assert "token_cost: inf" not in text


def test_score_summary_rejects_nonfinite_available():
    base = dict(
        llm_provider="gemini",
        security_level="low",
        total_modules_tested=1,
        score_distribution={0: 1},
        chain_exploits_achieved=0,
        highest_impact_outcome=None,
        guardrail_activations=0,
        total_iterations_used=0,
        longest_chain=None,
    )
    try:
        ScoreSummary(**base, token_cost=float("inf"), metric_availability={"token_cost": True})
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("available flag with nonfinite value must fail closed")


def test_artifact_summary_backfills_stub_nested():
    artifact = {
        "run_id": "r-1",
        "status": "success",
        "config": {"provider": "gemini"},
        **dict(AVAILABLE),
        "report": {
            "summary": {"chain_exploits_achieved": 0},
            "module_scores": {"sqli": {"score": 4, "label": "Chain Exploit"}},
        },
    }
    merged = artifact_summary(artifact)
    assert merged["chain_exploits_achieved"] == 0
    assert metric_reading(merged, "token_cost") == (1.25, True, None)
    assert "token_cost: 1.25" in format_module_scores_table(artifact)


def test_score_summary_rejects_unflagged_numeric():
    base = dict(
        llm_provider="gemini",
        security_level="low",
        total_modules_tested=1,
        score_distribution={0: 1},
        chain_exploits_achieved=0,
        highest_impact_outcome=None,
        guardrail_activations=0,
        total_iterations_used=0,
        longest_chain=None,
    )
    # Default None + empty maps stays valid (producer default + scorer path).
    assert ScoreSummary(**base).token_cost is None
    for bad_kwargs in (
        dict(token_cost=1.5),
        dict(token_cost=0.0),
        dict(token_cost=float("nan")),
        dict(token_cost=2.0, metric_availability={"token_cost": False}),
        dict(consistency_score=0.9, metric_availability={"consistency_score": 1}),
    ):
        try:
            ScoreSummary(**base, **bad_kwargs)
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"unflagged metric must fail closed: {bad_kwargs!r}")
    # Explicit measured zero with True stays valid.
    assert ScoreSummary(**base, token_cost=0.0, metric_availability={"token_cost": True}).token_cost == 0.0
