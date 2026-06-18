"""Tests for thesis composite scoring (Srun) and output-quality score (Soutput)."""

from evaluation.metrics import (
    SCORE_WEIGHTS,
    composite_run_score,
    output_validity_score,
    invalid_json_rate,
    fallback_rate,
)
from core.scorer import build_score_report, scorer
from core.state import new_default_state


def test_score_weights_match_thesis():
    """Composite weights must follow thesis §7.1 (0.20/0.20/0.30/0.10/0.20)."""
    assert SCORE_WEIGHTS == {
        "method": 0.20,
        "payload": 0.20,
        "exploit": 0.30,
        "chain": 0.10,
        "output": 0.20,
    }
    assert round(sum(SCORE_WEIGHTS.values()), 6) == 1.0


def test_composite_run_score_weighted_sum():
    """Composite score should be the weighted sum of the five dimensions."""
    # 0.20*4 + 0.20*4 + 0.30*4 + 0.10*4 + 0.20*4 = 4.0
    assert composite_run_score(4, 4, 4, 4, 4) == 4.0
    # 0.20*3 + 0.20*2 + 0.30*3 + 0.10*0 + 0.20*3 = 0.6+0.4+0.9+0+0.6 = 2.5
    assert composite_run_score(3, 2, 3, 0, 3) == 2.5
    assert composite_run_score(0, 0, 0, 0, 0) == 0.0


def test_output_validity_score_clean_output_is_max():
    """Perfectly clean output (no guardrail/invalid/fallback) scores 4."""
    assert output_validity_score(0.0, 0.0, 0.0) == 4


def test_output_validity_score_degrades_with_penalty():
    """Output score should drop as guardrail/invalid/fallback rates rise."""
    assert output_validity_score(1.0, 1.0, 1.0) == 0
    mid = output_validity_score(0.5, 0.5, 0.5)
    assert 0 < mid < 4


def test_rate_helpers_clamp():
    """Rate helpers return 0.0 with no iterations and clamp to 1.0."""
    assert invalid_json_rate([{"x": 1}], 0) == 0.0
    assert fallback_rate([{"x": 1}] * 5, 2) == 1.0


def test_scorer_emits_composite_and_output_fields():
    """The scorer node must emit composite_score, output_scores, composite_scores."""
    state = new_default_state()
    state["iteration_count"] = 4
    state["invalid_json_events"] = [{"x": 1}]
    state["fallback_events"] = [{"y": 1}]
    state["scores"] = {"sqli_union": 3}
    state["method_scores"] = {"sqli_union": 3}
    state["exploitation_scores"] = {"sqli_union": 3}
    state["payload_scores"] = {"c1": 2}
    state["chain_scores"] = {"sqli_union": 0}

    report = build_score_report(state)
    assert report.summary.composite_score == composite_run_score(3, 2, 3, 0, report.summary.output_validity_score)

    out = scorer(state)
    assert "composite_score" in out
    assert "output_scores" in out
    assert "composite_scores" in out
    assert out["composite_score"] == report.summary.composite_score
