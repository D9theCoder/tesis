from copy import deepcopy

from core.scorer import build_score_report, scorer
from core.state import ALL_METHOD_AGENTS, MODULE_TO_KG_NODE, SCORE_LABELS, new_default_state


def test_build_score_report_includes_all_methods_in_canonical_order():
    state = new_default_state()
    report = build_score_report(state)
    assert list(report.module_scores.keys()) == ALL_METHOD_AGENTS


def test_build_score_report_defaults_missing_scores_to_zero():
    state = new_default_state()
    report = build_score_report(state)
    assert report.module_scores["sqli_union"].score == 0
    assert report.module_scores["sqli_union"].label == SCORE_LABELS[0]


def test_scorer_clamps_out_of_range_values():
    state = new_default_state()
    state["scores"] = {"sqli_union": 99, "ac_idor": -5}
    update = scorer(state)
    assert update["scores"]["sqli_union"] == 4
    assert update["scores"]["ac_idor"] == 0


def test_scorer_returns_end_routing_without_mutating_input():
    state = new_default_state()
    snapshot = deepcopy(state)
    update = scorer(state)
    assert update["next_agent"] == "END"
    assert state == snapshot


def test_build_score_report_matches_agents_shape_keys():
    state = new_default_state()
    payload = build_score_report(state).to_dict()
    assert "module_scores" in payload
    assert "summary" in payload
    assert "score_distribution" in payload["summary"]
    assert "total_modules_tested" in payload["summary"]


def test_scorer_returns_method_quality_metrics():
    state = new_default_state()
    update = scorer(state)
    assert "method_quality_metrics" in update
    assert "adaptation_rate" in update["method_quality_metrics"]


def test_scorer_returns_surface_scores():
    state = new_default_state()
    state["scores"] = {"sqli_union": 3}
    update = scorer(state)
    assert "surface_scores" in update
    assert update["surface_scores"]["sqli"] == 3


def test_highest_impact_outcome_prefers_rce_over_admin():
    state = new_default_state()
    state["confirmed_vulns"] = ["admin_session_obtained", "rce_achieved"]
    report = build_score_report(state)
    assert report.summary.highest_impact_outcome == "rce_achieved"
