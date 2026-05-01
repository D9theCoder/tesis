from copy import deepcopy

from langgraph.graph import END

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
    assert update["next_agent"] == END
    assert state == snapshot


def test_build_score_report_matches_agents_shape_keys():
    state = new_default_state()
    payload = build_score_report(state).to_dict()
    assert "module_scores" in payload
    assert "summary" in payload
    assert "score_distribution" in payload["summary"]
    assert "total_modules_tested" in payload["summary"]


def test_scorer_returns_summary_instead_of_method_quality_metrics():
    state = new_default_state()
    update = scorer(state)
    assert "summary" in update
    assert "method_quality_metrics" not in update
    assert "adaptation_rate" in update["summary"]


def test_scorer_returns_nested_surface_scores():
    state = new_default_state()
    state["scores"] = {"sqli_union": 3}
    update = scorer(state)
    assert "surface_scores" in update
    assert isinstance(update["surface_scores"]["sqli"], dict)
    assert update["surface_scores"]["sqli"]["score"] == 3


def test_highest_impact_outcome_prefers_admin_over_data_exfiltrated():
    state = new_default_state()
    state["confirmed_vulns"] = ["admin_session_obtained", "data_exfiltrated"]
    report = build_score_report(state)
    assert report.summary.highest_impact_outcome == "admin_session_obtained"


def test_build_score_report_stage6_metrics_are_computed():
    state = new_default_state()
    state["scores"] = {"sqli_union": 3, "sqli_error": 0, "sqli_boolean_blind": 4}
    state["attempted_agents"] = ["sqli_union", "sqli_error", "sqli_boolean_blind"]
    state["tried_payloads"] = {
        "sqli_union": ["p1", "p2"],
        "sqli_boolean_blind": ["p3", "p4", "p5"],
    }

    report = build_score_report(state)

    assert report.summary.method_selection_accuracy > 0.0
    assert report.summary.adaptation_rate > 0.0
    assert report.summary.mean_attempts_to_success > 0.0
