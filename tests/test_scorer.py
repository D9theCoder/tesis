"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from copy import deepcopy

from langgraph.graph import END

from core.scorer import build_score_report, scorer
from core.state import SCORE_LABELS, new_default_state


def test_build_score_report_defaults_missing_scores_to_zero():
    """Verifies build score report defaults missing scores to zero behavior."""
    state = new_default_state()
    report = build_score_report(state)
    assert report.module_scores["sqli_union"].score == 0
    assert report.module_scores["sqli_union"].label == SCORE_LABELS[0]


def test_scorer_clamps_out_of_range_values():
    """Verifies scorer clamps out of range values behavior."""
    state = new_default_state()
    state["scores"] = {"sqli_union": 99, "ac_idor": -5}
    update = scorer(state)
    assert update["scores"]["sqli_union"] == 4
    assert update["scores"]["ac_idor"] == 0


def test_scorer_returns_end_routing_without_mutating_input():
    """Verifies scorer returns end routing without mutating input behavior."""
    state = new_default_state()
    snapshot = deepcopy(state)
    update = scorer(state)
    assert update["next_agent"] == END
    assert state == snapshot


def test_build_score_report_matches_agents_shape_keys():
    """Verifies build score report matches agents shape keys behavior."""
    state = new_default_state()
    payload = build_score_report(state).to_dict()
    assert "module_scores" in payload
    assert "summary" in payload
    assert "score_distribution" in payload["summary"]
    assert "total_modules_tested" in payload["summary"]


def test_highest_impact_outcome_prefers_admin_over_data_exfiltrated():
    """Verifies highest impact outcome prefers admin over data exfiltrated behavior."""
    state = new_default_state()
    state["confirmed_vulns"] = ["admin_session_obtained", "data_exfiltrated"]
    report = build_score_report(state)
    assert report.summary.highest_impact_outcome == "admin_session_obtained"


def test_scorer_preserves_all_dimensions_and_weighted_composite():
    state = new_default_state()
    state.update({
        "selected_method": "sqli_union",
        "method_scores": {"sqli_union": 3},
        "exploitation_scores": {"sqli_union": 3},
        "chain_scores": {"sqli_union": 4},
        "payload_candidates": {
            "sqli_union": [{"candidate_id": "candidate-1", "payload_or_logic": "1 UNION SELECT"}],
        },
        "payload_scores": {"candidate-1": 3},
    })

    update = scorer(state)

    assert update["output_scores"]["sqli_union"] == 4
    assert update["composite_scores"]["sqli_union"] == 3.3
    assert update["summary"]["output_scores"]["sqli_union"] == 4
