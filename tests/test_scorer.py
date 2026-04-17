from copy import deepcopy

from core.scorer import build_score_report, scorer
from core.state import MODULE_NAMES, MODULE_TO_KG_NODE, SCORE_LABELS, new_default_state


def test_build_score_report_includes_all_modules_in_canonical_order():
    state = new_default_state()
    report = build_score_report(state)
    assert list(report.module_scores.keys()) == MODULE_NAMES


def test_build_score_report_defaults_missing_scores_to_zero():
    state = new_default_state()
    report = build_score_report(state)
    assert report.module_scores["sqli"].score == 0
    assert report.module_scores["sqli"].label == SCORE_LABELS[0]


def test_scorer_clamps_out_of_range_values():
    state = new_default_state()
    state["scores"] = {"sqli": 99, "cmdi": -5}
    update = scorer(state)
    assert update["scores"]["sqli"] == 4
    assert update["scores"]["cmdi"] == 0


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


def test_chain_path_derived_for_score_4_modules():
    state = new_default_state()
    state["scores"] = {"sqli": 4, "cmdi": 4}
    state["current_chain"] = ["sqli_confirmed", "credentials_extracted", "admin_session_obtained"]
    report = build_score_report(state)
    # sqli should have a chain path because its KG node is in current_chain
    assert report.module_scores["sqli"].chain is not None
    assert "sqli_confirmed" in report.module_scores["sqli"].chain
    # cmdi's KG node (cmd_injection_confirmed) is NOT in this chain — must be None
    assert report.module_scores["cmdi"].chain is None


def test_chain_path_uses_canonical_kg_node_names():
    """Verify MODULE_TO_KG_NODE mapping is used, not naive f-string."""
    state = new_default_state()
    state["scores"] = {"sqli_blind": 4, "xss_r": 4, "upload": 4}
    state["current_chain"] = [
        "blind_sqli_confirmed", "data_exfiltrated",
    ]
    report = build_score_report(state)
    # sqli_blind maps to blind_sqli_confirmed (not sqli_blind_confirmed)
    assert report.module_scores["sqli_blind"].chain is not None
    assert "blind_sqli_confirmed" in report.module_scores["sqli_blind"].chain
    # xss_r maps to xss_reflected_confirmed (not xss_r_confirmed) — not in chain
    assert report.module_scores["xss_r"].chain is None
    # upload maps to file_upload_confirmed (not upload_confirmed) — not in chain
    assert report.module_scores["upload"].chain is None


def test_module_to_kg_node_mapping_covers_all_modules():
    """Every MODULE_NAME must have a corresponding KG node mapping."""
    for module in MODULE_NAMES:
        assert module in MODULE_TO_KG_NODE, f"Missing mapping for module: {module}"


def test_chain_path_none_for_non_chain_scores():
    state = new_default_state()
    state["scores"] = {"xss_r": 3}
    report = build_score_report(state)
    assert report.module_scores["xss_r"].chain is None


def test_highest_impact_outcome_prefers_rce_over_admin():
    state = new_default_state()
    state["confirmed_vulns"] = ["admin_session_obtained", "rce_achieved"]
    report = build_score_report(state)
    assert report.summary.highest_impact_outcome == "rce_achieved"
