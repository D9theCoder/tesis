from core.scorer import scorer
from core.state import new_default_state, SURFACES


def test_scorer_returns_nested_surface_scores():
    state = new_default_state()
    state["scores"] = {"sqli_union": 3}
    update = scorer(state)
    assert "surface_scores" in update
    for surface in SURFACES:
        surface_dict = update["surface_scores"][surface]
        assert isinstance(surface_dict, dict)
        assert "score" in surface_dict
        assert "label" in surface_dict
        assert "method_selected" in surface_dict
        assert "attempts" in surface_dict
        assert "akg_path" in surface_dict
        assert "adapted" in surface_dict


def test_scorer_returns_summary():
    state = new_default_state()
    update = scorer(state)
    assert "summary" in update
    summary = update["summary"]
    assert "llm_provider" in summary
    assert "security_level" in summary
    assert "total_surfaces_tested" in summary
    assert "score_distribution" in summary
    assert "method_selection_accuracy" in summary
    assert "adaptation_rate" in summary
    assert "mean_attempts_to_success" in summary
    assert "chain_exploits_achieved" in summary
    assert "guardrail_activations" in summary
    assert "total_iterations_used" in summary
    assert "incomplete_surfaces" in summary
    assert "incomplete_reasons" in summary


def test_scorer_no_method_quality_metrics_key():
    state = new_default_state()
    update = scorer(state)
    assert "method_quality_metrics" not in update


def test_scorer_nested_surface_scores_correct_values():
    state = new_default_state()
    state["scores"] = {"sqli_union": 3, "sqli_error": 1}
    state["attempted_agents"] = ["sqli_union", "sqli_error"]
    update = scorer(state)
    sqli_scores = update["surface_scores"]["sqli"]
    assert sqli_scores["score"] == 3
    assert sqli_scores["method_selected"] == "sqli_union"
    assert sqli_scores["attempts"] == 2
