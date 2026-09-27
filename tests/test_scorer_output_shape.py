"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from core.scorer import scorer
from core.state import new_default_state


def test_scorer_nested_surface_scores_correct_values():
    """Verifies scorer nested surface scores correct values behavior."""
    state = new_default_state()
    state["scores"] = {"sqli_union": 3, "sqli_error": 1}
    state["attempted_agents"] = ["sqli_union", "sqli_error"]
    update = scorer(state)
    sqli_scores = update["surface_scores"]["sqli"]
    assert sqli_scores["score"] == 3
    assert sqli_scores["method_selected"] == "sqli_union"
    assert sqli_scores["attempts"] == 2
