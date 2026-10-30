"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""


from core.scorer import scorer
from core.state import new_default_state


def test_scorer_clamps_out_of_range_values():
    """Verifies scorer clamps out of range values behavior."""
    state = new_default_state()
    state["scores"] = {"sqli_union": 99, "ac_idor": -5}
    update = scorer(state)
    assert update["scores"]["sqli_union"] == 4
    assert update["scores"]["ac_idor"] == 0


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
