"""Regression coverage for confirmed findings at chain exhaustion."""

from core.chaining_coordinator import (
    chaining_router_node,
    confirmed_success_achieved,
    evaluate_chain_route,
)
from core.scorer import scorer


def _brute_force_chain_state(**overrides):
    state = {
        "iteration_count": 5,
        "max_iterations": 30,
        "current_surface": "brute_force",
        "experiment_condition": "akg_guided_hybrid",
        "confirmed_vulns": ["bf_spray_confirmed"],
        "achieved_outcomes": ["authenticated_session"],
        "attempted_agents": ["bf_dictionary", "bf_spray", "ac_idor"],
        "blocked_agents": [],
        "failure_agents": [],
        "observations": {"no_rate_limit": True},
    }
    state.update(overrides)
    return state


def test_confirmed_vulnerability_is_terminal_success_after_chain_exhaustion():
    """A failed follow-up chain must not erase a verifier-backed finding."""
    next_agent, event = evaluate_chain_route(_brute_force_chain_state())

    assert next_agent == "scorer"
    assert event["reason"] == "confirmed_success"
    assert event["task_result"] == "SUCCESS"
    assert "incomplete_reason" not in event


def test_chaining_router_node_clears_stale_exhaustion_status():
    """The state update must persist success for the scorer and artifact."""
    state = _brute_force_chain_state(
        task_result="INCOMPLETE",
        incomplete_reason="ALL_METHODS_FAILED",
    )

    update = chaining_router_node(state)

    assert update["next_agent"] == "scorer"
    assert update["task_result"] == "SUCCESS"
    assert update["incomplete_reason"] is None


def test_scorer_preserves_confirmed_success_terminal_status():
    """The scorer/artifact boundary must retain the router's success result."""
    state = _brute_force_chain_state(
        task_result="INCOMPLETE",
        incomplete_reason="ALL_METHODS_FAILED",
    )
    state.update(chaining_router_node(state))

    scored = scorer(state)

    assert scored["task_result"] == "SUCCESS"
    assert scored["incomplete_reason"] is None


def test_achieved_outcome_without_confirmed_vulnerability_is_not_success():
    """An enabling outcome must not be promoted to a confirmed vulnerability."""
    state = _brute_force_chain_state(confirmed_vulns=[])

    assert not confirmed_success_achieved(state)
    next_agent, event = evaluate_chain_route(state)

    assert next_agent == "scorer"
    assert event["reason"] == "all_methods_exhausted"
    assert event["incomplete_reason"] == "ALL_METHODS_FAILED"


def test_confirmed_success_does_not_prevent_an_unattempted_chain():
    """A confirmed finding still gets its available AKG follow-up attempt."""
    state = _brute_force_chain_state(attempted_agents=["bf_dictionary", "bf_spray"])

    next_agent, event = evaluate_chain_route(state)

    assert next_agent == "ac_idor"
    assert event["reason"] == "chain_ready"
