"""Regression coverage for confirmed findings at chain exhaustion."""

from core.chaining_coordinator import (
    confirmed_success_achieved,
    evaluate_chain_route,
)
from tests.test_chaining_coordinator import proved_chain_source
from tests.support import READY_RECEIPT

def _brute_force_chain_state(**overrides):
    state = {
        "iteration_count": 5,
        "max_iterations": 30,
        "current_surface": "brute_force",
        "experiment_condition": "akg_guided_hybrid",
        "confirmed_vulns": ["bf_spray_confirmed"],
        "achieved_outcomes": ["authenticated_session"],
        "attempted_agents": ["bf_dictionary", "bf_spray", "ac_force_browse", "ac_idor"],
        "blocked_agents": [],
        "failure_agents": [],
        "observations": {"no_rate_limit": True, "force_browse_endpoints_visible": True},
        "readiness": dict(READY_RECEIPT),
        **proved_chain_source("authenticated_session"),
    }
    state.update(overrides)
    return state


def test_achieved_outcome_without_confirmed_vulnerability_is_not_success():
    """An enabling outcome must not be promoted to a confirmed vulnerability."""
    state = _brute_force_chain_state(confirmed_vulns=[])

    assert not confirmed_success_achieved(state)
    next_agent, event = evaluate_chain_route(state)

    assert next_agent == "scorer"
    assert event["reason"] == "all_methods_exhausted"
    assert event["incomplete_reason"] == "ALL_METHODS_FAILED"
