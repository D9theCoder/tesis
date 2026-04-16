import pytest

from core.chaining_coordinator import critical_outcome_achieved, route_after_agent


@pytest.mark.parametrize("level", ["low", "medium", "high"])
def test_route_after_agent_parametrized_levels(level):
    state = {
        "security_level": level,
        "confirmed_vulns": ["sqli_confirmed", "credentials_extracted"],
        "achieved_outcomes": [],
        "iteration_count": 2,
        "max_iterations": 30,
    }

    nxt = route_after_agent(state)
    assert nxt == "sqli_to_creds_chain"


def test_route_after_agent_returns_chain_agent_when_preconditions_met():
    state = {
        "confirmed_vulns": ["lfi_confirmed", "log_access_confirmed"],
        "achieved_outcomes": [],
        "iteration_count": 2,
        "max_iterations": 30,
    }

    assert route_after_agent(state) == "lfi_to_rce_chain"


def test_route_after_agent_prefers_chain_before_critical_short_circuit():
    state = {
        "confirmed_vulns": [
            "sqli_confirmed",
            "credentials_extracted",
            "admin_session_obtained",
        ],
        "achieved_outcomes": [],
        "iteration_count": 2,
        "max_iterations": 30,
    }

    assert route_after_agent(state) == "upload_to_rce_chain"


def test_route_after_agent_stops_when_chain_target_already_known():
    state = {
        "confirmed_vulns": [
            "sqli_confirmed",
            "credentials_extracted",
            "admin_session_obtained",
            "rce_achieved",
        ],
        "achieved_outcomes": [],
        "iteration_count": 2,
        "max_iterations": 30,
    }

    assert route_after_agent(state) == "scorer"


def test_route_after_agent_budget_exhausted_goes_to_scorer():
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "iteration_count": 30,
        "max_iterations": 30,
    }

    assert route_after_agent(state) == "scorer"


def test_route_after_agent_fallback_orchestrator_when_no_chain():
    state = {
        "confirmed_vulns": ["xss_reflected_confirmed"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
    }

    assert route_after_agent(state) == "orchestrator"


def test_critical_outcome_achieved_checks_confirmed_and_achieved():
    assert critical_outcome_achieved({"achieved_outcomes": ["rce_achieved"], "confirmed_vulns": []})
    assert critical_outcome_achieved({"achieved_outcomes": [], "confirmed_vulns": ["session_hijack"]})
    assert not critical_outcome_achieved({"achieved_outcomes": [], "confirmed_vulns": ["sqli_confirmed"]})
