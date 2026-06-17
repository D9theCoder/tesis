"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import pytest
from agents.sqli.sqli_union_agent import sqli_union_agent
from agents.sqli.sqli_error_agent import sqli_error_agent
from agents.sqli.sqli_boolean_blind_agent import sqli_boolean_blind_agent
from agents.sqli.sqli_time_blind_agent import sqli_time_blind_agent


@pytest.mark.parametrize("agent_func,agent_id", [
    (sqli_union_agent, "sqli_union"),
    (sqli_error_agent, "sqli_error"),
    (sqli_boolean_blind_agent, "sqli_boolean_blind"),
    (sqli_time_blind_agent, "sqli_time_blind"),
])
def test_sqli_agent_returns_dict(agent_func, agent_id):
    """Verifies sqli agent returns dict behavior."""
    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [],
        "observations": {},
        "confirmed_vulns": [],
        "tried_payloads": {},
        "attempted_agents": [],
        "scores": {},
    }
    result = agent_func(state)
    assert isinstance(result, dict)
    assert "scores" in result or "observations" in result
