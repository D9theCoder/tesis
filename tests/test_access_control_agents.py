"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import pytest
from agents.access_control.ac_idor_agent import ac_idor_agent
from agents.access_control.ac_vertical_escalation_agent import ac_vertical_escalation_agent
from agents.access_control.ac_force_browse_agent import ac_force_browse_agent


@pytest.mark.parametrize("agent_func,agent_id", [
    (ac_idor_agent, "ac_idor"),
    (ac_vertical_escalation_agent, "ac_vertical_escalation"),
    (ac_force_browse_agent, "ac_force_browse"),
])
def test_access_control_agent_returns_dict(agent_func, agent_id):
    """Verifies access control agent returns dict behavior."""
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
