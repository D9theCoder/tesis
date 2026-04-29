import pytest
from agents.brute_force.bf_dictionary_agent import bf_dictionary_agent
from agents.brute_force.bf_spray_agent import bf_spray_agent


@pytest.mark.parametrize("agent_func,agent_id", [
    (bf_dictionary_agent, "bf_dictionary"),
    (bf_spray_agent, "bf_spray"),
])
def test_brute_force_agent_returns_dict(agent_func, agent_id):
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
