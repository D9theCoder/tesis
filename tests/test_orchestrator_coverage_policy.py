from agents.orchestrator import orchestrator


def test_orchestrator_budget_exhausted_returns_scorer():
    state = {
        "target_url": "http://localhost/dvwa",
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "iteration_count": 30,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
        "current_surface": "sqli",
        "observations": {},
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "scores": {},
        "evasion_enabled": False,
        "evasion_mode": "reactive",
        "evasion_max_retries": 3,
        "consecutive_clean_responses": 0,
    }
    update = orchestrator(state)
    assert update["next_agent"] == "scorer"
