import agents.orchestrator as orchestrator_module
from agents.orchestrator import orchestrator


def test_impact_policy_stops_on_critical_outcome():
    state = {
        "confirmed_vulns": ["rce_achieved"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
        "stop_policy": "impact",
        "scores": {},
    }

    update = orchestrator(state)
    assert update["next_agent"] == "scorer"


def test_coverage_policy_continues_until_target_or_budget(monkeypatch):
    class FakeResponse:
        content = '{"next_agent": "sqli_agent"}'

    class FakeLLM:
        def invoke(self, messages):
            return FakeResponse()

    monkeypatch.setattr(orchestrator_module, "get_llm", lambda *args, **kwargs: FakeLLM())

    state = {
        "confirmed_vulns": ["rce_achieved"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
        "stop_policy": "coverage",
        "coverage_target": 0.90,
        "scores": {"sqli": 1},
    }

    update = orchestrator(state)
    assert update["next_agent"] != "scorer"
