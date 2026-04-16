import agents.orchestrator as orchestrator_module

from agents.orchestrator import orchestrator


def test_orchestrator_stops_when_budget_exhausted():
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "iteration_count": 30,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
    }

    update = orchestrator(state)
    assert update["next_agent"] == "scorer"


def test_orchestrator_critical_outcome_routes_to_scorer():
    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": ["rce_achieved"],
        "iteration_count": 1,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
    }

    update = orchestrator(state)
    assert update["next_agent"] == "scorer"


def test_orchestrator_critical_outcome_in_confirmed_routes_to_scorer():
    state = {
        "confirmed_vulns": ["rce_achieved"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
    }

    update = orchestrator(state)
    assert update["next_agent"] == "scorer"


def test_orchestrator_fallback_when_llm_fails(monkeypatch):
    def fail_get_llm(*args, **kwargs):
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(orchestrator_module, "get_llm", fail_get_llm)

    state = {
        "confirmed_vulns": ["sqli_confirmed"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
    }

    update = orchestrator(state)
    assert update["next_agent"] == "sqli_agent"
    assert "current_chain" in update


def test_orchestrator_uses_canonical_viable_paths(monkeypatch):
    class FakeKG:
        HIGH_IMPACT_OUTCOMES = (
            "admin_session_obtained",
            "rce_achieved",
            "user_compromised",
            "data_exfiltrated",
            "session_hijack",
        )

        def get_viable_chains(self, confirmed_vulns, achieved_outcomes=None, max_paths=5):
            return [["credentials_extracted", "admin_session_obtained"]]

        def get_next_actions(self, node):
            if node == "credentials_extracted":
                return [
                    {
                        "source": "credentials_extracted",
                        "target": "admin_session_obtained",
                        "is_chain": True,
                        "preconditions": ["sqli_confirmed", "credentials_extracted"],
                        "target_agent": "sqli_to_creds_chain",
                    }
                ]
            return []

    def fail_get_llm(*args, **kwargs):
        raise RuntimeError("offline test")

    monkeypatch.setattr(orchestrator_module, "AttackKnowledgeGraph", FakeKG)
    monkeypatch.setattr(orchestrator_module, "get_llm", fail_get_llm)

    state = {
        "confirmed_vulns": ["sqli_confirmed", "credentials_extracted"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
        "security_level": "medium",
        "llm_provider": "gemini",
    }

    update = orchestrator(state)
    assert update["next_agent"] == "sqli_to_creds_chain"
    assert update["current_chain"] == ["credentials_extracted", "admin_session_obtained"]


def test_orchestrator_rejects_invalid_runtime_next_agent(monkeypatch):
    class FakeResponse:
        content = '{"next_agent": "credentials_extracted"}'

    class FakeLLM:
        def invoke(self, messages):
            return FakeResponse()

    monkeypatch.setattr(orchestrator_module, "get_llm", lambda *args, **kwargs: FakeLLM())

    state = {
        "confirmed_vulns": ["sqli_confirmed"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
    }

    update = orchestrator(state)
    assert update["next_agent"] == "sqli_agent"


def test_orchestrator_rejects_infeasible_chain_runtime_next_agent(monkeypatch):
    class FakeResponse:
        content = '{"next_agent": "upload_to_rce_chain"}'

    class FakeLLM:
        def invoke(self, messages):
            return FakeResponse()

    monkeypatch.setattr(orchestrator_module, "get_llm", lambda *args, **kwargs: FakeLLM())

    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "iteration_count": 0,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
    }

    update = orchestrator(state)
    assert update["next_agent"] == "sqli_agent"


def test_orchestrator_current_chain_tracks_accepted_llm_decision(monkeypatch):
    class FakeResponse:
        content = '{"next_agent": "sqli_agent"}'

    class FakeLLM:
        def invoke(self, messages):
            return FakeResponse()

    class FakeKG:
        HIGH_IMPACT_OUTCOMES = (
            "admin_session_obtained",
            "rce_achieved",
            "user_compromised",
            "data_exfiltrated",
            "session_hijack",
        )

        def get_viable_chains(self, confirmed_vulns, achieved_outcomes=None, max_paths=5):
            return [["sqli_confirmed", "credentials_extracted"]]

        def get_next_actions(self, node):
            return []

    monkeypatch.setattr(orchestrator_module, "get_llm", lambda *args, **kwargs: FakeLLM())
    monkeypatch.setattr(orchestrator_module, "AttackKnowledgeGraph", FakeKG)

    state = {
        "confirmed_vulns": ["sqli_confirmed"],
        "achieved_outcomes": [],
        "iteration_count": 1,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
    }

    update = orchestrator(state)
    assert update["next_agent"] == "sqli_agent"
    assert update["current_chain"]
    assert "sqli_confirmed" in update["current_chain"]


def test_orchestrator_guardrail_refusal_logs_activation(monkeypatch):
    class FakeResponse:
        content = "I cannot assist with that request."

    class FakeLLM:
        def invoke(self, messages):
            return FakeResponse()

    monkeypatch.setattr(orchestrator_module, "get_llm", lambda *args, **kwargs: FakeLLM())

    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "iteration_count": 0,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
    }

    update = orchestrator(state)
    assert update["next_agent"] == "sqli_agent"
    assert "guardrail_activations" in update
    assert update["guardrail_activations"][0]["provider"] == "gemini"
    assert update["guardrail_activations"][0]["context"] == "orchestrator"


def test_orchestrator_guardrail_refusal_with_unicode_apostrophe_logs_activation(monkeypatch):
    class FakeResponse:
        content = "I won’t assist with that request."

    class FakeLLM:
        def invoke(self, messages):
            return FakeResponse()

    monkeypatch.setattr(orchestrator_module, "get_llm", lambda *args, **kwargs: FakeLLM())

    state = {
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "iteration_count": 0,
        "max_iterations": 30,
        "security_level": "low",
        "llm_provider": "gemini",
    }

    update = orchestrator(state)
    assert update["next_agent"] == "sqli_agent"
    assert "guardrail_activations" in update
