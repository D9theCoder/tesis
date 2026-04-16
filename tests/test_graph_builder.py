from copy import deepcopy

import agents.orchestrator as orchestrator_module

from core.graph_builder import build_framework, route_from_orchestrator
from core.state import DEFAULT_STATE


def test_build_framework_compiles():
    app = build_framework(llm_provider="gemini")
    assert app is not None


def test_runtime_starts_from_recon(monkeypatch):
    def fail_get_llm(*args, **kwargs):
        raise RuntimeError("offline test")

    monkeypatch.setattr(orchestrator_module, "get_llm", fail_get_llm)

    app = build_framework(llm_provider="gemini")
    state = deepcopy(DEFAULT_STATE)
    state["max_iterations"] = 1

    result = app.invoke(state)
    assert "next_agent" in result


def test_runtime_with_default_budget_remains_bounded(monkeypatch):
    def fail_get_llm(*args, **kwargs):
        raise RuntimeError("offline test")

    monkeypatch.setattr(orchestrator_module, "get_llm", fail_get_llm)

    app = build_framework(llm_provider="gemini")
    state = deepcopy(DEFAULT_STATE)

    result = app.invoke(state)
    assert "next_agent" in result
    assert result.get("iteration_count", 0) <= state["max_iterations"]


def test_route_from_orchestrator_unknown_agent_defaults_to_scorer():
    state = {"next_agent": "not_a_real_node"}
    assert route_from_orchestrator(state) == "scorer"
