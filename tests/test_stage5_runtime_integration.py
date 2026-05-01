from copy import deepcopy

from core.graph_builder import (
    RUNTIME_AGENT_HANDLERS,
    RUNTIME_AGENT_NODE_NAMES,
    build_framework,
    route_from_orchestrator,
)
from core.state import DEFAULT_STATE


def test_build_framework_compiles():
    app = build_framework(llm_provider="gemini", surface="sqli")
    assert app is not None


def test_runtime_starts_from_recon(monkeypatch):
    def fail_get_llm(*args, **kwargs):
        raise RuntimeError("offline test")

    monkeypatch.setattr("agents.orchestrator.get_llm", fail_get_llm)

    app = build_framework(llm_provider="gemini", surface="sqli")
    state = deepcopy(DEFAULT_STATE)
    state["max_iterations"] = 1

    result = app.invoke(state, config={"configurable": {"thread_id": "test"}})
    assert "next_agent" in result


def test_route_from_orchestrator_unknown_agent_defaults_to_scorer():
    state = {"next_agent": "not_a_real_node"}
    assert route_from_orchestrator(state) == "scorer"


def test_runtime_handlers_are_real_callables():
    assert set(RUNTIME_AGENT_NODE_NAMES) == set(RUNTIME_AGENT_HANDLERS.keys())
    for name, handler in RUNTIME_AGENT_HANDLERS.items():
        assert callable(handler), f"Handler for {name} is not callable"
