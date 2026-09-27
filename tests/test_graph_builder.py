"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from copy import deepcopy

import agents.orchestrator as orchestrator_module
from langgraph.graph import END

from core.graph_builder import (
    build_framework,
    route_from_orchestrator,
    route_from_payload_validator,
)
from core.state import DEFAULT_STATE

def test_runtime_with_default_budget_remains_bounded(monkeypatch):
    """Verifies runtime with default budget remains bounded behavior."""
    def fail_get_llm(*args, **kwargs):
        """Supports regression tests for test graph builder."""
        raise RuntimeError("offline test")

    monkeypatch.setattr(orchestrator_module, "get_llm", fail_get_llm)

    app = build_framework(llm_provider="gemini")
    state = deepcopy(DEFAULT_STATE)

    result = app.invoke(state, config={"configurable": {"thread_id": "test"}})
    assert "next_agent" in result
    assert result.get("iteration_count", 0) <= state["max_iterations"]

def test_route_from_orchestrator_unknown_agent_defaults_to_scorer():
    """Verifies route from orchestrator unknown agent defaults to scorer behavior."""
    state = {"next_agent": "not_a_real_node"}
    assert route_from_orchestrator(state) == "scorer"

def test_payload_validator_does_not_route_rejected_candidate_to_method_agent():
    """Rejected payload history must not become an executable candidate queue."""
    state = {
        "selected_method": "ac_force_browse",
        "payload_candidates": {
            "ac_force_browse": [{"candidate_id": "blocked-candidate"}],
        },
        "payload_validation_results": {
            "ac_force_browse": [{
                "candidate_id": "blocked-candidate",
                "valid": False,
                "reason": "out_of_scope_target",
            }],
        },
    }

    assert route_from_payload_validator(state) == "chaining_router"

def test_stage6_real_scorer_node_executes(monkeypatch):
    """Verifies stage6 real scorer node executes behavior."""
    def fail_get_llm(*args, **kwargs):
        """Supports regression tests for test graph builder."""
        raise RuntimeError("offline test")

    monkeypatch.setattr(orchestrator_module, "get_llm", fail_get_llm)

    app = build_framework(llm_provider="gemini")
    state = deepcopy(DEFAULT_STATE)
    state["iteration_count"] = state["max_iterations"]
    state["scores"] = {"sqli_union": 3}

    result = app.invoke(state, config={"configurable": {"thread_id": "test"}})
    assert result["scores"]["sqli_union"] == 3
    assert result["next_agent"] == END
