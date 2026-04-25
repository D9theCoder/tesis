"""Tests for the Stage 8 evasion pipeline (LangGraph subgraph)."""

from __future__ import annotations

import pytest

import llm.evasion.pipeline as pipeline_module
from llm.evasion.pipeline import (
    EvasionState,
    build_evasion_graph,
    check_compliance,
    check_validity,
    finalize_fallback,
    finalize_success,
    generate_candidate,
    route_evasion,
)


def _make_state(**overrides) -> EvasionState:
    """Return a valid EvasionState with sensible defaults."""
    defaults: EvasionState = {
        "base_seed": "seed",
        "candidate_input": "",
        "strategy_reasoning": "",
        "is_compliant": False,
        "is_valid": False,
        "retries": 0,
        "max_retries": 3,
        "final_prompt": "",
        "evasion_strategy": "prompt_injection",
    }
    defaults.update(overrides)  # type: ignore[typeddict-item]
    return defaults


class FakeLLM:
    """Configurable fake LLM for testing structured output nodes.

    Implements the minimal Runnable-like interface so it can be used with
    LangChain's ``prompt | llm`` pipe operator.
    """

    def __init__(self, responses: list[dict] | None = None):
        self.responses = responses or []
        self.call_count = 0

    def with_structured_output(self, schema):
        return self

    def invoke(self, *args, **kwargs):
        if self.call_count < len(self.responses):
            resp = self.responses[self.call_count]
            self.call_count += 1
            return resp
        return {}

    def __call__(self, inputs: dict, **kwargs):
        """Make the fake runnable-compatible for the pipe operator."""
        return self.invoke(inputs, **kwargs)


class SharedFakeLLM:
    """Fake LLM with a shared response queue across all instances.

    Use this when ``get_simulator_llm`` is expected to be called multiple
    times and each call should consume the next response in a single queue.
    """

    def __init__(self, shared_responses: list[dict], shared_state: dict[str, int]):
        self._responses = shared_responses
        self._state = shared_state

    def with_structured_output(self, schema):
        return self

    def invoke(self, *args, **kwargs):
        index = self._state.get("index", 0)
        if index < len(self._responses):
            resp = self._responses[index]
            self._state["index"] = index + 1
            return resp
        return {}

    def __call__(self, inputs: dict, **kwargs):
        return self.invoke(inputs, **kwargs)


def test_pipeline_returns_enhanced_candidate(monkeypatch):
    """When compliance and validity pass, the enhanced candidate is returned."""

    monkeypatch.setattr(
        pipeline_module, "enhance_with_deepteam", lambda base, strategy, **kwargs: "enhanced candidate"
    )
    shared_responses = [
        {"non_compliant": False},
        {"is_valid_injection": True},
    ]
    shared_state = {"index": 0}
    monkeypatch.setattr(
        pipeline_module,
        "get_simulator_llm",
        lambda _model, **kwargs: SharedFakeLLM(shared_responses, shared_state),
    )

    evasion_graph = build_evasion_graph()
    result = evasion_graph.invoke(
        {"base_seed": "base seed", "retries": 0, "max_retries": 3, "evasion_strategy": "prompt_injection"}
    )
    assert result["final_prompt"] == "enhanced candidate"


def test_pipeline_falls_back_after_retries_exhausted(monkeypatch):
    """When all retries fail validation, the original seed is returned."""

    monkeypatch.setattr(
        pipeline_module, "enhance_with_deepteam", lambda base, strategy, **kwargs: "bad candidate"
    )
    # Each full retry cycle consumes 2 LLM calls:
    # check_compliance → check_validity
    # For max_retries=3 we need 3 cycles = 6 responses.
    shared_responses = [
        {"non_compliant": True}, {"is_valid_injection": False},
        {"non_compliant": True}, {"is_valid_injection": False},
        {"non_compliant": True}, {"is_valid_injection": False},
    ]
    shared_state = {"index": 0}
    monkeypatch.setattr(
        pipeline_module,
        "get_simulator_llm",
        lambda _model, **kwargs: SharedFakeLLM(shared_responses, shared_state),
    )

    evasion_graph = build_evasion_graph()
    result = evasion_graph.invoke(
        {"base_seed": "original seed", "retries": 0, "max_retries": 3, "evasion_strategy": "prompt_injection"}
    )
    assert result["final_prompt"] == "original seed"


def test_generate_candidate_increments_retries(monkeypatch):
    """generate_candidate should increment retries by one."""
    monkeypatch.setattr(
        pipeline_module, "enhance_with_deepteam", lambda base, strategy, **kwargs: f"candidate:{strategy}"
    )

    state = _make_state(retries=2)

    result = generate_candidate(state)
    assert result["retries"] == 3
    assert result["candidate_input"] == "candidate:prompt_injection"
    assert result["strategy_reasoning"] == "deep_team:prompt_injection"


def test_generate_candidate_uses_custom_strategy(monkeypatch):
    """generate_candidate should respect the evasion_strategy from state."""
    monkeypatch.setattr(
        pipeline_module, "enhance_with_deepteam", lambda base, strategy, **kwargs: f"candidate:{strategy}"
    )

    state = _make_state(evasion_strategy="base64")

    result = generate_candidate(state)
    assert result["candidate_input"] == "candidate:base64"
    assert result["strategy_reasoning"] == "deep_team:base64"


def test_generate_candidate_normalizes_strategy(monkeypatch):
    """generate_candidate should normalize case/whitespace variants."""

    monkeypatch.setattr(
        pipeline_module, "enhance_with_deepteam", lambda base, strategy, **kwargs: f"candidate:{strategy}"
    )

    state = _make_state(evasion_strategy=" Prompt_Injection ")

    result = generate_candidate(state)
    assert result["candidate_input"] == "candidate:prompt_injection"
    assert result["strategy_reasoning"] == "deep_team:prompt_injection"


def test_generate_candidate_falls_back_on_exception(monkeypatch):
    """When enhance_with_deepteam raises, fall back to base_seed."""
    def _boom(base, strategy, **kwargs):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(pipeline_module, "enhance_with_deepteam", _boom)

    state = _make_state(base_seed="original seed")

    result = generate_candidate(state)
    assert result["candidate_input"] == "original seed"
    assert result["retries"] == 1


def test_check_compliance_returns_not_non_compliant(monkeypatch):
    """check_compliance inverts non_compliant to produce is_compliant."""
    fake_llm = FakeLLM(responses=[{"non_compliant": False}])

    state = _make_state(candidate_input="candidate text")

    monkeypatch.setattr(pipeline_module, "get_simulator_llm", lambda *args, **kwargs: fake_llm)

    result = check_compliance(state)
    assert result["is_compliant"] is True


def test_check_compliance_falls_back_on_exception(monkeypatch):
    """When the simulator LLM fails, treat candidate as non-compliant."""
    monkeypatch.setattr(pipeline_module, "get_simulator_llm", lambda _: None)

    state = _make_state(candidate_input="candidate text")

    result = check_compliance(state)
    assert result["is_compliant"] is False


def test_check_validity_returns_valid(monkeypatch):
    """check_validity forwards is_valid_injection as is_valid."""
    fake_llm = FakeLLM(responses=[{"is_valid_injection": True}])

    state = _make_state(candidate_input="candidate text")

    monkeypatch.setattr(pipeline_module, "get_simulator_llm", lambda *args, **kwargs: fake_llm)

    result = check_validity(state)
    assert result["is_valid"] is True


def test_check_validity_falls_back_on_exception(monkeypatch):
    """When the simulator LLM fails, treat candidate as invalid."""
    monkeypatch.setattr(pipeline_module, "get_simulator_llm", lambda _: None)

    state = _make_state(candidate_input="candidate text")

    result = check_validity(state)
    assert result["is_valid"] is False


def test_route_evasion_success_when_both_gates_pass():
    state = _make_state(
        candidate_input="candidate", strategy_reasoning="reason", is_compliant=True, is_valid=True, retries=1
    )
    assert route_evasion(state) == "success"


def test_route_evasion_fallback_when_retries_exhausted():
    state = _make_state(
        candidate_input="candidate", strategy_reasoning="reason", is_compliant=False, is_valid=False, retries=3
    )
    assert route_evasion(state) == "fallback"


def test_route_evasion_retry_when_gates_fail_and_budget_remains():
    state = _make_state(
        candidate_input="candidate", strategy_reasoning="reason", is_compliant=True, is_valid=False, retries=1
    )
    assert route_evasion(state) == "retry"


def test_route_evasion_fallback_for_deterministic_strategy_after_first_failure():
    state = _make_state(
        evasion_strategy=" base64 ",
        candidate_input="candidate",
        strategy_reasoning="reason",
        is_compliant=False,
        is_valid=False,
        retries=1,
        max_retries=3,
    )
    assert route_evasion(state) == "fallback"


def test_build_evasion_graph_is_cached_singleton():
    graph1 = build_evasion_graph()
    graph2 = build_evasion_graph()
    assert graph1 is graph2


def test_finalize_success_returns_candidate():
    state = _make_state(
        candidate_input="final candidate", strategy_reasoning="reason", is_compliant=True, is_valid=True, retries=1
    )
    result = finalize_success(state)
    assert result["final_prompt"] == "final candidate"


def test_finalize_fallback_returns_base_seed():
    state = _make_state(
        base_seed="original seed",
        candidate_input="candidate",
        strategy_reasoning="reason",
        is_compliant=False,
        is_valid=False,
        retries=3,
    )
    result = finalize_fallback(state)
    assert result["final_prompt"] == "original seed"
