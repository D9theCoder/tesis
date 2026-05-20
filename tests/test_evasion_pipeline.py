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
        """Supports regression tests for test evasion pipeline."""
        return self

    def invoke(self, *args, **kwargs):
        """Supports regression tests for test evasion pipeline."""
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
        """Supports regression tests for test evasion pipeline."""
        return self

    def invoke(self, *args, **kwargs):
        """Supports regression tests for test evasion pipeline."""
        index = self._state.get("index", 0)
        if index < len(self._responses):
            resp = self._responses[index]
            self._state["index"] = index + 1
            return resp
        return {}

    def __call__(self, inputs: dict, **kwargs):
        return self.invoke(inputs, **kwargs)


def test_pipeline_returns_mutated_candidate(monkeypatch):
    """When compliance and validity pass, the mutated candidate is returned."""

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

    # Use a seed that contains phrases the mutator will transform
    seed = "You are a certified security assessor conducting a security assessment"
    evasion_graph = build_evasion_graph()
    result = evasion_graph.invoke(
        {"base_seed": seed, "retries": 0, "max_retries": 3, "evasion_strategy": "pipeline"}
    )
    # The template mutator should have changed the seed
    assert result["final_prompt"] != seed
    assert "security assessor" in result["final_prompt"]


def test_pipeline_falls_back_after_retries_exhausted(monkeypatch):
    """When all retries fail validation, the original seed is returned."""

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
        {"base_seed": "original seed", "retries": 0, "max_retries": 3, "evasion_strategy": "pipeline"}
    )
    assert result["final_prompt"] == "original seed"


def test_generate_candidate_increments_retries():
    """generate_candidate should increment retries by one."""
    state = _make_state(retries=2, base_seed="You are a certified security assessor")

    result = generate_candidate(state)
    assert result["retries"] == 3
    # Strategy 3 mutation changes "certified security assessor" to include "authorization"
    assert "authorization" in result["candidate_input"]
    assert result["strategy_reasoning"].startswith("template_mutation:")


def test_generate_candidate_applies_rotation():
    """generate_candidate should apply different mutations per retry count."""
    state = _make_state(retries=0, base_seed="You are a certified security assessor")

    result0 = generate_candidate(state)
    result1 = generate_candidate({**state, "retries": 1})
    result2 = generate_candidate({**state, "retries": 2})

    assert result0["candidate_input"] != result1["candidate_input"]
    assert result1["candidate_input"] != result2["candidate_input"]


def test_generate_candidate_falls_back_on_exception(monkeypatch):
    """When _mutate_prompt raises, fall back to base_seed."""
    def _boom(seed, attempt):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(pipeline_module, "_mutate_prompt", _boom)

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


def test_check_compliance_fails_open_on_exception(monkeypatch):
    """When the simulator LLM fails, treat candidate as compliant (fail-open)."""
    monkeypatch.setattr(pipeline_module, "get_simulator_llm", lambda _: None)

    state = _make_state(candidate_input="candidate text")

    result = check_compliance(state)
    assert result["is_compliant"] is True


def test_check_validity_returns_valid(monkeypatch):
    """check_validity forwards is_valid_injection as is_valid."""
    fake_llm = FakeLLM(responses=[{"is_valid_injection": True}])

    state = _make_state(candidate_input="candidate text")

    monkeypatch.setattr(pipeline_module, "get_simulator_llm", lambda *args, **kwargs: fake_llm)

    result = check_validity(state)
    assert result["is_valid"] is True


def test_check_validity_fails_open_on_exception(monkeypatch):
    """When the simulator LLM fails, treat candidate as valid (fail-open)."""
    monkeypatch.setattr(pipeline_module, "get_simulator_llm", lambda _: None)

    state = _make_state(candidate_input="candidate text")

    result = check_validity(state)
    assert result["is_valid"] is True


def test_route_evasion_success_when_both_gates_pass():
    """Verifies route evasion success when both gates pass behavior."""
    state = _make_state(
        candidate_input="candidate", strategy_reasoning="reason", is_compliant=True, is_valid=True, retries=1
    )
    assert route_evasion(state) == "success"


def test_route_evasion_fallback_when_retries_exhausted():
    """Verifies route evasion fallback when retries exhausted behavior."""
    state = _make_state(
        candidate_input="candidate", strategy_reasoning="reason", is_compliant=False, is_valid=False, retries=3
    )
    assert route_evasion(state) == "fallback"


def test_route_evasion_retry_when_gates_fail_and_budget_remains():
    """Verifies route evasion retry when gates fail and budget remains behavior."""
    state = _make_state(
        candidate_input="candidate", strategy_reasoning="reason", is_compliant=True, is_valid=False, retries=1
    )
    assert route_evasion(state) == "retry"


def test_route_evasion_retries_when_gates_fail_and_budget_remains_for_any_strategy():
    """Without deterministic strategy special-casing, always retry when budget remains."""
    state = _make_state(
        evasion_strategy="pipeline",
        candidate_input="candidate",
        strategy_reasoning="reason",
        is_compliant=False,
        is_valid=False,
        retries=1,
        max_retries=3,
    )
    assert route_evasion(state) == "retry"


def test_build_evasion_graph_is_cached_singleton():
    """Verifies build evasion graph is cached singleton behavior."""
    graph1 = build_evasion_graph()
    graph2 = build_evasion_graph()
    assert graph1 is graph2


def test_finalize_success_returns_candidate():
    """Verifies finalize success returns candidate behavior."""
    state = _make_state(
        candidate_input="final candidate", strategy_reasoning="reason", is_compliant=True, is_valid=True, retries=1
    )
    result = finalize_success(state)
    assert result["final_prompt"] == "final candidate"


def test_finalize_fallback_returns_base_seed():
    """Verifies finalize fallback returns base seed behavior."""
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
