"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import json

from evaluation.telemetry import RunTelemetry, stable_sha256


def test_run_telemetry_seq_is_monotonic():
    """Verifies run telemetry seq is monotonic behavior."""
    telemetry = RunTelemetry("run-1")
    telemetry.emit(iteration=0, node="orchestrator", event_type="orchestrator.prompt.generated", status="ok", payload={})
    telemetry.emit(iteration=0, node="orchestrator", event_type="orchestrator.llm.response", status="ok", payload={})

    events = telemetry.as_dict_list()
    assert events[0]["seq"] == 1
    assert events[1]["seq"] == 2


def test_write_jsonl_is_deterministic_ordered(tmp_path):
    """Verifies write jsonl is deterministic ordered behavior."""
    telemetry = RunTelemetry("run-2")
    telemetry.emit(iteration=1, node="orchestrator", event_type="one", status="ok", payload={"a": 1})
    telemetry.emit(iteration=2, node="orchestrator", event_type="two", status="ok", payload={"b": 2})

    out = telemetry.write_jsonl(tmp_path / "events.jsonl")
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    first = json.loads(lines[0])
    second = json.loads(lines[1])

    assert first["seq"] == 1
    assert second["seq"] == 2


def test_prompt_hash_stable_across_runs():
    """Verifies prompt hash stable across runs behavior."""
    text = "same content"
    assert stable_sha256(text) == stable_sha256(text)
