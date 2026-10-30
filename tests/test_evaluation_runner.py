"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import json

import pytest

from evaluation.runner import run_single_engagement


def test_orchestrator_provider_failure_is_not_reported_as_success(monkeypatch, tmp_path):
    """Regression for instant-success runs that made zero provider requests."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {
                **state,
                "iteration_count": 1,
                "task_result": "INCOMPLETE",
                "incomplete_reason": "LLM_RUNTIME_FAILURE",
                "fallback_events": [{
                    "event": "orchestrator.llm_failure",
                    "error_type": "OpenAIError",
                    "next_agent": "scorer",
                }],
                "telemetry_events": [{
                    "node": "orchestrator",
                    "iteration": 0,
                    "event": "orchestrator.fallback.applied",
                    "status": "fallback",
                    "payload": {"error_type": "OpenAIError", "next_agent": "scorer"},
                }],
            }

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kwargs: FakeApp())

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="openai_compatible",
        enriched_reporting=True,
        output_dir=str(tmp_path),
    )

    assert artifact["status"] == "error"
    assert artifact["task_result"] == "INCOMPLETE"
    assert artifact["incomplete_reason"] == "LLM_RUNTIME_FAILURE"
    assert artifact["llm_activity"] == {"started": 0, "completed": 0, "failed": 0, "tokens": 0}
    assert "OpenAIError" in artifact["error"]
    event_rows = [
        json.loads(line)
        for line in (tmp_path / f"{artifact['execution_id']}.events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(row["event_type"] == "orchestrator.fallback.applied" for row in event_rows)
    assert any(row["event_type"] == "run.failed" for row in event_rows)


def test_hybrid_payload_provider_fallback_is_not_reported_as_success(monkeypatch):
    """A payload-generation provider error must invalidate a hybrid run."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {
                **state,
                "iteration_count": 2,
                "task_result": "SUCCESS",
                "fallback_events": [{
                    "event": "payload_generation.static_seed_fallback",
                    "method": "sqli_union",
                    "payload_mode": "hybrid",
                    "reason": "llm_error",
                }],
                "telemetry_events": [
                    {"event": "llm.started", "status": "ok", "payload": {}},
                    {"event": "llm.failed", "status": "error", "payload": {"error_type": "TimeoutError"}},
                ],
            }

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kwargs: FakeApp())

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="openai_compatible",
        payload_mode="hybrid",
    )

    assert artifact["status"] == "error"
    assert artifact["task_result"] == "INCOMPLETE"
    assert artifact["incomplete_reason"] == "LLM_RUNTIME_FAILURE"
    assert artifact["llm_required"] is True
    assert artifact["llm_activity"]["failed"] == 1


@pytest.mark.parametrize("error_type", ["TransportError", "RequestTimeoutError"])
def test_true_target_transport_failure_remains_failed(monkeypatch, error_type):
    from foundation import http_client
    error = getattr(http_client, error_type)("unit target unavailable")
    monkeypatch.setattr("evaluation.runner.build_framework", lambda **kwargs: (_ for _ in ()).throw(error))
    artifact = run_single_engagement(target_url="http://localhost/dvwa", security_level="low", llm_provider="openai_compatible")
    assert artifact["execution_status"] == "failed"
    assert artifact["execution_reason"]["code"] == "TARGET_TRANSPORT_FAILURE"
    assert artifact["security_outcome"] == "unconfirmed"
