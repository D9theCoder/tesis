"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import json

from evaluation.runner import _llm_activity, run_single_engagement
from tesis.runtime_events import CancellationToken, CollectingEventSink


def test_runtime_activity_does_not_look_like_a_retry():
    """Runtime and provider callbacks for one call count as one attempt."""
    events = [
        {"event_type": "llm.started", "data": {"source": "llm_runtime"}},
        {"event_type": "llm.started", "data": {"provider": "openai_compatible"}},
        {
            "event_type": "llm.failed",
            "data": {
                "source": "llm_runtime",
                "parse_status": "invalid",
            },
        },
        {"event_type": "llm.completed", "data": {"provider": "openai_compatible"}},
    ]

    assert _llm_activity(events) == {
        "started": 1,
        "completed": 1,
        "failed": 0,
        "tokens": 0,
    }


def test_run_single_engagement_artifact_shape(monkeypatch):
    """Verifies run single engagement artifact shape behavior."""
    class FakeApp:
        """Groups regression tests for FakeApp behavior."""
        def invoke(self, state):
            """Supports regression tests for test evaluation runner."""
            return {
                "scores": {"sqli": 4},
                "confirmed_vulns": ["admin_session_obtained"],
                "achieved_outcomes": ["admin_session_obtained"],
                "guardrail_activations": [],
                "iteration_count": 3,
            }

        def stream(self, state, stream_mode=None):
            """Supports regression tests for test evaluation runner."""
            yield {
                "scores": {"sqli": 4},
                "confirmed_vulns": ["admin_session_obtained"],
                "achieved_outcomes": ["admin_session_obtained"],
                "guardrail_activations": [],
                "iteration_count": 3,
            }

    monkeypatch.setattr("evaluation.runner.build_framework", lambda llm_provider, surface="sqli": FakeApp())

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        max_iterations=5,
        repeat_index=0,
        target_method="sqli_union",
    )

    assert artifact["status"] == "success"
    assert artifact["run_id"] == "gemini-sqli-low-static_only-0"
    assert artifact["config"]["payload_mode"] == "static_only"
    assert artifact["llm_required"] is False
    assert artifact["llm_activity"] == {"started": 0, "completed": 0, "failed": 0, "tokens": 0}
    assert "report" in artifact


def test_static_auto_selection_without_provider_callback_is_not_reported_as_success(monkeypatch):
    """Automatic method selection still requires an observed model call."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {**state, "iteration_count": 1, "task_result": "SUCCESS"}

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kwargs: FakeApp())

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        payload_mode="static_only",
    )

    assert artifact["status"] == "error"
    assert artifact["incomplete_reason"] == "LLM_NOT_CALLED"


def test_run_single_engagement_error_path(monkeypatch):
    """Verifies run single engagement error path behavior."""
    def fail_framework(llm_provider, surface="sqli"):
        """Supports regression tests for test evaluation runner."""
        raise RuntimeError("offline test")

    monkeypatch.setattr("evaluation.runner.build_framework", fail_framework)

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        max_iterations=5,
        repeat_index=0,
    )

    assert artifact["status"] == "error"
    assert "RuntimeError" in artifact["error"]
    assert artifact["final_state"]["confirmed_vulns"] == []
    assert "module_scores" in artifact["report"]


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


def test_hybrid_run_without_provider_callback_is_not_reported_as_success(monkeypatch):
    """Model-backed modes must observe at least one provider callback."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {**state, "iteration_count": 1, "task_result": "SUCCESS"}

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kwargs: FakeApp())

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="openai_compatible",
        payload_mode="hybrid",
    )

    assert artifact["status"] == "error"
    assert artifact["task_result"] == "INCOMPLETE"
    assert artifact["incomplete_reason"] == "LLM_NOT_CALLED"
    assert artifact["llm_activity"] == {"started": 0, "completed": 0, "failed": 0, "tokens": 0}


def test_llm_failed_callback_is_not_reported_as_success(monkeypatch):
    """An explicit provider failure remains an error even after graph fallback."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {
                **state,
                "iteration_count": 1,
                "task_result": "SUCCESS",
                "telemetry_events": [
                    {"event": "llm.started", "status": "ok", "payload": {}},
                    {"event": "llm.failed", "status": "error", "payload": {"error_type": "RuntimeError"}},
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
    assert artifact["incomplete_reason"] == "LLM_RUNTIME_FAILURE"
    assert artifact["llm_activity"] == {"started": 1, "completed": 0, "failed": 1, "tokens": 0}


def test_partial_llm_activity_is_not_reported_as_success(monkeypatch):
    """Every observed provider start must have a matching completion."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {
                **state,
                "iteration_count": 1,
                "task_result": "SUCCESS",
                "telemetry_events": [
                    {"event": "llm.started", "status": "ok", "payload": {}},
                    {"event": "llm.started", "status": "ok", "payload": {}},
                    {"event": "llm.completed", "status": "ok", "payload": {}},
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
    assert artifact["incomplete_reason"] == "LLM_ACTIVITY_INCOMPLETE"
    assert artifact["llm_activity"] == {"started": 2, "completed": 1, "failed": 0, "tokens": 0}


def test_terminal_incomplete_run_is_not_reported_as_success(monkeypatch, tmp_path):
    """A completed graph must preserve its incomplete terminal result."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {
                **state,
                "iteration_count": 4,
                "task_result": "INCOMPLETE",
                "incomplete_reason": "ALL_METHODS_FAILED",
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
    assert artifact["incomplete_reason"] == "ALL_METHODS_FAILED"
    assert "ALL_METHODS_FAILED" in artifact["error"]
    failure_path = tmp_path / f"{artifact['execution_id']}.failure.json"
    assert failure_path.exists()
    failure = json.loads(failure_path.read_text(encoding="utf-8"))
    assert failure["final_state"]["task_result"] == "INCOMPLETE"
    assert failure["final_state"]["incomplete_reason"] == "ALL_METHODS_FAILED"

    event_rows = [
        json.loads(line)
        for line in (tmp_path / f"{artifact['execution_id']}.events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    failed = next(row for row in event_rows if row["event_type"] == "run.failed")
    assert failed["data"] == {"task_result": "INCOMPLETE", "reason": "ALL_METHODS_FAILED"}
    assert event_rows[-1]["event_type"] == "run.finished"
    assert event_rows[-1]["data"]["status"] == "error"


def test_iteration_limit_reason_is_preserved_in_artifact_events(monkeypatch, tmp_path):
    """The runner persists budget exhaustion distinctly from semantic failure."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {
                **state,
                "iteration_count": 30,
                "task_result": "INCOMPLETE",
                "incomplete_reason": "ITERATION_LIMIT",
                "telemetry_events": [{
                    "node": "orchestrator",
                    "iteration": 30,
                    "event": "orchestrator.stop",
                    "status": "incomplete",
                    "payload": {"reason": "ITERATION_LIMIT"},
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
    assert artifact["incomplete_reason"] == "ITERATION_LIMIT"
    event_rows = [
        json.loads(line)
        for line in (tmp_path / f"{artifact['execution_id']}.events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    failed = next(row for row in event_rows if row["event_type"] == "run.failed")
    assert failed["data"] == {"task_result": "INCOMPLETE", "reason": "ITERATION_LIMIT"}


def test_terminal_incomplete_without_reason_uses_a_stable_reason(monkeypatch, tmp_path):
    """Incomplete graph output without a reason remains auditable as an error."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {**state, "iteration_count": 2, "task_result": "INCOMPLETE"}

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
    assert artifact["incomplete_reason"] == "UNSPECIFIED"
    failure = json.loads(
        (tmp_path / f"{artifact['execution_id']}.failure.json").read_text(encoding="utf-8")
    )
    assert failure["final_state"]["incomplete_reason"] == "UNSPECIFIED"


def test_failure_sidecar_is_written_without_rich_reporting(monkeypatch, tmp_path):
    """Default/error runs retain a compact failure artifact for audit."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {**state, "iteration_count": 1, "task_result": "INCOMPLETE", "incomplete_reason": "ALL_METHODS_FAILED"}

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kwargs: FakeApp())

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        output_dir=str(tmp_path),
        enriched_reporting=False,
    )

    failure_path = tmp_path / f"{artifact['execution_id']}.failure.json"
    assert failure_path.exists()
    failure = json.loads(failure_path.read_text(encoding="utf-8"))
    assert failure["final_state"]["task_result"] == "INCOMPLETE"
    assert failure["final_state"]["incomplete_reason"] == "ALL_METHODS_FAILED"
    assert failure["final_state"]["llm_activity"]["started"] == 0


def test_reason_only_terminal_state_from_invoke_is_not_reported_as_success(monkeypatch):
    """The runner recognizes scorer-compatible reason-only terminal output."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            if False:
                yield state

        def invoke(self, state, config=None):
            return {**state, "iteration_count": 3, "incomplete_reason": "ALL_METHODS_FAILED"}

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kwargs: FakeApp())

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="openai_compatible",
    )

    assert artifact["status"] == "error"
    assert artifact["task_result"] == "INCOMPLETE"
    assert artifact["incomplete_reason"] == "ALL_METHODS_FAILED"


def test_unknown_terminal_state_is_not_reported_as_success(monkeypatch):
    """Malformed graph terminal values are normalized to an error."""
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {**state, "iteration_count": 1, "task_result": "FAILED"}

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kwargs: FakeApp())

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
    )

    assert artifact["status"] == "error"
    assert artifact["task_result"] == "INCOMPLETE"
    assert artifact["incomplete_reason"] == "INVALID_TASK_RESULT:FAILED"


def test_cancelled_before_execution_persists_cancelled_artifact(monkeypatch, tmp_path):
    token = CancellationToken()
    token.cancel("test requested cancellation")
    monkeypatch.setattr(
        "evaluation.runner.build_framework",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("graph must not build")),
    )

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        cancellation_token=token,
        output_dir=str(tmp_path),
    )

    assert artifact["status"] == "cancelled"
    assert artifact["execution_id"]
    assert artifact["config_fingerprint"]
    assert (tmp_path / f"{artifact['execution_id']}.json").exists()


def test_runtime_sink_receives_ordered_lifecycle_and_state_events(monkeypatch):
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {
                **state,
                "iteration_count": 1,
                "selected_method": "sqli_union",
                "telemetry_events": [{
                    "event": "payload.validation.completed",
                    "node": "payload_validator",
                    "status": "ok",
                    "payload": {"accepted": 1},
                }],
            }

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kwargs: FakeApp())
    sink = CollectingEventSink()

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        event_sink=sink,
    )

    event_types = [event.event_type for event in sink.events]
    assert event_types[0] == "run.started"
    assert "payload.validation.completed" in event_types
    assert "graph.state" in event_types
    assert event_types[-1] == "run.finished"
    assert artifact["execution_log"]


def test_cancellation_between_graph_states_keeps_latest_snapshot(monkeypatch):
    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {**state, "iteration_count": 1, "selected_method": "sqli_union"}
            raise AssertionError("second graph operation must not be scheduled")

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kwargs: FakeApp())
    token = CancellationToken()

    def cancel_on_state(event):
        if event.event_type == "graph.state":
            token.cancel("stop at graph boundary")

    sink = CollectingEventSink(cancel_on_state)
    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        event_sink=sink,
        cancellation_token=token,
    )

    assert artifact["status"] == "cancelled"
    assert artifact["final_state"]["iteration_count"] == 1


def test_runtime_calls_feed_runner_activity_and_effective_runtime_metadata(monkeypatch):
    """Direct runtime calls remain visible to runner audit telemetry."""
    from agents.orchestrator import orchestrator

    class Response:
        content = '{"next_agent":"sqli_union","reason_code":"best_viable"}'
        usage_metadata = {"input_tokens": 11, "output_tokens": 4}

    class FakeClient:
        def __init__(self):
            self.calls = 0

        def invoke(self, messages):
            self.calls += 1
            assert messages  # The runtime still supplies stable system/user messages.
            return Response()

    client = FakeClient()
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: client)

    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            del stream_mode, config
            yield {
                **state,
                **orchestrator(state),
                "iteration_count": 1,
                "task_result": "SUCCESS",
            }

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kwargs: FakeApp())

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="openai_compatible",
        payload_mode="static_only",
        model_config={"model_name": "base", "api_key": "do-not-store"},
        llm_role_configs={
            "orchestrator": {
                "model_profile": "openai_compatible",
                "model_name": "planner",
                "temperature": 0,
                "max_tokens": 96,
                "structured_output": "json_prompt",
            },
            "payload_generator": {
                "model_profile": "openai_compatible",
                "model_name": "mutator",
                "temperature": 0,
                "structured_output": "auto",
            },
        },
        llm_cache_scope="run",
    )

    assert artifact["status"] == "success"
    assert artifact["llm_activity"] == {"started": 1, "completed": 1, "failed": 0, "tokens": 0}
    assert client.calls == 1
    runtime_events = [
        event for event in artifact["execution_log"]
        if event["event_type"].startswith("llm.")
        and event["data"].get("source") == "llm_runtime"
    ]
    assert [event["event_type"] for event in runtime_events] == [
        "llm.started",
        "llm.completed",
    ]
    assert runtime_events[0]["data"]["role"] == "orchestrator"
    assert runtime_events[0]["data"]["prompt_hash"].startswith("sha256:")
    assert "prompts" not in runtime_events[0]["data"]
    assert "response" not in runtime_events[-1]["data"]

    effective = artifact["llm_runtime_config"]
    assert effective["max_concurrency"] == 1
    assert effective["cache_scope"] == "run"
    assert effective["roles"]["orchestrator"] == {
        "model_profile": "openai_compatible",
        "provider": "openai_compatible",
        "model_name": "planner",
        "temperature": 0,
        "max_tokens": 96,
        "structured_output": "json_prompt",
        "model_fingerprint": effective["roles"]["orchestrator"]["model_fingerprint"],
    }
    assert effective["roles"]["payload_generator"]["model_name"] == "mutator"
    assert "do-not-store" not in json.dumps(effective)
    assert artifact["config"]["llm_cache_scope"] == "run"
    assert artifact["config"]["llm_max_concurrency"] == 1
