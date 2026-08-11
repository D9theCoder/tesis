"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from evaluation.runner import run_single_engagement
from tesis.runtime_events import CancellationToken, CollectingEventSink


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
    )

    assert artifact["status"] == "success"
    assert artifact["run_id"] == "gemini-sqli-low-static_only-0"
    assert artifact["config"]["payload_mode"] == "static_only"
    assert "report" in artifact


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
