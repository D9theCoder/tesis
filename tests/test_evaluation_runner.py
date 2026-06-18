"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from evaluation.runner import run_single_engagement


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
    assert artifact["run_id"] == "gemini-akg_guided_hybrid-sqli-low-static_only-0"
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
