from evaluation.runner import run_single_engagement


def test_run_single_engagement_artifact_shape(monkeypatch):
    class FakeApp:
        def invoke(self, state):
            return {
                "scores": {"sqli": 4},
                "confirmed_vulns": ["rce_achieved"],
                "achieved_outcomes": ["rce_achieved"],
                "guardrail_activations": [],
                "iteration_count": 3,
            }

        def stream(self, state, stream_mode=None):
            yield {
                "scores": {"sqli": 4},
                "confirmed_vulns": ["rce_achieved"],
                "achieved_outcomes": ["rce_achieved"],
                "guardrail_activations": [],
                "iteration_count": 3,
            }

    monkeypatch.setattr("evaluation.runner.build_framework", lambda llm_provider: FakeApp())

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        max_iterations=5,
        repeat_index=0,
    )

    assert artifact["status"] == "success"
    assert artifact["run_id"] == "gemini-low-0"
    assert "report" in artifact


def test_run_single_engagement_error_path(monkeypatch):
    def fail_framework(llm_provider):
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
