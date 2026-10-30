"""Checkpoint allowlisting, CLI opt-in, start failure and repeat isolation."""


def test_start_identity_failure_fails_closed_before_graph(tmp_path, monkeypatch):
    """save_started failure must refuse the run before any external action."""
    from evaluation import runner as runner_mod
    from evaluation.runner import run_single_engagement

    class MustNotRun:
        def stream(self, *a, **k):
            raise AssertionError("graph must not run when identity row fails")

        def invoke(self, *a, **k):
            raise AssertionError("graph must not run when identity row fails")

    monkeypatch.setattr(runner_mod, "build_framework", lambda **_kw: MustNotRun())
    real_store = runner_mod.ExperimentCheckpointStore

    class FailingStore(real_store):
        def save_started(self, *a, **k):
            raise OSError("readonly checkpoint dir")

    monkeypatch.setattr(runner_mod, "ExperimentCheckpointStore", FailingStore)
    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="openai_compatible",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="start-fail",
    )
    assert artifact["status"] == "error"
    assert artifact["resumed_from_checkpoint"] is False
    assert "refusing run" in artifact["error"]
