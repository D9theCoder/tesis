"""Checkpoint allowlisting, CLI opt-in, start failure and repeat isolation."""

from core.state import (
    ARTIFACT_ONLY_STATE_FIELDS,
    PERSISTENT_STATE_FIELDS,
    checkpoint_safe_state,
    new_default_state,
)


def test_checkpoint_safe_state_honors_explicit_allowlist():
    state = new_default_state()
    state["messages"] = ["rendered-prompt"]  # artifact-only
    state["mystery_future_field"] = "must-not-persist"  # unknown
    safe = checkpoint_safe_state(state)
    assert set(safe) <= PERSISTENT_STATE_FIELDS
    assert not (set(safe) & ARTIFACT_ONLY_STATE_FIELDS)
    assert "mystery_future_field" not in safe
    assert "messages" not in safe
    assert "selected_method" in safe


def test_cli_resume_flags_opt_in():
    import tesis.cli as cli

    namespace = cli._headless_parser().parse_args(
        ["--headless", "--mode", "single", "--resume",
         "--checkpoint-dir", "/tmp/exp", "--experiment-id", "exp1"]
    )
    overrides = cli._headless_overrides(namespace)
    assert overrides["resume"] is True
    assert overrides["checkpoint_dir"] == "/tmp/exp"
    assert overrides["experiment_id"] == "exp1"

    namespace = cli._headless_parser().parse_args(["--headless", "--mode", "single"])
    assert "resume" not in cli._headless_overrides(namespace)


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
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="start-fail",
    )
    assert artifact["status"] == "error"
    assert artifact["resumed_from_checkpoint"] is False
    assert "refusing run" in artifact["error"]


def test_repeat_index_isolates_checkpoint_identity(tmp_path, monkeypatch):
    """Repeat 0 receipt must not satisfy resume for repeat 1 (stable identity)."""
    from evaluation.runner import run_single_engagement

    class RunOnce:
        def stream(self, state, stream_mode=None, config=None):
            yield {**state, "iteration_count": 1, "task_result": "SUCCESS"}

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: RunOnce())
    first = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        repeat_index=0,
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="rep-exp",
    )
    assert first["status"] == "success"

    class MustNotRun:
        def stream(self, *a, **k):
            raise AssertionError("graph must not run on thread mismatch")

        def invoke(self, *a, **k):
            raise AssertionError("graph must not run on thread mismatch")

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: MustNotRun())
    bad = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        repeat_index=1,
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="rep-exp",
        resume=True,
    )
    assert bad["status"] == "error"
    assert bad["resumed_from_checkpoint"] is False
    assert "refus" in bad["error"]
    assert bad["checkpoint_thread_id"] != first["checkpoint_thread_id"]
