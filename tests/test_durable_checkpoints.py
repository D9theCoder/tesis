"""Durable SQLite checkpoint + opt-in resume contract (arch handoff slice 2).

Covers: stable thread identity, allowlist-only checkpoint state, completion
receipt gating, fail-closed validation, CLI opt-in passthrough, and one
crash/restart integration test proving completed nodes are not re-executed.
"""

from core.checkpoint_store import (
    ExperimentCheckpointStore,
    coordinate_fingerprint,
    default_store_path,
    stable_thread_id,
    validate_resume,
)
from core.state import (
    ARTIFACT_ONLY_STATE_FIELDS,
    PERSISTENT_STATE_FIELDS,
    checkpoint_safe_state,
    new_default_state,
)


def _coordinate(**overrides):
    base = {
        "target_url": "http://localhost/dvwa",
        "provider": "gemini",
        "surface": "sqli",
        "security_level": "low",
        "payload_mode": "static_only",
        "experiment_condition": "linear_hybrid",
        "target_method": "sqli_union",
        "repeat_index": 0,
    }
    base.update(overrides)
    return base


def test_stable_thread_id_deterministic():
    coord = _coordinate()
    assert stable_thread_id("exp-A", coord) == stable_thread_id("exp-A", coord)
    assert stable_thread_id("exp-A", coord) != stable_thread_id("exp-B", coord)
    assert stable_thread_id("exp-A", coord) != stable_thread_id(
        "exp-A", _coordinate(repeat_index=1)
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


def test_validate_resume_fail_closed_matrix(tmp_path):
    coord = _coordinate()
    store = ExperimentCheckpointStore(
        tmp_path / "checkpoints.sqlite3", experiment_id="exp1"
    )
    try:
        thread = stable_thread_id("exp1", coord)
        artifact = {"run_id": "r1", "status": "success"}
        store.save_completed(
            thread_id=thread,
            final_state={**new_default_state(), "selected_method": "sqli_union"},
            artifact=artifact,
            coordinate=coord,
        )
        stored = store.load(thread)
        ok, _ = validate_resume(stored, coordinate=coord)
        assert ok
        # Config drift fails closed.
        ok, reason = validate_resume(
            stored, coordinate=_coordinate(payload_mode="hybrid")
        )
        assert not ok and "refus" in reason
        # Target drift fails closed.
        ok, reason = validate_resume(
            stored, coordinate=_coordinate(target_url="http://evil/x")
        )
        assert not ok and "refus" in reason
        # No completion receipt fails closed (unsafe replay of external nodes).
        tampered = dict(stored, completion_receipt=0)
        ok, reason = validate_resume(tampered, coordinate=coord)
        assert not ok and "refus" in reason
        # Version drift fails closed.
        tampered = dict(stored, graph_build_version="graph.v999")
        ok, reason = validate_resume(tampered, coordinate=coord)
        assert not ok and "refus" in reason
        # Missing thread returns None.
        assert store.load("nope:no-such-coordinate") is None
    finally:
        store.close()


def test_default_store_path_experiment_local(tmp_path):
    assert default_store_path(str(tmp_path), None) == tmp_path / "checkpoints.sqlite3"
    assert default_store_path(None, str(tmp_path)) == tmp_path / "checkpoints.sqlite3"


def test_crash_restart_does_not_rerun_completed_nodes(tmp_path, monkeypatch):
    """Completed run -> crash (new process) -> resume replays zero nodes."""
    from evaluation.runner import run_single_engagement

    calls: list[str] = []

    class RunOnceThenDie:
        """First process: completes, then simulates a crash before returning."""

        def stream(self, state, stream_mode=None, config=None):
            calls.append("graph-invoked")
            yield {**state, "iteration_count": 1, "task_result": "SUCCESS"}

    monkeypatch.setattr(
        "evaluation.runner.build_framework", lambda **_kw: RunOnceThenDie()
    )
    first = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="crash-exp",
    )
    assert first["status"] == "success"
    assert first["checkpoint_thread_id"] == stable_thread_id(
        "crash-exp", _coordinate()
    )
    assert (tmp_path / "checkpoints.sqlite3").exists()
    assert calls == ["graph-invoked"]

    # Simulate process restart: a fresh interpreter state where the graph
    # would explode if invoked again.
    calls.clear()

    class MustNotRun:
        def stream(self, *a, **k):
            calls.append("graph-invoked-after-crash")
            raise AssertionError("graph must not rerun on resume")

        def invoke(self, *a, **k):
            calls.append("graph-invoked-after-crash")
            raise AssertionError("graph must not rerun on resume")

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: MustNotRun())
    resumed = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="crash-exp",
        resume=True,
    )
    assert resumed["resumed_from_checkpoint"] is True
    assert resumed["status"] == "success"
    assert calls == []


def test_resume_mismatch_fails_closed_without_running_graph(tmp_path, monkeypatch):
    from evaluation.runner import run_single_engagement

    class RunOnce:
        def stream(self, state, stream_mode=None, config=None):
            yield {**state, "iteration_count": 1, "task_result": "SUCCESS"}

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: RunOnce())
    run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="exp-mismatch",
    )

    class MustNotRun:
        def stream(self, *a, **k):
            raise AssertionError("graph must not run on failed resume")

        def invoke(self, *a, **k):
            raise AssertionError("graph must not run on failed resume")

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: MustNotRun())
    bad = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        stop_policy="coverage",  # drifted setup, same thread, new fingerprint
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="exp-mismatch",
        resume=True,
    )
    assert bad["status"] == "error"
    assert bad["resumed_from_checkpoint"] is False
    assert "refus" in bad["error"]


def test_resume_defaults_off_no_sqlite_written(tmp_path, monkeypatch):
    from evaluation.runner import run_single_engagement

    class RunOnce:
        def stream(self, state, stream_mode=None, config=None):
            yield {**state, "iteration_count": 1, "task_result": "SUCCESS"}

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: RunOnce())
    run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
    )
    assert not (tmp_path / "checkpoints.sqlite3").exists()


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


def test_coordinate_fingerprint_stable_and_secret_free():
    coord = _coordinate()
    assert coordinate_fingerprint(coord) == coordinate_fingerprint(dict(coord))
    assert coordinate_fingerprint(coord) != coordinate_fingerprint(
        _coordinate(security_level="high")
    )


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


def test_resume_missing_metadata_file_fails_closed_without_graph(tmp_path, monkeypatch):
    """--resume with no metadata DB must fail closed before touching the graph."""
    from evaluation.runner import run_single_engagement

    class MustNotRun:
        def stream(self, *a, **k):
            raise AssertionError("graph must not run with missing metadata")

        def invoke(self, *a, **k):
            raise AssertionError("graph must not run with missing metadata")

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: MustNotRun())
    missing = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path / "empty"),
        experiment_id="nope",
        resume=True,
    )
    assert missing["status"] == "error"
    assert missing["resumed_from_checkpoint"] is False
    assert "refus" in missing["error"]
