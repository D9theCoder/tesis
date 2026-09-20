"""P0 opt-in checkpoint regression (handoff 2026-09-20).

Default single/matrix runs must not create SQLite checkpoint databases and
must forward checkpoint flags unchanged; explicit runs must. ``--resume``
without metadata must fail closed before the graph runs, and the default
path must work without the sqlite-saver package installed.
"""

import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class _RunOnce:
    def stream(self, state, stream_mode=None, config=None):
        yield {**state, "iteration_count": 1, "task_result": "SUCCESS"}


def test_default_single_creates_no_sqlite(tmp_path, monkeypatch):
    from evaluation.runner import run_single_engagement

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: _RunOnce())
    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
    )
    assert artifact["status"] == "success"
    assert artifact["checkpoint_store"] is None
    assert artifact["graph_checkpoint_store"] is None
    assert artifact["resumed_from_checkpoint"] is False
    assert artifact["resumed"] is False
    assert list(tmp_path.rglob("*.sqlite3")) == []


def test_default_matrix_forwards_none_and_creates_no_sqlite(tmp_path, monkeypatch):
    import evaluation.multi_llm_runner as multi_mod
    from evaluation.multi_llm_runner import run_provider_matrix

    seen = []

    def fake_run(**kwargs):
        seen.append(kwargs)
        return {"status": "success"}

    monkeypatch.setattr(multi_mod, "run_single_engagement", fake_run)
    artifacts = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low"],
        surfaces=["sqli"],
        payload_modes=["static_only"],
        target_method="sqli_union",
        output_dir=str(tmp_path),
    )
    assert len(artifacts) == 1
    assert seen and all(
        kwargs["checkpoint_dir"] is None and kwargs["experiment_id"] is None
        for kwargs in seen
    )
    assert list(tmp_path.rglob("*.sqlite3")) == []


def test_explicit_matrix_forwards_dir_and_id_and_creates_both_dbs(
    tmp_path, monkeypatch
):
    import evaluation.multi_llm_runner as multi_mod
    from evaluation.multi_llm_runner import run_provider_matrix

    ckpt_dir = tmp_path / "ckpt"
    seen = []
    real_run = multi_mod.run_single_engagement

    def spy(**kwargs):
        seen.append(kwargs)
        return real_run(**kwargs)

    monkeypatch.setattr(multi_mod, "run_single_engagement", spy)
    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: _RunOnce())
    artifacts = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low"],
        surfaces=["sqli"],
        payload_modes=["static_only"],
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(ckpt_dir),
        experiment_id="exp1",
    )
    assert len(artifacts) == 1
    assert seen and all(
        kwargs["checkpoint_dir"] == str(ckpt_dir)
        and kwargs["experiment_id"] == "exp1"
        for kwargs in seen
    )
    artifact = artifacts[0]
    assert artifact["status"] == "success"
    assert artifact["checkpoint_store"] == str(ckpt_dir / "checkpoints.sqlite3")
    assert artifact["graph_checkpoint_store"] == str(
        ckpt_dir / "langgraph_checkpoints.sqlite3"
    )
    assert (ckpt_dir / "checkpoints.sqlite3").exists()
    assert (ckpt_dir / "langgraph_checkpoints.sqlite3").exists()


def test_resume_without_metadata_fails_closed_pre_execution(tmp_path, monkeypatch):
    from evaluation.runner import run_single_engagement

    class MustNotRun:
        def stream(self, *a, **k):
            raise AssertionError("graph must not run on failed resume")

        def invoke(self, *a, **k):
            raise AssertionError("graph must not run on failed resume")

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
    assert missing["resumed"] is False
    assert "refus" in missing["error"]

def test_corrupt_metadata_db_fails_closed_pre_execution(tmp_path, monkeypatch):
    from evaluation.runner import run_single_engagement

    ckpt_dir = tmp_path / "ckpt"
    ckpt_dir.mkdir()
    (ckpt_dir / "checkpoints.sqlite3").write_bytes(b"not a sqlite db\x00\x01\x02")

    class MustNotRun:
        def stream(self, *a, **k):
            raise AssertionError("graph must not run on corrupt metadata")

        def invoke(self, *a, **k):
            raise AssertionError("graph must not run on corrupt metadata")

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: MustNotRun())
    bad = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(ckpt_dir),
        experiment_id="corrupt-exp",
        resume=True,
    )
    assert bad["status"] == "error"
    assert bad["resumed_from_checkpoint"] is False
    assert bad["resumed"] is False
    assert "refus" in bad["error"]

def test_malformed_receipt_fails_closed_pre_execution(tmp_path, monkeypatch):
    from core.checkpoint_store import (
        ExperimentCheckpointStore,
        stable_thread_id,
    )
    from evaluation.runner import run_single_engagement

    coord = {
        "target_url": "http://localhost/dvwa",
        "provider": "gemini",
        "surface": "sqli",
        "security_level": "low",
        "payload_mode": "static_only",
        "experiment_condition": "linear_hybrid",
        "target_method": "sqli_union",
        "repeat_index": 0,
        "stop_policy": "impact",
        "coverage_target": 0.70,
        "candidate_budget": 5,
        "max_iterations": 30,
        "model_name": None,
        "evasion_enabled": False,
        "evasion_mode": "reactive",
    }
    db = tmp_path / "checkpoints.sqlite3"
    store = ExperimentCheckpointStore(db, experiment_id="bad-receipt")
    store.save_completed(
        thread_id=stable_thread_id("bad-receipt", coord),
        final_state={},
        artifact={"status": "success"},
        coordinate=coord,
    )
    store.close()

    class MustNotRun:
        def stream(self, *a, **k):
            raise AssertionError("graph must not run on malformed receipt")

        def invoke(self, *a, **k):
            raise AssertionError("graph must not run on malformed receipt")

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: MustNotRun())
    import sqlite3

    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "UPDATE checkpoints SET completion_receipt = 'not-an-int'"
        )
        conn.commit()
    finally:
        conn.close()
    bad = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="bad-receipt",
        resume=True,
    )
    assert bad["status"] == "error"
    assert bad["resumed_from_checkpoint"] is False
    assert bad["resumed"] is False
    assert "refus" in bad["error"]


def test_completed_receipt_replay_sets_both_resume_flags(tmp_path, monkeypatch):
    from evaluation.runner import run_single_engagement

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: _RunOnce())
    first = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="replay-exp",
    )
    assert first["status"] == "success"

    class MustNotRun:
        def stream(self, *a, **k):
            raise AssertionError("graph must not rerun on completed replay")

        def invoke(self, *a, **k):
            raise AssertionError("graph must not rerun on completed replay")

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: MustNotRun())
    replayed = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="replay-exp",
        resume=True,
    )
    assert replayed["status"] == "success"
    assert replayed["resumed_from_checkpoint"] is True
    assert replayed["resumed"] is True


def test_legacy_completed_artifact_replay_normalizes_resumed_flag(tmp_path, monkeypatch):
    import json
    import sqlite3

    from core.checkpoint_store import (
        ExperimentCheckpointStore,
        coordinate_fingerprint,
        stable_thread_id,
    )
    from core.state import CHECKPOINT_SCHEMA_VERSION, STATE_SCHEMA_VERSION
    from core.graph_builder import GRAPH_BUILD_VERSION
    from evaluation.runner import run_single_engagement

    coord = {
        "target_url": "http://localhost/dvwa",
        "provider": "gemini",
        "surface": "sqli",
        "security_level": "low",
        "payload_mode": "static_only",
        "experiment_condition": "linear_hybrid",
        "target_method": "sqli_union",
        "repeat_index": 0,
        "stop_policy": "impact",
        "coverage_target": 0.70,
        "candidate_budget": 5,
        "max_iterations": 30,
        "model_name": None,
        "evasion_enabled": False,
        "evasion_mode": "reactive",
    }
    thread = stable_thread_id("legacy-exp", coord)
    db = tmp_path / "checkpoints.sqlite3"
    store = ExperimentCheckpointStore(db, experiment_id="legacy-exp")
    store.close()
    # Legacy fixture: stored success artifact predates the canonical `resumed` flag.
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "INSERT OR REPLACE INTO checkpoints (thread_id, experiment_id,"
            " state_json, artifact_json, state_schema_version,"
            " checkpoint_schema_version, graph_build_version,"
            " coordinate_fingerprint, target_url, last_completed_node,"
            " completion_receipt, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                thread,
                "legacy-exp",
                "{}",
                json.dumps({"status": "success", "resumed_from_checkpoint": False}),
                STATE_SCHEMA_VERSION,
                CHECKPOINT_SCHEMA_VERSION,
                GRAPH_BUILD_VERSION,
                coordinate_fingerprint(coord),
                "http://localhost/dvwa",
                "scorer",
                1,
                "2026-09-20T00:00:00+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    class MustNotRun:
        def stream(self, *a, **k):
            raise AssertionError("graph must not rerun on legacy replay")

        def invoke(self, *a, **k):
            raise AssertionError("graph must not rerun on legacy replay")

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kw: MustNotRun())
    replayed = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(tmp_path),
        checkpoint_dir=str(tmp_path),
        experiment_id="legacy-exp",
        resume=True,
    )
    assert replayed["status"] == "success"
    assert replayed["resumed_from_checkpoint"] is True
    assert replayed["resumed"] is True

def test_default_path_runs_without_sqlite_saver_subprocess(tmp_path):
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    script = textwrap.dedent(
        """
        import importlib.abc
        import sys
        from pathlib import Path

        out_dir = Path(sys.argv[1])


        class Block(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path=None, target=None):
                if name == "langgraph.checkpoint.sqlite" or name.startswith(
                    "langgraph.checkpoint.sqlite."
                ):
                    raise ImportError("blocked for opt-in regression test")
                return None


        sys.meta_path.insert(0, Block())
        for mod in [m for m in sys.modules if m.startswith("langgraph.checkpoint.sqlite")]:
            del sys.modules[mod]

        try:
            import langgraph.checkpoint.sqlite  # noqa: F401
        except ImportError:
            pass
        else:
            raise AssertionError("sqlite saver import was not blocked")

        from evaluation.runner import run_single_engagement
        import evaluation.runner as runner_mod


        class FakeApp:
            def stream(self, state, stream_mode=None, config=None):
                yield {**state, "iteration_count": 1, "task_result": "SUCCESS"}


        runner_mod.build_framework = lambda **kw: FakeApp()
        artifact = run_single_engagement(
            target_url="http://localhost/dvwa",
            security_level="low",
            llm_provider="gemini",
            target_method="sqli_union",
            output_dir=str(out_dir),
        )
        assert artifact["status"] == "success", artifact
        assert artifact["checkpoint_store"] is None
        assert list(out_dir.rglob("*.sqlite3")) == []

        blocked = run_single_engagement(
            target_url="http://localhost/dvwa",
            security_level="low",
            llm_provider="gemini",
            target_method="sqli_union",
            output_dir=str(out_dir),
            checkpoint_dir=str(out_dir / "ckpt"),
            experiment_id="blocked-exp",
        )
        assert blocked["status"] == "error", blocked
        assert "uv sync" in blocked["error"], blocked
        print("DEFAULT-PATH-OK")
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", script, str(out_dir)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=240,
    )
    assert proc.returncode == 0, proc.stderr[-4000:]
    assert "DEFAULT-PATH-OK" in proc.stdout
    assert list(tmp_path.rglob("langgraph_checkpoints.sqlite3")) == []


def test_compat_strips_default_checkpoint_flags_for_legacy_signature(monkeypatch):
    import evaluation.multi_llm_runner as multi_mod

    calls = []

    def legacy_fake(**kwargs):
        for key in ("resume", "checkpoint_dir", "experiment_id"):
            if key in kwargs:
                raise TypeError(f"got an unexpected keyword argument '{key}'")
        calls.append(kwargs)
        return {"status": "success"}

    monkeypatch.setattr(multi_mod, "run_single_engagement", legacy_fake)
    result = multi_mod._run_single_with_payload_kwargs({
        "target_url": "http://localhost/dvwa",
        "resume": False,
        "checkpoint_dir": None,
        "experiment_id": None,
    })
    assert result == {"status": "success"}
    assert calls and all(
        key not in seen for seen in calls for key in ("resume", "checkpoint_dir", "experiment_id")
    )


def test_compat_never_strips_explicit_checkpoint_flags(monkeypatch):
    import evaluation.multi_llm_runner as multi_mod

    def legacy_fake(**kwargs):
        for key in ("resume", "checkpoint_dir", "experiment_id"):
            if key in kwargs:
                raise TypeError(f"got an unexpected keyword argument '{key}'")
        return {"status": "success"}

    monkeypatch.setattr(multi_mod, "run_single_engagement", legacy_fake)
    for explicit in (
        {"resume": True, "checkpoint_dir": None, "experiment_id": None},
        {"resume": False, "checkpoint_dir": "/tmp/ckpt", "experiment_id": None},
        {"resume": False, "checkpoint_dir": None, "experiment_id": "exp1"},
    ):
        try:
            multi_mod._run_single_with_payload_kwargs({
                "target_url": "http://localhost/dvwa",
                **explicit,
            })
        except TypeError:
            pass
        else:
            raise AssertionError(f"explicit flags must raise, not run uncheckpointed: {explicit}")
