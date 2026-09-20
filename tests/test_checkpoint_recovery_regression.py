"""Checkpoint recovery regression (handoff 2026-09-20, RecoveryBounds slice).

Owns ONLY core/checkpoint_store.py + this file. Calls evaluation/runner.py
and evaluation/multi_llm_runner.py as black boxes; never edits them.
CheckpointOptIn covers opt-in forwarding, the blocked sqlite-saver default,
completed/legacy replay flags, and both-DB creation — none of that is
repeated here. This file covers the remainder: store-level fail-closed
identity, abrupt-crash subprocess restart at the three safe pure boundaries
(new OS processes, not same-process reopen), runner SQLite lifecycle on
success/error/cancel/refusal, partial-resume flags, and shared-DB matrix
concurrency. All DBs are tmp_path-disposable; resumed external leaves are
stubbed and httpx is hard-guarded so no localhost DVWA traffic is possible.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

from core.checkpoint_store import (
    ExperimentCheckpointStore,
    stable_thread_id,
    validate_checkpoint_identity,
    validate_resume,
)
from core.state import new_default_state

ROOT = Path(__file__).resolve().parent.parent


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
        # Runner fingerprint fields; must mirror run_single_engagement defaults.
        "stop_policy": "impact",
        "coverage_target": 0.70,
        "candidate_budget": 5,
        "max_iterations": 30,
        "model_name": None,
        "evasion_enabled": False,
        "evasion_mode": "reactive",
    }
    base.update(overrides)
    return base


def _saved_row(tmp_path, *, experiment_id="exp1", coord=None, artifact=None):
    coord = coord if coord is not None else _coordinate()
    store = ExperimentCheckpointStore(
        tmp_path / "checkpoints.sqlite3", experiment_id=experiment_id
    )
    try:
        thread = stable_thread_id(experiment_id, coord)
        store.save_completed(
            thread_id=thread,
            final_state={**new_default_state(), "selected_method": "sqli_union"},
            artifact=artifact or {"run_id": "r1", "status": "success"},
            coordinate=coord,
        )
        return store.load(thread)
    finally:
        store.close()


def test_recovery_identity_fail_closed_matrix(tmp_path):
    coord = _coordinate()
    stored = _saved_row(tmp_path, coord=coord)
    ok, _ = validate_resume(stored, coordinate=coord)
    assert ok

    cases = [
        ("state version", dict(stored, state_schema_version="state.v999")),
        ("checkpoint version", dict(stored, checkpoint_schema_version="checkpoint.v999")),
        ("graph version", dict(stored, graph_build_version="graph.v999")),
        ("config drift", dict(stored, coordinate_fingerprint="sha256:drift")),
        ("target drift", dict(stored, target_url="http://evil/x")),
        ("no receipt", dict(stored, completion_receipt=0)),
        ("malformed receipt", dict(stored, completion_receipt="bad")),
        ("malformed json", {**stored, "decode_error": "JSONDecodeError: bad"}),
    ]
    for label, tampered in cases:
        ok, reason = validate_resume(tampered, coordinate=coord)
        assert not ok, label
        assert "refus" in reason, label

    for label, other in [
        ("config coordinate", _coordinate(payload_mode="hybrid")),
        ("target coordinate", _coordinate(target_url="http://evil/x")),
        ("repeat coordinate", _coordinate(repeat_index=1)),
    ]:
        ok, reason = validate_resume(stored, coordinate=other)
        assert not ok, label
        assert "refus" in reason, label

    ok, reason = validate_checkpoint_identity(
        stored, coordinate=coord, experiment_id="other-exp"
    )
    assert not ok and "refus" in reason
    ok, reason = validate_checkpoint_identity(None, coordinate=coord)
    assert not ok and "refus" in reason
    ok, reason = validate_resume(None, coordinate=coord)  # type: ignore[arg-type]
    assert not ok and "refus" in reason


def test_recovery_corrupted_json_row_fails_closed(tmp_path):
    db = tmp_path / "checkpoints.sqlite3"
    coord = _coordinate()
    thread = stable_thread_id("exp1", coord)
    store = ExperimentCheckpointStore(db, experiment_id="exp1")
    store.save_completed(
        thread_id=thread,
        final_state={**new_default_state(), "selected_method": "sqli_union"},
        artifact={"run_id": "r1", "status": "success"},
        coordinate=coord,
    )
    store.close()
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "UPDATE checkpoints SET state_json='not-json{{' WHERE thread_id=?",
            (thread,),
        )
        conn.commit()
    finally:
        conn.close()
    reopened = ExperimentCheckpointStore(db, experiment_id="exp1")
    try:
        stored = reopened.load(thread)
        assert stored is not None and stored.get("decode_error") is not None
        ok, reason = validate_resume(stored, coordinate=coord)
        assert not ok and "refus" in reason
    finally:
        reopened.close()


_CRASH_WRITER = textwrap.dedent(
    """
    import os
    import sqlite3
    import sys
    from pathlib import Path

    from langgraph.checkpoint.sqlite import SqliteSaver

    from core.graph_builder import build_framework
    from core.state import new_default_state
    from foundation.payload_library import PayloadLibrary

    graph_db = Path(sys.argv[1])

    def base(**over):
        st = {
            **new_default_state(),
            "target_url": "http://localhost/dvwa",
            "selected_method": "sqli_union",
            "target_method": "sqli_union",
            "payload_mode": "static_only",
            "security_level": "low",
        }
        st.update(over)
        return st

    seeds = PayloadLibrary().load_seed_candidates("sqli_union", "low")[:2]
    assert seeds

    conn = sqlite3.connect(str(graph_db), check_same_thread=False)
    saver = SqliteSaver(conn)
    saver.setup()
    app = build_framework(llm_provider="gemini", surface="sqli", checkpointer=saver)
    app.update_state(
        {"configurable": {"thread_id": "sp-validator-empty"}},
        base(next_agent="sqli_union", payload_candidates={}),
        as_node="payload_candidate_builder",
    )
    app.update_state(
        {"configurable": {"thread_id": "sp-validator-seeds"}},
        base(next_agent="sqli_union", payload_candidates={"sqli_union": seeds}),
        as_node="payload_candidate_builder",
    )
    app.update_state(
        {"configurable": {"thread_id": "sp-router"}},
        base(
            next_agent="scorer",
            attempted_agents=["sqli_union"],
            confirmed_vulns=["sqli_confirmed"],
            achieved_outcomes=[],
        ),
        as_node="sqli_union",
    )
    app.update_state(
        {"configurable": {"thread_id": "sp-scorer"}},
        base(
            next_agent="scorer",
            attempted_agents=["sqli_union"],
            confirmed_vulns=["sqli_confirmed"],
            achieved_outcomes=[],
        ),
        as_node="chaining_router",
    )
    os._exit(42)  # abrupt crash: no close, no checkpoint, locks die here
    """
)

_CRASH_READER = textwrap.dedent(
    """
    import sqlite3
    import sys
    from pathlib import Path

    graph_db = Path(sys.argv[1])
    marker = Path(sys.argv[2])

    import httpx

    class _NoNet:
        def __init__(self, *a, **k):
            raise AssertionError("network forbidden in recovery test")

    httpx.Client = _NoNet

    import core.graph_builder as gb

    def stub_sqli_union(state):
        with open(marker, "a") as fh:
            fh.write("sqli_union\\n")
        return {"attempted_agents": ["sqli_union"], "next_agent": "scorer"}

    gb.RUNTIME_AGENT_HANDLERS["sqli_union"] = stub_sqli_union

    from langgraph.checkpoint.sqlite import SqliteSaver

    from core.graph_builder import build_framework

    conn = sqlite3.connect(str(graph_db), check_same_thread=False)
    try:
        saver = SqliteSaver(conn)
        saver.setup()
        app = build_framework(
            llm_provider="gemini", surface="sqli", checkpointer=saver
        )
        for thread in (
            "sp-validator-empty",
            "sp-validator-seeds",
            "sp-router",
            "sp-scorer",
        ):
            outs = list(
                app.stream(
                    None,
                    stream_mode="updates",
                    config={"configurable": {"thread_id": thread}},
                )
            )
            print(
                "THREAD " + thread + " " + repr([list(u.keys()) for u in outs]),
                flush=True,
            )
    finally:
        conn.close()
    print("READER-OK", flush=True)
    """
)


def _run_script(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", script, *[str(a) for a in args]],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=240,
    )


def test_recovery_subprocess_crash_restart_pure_boundaries(tmp_path):
    """Abrupt crash (os._exit, fresh OS processes) then resume at each safe
    pure boundary. Validator-pending with seeds schedules the method leaf as
    NEW work (stubbed, counted once); router-pending never replays it."""
    graph_db = tmp_path / "langgraph_checkpoints.sqlite3"
    marker = tmp_path / "method_calls.txt"

    crashed = _run_script(_CRASH_WRITER, graph_db)
    assert crashed.returncode == 42, crashed.stderr[-3000:]
    assert graph_db.exists()

    resumed = _run_script(_CRASH_READER, graph_db, marker)
    assert resumed.returncode == 0, resumed.stderr[-4000:]
    assert "READER-OK" in resumed.stdout

    seqs: dict[str, list[list[str]]] = {}
    for line in resumed.stdout.splitlines():
        if line.startswith("THREAD "):
            _, thread, raw = line.split(" ", 2)
            seqs[thread] = eval(raw)  # noqa: S307 — own subprocess output
    assert set(seqs) == {
        "sp-validator-empty",
        "sp-validator-seeds",
        "sp-router",
        "sp-scorer",
    }

    empty, seeds, router, scorer = (
        seqs["sp-validator-empty"],
        seqs["sp-validator-seeds"],
        seqs["sp-router"],
        seqs["sp-scorer"],
    )
    assert empty[0] == ["payload_validator"] and empty[-1] == ["scorer"]
    assert seeds[0] == ["payload_validator"] and seeds[-1] == ["scorer"]
    assert router == [["chaining_router"], ["scorer"]]
    assert scorer == [["scorer"]]
    for seq in (empty, seeds, router, scorer):
        flat = [node for update in seq for node in update]
        assert "recon" not in flat
        assert "orchestrator" not in flat
        assert "payload_candidate_builder" not in flat
    seeds_flat = [node for update in seeds for node in update]
    assert seeds_flat.count("sqli_union") == 1  # new work ran once
    router_flat = [node for update in router for node in update]
    assert "sqli_union" not in router_flat  # acted node not replayed
    assert marker.read_text().splitlines() == ["sqli_union"]


class _RunOnce:
    def stream(self, state, stream_mode=None, config=None):
        yield {**state, "iteration_count": 1, "task_result": "SUCCESS"}


class _MustNotRun:
    def stream(self, *a, **k):
        raise AssertionError("graph must not run on failed resume")

    def invoke(self, *a, **k):
        raise AssertionError("graph must not run on failed resume")


class _Boom:
    def stream(self, state, stream_mode=None, config=None):
        raise RuntimeError("boom")

    def invoke(self, *a, **k):
        raise RuntimeError("boom")


def _base_run_kwargs(out_dir: Path, ckpt: Path, experiment_id: str) -> dict:
    return {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "llm_provider": "gemini",
        "target_method": "sqli_union",
        "output_dir": str(out_dir),
        "checkpoint_dir": str(ckpt),
        "experiment_id": experiment_id,
    }


def _assert_db_reusable(meta_db: Path, graph_db: Path) -> None:
    """Observable proof both SQLite connections closed: fresh connections can
    read and write both DBs (a leaked open handle would lock them)."""
    conn = sqlite3.connect(str(meta_db), timeout=5.0)
    try:
        conn.execute("SELECT COUNT(*) FROM checkpoints").fetchone()
        conn.execute(
            "INSERT OR REPLACE INTO checkpoints (thread_id, experiment_id,"
            " state_json, artifact_json, state_schema_version,"
            " checkpoint_schema_version, graph_build_version,"
            " coordinate_fingerprint, target_url, last_completed_node,"
            " completion_receipt, updated_at)"
            " VALUES ('probe:thread', 'probe', '{}', '{}', 'x', 'x', 'x',"
            " 'x', '', '', 0, 'x')"
        )
        conn.commit()
        conn.execute("DELETE FROM checkpoints WHERE thread_id='probe:thread'")
        conn.commit()
    finally:
        conn.close()
    gconn = sqlite3.connect(str(graph_db), timeout=5.0)
    try:
        gconn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    finally:
        gconn.close()


def test_recovery_runner_sqlite_lifecycle(tmp_path, monkeypatch):
    """Success stores a receipt; error/cancel/refusal store none; every path
    leaves both DBs closed and reusable. Runner is called, never edited."""
    import evaluation.runner as runner_mod
    from evaluation.runner import run_single_engagement

    out_dir = tmp_path / "out"
    out_dir.mkdir()

    # Success: receipt stored, both DBs closed and reusable.
    ckpt = tmp_path / "ckpt-ok"
    monkeypatch.setattr(runner_mod, "build_framework", lambda **_kw: _RunOnce())
    ok_artifact = run_single_engagement(**_base_run_kwargs(out_dir, ckpt, "exp-ok"))
    assert ok_artifact["status"] == "success"
    assert ok_artifact["resumed_from_checkpoint"] is False
    meta_db, graph_db = (
        ckpt / "checkpoints.sqlite3",
        ckpt / "langgraph_checkpoints.sqlite3",
    )
    assert meta_db.exists() and graph_db.exists()
    ok_store = ExperimentCheckpointStore(meta_db, experiment_id="exp-ok")
    try:
        stored = ok_store.load(ok_artifact["checkpoint_thread_id"])
    finally:
        ok_store.close()
    assert stored is not None and int(stored["completion_receipt"]) == 1
    _assert_db_reusable(meta_db, graph_db)

    # Error mid-graph: no receipt, DBs still closed and reusable.
    ckpt_err = tmp_path / "ckpt-err"
    monkeypatch.setattr(runner_mod, "build_framework", lambda **_kw: _Boom())
    err_artifact = run_single_engagement(
        **_base_run_kwargs(out_dir, ckpt_err, "exp-err")
    )
    assert err_artifact["status"] == "error"
    # Error leaves the start-identity row only: present but never a receipt.
    err_store = ExperimentCheckpointStore(
        ckpt_err / "checkpoints.sqlite3", experiment_id="exp-err"
    )
    try:
        err_row = err_store.load(err_artifact["checkpoint_thread_id"])
    finally:
        err_store.close()
    assert err_row is not None
    assert int(err_row["completion_receipt"]) == 0
    _assert_db_reusable(
        ckpt_err / "checkpoints.sqlite3", ckpt_err / "langgraph_checkpoints.sqlite3"
    )

    # Cancel before graph work: status cancelled, no receipt, DBs reusable.
    from tesis.runtime_events import CancellationToken

    ckpt_cancel = tmp_path / "ckpt-cancel"
    monkeypatch.setattr(runner_mod, "build_framework", lambda **_kw: _MustNotRun())
    token = CancellationToken()
    token.cancel("recovery-test")
    cancelled = run_single_engagement(
        **_base_run_kwargs(out_dir, ckpt_cancel, "exp-cancel"),
        cancellation_token=token,
    )
    cancel_store = ExperimentCheckpointStore(
        ckpt_cancel / "checkpoints.sqlite3", experiment_id="exp-cancel"
    )
    try:
        cancel_row = cancel_store.load(cancelled["checkpoint_thread_id"])
    finally:
        cancel_store.close()
    assert cancel_row is not None
    assert int(cancel_row["completion_receipt"]) == 0
    # Saver never opened on the cancel path: no graph DB, metadata reusable.
    assert not (ckpt_cancel / "langgraph_checkpoints.sqlite3").exists()
    cancel_reuse = ExperimentCheckpointStore(
        ckpt_cancel / "checkpoints.sqlite3", experiment_id="exp-cancel"
    )
    try:
        assert cancel_reuse.load(cancelled["checkpoint_thread_id"]) is not None
    finally:
        cancel_reuse.close()

    # Resume refusal: graph never runs, metadata DB stays reusable.
    ckpt_ref = tmp_path / "ckpt-refuse"
    monkeypatch.setattr(runner_mod, "build_framework", lambda **_kw: _RunOnce())
    seed = run_single_engagement(**_base_run_kwargs(out_dir, ckpt_ref, "exp-ref"))
    assert seed["status"] == "success"
    monkeypatch.setattr(runner_mod, "build_framework", lambda **_kw: _MustNotRun())
    refused = run_single_engagement(
        **_base_run_kwargs(out_dir, ckpt_ref, "exp-ref"),
        stop_policy="coverage",  # drifted setup, same thread family
        resume=True,
    )
    assert refused["status"] == "error"
    assert refused["resumed_from_checkpoint"] is False
    assert "refus" in refused["error"]
    _assert_db_reusable(
        ckpt_ref / "checkpoints.sqlite3",
        ckpt_ref / "langgraph_checkpoints.sqlite3",
    )


def test_recovery_partial_resume_sets_both_flags(tmp_path, monkeypatch):
    """Start row (no receipt) + pure chaining_router graph checkpoint resumes
    through the real graph with no network: both resume flags set true."""
    import httpx

    from evaluation.runner import run_single_engagement

    ckpt = tmp_path / "ckpt-partial"
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    coord = _coordinate()
    thread = stable_thread_id("exp-partial", coord)

    meta_db = ckpt / "checkpoints.sqlite3"
    graph_db = ckpt / "langgraph_checkpoints.sqlite3"
    start_store = ExperimentCheckpointStore(meta_db, experiment_id="exp-partial")
    start_store.save_started(thread_id=thread, coordinate=coord)
    start_store.close()

    import sqlite3 as _sqlite3

    from langgraph.checkpoint.sqlite import SqliteSaver

    from core.graph_builder import build_framework

    conn = _sqlite3.connect(str(graph_db), check_same_thread=False)
    try:
        saver = SqliteSaver(conn)
        saver.setup()
        app = build_framework(
            llm_provider="gemini", surface="sqli", checkpointer=saver
        )
        app.update_state(
            {"configurable": {"thread_id": thread}},
            {
                **new_default_state(),
                "target_url": "http://localhost/dvwa",
                "selected_method": "sqli_union",
                "target_method": "sqli_union",
                "payload_mode": "static_only",
                "security_level": "low",
                "next_agent": "scorer",
                "attempted_agents": ["sqli_union"],
                "confirmed_vulns": ["sqli_confirmed"],
                "achieved_outcomes": [],
            },
            as_node="sqli_union",
        )
        assert set(app.get_state({"configurable": {"thread_id": thread}}).next or ()) == {
            "chaining_router"
        }
    finally:
        conn.close()

    class _NoNet:
        def __init__(self, *a, **k):
            raise AssertionError("network forbidden in recovery test")

    monkeypatch.setattr(httpx, "Client", _NoNet)
    resumed = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        target_method="sqli_union",
        output_dir=str(out_dir),
        checkpoint_dir=str(ckpt),
        experiment_id="exp-partial",
        resume=True,
    )
    assert resumed["status"] == "success", resumed.get("error")
    assert resumed["resumed_from_checkpoint"] is True
    assert resumed["resumed"] is True
    _assert_db_reusable(meta_db, graph_db)


def test_recovery_shared_db_matrix_concurrency(tmp_path, monkeypatch):
    """Two checkpointed matrix coordinates share both DB files concurrently
    (repeats=2, workers=2) with instrumented graph nodes and zero HTTP."""
    import httpx

    import evaluation.runner as runner_mod
    from evaluation.multi_llm_runner import run_provider_matrix

    class _NoNet:
        def __init__(self, *a, **k):
            raise AssertionError("network forbidden in recovery test")

    monkeypatch.setattr(httpx, "Client", _NoNet)
    monkeypatch.setattr(runner_mod, "build_framework", lambda **_kw: _RunOnce())

    ckpt = tmp_path / "ckpt-matrix"
    artifacts = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low"],
        surfaces=["sqli"],
        payload_modes=["static_only"],
        target_method="sqli_union",
        repeats=2,
        output_dir=str(tmp_path / "out"),
        checkpoint_dir=str(ckpt),
        experiment_id="exp-matrix",
        llm_max_concurrency=2,
    )
    if isinstance(artifacts, tuple):
        artifacts = artifacts[0]
    assert len(artifacts) == 2
    assert all(a["status"] == "success" for a in artifacts)

    meta_db, graph_db = (
        ckpt / "checkpoints.sqlite3",
        ckpt / "langgraph_checkpoints.sqlite3",
    )
    assert meta_db.exists() and graph_db.exists()
    check = ExperimentCheckpointStore(meta_db, experiment_id="exp-matrix")
    try:
        threads = set()
        for repeat_index in (0, 1):
            coord = _coordinate(repeat_index=repeat_index)
            thread = stable_thread_id("exp-matrix", coord)
            threads.add(thread)
            stored = check.load(thread)
            assert stored is not None, repeat_index
            assert int(stored["completion_receipt"]) == 1, repeat_index
            assert stored["artifact"]["repeat_index"] == repeat_index
            ok, _ = validate_resume(stored, coordinate=coord)
            assert ok
        assert len(threads) == 2  # repeat isolation held under concurrency
    finally:
        check.close()
    _assert_db_reusable(meta_db, graph_db)
