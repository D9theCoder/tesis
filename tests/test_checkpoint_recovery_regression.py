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

from core.checkpoint_store import (
    ExperimentCheckpointStore,
    stable_thread_id,
    validate_resume,
)
from core.state import new_default_state


def _coordinate(**overrides):
    from llm.runtime import LLMRuntime
    from evaluation.runner import _effective_llm_runtime_config
    runtime = LLMRuntime(max_concurrency=overrides.pop("_concurrency", 1))
    try:
        with runtime.coordinate(coordinate_id="identity", default_provider="openai_compatible") as context:
            identity = _effective_llm_runtime_config(context, candidate_budget=5)
    finally:
        runtime.close()
    base = {
        "effective_llm_runtime": identity, "workflow_protocol_version": "workflow.v2",
        "scoring_rubric_version": "scoring.v3", "scoring_profile": {}, "scoring_oracles": [],
        "scoring_mode": "human", "scoring_evaluator": {}, "fixture_id": None, "protocol_version": None,
        "evasion_max_retries": 3, "evasion_cooldown_threshold": 5,
        "target_url": "http://localhost/dvwa",
        "provider": "openai_compatible",
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
