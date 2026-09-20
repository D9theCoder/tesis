"""Experiment-local durable checkpoint stores (arch handoff slice 2).

Opt-in runner-level resume contract plus experiment-local LangGraph channel
checkpoints (``langgraph-checkpoint-sqlite``). The metadata store persists
completed-run artifacts and run-identity rows keyed by a stable
experiment+coordinate thread identity. Resume validates identity before
touching graph state: a completed receipt replays zero nodes, otherwise a
partial LangGraph checkpoint resumes only safe internal nodes via
``stream(None)`` on the same thread. Anything else fails closed.

Retention: SQLite files per experiment directory. Delete the files to purge.
No automatic migration: unsupported versions refuse resume (fail closed).
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from core.graph_builder import GRAPH_BUILD_VERSION
from core.state import (
    CHECKPOINT_SCHEMA_VERSION,
    STATE_SCHEMA_VERSION,
    checkpoint_safe_state,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoints (
    thread_id TEXT PRIMARY KEY,
    experiment_id TEXT NOT NULL,
    state_json TEXT NOT NULL,
    artifact_json TEXT NOT NULL,
    state_schema_version TEXT NOT NULL,
    checkpoint_schema_version TEXT NOT NULL,
    graph_build_version TEXT NOT NULL,
    coordinate_fingerprint TEXT NOT NULL,
    target_url TEXT NOT NULL,
    last_completed_node TEXT NOT NULL,
    completion_receipt INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
)
"""


def default_store_path(checkpoint_dir: str | None, output_dir: str | None) -> Path:
    """Experiment-local SQLite path. Defaults preserve current artifact roots."""
    base = checkpoint_dir or output_dir or str(Path("results") / "runs")
    return Path(base) / "checkpoints.sqlite3"


def default_graph_store_path(checkpoint_dir: str | None, output_dir: str | None) -> Path:
    """Experiment-local LangGraph saver path (separate from metadata store)."""
    base = checkpoint_dir or output_dir or str(Path("results") / "runs")
    return Path(base) / "langgraph_checkpoints.sqlite3"

# LangGraph topology is unchanged by this slice; these are the only nodes
# whose completion is recorded as safe-to-replay metadata. Externally acting
# nodes (recon, method agents) are NEVER replayed from this store: resume is
# only served for a fully completed run (completion_receipt=1), which replays
# zero graph nodes.
SAFE_COMPLETED_NODE = "scorer"


def _slug(value: object) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value).strip())
    return text.strip("-._") or "unknown"


def stable_coordinate_slug(coordinate: Mapping[str, Any]) -> str:
    """Stable, human-readable coordinate slug (no random IDs)."""
    parts = [
        coordinate.get("provider") or coordinate.get("llm_provider"),
        coordinate.get("surface"),
        coordinate.get("security_level"),
        coordinate.get("payload_mode"),
        coordinate.get("experiment_condition"),
        coordinate.get("target_method") or "surface",
        coordinate.get("repeat_index", 0),
    ]
    return "-".join(_slug(part) for part in parts)


def stable_thread_id(experiment_id: str, coordinate: Mapping[str, Any]) -> str:
    """Stable checkpoint/thread identity from experiment + coordinate."""
    return f"{_slug(experiment_id)}:{stable_coordinate_slug(coordinate)}"


def coordinate_fingerprint(coordinate: Mapping[str, Any]) -> str:
    """Secret-free fingerprint of the effective coordinate setup."""
    canonical = {
        "target_url": str(coordinate.get("target_url") or ""),
        "provider": str(coordinate.get("provider") or coordinate.get("llm_provider") or ""),
        "surface": str(coordinate.get("surface") or ""),
        "security_level": str(coordinate.get("security_level") or ""),
        "payload_mode": str(coordinate.get("payload_mode") or ""),
        "experiment_condition": str(coordinate.get("experiment_condition") or ""),
        "target_method": coordinate.get("target_method"),
        "repeat_index": coordinate.get("repeat_index", 0),
        "stop_policy": coordinate.get("stop_policy"),
        "coverage_target": coordinate.get("coverage_target"),
        "candidate_budget": coordinate.get("candidate_budget"),
        "max_iterations": coordinate.get("max_iterations"),
        "model_name": coordinate.get("model_name"),
        "evasion_enabled": coordinate.get("evasion_enabled"),
        "evasion_mode": coordinate.get("evasion_mode"),
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ExperimentCheckpointStore:
    """SQLite-backed completed-run checkpoint store for one experiment."""

    def __init__(self, path: Path, *, experiment_id: str) -> None:
        self.path = Path(path)
        self.experiment_id = str(experiment_id)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self) -> ExperimentCheckpointStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def save_completed(
        self,
        *,
        thread_id: str,
        final_state: Mapping[str, Any],
        artifact: Mapping[str, Any],
        coordinate: Mapping[str, Any],
    ) -> None:
        """Persist a completed run. Only called for terminal successful runs."""
        row = {
            "thread_id": thread_id,
            "experiment_id": self.experiment_id,
            "state_json": json.dumps(checkpoint_safe_state(dict(final_state)), sort_keys=True, default=str),
            "artifact_json": json.dumps(dict(artifact), sort_keys=True, default=str),
            "state_schema_version": STATE_SCHEMA_VERSION,
            "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
            "graph_build_version": GRAPH_BUILD_VERSION,
            "coordinate_fingerprint": coordinate_fingerprint(coordinate),
            "target_url": str(coordinate.get("target_url") or ""),
            "last_completed_node": SAFE_COMPLETED_NODE,
            "completion_receipt": 1,
            "updated_at": _now_iso(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO checkpoints "
            "(thread_id, experiment_id, state_json, artifact_json, state_schema_version,"
            " checkpoint_schema_version, graph_build_version, coordinate_fingerprint,"
            " target_url, last_completed_node, completion_receipt, updated_at)"
            " VALUES (:thread_id, :experiment_id, :state_json, :artifact_json,"
            " :state_schema_version, :checkpoint_schema_version, :graph_build_version,"
            " :coordinate_fingerprint, :target_url, :last_completed_node,"
            " :completion_receipt, :updated_at)",
            row,
        )
        self._conn.commit()

    def save_started(
        self,
        thread_id: str,
        coordinate: Mapping[str, Any],
    ) -> None:
        """Persist a start-of-run identity row (no receipt, no replayable state)."""
        row = {
            "thread_id": thread_id,
            "experiment_id": self.experiment_id,
            "state_json": "{}",
            "artifact_json": "{}",
            "state_schema_version": STATE_SCHEMA_VERSION,
            "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
            "graph_build_version": GRAPH_BUILD_VERSION,
            "coordinate_fingerprint": coordinate_fingerprint(coordinate),
            "target_url": str(coordinate.get("target_url") or ""),
            "last_completed_node": "",
            "completion_receipt": 0,
            "updated_at": _now_iso(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO checkpoints "
            "(thread_id, experiment_id, state_json, artifact_json, state_schema_version,"
            " checkpoint_schema_version, graph_build_version, coordinate_fingerprint,"
            " target_url, last_completed_node, completion_receipt, updated_at)"
            " VALUES (:thread_id, :experiment_id, :state_json, :artifact_json,"
            " :state_schema_version, :checkpoint_schema_version, :graph_build_version,"
            " :coordinate_fingerprint, :target_url, :last_completed_node,"
            " :completion_receipt, :updated_at)",
            row,
        )
        self._conn.commit()
    def load(self, thread_id: str) -> dict[str, Any] | None:
        cur = self._conn.execute(
            "SELECT thread_id, experiment_id, state_json, artifact_json, state_schema_version,"
            " checkpoint_schema_version, graph_build_version, coordinate_fingerprint,"
            " target_url, last_completed_node, completion_receipt, updated_at"
            " FROM checkpoints WHERE thread_id = ?",
            (thread_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        keys = [
            "thread_id", "experiment_id", "state_json", "artifact_json",
            "state_schema_version", "checkpoint_schema_version", "graph_build_version",
            "coordinate_fingerprint", "target_url", "last_completed_node",
            "completion_receipt", "updated_at",
        ]
        stored = dict(zip(keys, row))
        try:
            stored["state"] = json.loads(stored["state_json"])
            stored["artifact"] = json.loads(stored["artifact_json"])
        except (ValueError, TypeError) as exc:
            stored["decode_error"] = f"{type(exc).__name__}: {exc}"
        return stored


def validate_checkpoint_identity(
    stored: Mapping[str, Any],
    *,
    coordinate: Mapping[str, Any],
    experiment_id: str | None = None,
) -> tuple[bool, str]:
    """Fail closed on identity mismatch; does NOT require a completion receipt."""
    if stored.get("decode_error") is not None:
        return False, (
            f"checkpoint for thread {stored.get('thread_id')!r} is corrupted "
            f"({stored['decode_error']}); delete the checkpoint file and re-run "
            "without --resume; refusing resume"
        )
    if stored.get("state_schema_version") != STATE_SCHEMA_VERSION:
        return False, (
            f"unsupported state_schema_version {stored.get('state_schema_version')!r}; "
            f"expected {STATE_SCHEMA_VERSION!r}; refusing resume"
        )
    if stored.get("checkpoint_schema_version") != CHECKPOINT_SCHEMA_VERSION:
        return False, (
            f"unsupported checkpoint_schema_version {stored.get('checkpoint_schema_version')!r}; "
            f"expected {CHECKPOINT_SCHEMA_VERSION!r}; refusing resume"
        )
    if stored.get("graph_build_version") != GRAPH_BUILD_VERSION:
        return False, (
            f"graph_build_version {stored.get('graph_build_version')!r} does not match "
            f"{GRAPH_BUILD_VERSION!r}; refusing resume"
        )
    expected_fp = coordinate_fingerprint(coordinate)
    if stored.get("coordinate_fingerprint") != expected_fp:
        return False, (
            "coordinate setup changed since checkpoint "
            f"(stored {stored.get('coordinate_fingerprint')!r} != current {expected_fp!r}); "
            "re-run without --resume; refusing resume"
        )
    if str(stored.get("target_url") or "") != str(coordinate.get("target_url") or ""):
        return False, (
            f"target URL changed since checkpoint ({stored.get('target_url')!r}); "
            "resuming across targets could send prior state at a new target; "
            "re-run without --resume; refusing resume"
        )
    if experiment_id is not None and str(stored.get("experiment_id") or "") != str(experiment_id):
        return False, (
            f"experiment changed since checkpoint ({stored.get('experiment_id')!r}); "
            "re-run without --resume; refusing resume"
        )
    expected_thread = stable_thread_id(str(experiment_id or stored.get("experiment_id") or ""), coordinate)
    if str(stored.get("thread_id") or "") != expected_thread:
        return False, (
            f"checkpoint thread {stored.get('thread_id')!r} does not match "
            f"coordinate identity {expected_thread!r}; refusing resume"
        )
    return True, "compatible"


def validate_resume(
    stored: Mapping[str, Any],
    *,
    coordinate: Mapping[str, Any],
) -> tuple[bool, str]:
    """Fail closed unless the stored checkpoint is safe to replay.

    Checks, in order: decode integrity, completion receipt (no replay of
    externally acting nodes without one), state/checkpoint/graph versions,
    coordinate fingerprint, and exact target URL match.
    """
    ok, reason = validate_checkpoint_identity(stored, coordinate=coordinate)
    if not ok:
        return ok, reason
    if int(stored.get("completion_receipt", 0) or 0) != 1:
        return False, (
            f"checkpoint for thread {stored.get('thread_id')!r} has no completion "
            "receipt (run did not reach the terminal safe node); replaying it "
            "could duplicate external DVWA actions; delete the checkpoint and "
            "re-run without --resume; refusing resume"
        )
    return True, "compatible"


__all__ = [
    "ExperimentCheckpointStore",
    "coordinate_fingerprint",
    "default_graph_store_path",
    "default_store_path",
    "stable_coordinate_slug",
    "stable_thread_id",
    "validate_checkpoint_identity",
    "validate_resume",
]
