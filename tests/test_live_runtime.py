"""Tests for the live-run descriptor lifecycle and AKG snapshot export."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from core.knowledge_graph import AttackKnowledgeGraph
from tesis.live_runtime import (
    SCHEMA_VERSION,
    ACTIVE_STATUS,
    STALE_HEARTBEAT_STATUS,
    RuntimeDescriptor,
    RuntimeDescriptorHeartbeatSink,
    safe_target_scope,
    akg_snapshot,
    build_runtime_descriptor,
    descriptor_from_dict,
    descriptor_to_dict,
    descriptor_path,
    stale_status_if_old,
    terminal_status_for_event,
    write_descriptor,
    write_terminal_descriptor,
)
from tesis.runtime_events import RunEvent


def test_build_runtime_descriptor_starts_active_with_identity(tmp_path: Path) -> None:
    desc = build_runtime_descriptor(
        mode="single-run",
        experiment_dir=tmp_path,
        execution_id="exec-1",
        run_id="logical-1",
        config_fingerprint="sha256:abc",
        manifest_path=tmp_path / "experiment.manifest.json",
        coordinates={"provider": "openai", "surface": "sqli"},
    )

    assert desc.schema_version == SCHEMA_VERSION
    assert desc.status == ACTIVE_STATUS
    assert desc.is_active is True
    assert desc.is_terminal is False
    assert desc.execution_id == "exec-1"
    assert desc.run_id == "logical-1"
    assert desc.config_fingerprint == "sha256:abc"
    assert desc.manifest_path == str(tmp_path / "experiment.manifest.json")
    assert desc.coordinates == {"provider": "openai", "surface": "sqli"}


def test_active_descriptor_written_atomically(tmp_path: Path) -> None:
    desc = build_runtime_descriptor(experiment_dir=tmp_path, execution_id="exec-2")
    written = write_descriptor(desc)

    assert written == descriptor_path(tmp_path)
    assert written.name == "runtime.json"
    payload = json.loads(written.read_text(encoding="utf-8"))
    assert payload["status"] == ACTIVE_STATUS
    assert payload["execution_id"] == "exec-2"
    # No leftover temp file remains after the atomic replace.
    assert not list(tmp_path.glob(".runtime.json.tmp"))
    assert written.exists()


def test_terminal_status_for_event_maps_single_and_matrix() -> None:
    assert terminal_status_for_event("run.finished") == "finished"
    assert terminal_status_for_event("run.completed") == "finished"
    assert terminal_status_for_event("run.cancelled") == "cancelled"
    assert terminal_status_for_event("run.failed") == "failed"
    assert terminal_status_for_event("matrix.finished") == "finished"
    assert terminal_status_for_event("matrix.cancelled") == "cancelled"
    assert terminal_status_for_event("run.started") is None
    assert terminal_status_for_event(None) is None
    assert terminal_status_for_event("") is None


def test_terminal_transition_persists_and_is_immutable(tmp_path: Path) -> None:
    desc = build_runtime_descriptor(experiment_dir=tmp_path, execution_id="exec-3")
    updated = write_terminal_descriptor(desc, "run.finished")

    assert updated.status == "finished"
    assert updated.is_terminal is True
    assert updated.is_active is False
    # Original descriptor is unchanged.
    assert desc.status == ACTIVE_STATUS

    payload = json.loads(descriptor_path(tmp_path).read_text(encoding="utf-8"))
    assert payload["status"] == "finished"
    assert payload["execution_id"] == "exec-3"


def test_heartbeat_sink_refreshes_identity_without_terminating(tmp_path: Path) -> None:
    desc = build_runtime_descriptor(experiment_dir=tmp_path)
    write_descriptor(desc)
    sink = RuntimeDescriptorHeartbeatSink(desc, interval_seconds=0)

    sink.emit(RunEvent("run.started", execution_id="exec-live", run_id="run-live"))
    sink.emit(RunEvent("run.finished", execution_id="exec-live", run_id="run-live"))

    current = sink.descriptor
    assert current.execution_id == "exec-live"
    assert current.run_id == "run-live"
    assert current.heartbeat_at is not None
    assert current.status == ACTIVE_STATUS


def test_matrix_heartbeat_keeps_parent_identity(tmp_path: Path) -> None:
    desc = build_runtime_descriptor(
        mode="matrix",
        experiment_dir=tmp_path,
        execution_id="matrix-parent",
    )
    sink = RuntimeDescriptorHeartbeatSink(desc, interval_seconds=0)

    sink.emit(RunEvent("run.started", execution_id="child-exec", run_id="child-run"))

    assert sink.descriptor.execution_id == "matrix-parent"
    assert sink.descriptor.run_id is None


def test_heartbeat_terminal_transition_blocks_future_active_rewrites(tmp_path: Path) -> None:
    desc = build_runtime_descriptor(experiment_dir=tmp_path, execution_id="exec-stop")
    write_descriptor(desc)
    sink = RuntimeDescriptorHeartbeatSink(desc, interval_seconds=0)

    terminal = sink.terminate("cancelled")
    sink.emit(RunEvent("graph.node.started", execution_id="exec-stop"))

    persisted = json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8"))
    assert terminal.status == "cancelled"
    assert sink.descriptor.status == "cancelled"
    assert persisted["status"] == "cancelled"


def test_safe_target_scope_removes_url_credentials_and_query_secrets() -> None:
    assert (
        safe_target_scope(
            "http://dvwa-user:dvwa-pass@127.0.0.1:8080/dvwa/login.php?token=secret#step"
        )
        == "http://127.0.0.1:8080/dvwa/login.php"
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("finished", "finished"),
        ("cancelled", "cancelled"),
        ("failed", "failed"),
        ("matrix.finished", "finished"),
        ("matrix.error", "failed"),
    ],
)
def test_write_terminal_descriptor_accepts_direct_and_event_status(
    tmp_path: Path, status: str, expected: str
) -> None:
    desc = build_runtime_descriptor(experiment_dir=tmp_path)
    updated = write_terminal_descriptor(desc, status)
    assert updated.status == expected
    assert updated.is_terminal is True


def test_descriptor_round_trip_through_dict(tmp_path: Path) -> None:
    desc = build_runtime_descriptor(
        experiment_dir=tmp_path,
        execution_id="exec-4",
        coordinates={"provider": "anthropic", "model": "claude", "security_level": "high"},
    )
    rebuilt = descriptor_from_dict(descriptor_to_dict(desc))

    assert rebuilt == desc
    assert rebuilt.coordinates == desc.coordinates


def test_descriptor_from_dict_tolerates_unknown_keys(tmp_path: Path) -> None:
    desc = build_runtime_descriptor(experiment_dir=tmp_path)
    data = {**descriptor_to_dict(desc), "unexpected_future_field": 42}
    rebuilt = descriptor_from_dict(data)
    assert rebuilt == desc


def test_stale_heartbeat_resolves_to_terminal_status(tmp_path: Path) -> None:
    desc = build_runtime_descriptor(
        experiment_dir=tmp_path,
        started_at="2026-01-01T00:00:00+00:00",
    )
    now = "2026-01-01T00:00:50+00:00"
    # A fresh (50s old) descriptor is not stale within a 120s window.
    assert stale_status_if_old(desc, max_age_seconds=120, now=now) is None

    old_heartbeat = desc.with_heartbeat(at="2026-01-01T00:00:00+00:00")
    # 50 seconds later with a 10s threshold -> stale.
    assert stale_status_if_old(old_heartbeat, max_age_seconds=10, now=now) == STALE_HEARTBEAT_STATUS
    # 50 seconds is within a 120s window -> not stale.
    assert stale_status_if_old(old_heartbeat, max_age_seconds=120, now=now) is None

    # Terminal descriptors are never marked stale.
    terminal = write_terminal_descriptor(desc, "run.finished")
    assert stale_status_if_old(terminal, max_age_seconds=1, now=now) is None


def test_akg_snapshot_is_deterministic(tmp_path: Path) -> None:
    akg = AttackKnowledgeGraph()
    first = akg_snapshot(akg)
    second = akg_snapshot(akg)

    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["schema_version"] == "akg-snapshot.v1"
    assert first["node_count"] == len(first["nodes"])
    assert first["edge_count"] == len(first["edges"])


def test_akg_snapshot_shape_has_stable_metadata() -> None:
    akg = AttackKnowledgeGraph()
    snap = akg_snapshot(akg)

    # Node metadata: id, type, surface, and method payload profiles.
    by_id = {node["id"]: node for node in snap["nodes"]}
    assert "unauthenticated" in by_id
    assert "sqli_union" in by_id
    method = by_id["sqli_union"]
    assert method["type"] == "method"
    assert method["surface"] == "sqli"
    profile = method["payload_profile"]
    assert profile["target_params"] == ["id"]
    assert profile["provenance_required"] is True
    assert "allowed_mutation_types" in profile
    assert "expected_success_signals" in profile

    # Non-method nodes carry no payload_profile payload.
    assert by_id["sqli"].get("payload_profile") is None

    # Edge metadata: chain status, preconditions, target agent, priority.
    by_edge = {
        (edge["source"], edge["target"]): edge
        for edge in snap["edges"]
    }
    chain = by_edge[("brute_force_confirmed", "authenticated_session")]
    assert chain["is_chain"] is True
    assert chain["preconditions"] == ["brute_force_confirmed"]
    assert chain["target_agent"] == "ac_idor"
    assert chain["priority"] == 10

    discovery = by_edge[("sqli", "sqli_union")]
    assert discovery["is_chain"] is False
    assert discovery["preconditions"] == []
    assert discovery["priority"] == 100

    # Global method/precondition and target-param indexes exist.
    assert "sqli_union" in snap["method_preconditions"]
    assert snap["target_params"]["bf_dictionary"] == ["credential_pair"]


def test_akg_snapshot_does_not_mutate_graph() -> None:
    akg = AttackKnowledgeGraph()
    before_nodes = set(akg.graph.nodes)
    before_edges = set(akg.graph.edges)
    before_edges_data = {
        (src, tgt): dict(meta)
        for src, tgt, meta in akg.graph.edges(data=True)
    }

    akg_snapshot(akg)

    assert set(akg.graph.nodes) == before_nodes
    assert set(akg.graph.edges) == before_edges
    after_edges_data = {
        (src, tgt): dict(meta)
        for src, tgt, meta in akg.graph.edges(data=True)
    }
    assert after_edges_data == before_edges_data
    assert akg.get_payload_profile("sqli_union")["target_params"] == ["id"]
