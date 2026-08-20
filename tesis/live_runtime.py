"""Live-run descriptor writes and deterministic AKG snapshot export.

This module owns the atomic ``runtime.json`` descriptor lifecycle (active
start, terminal transitions for success/error/cancellation and stale
heartbeats) plus a read-only, deterministic serializer of the static Attack
Knowledge Graph for the observer UI.  It never mutates the AKG and leaves the
existing canonical artifact identities unchanged.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from time import monotonic
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from core.knowledge_graph import AttackKnowledgeGraph
from tesis.runtime_events import RunEvent, RuntimeEventSink


SCHEMA_VERSION: str = "runtime-descriptor.v1"
AKG_SNAPSHOT_VERSION: str = "akg-snapshot.v1"

ACTIVE_STATUS: str = "active"

# Terminal status sources described by the plan.  Values are the descriptor
# ``status`` strings applied when a matching runtime event arrives.
EVENT_TERMINAL_STATUS: Mapping[str, str] = {
    "run.finished": "finished",
    "run.completed": "finished",
    "run.cancelled": "cancelled",
    "run.failed": "failed",
    "run.error": "failed",
    "matrix.finished": "finished",
    "matrix.completed": "finished",
    "matrix.cancelled": "cancelled",
    "matrix.failed": "failed",
    "matrix.error": "failed",
}

TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"finished", "cancelled", "failed", "error", "stale"}
)

STALE_HEARTBEAT_STATUS: str = "stale"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_iso(value: str | None, *, default: str | None = None) -> str | None:
    if not value:
        return default
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.isoformat()
    except (TypeError, ValueError):
        # Preserve an unparseable timestamp rather than silently dropping it.
        return value


def safe_target_scope(target_url: str) -> str:
    """Return a credential-free target scope suitable for observer metadata.

    User information, query parameters, and fragments are not required to
    identify the contained DVWA host/path and may carry credentials, so they
    are intentionally omitted from ``runtime.json``.
    """

    try:
        parsed = urlsplit(target_url)
        hostname = parsed.hostname
        if not hostname:
            return target_url.split("?", 1)[0].split("#", 1)[0]
        host = f"[{hostname}]" if ":" in hostname else hostname
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = f"{host}:{port}" if port is not None else host
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    except (TypeError, ValueError):
        return str(target_url).split("?", 1)[0].split("#", 1)[0]


def terminal_status_for_event(event_type: str | None) -> str | None:
    """Map a runtime ``event_type`` to a terminal descriptor status.

    Returns ``None`` for non-terminal events (including ``active`` start
    events), matching the plan's one-way terminal transition.
    """

    if not event_type:
        return None
    return EVENT_TERMINAL_STATUS.get(str(event_type))


@dataclass(frozen=True, slots=True)
class RuntimeDescriptor:
    """Immutable live-run descriptor written atomically to ``runtime.json``."""

    schema_version: str = SCHEMA_VERSION
    mode: str = "single-run"
    experiment_dir: str = ""
    status: str = ACTIVE_STATUS
    started_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    heartbeat_at: str | None = None
    execution_id: str | None = None
    run_id: str | None = None
    config_fingerprint: str | None = None
    manifest_path: str | None = None
    coordinates: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @property
    def is_active(self) -> bool:
        return self.status == ACTIVE_STATUS

    def with_status(
        self,
        status: str,
        *,
        updated_at: str | None = None,
    ) -> "RuntimeDescriptor":
        """Return a new descriptor with ``status`` set (no mutation)."""

        now = _to_iso(updated_at) or _utc_now()
        return RuntimeDescriptor(**{
            **asdict(self),
            "status": status,
            "updated_at": now,
            "heartbeat_at": now if status == ACTIVE_STATUS else self.heartbeat_at,
        })

    def with_heartbeat(
        self,
        *,
        at: str | None = None,
    ) -> "RuntimeDescriptor":
        """Return a new descriptor with a refreshed heartbeat timestamp."""

        now = _to_iso(at) or _utc_now()
        return RuntimeDescriptor(**{
            **asdict(self),
            "heartbeat_at": now,
            "updated_at": now,
        })

    def as_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "coordinates": dict(self.coordinates),
        }

    to_dict = as_dict


def build_runtime_descriptor(
    *,
    mode: str = "single-run",
    experiment_dir: str | Path | None = None,
    execution_id: str | None = None,
    run_id: str | None = None,
    config_fingerprint: str | None = None,
    manifest_path: str | Path | None = None,
    coordinates: Mapping[str, Any] | None = None,
    started_at: str | None = None,
) -> RuntimeDescriptor:
    """Create an ``active`` descriptor before execution begins."""

    return RuntimeDescriptor(
        mode=mode,
        experiment_dir=str(experiment_dir) if experiment_dir is not None else "",
        started_at=_to_iso(started_at) or _utc_now(),
        execution_id=execution_id,
        run_id=run_id,
        config_fingerprint=config_fingerprint,
        manifest_path=str(manifest_path) if manifest_path is not None else None,
        coordinates=dict(coordinates or {}),
    )


def descriptor_to_dict(descriptor: RuntimeDescriptor) -> dict[str, Any]:
    return descriptor.as_dict()


def descriptor_from_dict(data: Mapping[str, Any]) -> RuntimeDescriptor:
    """Rebuild a :class:`RuntimeDescriptor` from a serialized mapping.

    Unknown or missing keys are tolerated so descriptors remain forward
    compatible across protocol revisions.
    """

    known = set(RuntimeDescriptor.__dataclass_fields__)
    values: dict[str, Any] = {
        key: (dict(value) if key == "coordinates" else value)
        for key, value in dict(data).items()
        if key in known
    }
    return RuntimeDescriptor(**values)


def descriptor_path(experiment_dir: str | Path) -> Path:
    return Path(experiment_dir) / "runtime.json"


def write_descriptor(
    descriptor: RuntimeDescriptor,
    path: str | Path | None = None,
) -> Path:
    """Persist ``descriptor`` atomically (temp file + ``os.replace``)."""

    target = Path(path) if path is not None else descriptor_path(descriptor.experiment_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(descriptor.as_dict(), indent=2, sort_keys=True) + "\n"

    tmp = target.with_name(f".{target.name}.tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, target)
    return target


def write_terminal_descriptor(
    descriptor: RuntimeDescriptor,
    status: str,
    *,
    updated_at: str | None = None,
) -> RuntimeDescriptor:
    """Transition ``descriptor`` to a terminal ``status`` and persist it.

    Returns the updated (immutable) descriptor.  ``status`` may be supplied
    directly or derived from a runtime event via :func:`terminal_status_for_event`.
    """

    next_status = terminal_status_for_event(status) or status
    updated = descriptor.with_status(next_status, updated_at=updated_at)
    write_descriptor(updated)
    return updated


class RuntimeDescriptorHeartbeatSink:
    """Refresh an active descriptor from runtime events at a bounded cadence.

    The sink is deliberately observation-only. It never changes graph state
    and it does not infer terminal status, because matrix child terminal events
    must not terminate their parent descriptor. Entry points write the final
    status from the authoritative runner result.
    """

    def __init__(
        self,
        descriptor: RuntimeDescriptor,
        *,
        interval_seconds: float = 2.0,
    ) -> None:
        self._descriptor = descriptor
        self._interval_seconds = max(0.0, float(interval_seconds))
        self._last_write = 0.0
        self._lock = RLock()

    @property
    def descriptor(self) -> RuntimeDescriptor:
        """Return the latest immutable descriptor snapshot."""

        with self._lock:
            return self._descriptor

    def emit(self, event: RunEvent) -> None:
        """Persist identity and heartbeat metadata without altering the event."""

        with self._lock:
            if self._descriptor.is_terminal:
                return
            now = monotonic()
            identity_changed = False
            execution_id = self._descriptor.execution_id
            run_id = self._descriptor.run_id

            if execution_id is None and event.execution_id:
                execution_id = event.execution_id
                identity_changed = True
            if (
                self._descriptor.mode != "matrix"
                and run_id is None
                and event.run_id
            ):
                run_id = event.run_id
                identity_changed = True

            if not identity_changed and now - self._last_write < self._interval_seconds:
                return

            current = replace(
                self._descriptor,
                execution_id=execution_id,
                run_id=run_id,
            ).with_heartbeat()
            write_descriptor(current)
            self._descriptor = current
            self._last_write = now

    def terminate(self, status: str) -> RuntimeDescriptor:
        """Persist a terminal descriptor and stop future heartbeat rewrites."""

        with self._lock:
            if self._descriptor.is_terminal:
                return self._descriptor
            self._descriptor = write_terminal_descriptor(self._descriptor, status)
            return self._descriptor


def stale_status_if_old(
    descriptor: RuntimeDescriptor,
    *,
    max_age_seconds: float = 30.0,
    now: str | None = None,
) -> str | None:
    """Return the stale terminal status when the heartbeat is too old.

    Returns ``STALE_HEARTBEAT_STATUS`` when the descriptor is active but its
    heartbeat (or start time, if no heartbeat exists) is older than
    ``max_age_seconds``.  Otherwise returns ``None`` so the caller can keep the
    current status.
    """

    if descriptor.is_terminal or descriptor.is_active is False:
        return None
    reference = descriptor.heartbeat_at or descriptor.started_at
    try:
        parsed = datetime.fromisoformat(reference)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        # Without a parseable timestamp we cannot judge staleness safely.
        return None

    now_iso = _to_iso(now) or _utc_now()
    current = datetime.fromisoformat(now_iso)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)

    age = (current - parsed).total_seconds()
    if age > max_age_seconds:
        return STALE_HEARTBEAT_STATUS
    return None


def akg_snapshot(akg: AttackKnowledgeGraph) -> dict[str, Any]:
    """Serialize the static AKG read-only and deterministically.

    Node and edge metadata is stable: node ids, node types, surfaces, method
    payload profiles/target parameters, and edge chain status, preconditions,
    target agent, and priority.  All collection-valued fields are sorted so the
    output is byte-for-byte deterministic across calls.  The AKG is never
    mutated.
    """

    nodes: list[dict[str, Any]] = []
    for node in sorted(akg.graph.nodes):
        attrs = akg.graph.nodes[node]
        payload_profile = attrs.get("payload_profile")
        entry: dict[str, Any] = {
            "id": str(node),
            "type": str(attrs.get("type", "node")),
            "surface": str(attrs["surface"]) if attrs.get("surface") else None,
        }
        if isinstance(payload_profile, Mapping):
            entry["payload_profile"] = {
                "target_params": sorted(payload_profile.get("target_params", [])),
                "payload_mode": str(payload_profile.get("payload_mode", "hybrid")),
                "payload_budget": payload_profile.get("payload_budget"),
                "allowed_mutation_types": sorted(
                    payload_profile.get("allowed_mutation_types", [])
                ),
                "forbidden_mutation_types": sorted(
                    payload_profile.get("forbidden_mutation_types", [])
                ),
                "expected_success_signals": sorted(
                    payload_profile.get("expected_success_signals", [])
                ),
                "seed_payload_refs": sorted(payload_profile.get("seed_payload_refs", [])),
                "provenance_required": bool(payload_profile.get("provenance_required", True)),
            }
        nodes.append(entry)

    edges: list[dict[str, Any]] = []
    for source, target in sorted(akg.graph.edges):
        meta = akg.graph.edges[source, target]
        edges.append({
            "source": str(source),
            "target": str(target),
            "is_chain": bool(meta.get("is_chain", False)),
            "preconditions": sorted(
                str(item) for item in meta.get("preconditions", [])
            ),
            "target_agent": (
                str(meta.get("target_agent")) if meta.get("target_agent") is not None else None
            ),
            "priority": int(meta.get("priority", 100)),
        })

    return {
        "schema_version": AKG_SNAPSHOT_VERSION,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "high_impact_outcomes": sorted(akg.HIGH_IMPACT_OUTCOMES),
        "method_preconditions": {
            str(key): sorted(str(item) for item in value)
            for key, value in sorted(akg.METHOD_PRECONDITIONS.items())
        },
        "target_params": {
            str(key): sorted(str(item) for item in value)
            for key, value in sorted(akg.TARGET_PARAMS.items())
        },
        "nodes": nodes,
        "edges": edges,
    }


__all__ = [
    "SCHEMA_VERSION",
    "AKG_SNAPSHOT_VERSION",
    "ACTIVE_STATUS",
    "EVENT_TERMINAL_STATUS",
    "TERMINAL_STATUSES",
    "STALE_HEARTBEAT_STATUS",
    "RuntimeDescriptor",
    "build_runtime_descriptor",
    "descriptor_to_dict",
    "descriptor_from_dict",
    "descriptor_path",
    "write_descriptor",
    "write_terminal_descriptor",
    "RuntimeDescriptorHeartbeatSink",
    "terminal_status_for_event",
    "stale_status_if_old",
    "akg_snapshot",
    "safe_target_scope",
]
