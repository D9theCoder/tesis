"""Pure operator state and event reduction for the TUI."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from tesis.runtime_events import RunEvent, redact_secrets

import tesis.tui_security as tui_security


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPOSITORY_ROOT / "config.yaml"

NOTICE_MAX_ENTRIES = 500

_DROP_COT_KEYS = frozenset({
    "raw_state", "chain_of_thought", "chain-of-thought", "chain_of_thoughts",
    "prompt", "reasoning", "cot",
})

RunStatus = Literal["ready", "running", "degraded", "succeeded", "failed", "cancelled"]
StageStatus = Literal["queued", "running", "succeeded", "warning", "failed"]

CANONICAL_STAGE_IDS = (
    "recon",
    "orchestrator",
    "payload_candidate_builder",
    "payload_validator",
    "method_agent",
    "chaining_router",
    "scorer",
)

_FINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled"})

# Coordinate statuses that a late or replayed matrix.run.started must not undo.
_FINAL_COORDINATE_STATUSES = frozenset({"succeeded", "failed", "skipped", "cancelled", "error"})


@dataclass(slots=True)
class StageRow:
    stage_id: str = ""
    status: str = "queued"
    label: str = ""
    detail: str = ""


@dataclass(slots=True)
class CoordinateRow:
    coordinate_index: int = 0
    index: int = 0
    execution_id: str | None = None
    coordinate_execution_id: str | None = None
    status: str = "queued"
    provider: str = "—"
    surface: str = "—"
    level: str = "—"
    mode: str = "—"
    target_method: str | None = None
    selected_method: str | None = None
    run_id: str | None = None
    task_result: str | None = None
    failure_class: str | None = None
    finding_count: int = 0
    confirmed_vulns: list = field(default_factory=list)
    achieved_outcomes: list = field(default_factory=list)
    started_at: float | None = None
    elapsed: str = "—"


@dataclass(slots=True)
class FailureSummary:
    failure_class: str = "unknown"
    message: str = ""
    remediation: str = ""
    provider: str = "—"
    request_id: str | None = None


@dataclass(slots=True)
class TuiRunState:
    status: str = "ready"
    execution_id: str | None = None
    run_mode: str = "single"
    stages: list = field(default_factory=list)
    coordinates: dict = field(default_factory=dict)
    exec_index: dict = field(default_factory=dict)
    selected_coordinate: int | None = None
    selected_method: str | None = None
    candidate_count: int = 0
    validation_count: int = 0
    confirmed_vulns: list = field(default_factory=list)
    achieved_outcomes: list = field(default_factory=list)
    verifier_decision: str | None = None
    failure: FailureSummary | None = None
    notices: list = field(default_factory=list)
    unseen_evidence: int = 0
    dropped_events: int = 0
    completed: int = 0
    total: int = 0
    guardrail_count: int = 0
    fallback_count: int = 0
    containment_count: int = 0
    #: Monotonic count of visible notice-list changes (append or coalesce).
    #: Length alone stops changing once NOTICE_MAX_ENTRIES is reached.
    notice_version: int = 0
    started_at: float | None = None
    last_event_at: float | None = None
    elapsed: str = "—"

    def __post_init__(self) -> None:
        if not self.stages:
            self.stages = [
                StageRow(stage_id=stage_id, label=stage_id.replace("_", " "))
                for stage_id in CANONICAL_STAGE_IDS
            ]


def _fresh_stages() -> list[StageRow]:
    return [StageRow(stage_id=sid, label=sid.replace("_", " ")) for sid in CANONICAL_STAGE_IDS]


def _push_notice(state: TuiRunState, text: str) -> None:
    """Append or coalesce one notice, bumping the visible-list generation.

    A repeated notice becomes ``(x2)`` and later repeats increment that count, so
    the coalescing branch is checked before the exact-equality case (which that
    first repeat would otherwise hit and return from unchanged).
    """
    safe = tui_security._redact_text(text)
    if state.notices:
        last = state.notices[-1]
        if last.startswith(safe + " (x"):
            stem, _, tail = last.rpartition("(x")
            try:
                count = int(tail.rstrip(")")) + 1
            except ValueError:
                count = 2
            state.notices[-1] = f"{stem}(x{count})"
            state.notice_version += 1
            return
        if last == safe:
            state.notices[-1] = f"{safe} (x2)"
            state.notice_version += 1
            return
    state.notices.append(safe)
    while len(state.notices) > NOTICE_MAX_ENTRIES:
        state.notices.pop(0)
    state.notice_version += 1


def _stage_for_node(state: TuiRunState, node: str | None) -> StageRow:
    name = str(node or "").strip().lower()
    ids = [row.stage_id for row in state.stages]
    if name in ids:
        return next(row for row in state.stages if row.stage_id == name)
    if "candidate" in name or "builder" in name:
        return next(row for row in state.stages if row.stage_id == "payload_candidate_builder")
    if "valid" in name:
        return next(row for row in state.stages if row.stage_id == "payload_validator")
    if "chain" in name or "router" in name:
        return next(row for row in state.stages if row.stage_id == "chaining_router")
    if "scor" in name:
        return next(row for row in state.stages if row.stage_id == "scorer")
    if "recon" in name:
        return next(row for row in state.stages if row.stage_id == "recon")
    if "orchestrat" in name:
        return next(row for row in state.stages if row.stage_id == "orchestrator")
    return next(row for row in state.stages if row.stage_id == "method_agent")


def _ensure_coordinate(state: TuiRunState, index: int, exec_id: str | None) -> CoordinateRow:
    row = state.coordinates.get(index)
    if row is None:
        row = CoordinateRow(coordinate_index=index, index=index)
        state.coordinates[index] = row
    if exec_id:
        row.execution_id = exec_id
        row.coordinate_execution_id = exec_id
        state.exec_index[exec_id] = index
    return row


def _row_failed(row: CoordinateRow) -> bool:
    if row.failure_class:
        return True
    return str(row.status).lower() in {"failed", "error"}


def _format_elapsed(seconds: float) -> str:
    if seconds < 0:
        return "—"
    if seconds < 60:
        return f"{seconds:.1f}s"
    return f"{int(seconds // 60)}m{seconds % 60:04.1f}s"


def _coordinate_elapsed(row: CoordinateRow, data: dict[str, Any], finished_at: float) -> str:
    """Elapsed for one coordinate, or ``—`` when nothing truthful is known.

    A runner-reported value wins; otherwise the elapsed time is derived from the
    coordinate's own start event, so a missing start (skipped coordinate, dropped
    event, out-of-order completion) stays unavailable instead of being invented.
    """

    reported = data.get("elapsed")
    if isinstance(reported, str) and reported.strip():
        return tui_security._redact_text(reported)[:40]
    for key in ("elapsed_ms", "duration_ms"):
        value = data.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return _format_elapsed(float(value) / 1000.0)
    if row.started_at is None:
        return "—"
    return _format_elapsed(finished_at - row.started_at)


def _failure_summary_from_data(data: dict[str, Any]) -> FailureSummary:
    failure = data.get("failure") if isinstance(data.get("failure"), dict) else data
    return FailureSummary(
        failure_class=tui_security._redact_text(data.get("failure_class") or failure.get("failure_class") or "unknown"),
        message=tui_security._redact_text(data.get("message") or failure.get("message") or data.get("error") or "")[:800],
        remediation=tui_security._redact_text(data.get("remediation") or failure.get("remediation") or "")[:800],
        provider=str(redact_secrets(data.get("provider") or failure.get("provider") or "—"))[:120],
        request_id=data.get("request_id") or failure.get("request_id"),
    )


def _advance_run_elapsed(state: TuiRunState, event: RunEvent) -> str:
    """Elapsed run time derived from the state's own start event timestamp.

    No wall-clock read or timer: the value is only ever the difference between
    the run-start event and the newest event timestamp seen. Out-of-order events
    (a provider or journal replaying an older timestamp) therefore cannot make
    the clock regress, and the value stays ``—`` when no run start was recorded.
    """

    if state.started_at is None:
        return "—"
    if state.last_event_at is not None:
        state.last_event_at = max(state.last_event_at, event.timestamp)
    else:
        state.last_event_at = event.timestamp
    return _format_elapsed(state.last_event_at - state.started_at)


def apply_run_event(state: TuiRunState, event: RunEvent) -> frozenset[str]:
    """Mutate only the UI model; return dirty region names."""

    prior_status = state.status
    dirty = set(_apply_event(state, event))
    if prior_status not in _FINAL_STATUSES:
        before = state.elapsed
        state.elapsed = _advance_run_elapsed(state, event)
        if state.elapsed != before:
            # The elapsed value lives in the status strip.
            dirty.add("header")
    return frozenset(dirty)


def _apply_event(state: TuiRunState, event: RunEvent) -> frozenset[str]:
    dirty: set[str] = set()
    event_type = str(event.event_type or "")
    try:
        data = dict(event.data or {})
    except (TypeError, ValueError):
        data = {}
    message = str(event.message or "")
    safe_message = tui_security._redact_text(message)[:500]

    if event_type in ("run.started", "matrix.started"):
        state.status = "running"
        state.execution_id = event.execution_id
        state.coordinates = {}
        state.exec_index = {}
        state.stages = _fresh_stages()
        state.selected_method = None
        state.confirmed_vulns = []
        state.achieved_outcomes = []
        state.verifier_decision = None
        state.failure = None
        state.completed = 0
        state.total = int(data.get("total", 0) or 0)
        state.started_at = event.timestamp
        state.last_event_at = event.timestamp
        state.elapsed = _format_elapsed(0.0)
        if safe_message:
            _push_notice(state, safe_message)
        return frozenset({"header", "pipeline", "coordinates", "evidence", "notices"})

    if event_type == "matrix.run.started":
        try:
            index = int(data.get("coordinate_index", 0))
        except (TypeError, ValueError):
            index = 0
        exec_id = data.get("coordinate_execution_id") or event.execution_id
        row = _ensure_coordinate(state, index, exec_id)
        if str(row.status).lower() not in _FINAL_COORDINATE_STATUSES:
            # A late or replayed start for a coordinate that already finished
            # must not revert its terminal status or restart its clock.
            row.status = "running"
            row.started_at = event.timestamp
            row.elapsed = "—"
        for attr, key in (("provider", "provider"), ("surface", "surface"),
                          ("level", "security_level"), ("mode", "payload_mode")):
            if data.get(key) not in (None, ""):
                setattr(row, attr, str(redact_secrets(data[key]))[:120])
        if data.get("target_method"):
            row.target_method = str(redact_secrets(data["target_method"]))[:160]
        if state.status == "ready":
            state.status = "running"
        state.total = int(data.get("total", 0) or state.total or 0)
        dirty.update({"header", "coordinates"})
        return frozenset(dirty)

    if event_type == "matrix.run.finished":
        try:
            index = int(data.get("coordinate_index", 0))
        except (TypeError, ValueError):
            index = 0
        exec_id = data.get("coordinate_execution_id") or event.execution_id
        row = _ensure_coordinate(state, index, exec_id)
        row.run_id = str(data["run_id"])[:240] if data.get("run_id") not in (None, "") else row.run_id
        if data.get("selected_method"):
            row.selected_method = str(redact_secrets(data["selected_method"]))[:160]
            state.selected_method = row.selected_method
        if data.get("task_result") not in (None, ""):
            row.task_result = str(data["task_result"])[:64]
        failure_class = data.get("failure_class")
        if isinstance(data.get("failure"), dict):
            failure_class = failure_class or data["failure"].get("failure_class")
        if failure_class:
            row.failure_class = str(redact_secrets(failure_class))[:120]
        raw_status = str(data.get("status", "") or "").lower()
        if raw_status in {"skipped", "cancelled"}:
            row.status = raw_status
        else:
            row.status = "failed" if (row.failure_class or raw_status in {"failed", "error"}) else "succeeded"
        for key, attr in (("confirmed_vulns", "confirmed_vulns"), ("achieved_outcomes", "achieved_outcomes")):
            values = data.get(key)
            if isinstance(values, (list, tuple)):
                redacted_values = redact_secrets(list(values))
                setattr(row, attr, redacted_values)
                if index == state.selected_coordinate or state.selected_coordinate is None:
                    setattr(state, key, list(redacted_values))
                row.finding_count = len(row.confirmed_vulns)
        row.elapsed = _coordinate_elapsed(row, data, event.timestamp)
        state.completed = int(data.get("completed", 0) or state.completed or 0)
        state.total = int(data.get("total", 0) or state.total or 0)
        if _row_failed(row):
            state.failure = _failure_summary_from_data(data)
            if state.status == "running":
                state.status = "degraded"
        dirty.update({"header", "coordinates", "evidence"})
        return frozenset(dirty)

    if event_type == "graph.state":
        safe = {k: v for k, v in data.items() if k not in _DROP_COT_KEYS}
        if safe.get("selected_method"):
            method = str(redact_secrets(safe["selected_method"]))[:160]
            if method != state.selected_method:
                state.selected_method = method
                dirty.add("pipeline")
        for key in ("candidate_count", "generated_candidates", "generation_budget"):
            if isinstance(safe.get(key), (int, float)):
                state.candidate_count = int(safe[key])
                break
        for key in ("validation_count", "accepted_candidates", "tried_candidates"):
            if isinstance(safe.get(key), (int, float)):
                state.validation_count = int(safe[key])
                break
        for key in ("confirmed_vulns", "achieved_outcomes"):
            if isinstance(safe.get(key), (list, tuple)):
                setattr(state, key, list(redact_secrets(safe[key]))[:200])
        verdict = safe.get("verifier_decision") or safe.get("latest_verifier") or safe.get("verifier_summary")
        if verdict not in (None, ""):
            state.verifier_decision = tui_security._redact_text(verdict)[:500]
        state.unseen_evidence += 1
        dirty.update({"evidence"})
        return frozenset(dirty)

    if event_type in ("llm.token", "llm.stream", "llm.progress"):
        return frozenset()

    if event_type in ("graph.node.started", "graph.node.completed", "graph.node.failed",
                      "node.started", "node.completed", "node.failed"):
        node = event.node or data.get("node") or data.get("name")
        stage = _stage_for_node(state, str(node) if node is not None else None)
        if event_type.endswith("started"):
            stage.status = "running"
        elif event_type.endswith("completed"):
            stage.status = "succeeded"
        else:
            stage.status = "failed"
        detail = safe_message or str(node or "")
        if detail:
            stage.detail = detail[:200]
        exec_id = event.execution_id
        if exec_id and exec_id in state.exec_index:
            row = state.coordinates[state.exec_index[exec_id]]
            if event_type.endswith("failed"):
                row.status = "failed"
                if state.status == "running":
                    state.status = "degraded"
            dirty.add("coordinates")
        _push_notice(state, f"{node or 'node'} {event_type.rsplit('.', 1)[-1]}{(': ' + safe_message) if safe_message else ''}"[:300])
        dirty.update({"pipeline", "notices"})
        return frozenset(dirty)

    if event_type in ("run.finished", "matrix.finished"):
        if state.status == "cancelled":
            if safe_message:
                _push_notice(state, safe_message)
            dirty.update({"header", "evidence", "notices"})
            return frozenset(dirty)
        failed = any(_row_failed(row) for row in state.coordinates.values())
        state.status = "failed" if failed else "succeeded"
        if safe_message:
            _push_notice(state, safe_message)
        dirty.update({"header", "evidence", "notices"})
        return frozenset(dirty)

    if event_type in ("run.failed", "matrix.failed", "run.error"):
        state.status = "failed"
        state.failure = _failure_summary_from_data({**data, "message": message or data.get("message")})
        _push_notice(state, f"failed: {safe_message or state.failure.failure_class}"[:300])
        dirty.update({"header", "evidence", "notices"})
        return frozenset(dirty)

    if event_type in ("run.cancelled", "matrix.cancelled", "run.cancellation"):
        state.status = "cancelled"
        if safe_message:
            _push_notice(state, safe_message)
        dirty.update({"header", "notices"})
        return frozenset(dirty)

    if event_type in ("llm.failed", "llm.error", "provider.failed"):
        state.failure = _failure_summary_from_data({**data, "message": message or data.get("message")})
        exec_id = event.execution_id
        if exec_id and exec_id in state.exec_index:
            row = state.coordinates[state.exec_index[exec_id]]
            row.status = "failed"
            row.failure_class = state.failure.failure_class
            if state.status == "running":
                state.status = "degraded"
            dirty.add("coordinates")
        _push_notice(
            state,
            f"{state.failure.failure_class}: {state.failure.message or safe_message}"[:300],
        )
        dirty.update({"evidence", "notices"})
        return frozenset(dirty)

    if event_type in ("containment.violated", "containment.violation", "guardrail.containment"):
        state.containment_count += 1
        if state.status == "running":
            state.status = "degraded"
        _push_notice(state, f"containment: {safe_message or 'violation'}"[:300])
        dirty.update({"header", "evidence", "notices"})
        return frozenset(dirty)

    if event_type in ("graph.completed", "scorer.completed", "verifier.decision"):
        if data.get("selected_method"):
            state.selected_method = str(redact_secrets(data["selected_method"]))[:160]
        dirty.update({"evidence"})
        if safe_message:
            _push_notice(state, safe_message)
            dirty.add("notices")
        return frozenset(dirty)

    if safe_message or data:
        redacted_data = tui_security._redact_mapping(data)
        fingerprint = json.dumps(redacted_data, default=str, sort_keys=True)[:200]
        _push_notice(state, f"{event_type}: {safe_message or fingerprint}"[:300])
        dirty.add("notices")
    return frozenset(dirty)




def _matrix_coordinate_count(config: Any) -> int:
    """Coordinate count for a resolved request, matching the headless formula."""
    if not getattr(config, "matrix", False):
        return 1
    providers = list(getattr(config, "providers", []) or []) or [getattr(config, "provider", "")]
    levels = list(getattr(config, "levels", []) or []) or [getattr(config, "level", "")]
    surfaces = list(getattr(config, "surfaces", []) or []) or [getattr(config, "surface", "")]
    modes = list(getattr(config, "payload_modes", []) or []) or [getattr(config, "payload_mode", "")]
    repeats = max(1, int(getattr(config, "repeats", 1) or 1))
    return len(providers) * len(levels) * len(surfaces) * len(modes) * repeats
