"""Mission-control Textual interface for configuring and observing TESIS runs."""

from __future__ import annotations

import inspect
import json
import os
import re
import tempfile
from collections import deque
from copy import deepcopy
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from pathlib import Path
from threading import Lock, Thread
from time import monotonic
from typing import Any, Literal
from urllib.parse import urlsplit

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.theme import Theme
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    ContentSwitcher,
    DataTable,
    Input,
    Label,
    OptionList,
    Select,
    SelectionList,
    Static,
    TextArea,
)
from textual.widgets.option_list import Option

from evaluation.multi_llm_runner import run_provider_matrix
from evaluation.runner import run_single_engagement
from tesis.artifact_repository import ArtifactRepository, config_fingerprint, new_execution_id
from tesis.config_loader import (
    ConfigError,
    dump_yaml_config,
    load_and_resolve_config,
    load_yaml_config,
    parse_yaml_config,
    save_yaml_config,
)
from tesis.config_fields import (
    ALL_FIELD_SPECS,
    REASONING_EFFORT_CHOICES,
)
from tesis.runtime_events import CancellationToken, RunEvent, redact_secrets


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPOSITORY_ROOT / "config.yaml"


# ---------------------------------------------------------------- themes

def _build_mono_theme() -> Theme:
    """Build the hex-monochrome theme against the installed Textual API."""
    params = inspect.signature(Theme).parameters
    defaults: dict[str, Any] = {
        "name": "tesis-mono",
        "primary": "#FFFFFF",
        "secondary": "#B0B0B0",
        "accent": "#FFFFFF",
        "foreground": "#FFFFFF",
        "background": "#000000",
        "success": "#FFFFFF",
        "error": "#FFFFFF",
        "warning": "#FFFFFF",
        "surface": "#000000",
        "panel": "#000000",
        "boost": "#FFFFFF",
        "dark": True,
    }
    return Theme(**{key: value for key, value in defaults.items() if key in params})


SHELL_MONO_THEME = _build_mono_theme()
SHELL_MONO_THEME_NAME = SHELL_MONO_THEME.name


# ---------------------------------------------------------------- preserved helpers

def _safe_config_error_text(exc: BaseException) -> str:
    """Format config-load failures without exposing YAML scalar values."""
    from tesis.doctor import sanitize_config_error

    return sanitize_config_error(exc)


def _contains_literal_secret(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    for key, item in value.items():
        if str(key).lower() in {"api_key", "secret", "token", "password"}:
            if isinstance(item, str) and item and not item.strip().startswith("${"):
                return True
        if isinstance(item, dict) and _contains_literal_secret(item):
            return True
    return False


def _mask_yaml_secrets(payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Mask literal YAML secrets while retaining restorable placeholders."""
    masked = deepcopy(payload)
    preserved: dict[str, str] = {}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in list(value.items()):
                normalized = str(key).lower().replace("-", "_")
                secret_key = any(part in normalized for part in ("api_key", "password", "secret", "token"))
                if secret_key and isinstance(item, str) and item and not item.strip().startswith("${"):
                    placeholder = f"__TESIS_PRESERVE_SECRET_{len(preserved)}__"
                    preserved[placeholder] = item
                    value[key] = placeholder
                else:
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(masked)
    return masked, preserved


def _restore_yaml_secrets(payload: Any, preserved: dict[str, str]) -> Any:
    if isinstance(payload, dict):
        for key, item in list(payload.items()):
            payload[key] = _restore_yaml_secrets(item, preserved)
    elif isinstance(value := payload, list):
        for index, item in enumerate(value):
            value[index] = _restore_yaml_secrets(item, preserved)
    elif isinstance(payload, str) and payload in preserved:
        return preserved[payload]
    return payload


def _sanitize_endpoint(value: Any) -> Any:
    """Display form for a URL: userinfo and every query/fragment *value* masked.

    Keys and their order are preserved so the URL stays readable and auditable,
    but no query or fragment value survives into a drawer, export, or
    screenshot — the canonical contract redacts all of them, not only
    credential-shaped keys.
    """

    if not isinstance(value, str) or "://" not in value:
        return value
    try:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
        parts = urlsplit(value)

        def _scrub(items: list[tuple[str, str]]) -> str:
            return urlencode([(key, "[REDACTED]") for key, _ in items], safe="[]")

        if parts.query or parts.fragment:
            query = _scrub(parse_qsl(parts.query, keep_blank_values=True)) if parts.query else ""
            fragment = parts.fragment
            if fragment:
                if "=" in fragment or "&" in fragment:
                    fragment = _scrub(parse_qsl(fragment, keep_blank_values=True))
                elif fragment.strip():
                    fragment = "[REDACTED]"
            value = urlunsplit((parts.scheme, parts.netloc, parts.path, query, fragment))
    except Exception:
        try:
            import re as _re2
            value = _re2.sub(r"([?&#][^=&#\s]*=)[^&\s#]+", r"\1[REDACTED]", value)
        except Exception:
            pass
    redacted = re.sub(r"(://[^/:\s?#]+:)[^@/\s?#]+@", r"\1[REDACTED]@", value)
    return redacted


def _safe_url(value: Any) -> str:
    """Display form for a target/endpoint URL.

    Every query/fragment value and any userinfo credential is masked by
    :func:`_sanitize_endpoint`; token-shaped text anywhere else is then
    redacted.
    """

    sanitized = _sanitize_endpoint(str(value))
    return _SECRET_TOKEN.sub("[REDACTED]", str(redact_secrets(sanitized)))


def _failure_mapping(failure: Any) -> dict[str, Any]:
    """Normalize a failure payload to a dict.

    The production state carries the slotted :class:`FailureSummary` dataclass;
    legacy callers pass mappings. Dataclass fields are read directly so a
    slotted instance is never silently dropped.
    """

    if failure is None:
        return {}
    if isinstance(failure, dict):
        return dict(failure)
    if is_dataclass(failure) and not isinstance(failure, type):
        return {spec.name: getattr(failure, spec.name) for spec in fields(failure)}
    data = getattr(failure, "__dict__", None)
    return dict(data) if isinstance(data, dict) else {}


def _mask_url_credentials(payload: Any, preserved: dict[str, str]) -> Any:
    """Display masking for URLs embedded in the settings document.

    Registers the exact sanitized spelling as a restore key so an untouched
    document still round-trips the original URL through the existing
    :func:`_restore_yaml_secrets` path.
    """

    if isinstance(payload, dict):
        for key, item in list(payload.items()):
            payload[key] = _mask_url_credentials(item, preserved)
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            payload[index] = _mask_url_credentials(item, preserved)
    elif isinstance(payload, str) and "://" in payload:
        sanitized = _sanitize_endpoint(payload)
        if isinstance(sanitized, str) and sanitized != payload:
            preserved.setdefault(sanitized, payload)
            return sanitized
    return payload


def _redact_mapping(value: Any) -> Any:
    redacted = redact_secrets(value)
    if isinstance(redacted, dict):
        redacted.pop("raw_state", None)
        redacted.pop("chain_of_thought", None)
        redacted.pop("chain-of-thought", None)
        redacted.pop("prompt", None)
        if isinstance(redacted.get("endpoint"), str):
            redacted["endpoint"] = _sanitize_endpoint(redacted["endpoint"])
    return redacted


_SECRET_TOKEN = re.compile(
    r"(?i)\b(?:thk_live|sk-live|sk-proj|xai-[A-Za-z0-9_-]*|AIza[\w-]{20,})[A-Za-z0-9_-]*"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:authorization|api[_-]?key|password|passwd|secret|token|session|cookie)"
    r"\s*[:=]\s*(?:bearer\s+)?)[^\s,;]+"
)


def _redact_text(value: Any) -> str:
    """Redact credential-shaped free text before it reaches state or widgets.

    :func:`redact_secrets` only masks known secret *values* and secret *keys*;
    a summary message embeds a token in prose, so it needs its own pass.
    """

    text = str(redact_secrets(value))
    text = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", text)
    return _SECRET_TOKEN.sub("[REDACTED]", text)


def _invoke_runner(runner: Any, kwargs: dict[str, Any]) -> Any:
    """Call single/matrix runners with only the kwargs they accept."""
    try:
        signature = inspect.signature(runner)
    except (TypeError, ValueError):
        return runner(**kwargs)
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values()):
        return runner(**kwargs)
    return runner(**{k: v for k, v in kwargs.items() if k in signature.parameters})


DETAIL_LOG_MAX_LINES = 2_000
DETAIL_RENDER_MAX_CHARS = 500_000

UI_PENDING_EVENT_MAX = 2_048
NOTICE_MAX_ENTRIES = 500
#: Most recent notices rendered in the scrollable pane; the bounded full stream
#: stays in the trace drawer.
NOTICE_PANE_MAX = 200
TRACE_MAX_ENTRIES = 500

_DROP_COT_KEYS = frozenset({
    "raw_state", "chain_of_thought", "chain-of-thought", "chain_of_thoughts",
    "prompt", "reasoning", "cot",
})


# ---------------------------------------------------------------- operator state contract

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

_DIRTY_REGIONS = frozenset({"header", "pipeline", "coordinates", "evidence", "notices"})

# Events that settle a run; a runner returning without one still needs a
# terminal state, so the runtime thread reconciles it (see _run_blocking).
_TERMINAL_EVENT_TYPES = frozenset({
    "run.finished", "run.failed", "run.cancelled", "run.error",
    "matrix.finished", "matrix.failed", "matrix.cancelled",
})

# Statuses that end a run. The elapsed clock stops once one is set, so a late
# event cannot keep extending a finished run.
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
    safe = _redact_text(text)
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
        return _redact_text(reported)[:40]
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
        failure_class=_redact_text(data.get("failure_class") or failure.get("failure_class") or "unknown"),
        message=_redact_text(data.get("message") or failure.get("message") or data.get("error") or "")[:800],
        remediation=_redact_text(data.get("remediation") or failure.get("remediation") or "")[:800],
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
    safe_message = _redact_text(message)[:500]

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
            state.verifier_decision = _redact_text(verdict)[:500]
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
        redacted_data = _redact_mapping(data)
        fingerprint = json.dumps(redacted_data, default=str, sort_keys=True)[:200]
        _push_notice(state, f"{event_type}: {safe_message or fingerprint}"[:300])
        dirty.add("notices")
    return frozenset(dirty)


# ---------------------------------------------------------------- command registry

@dataclass
class CommandSpec:
    name: str
    title: str
    summary: str
    keys: str = ""
    enabled_when: str = "always"


# ``keys`` is the launcher's advertised shortcut for a command, and is only set
# when MissionControlScreen really binds that key (see
# test_registry_keys_are_dispatchable_and_pane_keys_agree). Commands without a
# global key leave it empty and stay reachable through the launcher and `?`.
COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec("run", "Run single", "Guided single-coordinate launch", "r", "idle"),
    CommandSpec("matrix", "Run matrix", "Guided experiment-matrix launch", "m", "idle"),
    CommandSpec("plan", "Plan", "Preview resolved config and fingerprint", "p", "idle"),
    CommandSpec("cancel", "Cancel", "Request graceful cancellation", "ctrl+c", "active"),
    CommandSpec("coordinates", "Coordinates", "Inspect live coordinate rows", "2", "always"),
    CommandSpec("evidence", "Evidence", "Inspect verified findings and outcomes", "3", "always"),
    CommandSpec("failure", "Failure", "Inspect latest failure summary", "", "always"),
    CommandSpec("trace", "Trace", "Bounded redacted event stream", "", "always"),
    CommandSpec("doctor", "Doctor", "Configuration and target checks", "d", "always"),
    CommandSpec("results", "Results", "Scan and triage saved artifacts", "", "always"),
    CommandSpec("settings", "Settings", "Edit config YAML with secret masking", "", "idle"),
    CommandSpec("export", "Export", "Export triage summary as JSON", "", "always"),
    CommandSpec("about", "About", "Harness and runtime summary", "", "always"),
    CommandSpec("help", "Help", "Command registry and keys", "?", "always"),
    CommandSpec("quit", "Quit", "Exit the TUI", "q", "idle"),
)

_COMMAND_INDEX = {spec.name: spec for spec in COMMANDS}

# Keys the screen binds that are not registry commands. The footer hint and the
# help drawer both render this one list, so pane navigation is described once.
NAVIGATION_KEYS: tuple[tuple[str, str], ...] = (
    ("1", "pipeline"),
    ("2", "coordinates"),
    ("3", "evidence"),
    ("Tab/Shift+Tab", "focus"),
    ("Enter", "inspect"),
    ("/", "command"),
)


def navigation_hint() -> str:
    """Global navigation keys, rendered identically in the footer and help."""
    return " · ".join(f"{key} {label}" for key, label in NAVIGATION_KEYS)


#: Supported interactive floor. Below it the shell shows only the size notice
#: and the quit/help hints.
FLOOR_WIDTH = 60
FLOOR_HEIGHT = 18


def _below_floor(screen: Screen) -> bool:
    try:
        size = screen.app.size
    except Exception:
        return False
    return size.width < FLOOR_WIDTH or size.height < FLOOR_HEIGHT


def _dismisses_below_floor(screen: Screen) -> bool:
    """Pop an overlay that is not allowed below the floor; report if dismissed.

    Idempotent: a mount and a resize can both arrive for the same screen, and a
    second pop would take the screen underneath with it.
    """
    if getattr(screen, "ALLOW_BELOW_FLOOR", False) or not _below_floor(screen):
        return False
    try:
        if screen.app.screen is screen:
            screen.app.pop_screen()
    except Exception:
        pass
    return True


# ---------------------------------------------------------------- drawers

class BaseDrawer(Screen):
    """Shared drawer shell.

    A Textual ``Screen`` is always laid out at the full terminal size, so the
    docked panel has to be an inner container: every drawer's composed content
    is wrapped in one ``.drawer`` panel, which is what makes it a 76-cell
    right-docked surface at 80+ columns and a full-screen surface below 80.
    The wrapping happens here so no drawer has to repeat the shell.

    Below the supported 60x18 floor the shell renders nothing but the size
    notice, so an overlay must not stay on top of it: a drawer dismisses itself
    on mount or on resize below the floor. Help is the documented exception,
    because it is one of the only two actions a too-small terminal still has.
    """

    BINDINGS = [Binding("escape", "back", "Back", show=True)]

    #: Set on a drawer that is allowed to stay open below the 60x18 floor.
    ALLOW_BELOW_FLOOR = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        compose = cls.__dict__.get("compose")
        if compose is not None:
            def composed(self: Screen, _compose: Any = compose) -> ComposeResult:
                # Below 80 columns the panel takes the whole screen; at 80 and
                # above it stays the 76-cell right-docked panel.
                try:
                    self.set_class(self.app.size.width < 80, "drawer-full")
                except Exception:
                    pass
                with Vertical(classes="drawer"):
                    yield from _compose(self)

            composed.__name__ = "compose"
            cls.compose = composed  # type: ignore[method-assign]

        # Wrap the subclass handlers so the floor rule is applied once, here,
        # instead of in every drawer.
        on_mount = cls.__dict__.get("on_mount")

        def mounted(self: Screen) -> None:
            if _dismisses_below_floor(self):
                return
            if on_mount is not None:
                on_mount(self)

        mounted.__name__ = "on_mount"
        cls.on_mount = mounted  # type: ignore[method-assign]

        on_resize = cls.__dict__.get("on_resize")

        def resized(self: Screen, event: Any) -> None:
            if _dismisses_below_floor(self):
                return
            if on_resize is not None:
                on_resize(self, event)

        resized.__name__ = "on_resize"
        cls.on_resize = resized  # type: ignore[method-assign]

    def action_back(self) -> None:
        self.app.pop_screen()


class CommandLauncher(Screen):
    """Bottom-anchored command modal; the only chrome border in the shell.

    ``/``, ``:``, and Ctrl+P all open this same registry-backed surface, so the
    footer hint, the help drawer, and typed dispatch never disagree.
    """

    BINDINGS = [Binding("escape", "back", "Back", show=True)]

    def __init__(self) -> None:
        super().__init__()
        self._filtered: list[CommandSpec] = list(COMMANDS)

    def compose(self) -> ComposeResult:
        with Vertical(id="command-launcher"):
            yield Label("Command — type to filter, Enter to dispatch, Esc to close", id="launcher-title")
            yield Input(placeholder="command", id="launcher-input")
            yield OptionList(*(self._option(spec) for spec in COMMANDS), id="launcher-list")

    def on_mount(self) -> None:
        if _dismisses_below_floor(self):
            return
        try:
            self.query_one("#launcher-input", Input).focus()
        except Exception:
            pass

    def _run_active(self) -> bool:
        mission = self._mission()
        return bool(mission is not None and mission.run_active)

    def _enabled(self, spec: CommandSpec) -> bool:
        if spec.enabled_when == "idle":
            return not self._run_active()
        if spec.enabled_when == "active":
            return self._run_active()
        return True

    def _option(self, spec: CommandSpec) -> Option:
        enabled = self._enabled(spec)
        text = f"/{spec.name} — {spec.summary}"
        if not enabled:
            reason = "run active — cancel first" if spec.enabled_when == "idle" else "no active run"
            text = f"{text}  [disabled: {reason}]"
        return Option(text, id=spec.name, disabled=not enabled)

    def _refilter(self, text: str) -> None:
        needle = text.strip().lower().lstrip("/")
        self._filtered = [s for s in COMMANDS if needle in s.name or needle in s.summary.lower()] or list(COMMANDS)
        try:
            options = self.query_one("#launcher-list", OptionList)
            options.clear_options()
            for spec in self._filtered:
                options.add_option(self._option(spec))
        except Exception:
            pass

    @on(Input.Changed, "#launcher-input")
    def filter_commands(self, event: Input.Changed) -> None:
        self._refilter(event.value)

    @on(Input.Submitted, "#launcher-input")
    def dispatch_typed(self, event: Input.Submitted) -> None:
        # Only an exact command name dispatches; anything else is a filter term,
        # so a typo can never fire a neighbouring command.
        needle = event.value.strip().lower().lstrip("/")
        match = next((s for s in COMMANDS if s.name == needle), None)
        if match is not None:
            self._dispatch(match.name)

    @on(OptionList.OptionSelected, "#launcher-list")
    def dispatch_selected(self, event: OptionList.OptionSelected) -> None:
        self._dispatch(str(event.option.id))

    def _dispatch(self, name: str) -> None:
        spec = _COMMAND_INDEX.get(str(name))
        if spec is None or not self._enabled(spec):
            return
        app = self.app
        app.pop_screen()

        def push(screen: Screen) -> None:
            try:
                app.push_screen(screen)
            except Exception:
                pass

        if name in ("run", "matrix"):
            push(LaunchDrawer(mode="single" if name == "run" else "matrix"))
        elif name == "plan":
            push(PlanDrawer())
        elif name == "cancel":
            mission = self._mission()
            if mission is not None:
                mission.request_cancel()
                self._return_to_mission()
        elif name == "coordinates":
            push(CoordinateDrawer())
        elif name == "evidence":
            push(EvidenceDrawer())
        elif name == "failure":
            mission = self._mission()
            push(FailureDrawer(getattr(getattr(mission, "state", None), "failure", None)))
        elif name == "trace":
            push(TraceDrawer())
        elif name == "doctor":
            push(DoctorDrawer())
        elif name in ("results", "export"):
            push(ResultsDrawer())
        elif name == "settings":
            push(SettingsDrawer())
        elif name == "about":
            push(AboutDrawer())
        elif name == "help":
            push(HelpDrawer())
        elif name == "quit":
            try:
                mission = self._mission()
                if mission is None or not mission.run_active:
                    app.exit()
            except Exception:
                pass

    def _return_to_mission(self) -> None:
        """Cancelling is observed on the mission surface, not inside a stale modal."""
        mission = self._mission()
        if mission is None:
            return
        for _ in range(4):
            stack = self.app.screen_stack
            if not stack or stack[-1] is mission:
                return
            self.app.pop_screen()

    def _mission(self) -> MissionControlScreen | None:
        for screen in self.app.screen_stack:
            if isinstance(screen, MissionControlScreen):
                return screen
        return None

    def action_back(self) -> None:
        # Focus restoration is owned by MissionControlScreen.on_screen_resume,
        # which knows which surface is the live default.
        self.app.pop_screen()


_LAUNCH_SCOPE_FIELDS: tuple[str, ...] = ("target_url", "experiment_condition", "target_method")
_LAUNCH_COORDINATE_FIELDS: tuple[str, ...] = (
    "provider", "model_profile", "level", "surface", "payload_mode",
)
_LAUNCH_MATRIX_FIELDS: tuple[str, ...] = (
    "providers", "levels", "surfaces", "payload_modes", "repeats",
)
_LAUNCH_RUNTIME_FIELDS: tuple[str, ...] = (
    "candidate_budget", "iterations", "output_dir",
    "stop_policy", "coverage_target", "report_format", "enriched_reporting", "diagnose",
    "log_verbosity",
    "guardrail_retry_enabled", "guardrail_handling",
    "guardrail_retry_max", "guardrail_retry_cooldown_threshold",
)

# Canonical guardrail vocabulary (AGENTS.md). The TUI exposes guardrail_* names
# while reusing the existing legacy config_fields specs and CLI override keys, so
# loader/YAML semantics stay untouched.
_LAUNCH_GUARDRAIL_SPECS: tuple[tuple[str, str], ...] = (
    ("guardrail_retry_enabled", "evasion.enabled"),
    ("guardrail_handling", "evasion.mode"),
    ("guardrail_retry_max", "evasion.max_retries"),
    ("guardrail_retry_cooldown_threshold", "evasion.cooldown_threshold"),
)
_LAUNCH_GUARDRAIL_LABELS: dict[str, str] = {
    "guardrail_retry_enabled": "Guardrail retry enabled",
    "guardrail_handling": "Guardrail handling",
    "guardrail_retry_max": "Guardrail retry max",
    "guardrail_retry_cooldown_threshold": "Guardrail retry cooldown",
}
# Resolved attribute names per TUI field: canonical first, legacy fallback.
_LAUNCH_VALUE_ATTRS: dict[str, tuple[str, ...]] = {
    "guardrail_retry_enabled": ("guardrail_retry_enabled", "evasion_enabled"),
    "guardrail_handling": ("guardrail_handling", "evasion_mode"),
    "guardrail_retry_max": ("guardrail_retry_max", "evasion_max_retries"),
    "guardrail_retry_cooldown_threshold": (
        "guardrail_retry_cooldown_threshold", "evasion_cooldown_threshold",
    ),
}

# Launch inputs map to the same override keys the headless CLI uses, so the
# drawer resolves through the one existing config resolver.
_LAUNCH_CLI_KEYS: dict[str, str] = {
    "target_url": "target",
    "provider": "provider",
    "level": "level",
    "surface": "surface",
    "payload_mode": "payload_mode",
    "model_profile": "model_profile",
    "experiment_condition": "experiment_condition",
    "target_method": "target_method",
    "candidate_budget": "candidate_budget",
    "iterations": "iterations",
    "repeats": "repeats",
    "output_dir": "output_dir",
    "report_format": "format",
    "enriched_reporting": "enriched_reporting",
    "stop_policy": "stop_policy",
    "coverage_target": "coverage_target",
    "diagnose": "diagnose",
    "log_verbosity": "log_verbosity",
    "guardrail_retry_enabled": "guardrail_retry_enabled",
    "guardrail_handling": "guardrail_handling",
    "guardrail_retry_max": "guardrail_retry_max",
    "guardrail_retry_cooldown_threshold": "guardrail_retry_cooldown_threshold",
    "providers": "providers",
    "levels": "levels",
    "surfaces": "surfaces",
    "payload_modes": "payload_modes",
}


def _launch_field_id(path: str) -> str:
    """A CSS-safe widget id derived from a config field path."""
    return "launch-field-" + re.sub(r"[^a-z0-9]+", "-", path.casefold()).strip("-")


def _launch_field_value(resolved: Any, path: str) -> Any:
    """Resolved value for one launch field.

    Uses the canonical attribute name first and falls back to the legacy one, so
    a control's initial value never comes from a dotted-root ``getattr``.
    """

    if resolved is None:
        return None
    for attr in _LAUNCH_VALUE_ATTRS.get(path, ()):
        if hasattr(resolved, attr):
            return getattr(resolved, attr)
    return getattr(resolved, path.replace(".", "_"), None)


def _role_attr(roles: Any, role: str, attr: str) -> Any:
    """Read one resolved LLM role setting without touching provider secrets."""
    settings = roles.get(role) if isinstance(roles, dict) else None
    return getattr(settings, attr, None) if settings is not None else None


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


class LaunchDrawer(BaseDrawer):
    """Guided launch: Scope → Coordinates → Runtime → Review.

    Every step renders native controls bound to the existing config fields;
    Review resolves through the same loader the headless CLI uses and is the
    only step that offers Start. Started requests are frozen until terminal.
    """

    STEPS = ("Scope", "Coordinates", "Runtime", "Review")

    def __init__(self, mode: Literal["single", "matrix"] = "single") -> None:
        super().__init__()
        self.mode: Literal["single", "matrix"] = mode if mode in ("single", "matrix") else "single"
        self._tesis_closing = False
        self._step = 0
        self._frozen = None
        # The target Input only ever displays a masked endpoint. The raw value
        # the operator typed is captured privately and is the only thing that
        # can become the resolver's ``target`` override.
        self._target_seed = ""
        self._target_display = ""
        self._target_raw: str | None = None
        self._target_guard = False
        paths = (list(_LAUNCH_SCOPE_FIELDS) + list(_LAUNCH_COORDINATE_FIELDS)
                 + list(_LAUNCH_MATRIX_FIELDS) + list(_LAUNCH_RUNTIME_FIELDS))
        spec_paths = dict(_LAUNCH_GUARDRAIL_SPECS)
        self._field_specs = {
            path: ALL_FIELD_SPECS[spec_paths.get(path, path)]
            for path in paths
            if spec_paths.get(path, path) in ALL_FIELD_SPECS
        }

    # -- compose -----------------------------------------------------

    def _raw_config(self) -> dict:
        try:
            parsed = load_yaml_config(CONFIG_PATH)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _field_control(self, path: str, config: dict, resolved: Any) -> Any:
        spec = self._field_specs[path]
        field_id = _launch_field_id(path)
        choices = [str(value) for value in spec.choice_values(config)]
        value = _launch_field_value(resolved, path)
        label = _LAUNCH_GUARDRAIL_LABELS.get(path, spec.label)
        if spec.kind == "select" or (choices and spec.value_type is str and not spec.multiple):
            current = None if value in (None, "") else str(value)
            if current is not None and current not in choices:
                # An off-registry value degrades to blank rather than crashing;
                # leaving it untouched keeps the configured value on submit.
                current = None
            return Select([(choice, choice) for choice in choices],
                          value=current if current is not None else Select.NULL,
                          allow_blank=True, prompt=label, id=field_id)
        if spec.multiple or spec.kind == "multi_select":
            selected = {str(item) for item in (value or [])}
            return SelectionList(*[(choice, choice, choice in selected) for choice in choices],
                                 id=field_id)
        if spec.value_type is bool or spec.kind == "boolean":
            return Checkbox(label, value=bool(value), id=field_id)
        if path == "target_url":
            # The configured endpoint may carry userinfo/query/fragment secrets,
            # so the widget is seeded masked and the raw value never reaches it.
            self._target_seed = _safe_url(value) if value not in (None, "") else ""
            self._target_display = self._target_seed
            return Input(value=self._target_seed, placeholder=label, id=field_id)
        return Input(value="" if value in (None, "") else str(value),
                     placeholder=label, id=field_id)

    def _yield_step(self, paths: tuple[str, ...], config: dict, resolved: Any) -> None:
        for path in paths:
            if path in self._field_specs:
                yield self._field_control(path, config, resolved)

    def compose(self) -> ComposeResult:
        config = self._raw_config()
        try:
            resolved = self._resolved_config()
        except Exception:
            resolved = None
        yield Label(f"Launch — {self.mode} (Esc to close)", id="launch-title")
        yield Static("", id="launch-step-indicator", markup=False)
        with ContentSwitcher(initial="launch-step-scope", id="launch-steps"):
            with Vertical(id="launch-step-scope", classes="launch-step"):
                yield from self._yield_step(_LAUNCH_SCOPE_FIELDS, config, resolved)
            with Vertical(id="launch-step-coordinates", classes="launch-step"):
                yield from self._yield_step(_LAUNCH_COORDINATE_FIELDS, config, resolved)
                if self.mode == "matrix":
                    yield from self._yield_step(_LAUNCH_MATRIX_FIELDS, config, resolved)
            with Vertical(id="launch-step-runtime", classes="launch-step"):
                with Collapsible(title="Advanced", collapsed=False, id="launch-advanced"):
                    yield from self._yield_step(_LAUNCH_RUNTIME_FIELDS, config, resolved)
                    runtime = getattr(resolved, "llm_runtime", None)
                    roles = getattr(runtime, "roles", {}) or {}
                    concurrency = getattr(runtime, "max_concurrency", None)
                    reasoning = next(
                        (getattr(settings, "reasoning_effort", None) for settings in roles.values()
                         if getattr(settings, "reasoning_effort", None)),
                        None,
                    )
                    if reasoning is not None and str(reasoning) not in REASONING_EFFORT_CHOICES:
                        reasoning = None
                    profiles = [(name, name) for name in self._profile_names(config)]
                    profile_names = {name for name, _ in profiles}
                    yield Input(value="" if concurrency in (None, "") else str(concurrency),
                                placeholder="LLM max concurrency (1-4)",
                                id="launch-llm-concurrency")
                    yield Checkbox("LLM cache within run",
                                   value=bool(getattr(runtime, "cache_enabled", False)),
                                   id="launch-llm-cache")
                    yield Select([(choice, choice) for choice in REASONING_EFFORT_CHOICES],
                                 value=str(reasoning) if reasoning else Select.NULL,
                                 allow_blank=True,
                                 prompt="reasoning effort", id="launch-reasoning-effort")
                    orchestrator = _role_attr(roles, "orchestrator", "model_profile")
                    payload_role = _role_attr(roles, "payload_generator", "model_profile")
                    yield Select(profiles,
                                 value=orchestrator if orchestrator in profile_names else Select.NULL,
                                 allow_blank=True, prompt="orchestrator model profile",
                                 id="launch-orchestrator-profile")
                    yield Select(profiles,
                                 value=payload_role if payload_role in profile_names else Select.NULL,
                                 allow_blank=True, prompt="payload model profile",
                                 id="launch-payload-profile")
            with Vertical(id="launch-step-review", classes="launch-step"):
                yield Static("", id="launch-review", markup=False)
        with Horizontal(id="launch-nav"):
            yield Button("Back", id="launch-back")
            yield Button("Next", id="launch-next")
            yield Button("Start", id="launch-start")
            yield Button("Close", id="launch-close")

    def _profile_names(self, config: dict) -> tuple[str, ...]:
        try:
            return tuple(self._field_specs["model_profile"].choice_values(config))
        except Exception:
            return ()

    def on_mount(self) -> None:
        self._goto_step(0)
        self._render_review()

    # -- values ------------------------------------------------------

    def _widget_value(self, spec: Any, widget: Any) -> Any:
        if isinstance(widget, Select):
            return None if widget.value is Select.NULL else widget.value
        if isinstance(widget, SelectionList):
            return list(widget.selected)
        if isinstance(widget, Checkbox):
            return bool(widget.value)
        if isinstance(widget, Input):
            text = widget.value.strip()
            if not text:
                return None
            try:
                return spec.coerce(text)
            except Exception:
                return None
        return None

    def _cli_args(self) -> dict[str, Any]:
        args: dict[str, Any] = {}
        for path, spec in self._field_specs.items():
            if path == "target_url":
                # Untouched: the masked seed is display-only, so the resolver
                # keeps the configured endpoint. Edited: only the privately
                # captured raw value can become the override.
                if self._target_raw is not None:
                    args["target"] = self._target_raw
                continue
            try:
                widget = self.query_one(f"#{_launch_field_id(path)}")
            except Exception:
                continue
            value = self._widget_value(spec, widget)
            if value is None or value == "" or value == []:
                continue
            args[_LAUNCH_CLI_KEYS.get(path, path)] = value
        for key, widget_id in (
            ("llm_max_concurrency", "launch-llm-concurrency"),
            ("reasoning_effort", "launch-reasoning-effort"),
            ("orchestrator_model_profile", "launch-orchestrator-profile"),
            ("payload_model_profile", "launch-payload-profile"),
        ):
            try:
                widget = self.query_one(f"#{widget_id}")
            except Exception:
                continue
            raw = widget.value
            if raw in (None, "", Select.NULL):
                continue
            if isinstance(widget, Input):
                try:
                    raw = int(str(raw).strip())
                except (TypeError, ValueError):
                    continue
            args[key] = raw
        try:
            args["llm_cache"] = bool(self.query_one("#launch-llm-cache", Checkbox).value)
        except Exception:
            pass
        if self.mode == "matrix":
            args["matrix"] = True
        return args

    def _resolved_config(self) -> Any:
        return load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args=self._cli_args())

    # -- navigation --------------------------------------------------

    def _goto_step(self, index: int) -> None:
        self._step = max(0, min(index, len(self.STEPS) - 1))
        try:
            self.query_one("#launch-steps", ContentSwitcher).current = (
                f"launch-step-{self.STEPS[self._step].casefold()}"
            )
        except Exception:
            pass
        if self._step == len(self.STEPS) - 1:
            self._render_review()
        try:
            indicator = "Steps: " + " · ".join(
                f"> {name}" if position == self._step else name
                for position, name in enumerate(self.STEPS)
            )
            self.query_one("#launch-step-indicator", Static).update(indicator)
            self.query_one("#launch-back", Button).display = self._step > 0
            self.query_one("#launch-next", Button).display = self._step < len(self.STEPS) - 1
            self.query_one("#launch-start", Button).display = self._step == len(self.STEPS) - 1
        except Exception:
            pass

    @on(Button.Pressed, "#launch-next")
    def next_step(self) -> None:
        self._goto_step(self._step + 1)

    @on(Button.Pressed, "#launch-back")
    def previous_step(self) -> None:
        self._goto_step(self._step - 1)

    @on(Input.Changed, "#launch-field-target-url")
    def target_edited(self, event: Input.Changed) -> None:
        """Keep the target Input masked while privately capturing the raw value.

        Untouched seed == configured endpoint, so no override is emitted. Any
        real edit captures the typed endpoint and immediately re-masks the
        visible widget, so no literal query/fragment value persists in the
        widget, a screenshot, or the screen-reader surface.
        """

        if self._target_guard:
            return
        typed = str(event.value)
        if typed == self._target_display:
            # Our own re-mask (the widget already shows the masked spelling).
            return
        if typed == self._target_seed:
            self._target_raw = None
            self._target_display = typed
            return
        self._target_raw = typed
        masked = _safe_url(typed)
        self._target_display = masked
        self._target_guard = True
        try:
            event.input.value = masked
        finally:
            self._target_guard = False

    @on(Select.Changed)
    @on(Checkbox.Changed)
    @on(Input.Changed)
    @on(SelectionList.SelectedChanged)
    def refresh_review(self) -> None:
        self._render_review()

    def _render_review(self) -> None:
        try:
            cfg = self._resolved_config()
            fingerprint = config_fingerprint({
                "target_url": cfg.target_url,
                "provider": getattr(cfg, "provider", ""),
                "level": getattr(cfg, "level", ""),
            })
            runtime = getattr(cfg, "llm_runtime", None)
            roles = getattr(runtime, "roles", {}) or {}
            reasoning = next((getattr(role, "reasoning_effort", None) for role in roles.values()
                              if getattr(role, "reasoning_effort", None)), "—")
            text = (
                "Review — resolved request (Start freezes these values)\n"
                f"mode={self.mode} coordinates={_matrix_coordinate_count(cfg)}\n"
                f"target={_safe_url(cfg.target_url)}\n"
                f"condition={cfg.experiment_condition} target_method={cfg.target_method or '—'}\n"
                f"provider={cfg.provider} model_profile={getattr(cfg, 'model_profile', None) or '—'} "
                f"level={cfg.level} surface={cfg.surface} payload_mode={cfg.payload_mode}\n"
                f"candidate_budget={cfg.candidate_budget} iterations={cfg.iterations} "
                f"stop_policy={cfg.stop_policy} coverage_target={cfg.coverage_target}\n"
                f"output_dir={cfg.output_dir} format={cfg.report_format}\n"
                f"llm concurrency={getattr(runtime, 'max_concurrency', '—')} "
                f"cache={getattr(runtime, 'cache_enabled', '—')} reasoning={reasoning}\n"
                f"fingerprint={fingerprint}"
            )
        except Exception as exc:
            text = f"Review\nconfig error: {_safe_config_error_text(exc)}"
        try:
            self.query_one("#launch-review", Static).update(str(redact_secrets(text))[:8000])
        except Exception:
            pass

    @on(Button.Pressed, "#launch-close")
    def close_drawer(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#launch-start")
    def start_from_review(self) -> None:
        if self._frozen is not None:
            return
        try:
            cfg = self._resolved_config()
        except Exception as exc:
            try:
                self.query_one("#launch-review", Static).update(
                    f"Review\nconfig error: {_safe_config_error_text(exc)}"
                )
            except Exception:
                pass
            return
        self._frozen = cfg
        mission = next(
            (s for s in self.app.screen_stack if isinstance(s, MissionControlScreen)), None
        )
        self.app.pop_screen()
        if mission is not None:
            mission.start_run(cfg, mode=self.mode)

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True


class SettingsDrawer(BaseDrawer):
    def __init__(self) -> None:
        super().__init__()
        self.preserved_secret_placeholders: dict[str, str] = {}
        self.literal_warning_acknowledged = False
        self._tesis_closing = False
        self._settings_generation = 0

    def compose(self) -> ComposeResult:
        yield Label("Settings — config sections (Esc to close)", id="settings-title")
        with Collapsible(title="Target & defaults", collapsed=True, id="settings-section-target"):
            yield Static("", id="settings-target-body", markup=False)
        with Collapsible(title="Model profile", collapsed=True, id="settings-section-model"):
            yield Static("", id="settings-model-body", markup=False)
        with Collapsible(title="LLM runtime", collapsed=True, id="settings-section-llm"):
            yield Static("", id="settings-llm-body", markup=False)
        with Collapsible(title="Policy & output", collapsed=True, id="settings-section-policy"):
            yield Static("", id="settings-policy-body", markup=False)
        with Collapsible(title="Advanced YAML", collapsed=False, id="settings-section-yaml"):
            yield TextArea("", id="yaml-editor")
            yield Button("Save", id="settings-save")
            yield Static("", id="settings-status", markup=False)

    def on_mount(self) -> None:
        self._render_sections()
        try:
            raw = CONFIG_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            self._set_status(f"Not saved: cannot read config ({type(exc).__name__})")
            return
        try:
            parsed = load_yaml_config(CONFIG_PATH)
            masked, self.preserved_secret_placeholders = _mask_yaml_secrets(parsed)
            masked = _mask_url_credentials(masked, self.preserved_secret_placeholders)
            self.query_one("#yaml-editor", TextArea).text = (
                dump_yaml_config(masked) if masked != parsed else raw
            )
        except Exception as exc:
            try:
                self.query_one("#yaml-editor", TextArea).text = raw
            except Exception:
                pass
            self._set_status(f"Not saved: {_safe_config_error_text(exc)}")

    def _set_section(self, selector: str, lines: list[str]) -> None:
        try:
            self.query_one(selector, Static).update(str(redact_secrets("\n".join(lines)))[:4000])
        except Exception:
            pass

    def _render_sections(self) -> None:
        """Summarize the resolved config; credentials are never rendered."""
        try:
            cfg = load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={})
        except Exception as exc:
            self._set_section("#settings-target-body", [_safe_config_error_text(exc)])
            return
        runtime = getattr(cfg, "llm_runtime", None)
        roles = getattr(runtime, "roles", {}) or {}
        self._set_section("#settings-target-body", [
            f"target: {_safe_url(getattr(cfg, 'target_url', '—'))}",
            f"provider: {getattr(cfg, 'provider', '—')} · level: {getattr(cfg, 'level', '—')}",
            f"surface: {getattr(cfg, 'surface', '—')} · mode: {getattr(cfg, 'payload_mode', '—')}",
            f"condition: {getattr(cfg, 'experiment_condition', '—')} · "
            f"target method: {getattr(cfg, 'target_method', None) or '—'}",
        ])
        model_lines = [f"selected profile: {getattr(cfg, 'model_profile', None) or '—'}"]
        for name, model in (getattr(cfg, "models", {}) or {}).items():
            key_state = "set" if getattr(model, "api_key", "") else "—"
            model_lines.append(
                f"{name}: {getattr(model, 'model_name', '—') or '—'} · api key {key_state}"
            )
        self._set_section("#settings-model-body", model_lines or ["no model profiles configured"])
        llm_lines = [
            f"max concurrency: {getattr(runtime, 'max_concurrency', '—')} · "
            f"cache scope: {getattr(runtime, 'cache_scope', '—')}",
        ]
        for role, settings in roles.items():
            llm_lines.append(
                f"{role}: {getattr(settings, 'model_profile', None) or '—'} · "
                f"reasoning {getattr(settings, 'reasoning_effort', None) or '—'}"
            )
        self._set_section("#settings-llm-body", llm_lines)
        self._set_section("#settings-policy-body", [
            f"candidate budget: {getattr(cfg, 'candidate_budget', '—')} · "
            f"iterations: {getattr(cfg, 'iterations', '—')}",
            f"stop policy: {getattr(cfg, 'stop_policy', '—')} · "
            f"coverage target: {getattr(cfg, 'coverage_target', '—')}",
            f"output: {getattr(cfg, 'output_dir', '—')} · format: {getattr(cfg, 'report_format', '—')}",
            f"diagnostics: {getattr(cfg, 'diagnose', '—')} · "
            f"enriched reporting: {getattr(cfg, 'enriched_reporting', '—')}",
            # Labels are canonical guardrail vocabulary; the attribute names are
            # the ones the resolver actually produces on EngagementConfig.
            f"guardrail handling: {getattr(cfg, 'evasion_mode', '—')} · "
            f"guardrail retry: {getattr(cfg, 'evasion_enabled', '—')} · "
            f"max retries: {getattr(cfg, 'evasion_max_retries', '—')} · "
            f"cooldown: {getattr(cfg, 'evasion_cooldown_threshold', '—')}",
        ])

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#settings-status", Static).update(str(redact_secrets(text)))
        except Exception:
            pass

    @on(Button.Pressed, "#settings-save")
    def save_settings(self) -> None:
        self._settings_generation += 1
        try:
            text = self.query_one("#yaml-editor", TextArea).text
        except Exception as exc:
            self._set_status(f"Not saved: {type(exc).__name__}")
            return
        try:
            payload = parse_yaml_config(text)
        except Exception as exc:
            self._set_status(f"Not saved: invalid YAML ({_safe_config_error_text(exc)})")
            return
        if not isinstance(payload, dict):
            self._set_status("Not saved: config must be a mapping")
            return
        if _contains_literal_secret(payload):
            if not self.literal_warning_acknowledged:
                self.literal_warning_acknowledged = True
                self._set_status(
                    "Save again to confirm: literal secret detected. "
                    "Prefer an ENV_VAR placeholder such as ${GEMINI_KEY}."
                )
                return
        concurrency = payload.get("llm_max_concurrency", payload.get("llm-max-concurrency"))
        if concurrency not in (None, ""):
            try:
                if not 1 <= int(concurrency) <= 4:
                    raise ValueError(str(concurrency))
            except (TypeError, ValueError):
                self._set_status("Not saved: llm_max_concurrency must be between 1 and 4")
                return
        payload = _restore_yaml_secrets(payload, self.preserved_secret_placeholders)
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as temp:
                temp.write(dump_yaml_config(payload))
                temp_path = temp.name
            try:
                load_and_resolve_config(config_path=temp_path, cli_args={})
            finally:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            save_yaml_config(CONFIG_PATH, payload)
        except Exception as exc:
            self._set_status(f"Not saved: {_safe_config_error_text(exc)}")
            return
        try:
            masked, self.preserved_secret_placeholders = _mask_yaml_secrets(payload)
            masked = _mask_url_credentials(masked, self.preserved_secret_placeholders)
            self.query_one("#yaml-editor", TextArea).text = dump_yaml_config(masked)
        except Exception:
            pass
        self.literal_warning_acknowledged = False
        self._set_status("Saved config.")

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True
        self._settings_generation += 1


class CoordinateDrawer(BaseDrawer):
    """Live coordinate table: status/provider/surface/level/mode filtering and
    Enter-to-inspect, mirroring the values the mission surface shows."""

    FILTER_FIELDS: tuple[tuple[str, str], ...] = (
        ("filter-status", "status"), ("filter-provider", "provider"),
        ("filter-surface", "surface"), ("filter-level", "level"),
        ("filter-mode", "mode"),
    )

    def __init__(self) -> None:
        super().__init__()
        self._tesis_closing = False
        self._coordinate_generation = 0
        self._rows: dict[int, Any] = {}
        self._filters: dict[str, str] = {}
        self._populating = False

    def compose(self) -> ComposeResult:
        yield Label("Coordinates (Esc to close)", id="coordinates-title")
        with Horizontal(id="coordinates-filters", classes="filters"):
            yield Label("Filters", id="coordinates-filters-label")
            for select_id, attr in self.FILTER_FIELDS:
                yield Select([], prompt=attr, id=select_id, allow_blank=True)
        yield DataTable(id="coordinates-table")
        yield Static("Select a row and press Enter to inspect the coordinate",
                     id="coordinates-detail", markup=False)
        yield Static("Enter inspect · Esc back", id="coordinates-hint", markup=False)

    def on_mount(self) -> None:
        try:
            table = self.query_one("#coordinates-table", DataTable)
            table.cursor_type = "row"
            for key, label in (("index", "Index"), ("status", "Status"),
                               ("provider", "Provider"), ("surface", "Surface"),
                               ("level", "Level"), ("mode", "Mode"), ("method", "Method"),
                               ("findings", "Findings"), ("elapsed", "Elapsed")):
                table.add_column(label, key=key)
        except Exception:
            pass
        mission = next(
            (s for s in self.app.screen_stack if isinstance(s, MissionControlScreen)), None
        )
        self._rows = dict(getattr(getattr(mission, "state", None), "coordinates", {}) or {})
        self._populate_filter_options()
        self._render_table()
        _stack_filter_row(self, "#coordinates-filters")

    def on_resize(self, event: Any) -> None:
        _stack_filter_row(self, "#coordinates-filters")

    def _matches(self, row: Any) -> bool:
        for attr, expected in self._filters.items():
            if not expected:
                continue
            actual = str(getattr(row, attr, "") or "").casefold()
            if actual != expected.casefold():
                return False
        return True

    def _populate_filter_options(self) -> None:
        self._populating = True
        try:
            for select_id, attr in self.FILTER_FIELDS:
                try:
                    select = self.query_one(f"#{select_id}", Select)
                except Exception:
                    continue
                values = sorted({str(getattr(row, attr)) for row in self._rows.values()
                                 if getattr(row, attr) not in (None, "")})
                try:
                    select.set_options([(value, value) for value in values])
                except Exception:
                    pass
        finally:
            self._populating = False

    @on(Select.Changed)
    def filter_changed(self, event: Select.Changed) -> None:
        if self._populating:
            return
        attr = dict(self.FILTER_FIELDS).get(event.select.id or "")
        if attr is None:
            return
        self._filters[attr] = event.value if isinstance(event.value, str) else ""
        self._render_table()

    def _render_table(self) -> None:
        try:
            table = self.query_one("#coordinates-table", DataTable)
            table.clear()
            for index, row in sorted(self._rows.items()):
                if not self._matches(row):
                    continue
                table.add_row(
                    str(index),
                    _cell(row.status),
                    _cell(row.provider),
                    _cell(row.surface),
                    _cell(row.level),
                    _cell(row.mode),
                    _cell(row.selected_method or row.target_method),
                    str(row.finding_count),
                    _cell(getattr(row, "elapsed", None)),
                    key=str(index),
                )
        except Exception:
            pass

    @on(DataTable.RowSelected, "#coordinates-table")
    def inspect_row(self, event: DataTable.RowSelected) -> None:
        key = str(event.row_key.value) if event.row_key is not None else ""
        row = self._rows.get(int(key)) if key.isdigit() else None
        if row is None:
            return
        try:
            detail = (
                f"coordinate {key} · {_cell(row.status)}\n"
                f"provider={_cell(row.provider)} surface={_cell(row.surface)} "
                f"level={_cell(row.level)} mode={_cell(row.mode)}\n"
                f"method={_cell(row.selected_method or row.target_method)} "
                f"run={_cell(row.run_id)} elapsed={_cell(getattr(row, 'elapsed', None))}\n"
                f"findings={', '.join(str(v) for v in (row.confirmed_vulns or [])) or '—'}\n"
                f"outcomes={', '.join(str(v) for v in (row.achieved_outcomes or [])) or '—'}"
            )
            self.query_one("#coordinates-detail", Static).update(str(redact_secrets(detail))[:4000])
        except Exception:
            pass

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True
        self._coordinate_generation += 1


class EvidenceDrawer(BaseDrawer):
    """Redacted evidence summary; Enter expands the chosen finding/outcome/verifier."""

    def __init__(self) -> None:
        super().__init__()
        self._tesis_closing = False
        self._evidence_generation = 0
        self._records: list[tuple[str, list[str]]] = []

    def compose(self) -> ComposeResult:
        yield Label("Evidence (Esc to close)", id="evidence-title")
        yield Static("loading…", id="evidence-body", markup=False)
        yield DataTable(id="evidence-records")
        yield Static("Select a record and press Enter to expand it", id="evidence-detail", markup=False)

    def on_mount(self) -> None:
        mission = next(
            (s for s in self.app.screen_stack if isinstance(s, MissionControlScreen)), None
        )
        state = getattr(mission, "state", None)
        try:
            table = self.query_one("#evidence-records", DataTable)
            table.cursor_type = "row"
            table.add_columns("Record", "Summary")
        except Exception:
            pass
        if state is None:
            self._update_static("#evidence-body", "Evidence\nno run yet")
            return
        findings = [str(redact_secrets(v))[:200] for v in (getattr(state, "confirmed_vulns", []) or [])]
        outcomes = [str(redact_secrets(v))[:200] for v in (getattr(state, "achieved_outcomes", []) or [])]
        method = str(getattr(state, "selected_method", None) or "—")
        verifier = str(redact_secrets(getattr(state, "verifier_decision", None) or "—"))[:300]
        self._update_static(
            "#evidence-body",
            "Evidence\n"
            f"method={method}\n"
            f"findings={len(findings)} outcomes={len(outcomes)}\n"
            f"verifier={verifier}\n"
            f"guardrails={getattr(state, 'guardrail_count', 0)} "
            f"containment={getattr(state, 'containment_count', 0)} "
            f"fallbacks={getattr(state, 'fallback_count', 0)}",
        )
        records: list[tuple[str, list[str]]] = [
            ("verifier", [f"method: {method}", f"verifier decision: {verifier}"]),
        ]
        records.extend(("finding", [f"confirmed vulnerability: {value}"]) for value in findings)
        records.extend(("outcome", [f"achieved outcome: {value}"]) for value in outcomes)
        self._records = records
        try:
            table = self.query_one("#evidence-records", DataTable)
            table.clear()
            for index, (kind, lines) in enumerate(records):
                table.add_row(kind, lines[0][:80], key=str(index))
        except Exception:
            pass

    def _update_static(self, selector: str, text: str) -> None:
        try:
            self.query_one(selector, Static).update(str(redact_secrets(text))[:8000])
        except Exception:
            pass

    @on(DataTable.RowSelected, "#evidence-records")
    def inspect_row(self, event: DataTable.RowSelected) -> None:
        key = str(event.row_key.value) if event.row_key is not None else ""
        try:
            _, lines = self._records[int(key)]
        except (ValueError, IndexError):
            return
        self._update_static("#evidence-detail", "Evidence detail\n" + "\n".join(lines))

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True
        self._evidence_generation += 1


class FailureDrawer(BaseDrawer):
    """Redacted failure summary; remediation leads and Enter expands a record."""

    def __init__(self, failure: Any = None) -> None:
        super().__init__()
        # Accepts the production slotted FailureSummary dataclass as well as
        # plain mappings; fields are normalized then redacted exactly once.
        self.failure: dict[str, Any] = _redact_mapping(_failure_mapping(failure))
        self._tesis_closing = False
        self._failure_generation = 0
        self._records: list[tuple[str, list[str]]] = []

    def _record_lines(self) -> list[str]:
        order = ("failure_class", "provider", "request_id", "endpoint", "message", "error", "remediation")
        lines = []
        for key in order:
            if key in self.failure and self.failure[key] not in (None, ""):
                lines.append(f"{key.replace('_', ' ')}: {self.failure[key]}")
        for key in sorted(self.failure):
            if key not in order:
                lines.append(f"{key}: {self.failure[key]}")
        return lines

    def compose(self) -> ComposeResult:
        remediation = str(self.failure.get("remediation") or "Check the provider profile and retry.")
        failure_class = str(self.failure.get("failure_class") or "unknown")
        provider = str(self.failure.get("provider") or "—")
        request_id = str(self.failure.get("request_id") or "—")
        endpoint = str(self.failure.get("endpoint") or "—")
        message = str(self.failure.get("message") or self.failure.get("error") or "—")
        yield Label("Failure (Esc to close)", id="failure-title")
        yield Static(
            f"Remediation: {remediation}\n"
            f"failure class: {failure_class}\n"
            f"provider: {provider}\n"
            f"request id: {request_id}\n"
            f"endpoint: {endpoint}\n"
            f"message: {message}",
            id="failure-body", markup=False,
        )
        yield DataTable(id="failure-records")
        yield Static("Select a record and press Enter to expand it", id="failure-detail", markup=False)

    def on_mount(self) -> None:
        try:
            table = self.query_one("#failure-records", DataTable)
            table.cursor_type = "row"
            table.add_columns("Field", "Value")
        except Exception:
            pass
        self._records = []
        for key in ("failure_class", "provider", "request_id", "endpoint", "message", "remediation"):
            value = self.failure.get(key)
            if value in (None, ""):
                continue
            self._records.append((key.replace("_", " "), [f"{key}: {value}"]))
        try:
            table = self.query_one("#failure-records", DataTable)
            table.clear()
            for index, (label, lines) in enumerate(self._records):
                table.add_row(label, lines[0][:80], key=str(index))
        except Exception:
            pass

    @on(DataTable.RowSelected, "#failure-records")
    def inspect_row(self, event: DataTable.RowSelected) -> None:
        lines = self._record_lines()
        try:
            self.query_one("#failure-detail", Static).update(
                "Failure detail\n" + "\n".join(lines)
            )
        except Exception:
            pass

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True
        self._failure_generation += 1


class TraceDrawer(BaseDrawer):
    # Paused on open: history holds position; ``f``/End resumes auto-follow.
    BINDINGS = [*BaseDrawer.BINDINGS, Binding("f", "toggle_follow", "Follow", show=True),
                Binding("end", "toggle_follow", "Follow", show=False)]

    def __init__(self) -> None:
        super().__init__()
        self._tesis_closing = False
        self._trace_generation = 0
        self._mission: MissionControlScreen | None = None
        self._following = False
        self._seen = 0

    def compose(self) -> ComposeResult:
        yield Label("Trace — bounded redacted stream (Esc to close)", id="trace-title")
        yield Static("new events: 0", id="trace-new-badge", markup=False, classes="trace-new-badge")
        yield Static("loading…", id="trace-body", markup=False)

    def on_mount(self) -> None:
        self._mission = next(
            (s for s in self.app.screen_stack if isinstance(s, MissionControlScreen)), None
        )
        register = getattr(self._mission, "add_drawer_observer", None)
        if callable(register):
            register(self.refresh_trace)
        self._seen = len(self._entries())
        self._render_trace()
        self._set_badge(0)

    def _entries(self) -> list[str]:
        state = getattr(self._mission, "state", None)
        raw = list(getattr(state, "notices", []) or [])
        return [str(redact_secrets(str(entry)))[:200] for entry in raw][-TRACE_MAX_ENTRIES:]

    def refresh_trace(self) -> None:
        """Called by the mission screen after each drained event batch."""
        if self._tesis_closing:
            return
        count = len(self._entries())
        new = max(0, count - self._seen)
        if self._following:
            self._seen = count
            self._render_trace()
        self._set_badge(new)

    def _render_trace(self) -> None:
        entries = self._entries()
        body = "\n".join(entries) if entries else "no events yet"
        try:
            self.query_one("#trace-body", Static).update(body[:20000])
        except Exception:
            pass

    def _set_badge(self, count: int) -> None:
        text = f"{count} new" if count else ("following" if self._following else "paused")
        try:
            self.query_one("#trace-new-badge", Static).update(text)
        except Exception:
            pass

    def action_toggle_follow(self) -> None:
        self._following = not self._following
        if self._following:
            self._seen = len(self._entries())
            self._render_trace()
        self._set_badge(0)

    def on_unmount(self) -> None:
        self.prepare_shutdown()

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True
        self._trace_generation += 1
        remove = getattr(self._mission, "remove_drawer_observer", None)
        if callable(remove):
            try:
                remove(self.refresh_trace)
            except Exception:
                pass


_TRIAGE_SCORE_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("method", ("method_score",)),
    ("exploitation", ("exploitation_score", "exploitation")),
    ("chain", ("chain_score", "chain")),
    ("output", ("output_score", "output")),
    ("composite", ("composite_score", "composite")),
)


def _nested_scores(raw: dict) -> dict:
    scores = raw.get("scores")
    return scores if isinstance(scores, dict) else {}


def _score_text(raw: dict, *keys: str) -> str:
    """Return the first present score or ``—``; values are never synthesized."""
    nested = _nested_scores(raw)
    for key in keys:
        for source in (raw, nested):
            value = source.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                return str(value)
            if isinstance(value, str) and value.strip():
                return value.strip()[:80]
    return "—"


def _joined(values: Any) -> str:
    if isinstance(values, (list, tuple, set)):
        items = [str(redact_secrets(str(value)))[:80] for value in values]
        return ", ".join(items)[:200] if items else "—"
    return "—"


def _count_text(raw: dict, *keys: str) -> str:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, (list, tuple, set)):
            return str(len(value))
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
    return "—"


def _payload_text(raw: dict) -> str:
    scores = raw.get("payload_scores")
    if not isinstance(scores, dict) or not scores:
        return "—"
    return ", ".join(f"{key}={value}" for key, value in list(scores.items())[:6])[:200]


_STACKED_FILTER_WIDTH = 90


def _stack_filter_row(drawer: Any, row_id: str) -> None:
    """Stack the filter row when the surface it renders in is too narrow.

    A docked drawer is a 76-cell panel inside a full-size screen, so the screen
    width is the wrong measure: the panel is what the selects have to fit in.
    The panel is used whenever it has been laid out, otherwise the drawer width
    stands in.
    """
    width = 0
    try:
        panel = drawer.query_one(".drawer")
        if panel.size.width:
            width = int(panel.size.width)
    except Exception:
        pass
    if not width:
        try:
            width = int(drawer.size.width)
        except Exception:
            return
    try:
        drawer.query_one(row_id).set_class(width < _STACKED_FILTER_WIDTH, "stacked")
    except Exception:
        pass


class ResultsDrawer(BaseDrawer):
    """Triage-only view over saved artifacts.

    Scans lazily (``retain_raw=False``); Enter loads exactly one artifact and
    renders redacted triage fields. Missing score values render as ``—`` and
    are never synthesized. Deep JSON, AKG graphs, charts, and run comparison
    stay in the web companion.
    """

    FILTER_FIELDS: tuple[tuple[str, str], ...] = (
        ("filter-status", "status"), ("filter-provider", "provider"),
        ("filter-surface", "surface"), ("filter-level", "security_level"),
        ("filter-mode", "payload_mode"),
    )

    def __init__(self) -> None:
        super().__init__()
        self._scan_generation = 0
        self._tesis_closing = False
        self._scan_thread: Thread | None = None
        self._items: list = []
        self._closing_guard = False
        self._filters: dict[str, str] = {}
        self._populating = False

    def compose(self) -> ComposeResult:
        yield Label("Results (Esc to close)", id="results-title")
        yield Static("—", id="results-summary", markup=False)
        with Horizontal(id="results-filters", classes="filters"):
            yield Label("Filters", id="results-filters-label")
            for select_id, _ in self.FILTER_FIELDS:
                yield Select([], prompt=select_id.removeprefix("filter-"), id=select_id,
                             allow_blank=True)
        yield DataTable(id="results-table")
        yield Static("Select a row and press Enter for triage detail", id="results-detail", markup=False)
        yield Button("Export JSON", id="results-export")
        yield Static("", id="results-status", markup=False)

    def on_mount(self) -> None:
        try:
            table = self.query_one("#results-table", DataTable)
            # A docked drawer gives this table roughly 70 cells, so the summary
            # keeps only what is readable there: identity, outcome, provider and
            # level. Surface and payload mode stay one keystroke away in the five
            # filters above, and every field remains in the Enter detail view.
            for key, label, width in (("run", "Run", 20), ("status", "Status", 9),
                                      ("provider", "Provider", 18), ("level", "Level", 6)):
                table.add_column(label, key=key, width=width)
        except Exception:
            pass
        self.refresh_scan()
        _stack_filter_row(self, "#results-filters")

    def on_resize(self, event: Any) -> None:
        _stack_filter_row(self, "#results-filters")

    def _output_dir(self) -> Path:
        try:
            cfg = load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={})
            return Path(cfg.output_dir)
        except Exception:
            return REPOSITORY_ROOT / "results"

    def refresh_scan(self) -> None:
        self._scan_generation += 1
        generation = self._scan_generation
        output_dir = self._output_dir()
        self._scan_thread = Thread(
            target=self._scan_rows, args=(generation, output_dir),
            name="tesis-result-scan", daemon=True,
        )
        self._scan_thread.start()

    def _scan_rows(self, generation: int, output_dir: Path) -> None:
        try:
            items = ArtifactRepository(output_dir).scan(retain_raw=False)
            error: str | None = None
        except Exception as exc:
            items, error = [], f"{type(exc).__name__}: {exc}"
        if self._tesis_closing or generation != self._scan_generation:
            return
        try:
            self.app.call_from_thread(self._render_scan, generation, items, error)
        except Exception:
            pass

    def _render_scan(self, generation: int, items: list, error: str | None) -> None:
        if self._tesis_closing or generation != self._scan_generation:
            return
        self._items = list(items)
        self._populate_filter_options()
        self._render_table()
        if error:
            self._set_status(str(redact_secrets(error))[:300])

    @staticmethod
    def _cell(item: Any, *attrs: str) -> str:
        for attr in attrs:
            value = getattr(item, attr, None)
            if value not in (None, ""):
                return str(value)[:80]
        return "—"

    def _visible_items(self) -> list:
        active = {key: value for key, value in self._filters.items() if value}
        if not active:
            return list(self._items)
        try:
            return list(ArtifactRepository(self._output_dir()).filter(self._items, **active))
        except Exception:
            return list(self._items)

    def _populate_filter_options(self) -> None:
        self._populating = True
        try:
            for select_id, attr in self.FILTER_FIELDS:
                try:
                    select = self.query_one(f"#{select_id}", Select)
                except Exception:
                    continue
                values = sorted({str(getattr(item, attr)) for item in self._items
                                 if getattr(item, attr) not in (None, "")})
                try:
                    select.set_options([(value, value) for value in values])
                except Exception:
                    pass
        finally:
            self._populating = False

    @on(Select.Changed)
    def filter_changed(self, event: Select.Changed) -> None:
        if self._populating:
            return
        attr = dict(self.FILTER_FIELDS).get(event.select.id or "")
        if attr is None:
            return
        self._filters[attr] = event.value if isinstance(event.value, str) else ""
        self._render_table()

    def _render_table(self) -> None:
        visible = self._visible_items()
        try:
            table = self.query_one("#results-table", DataTable)
            table.clear()
            for item in visible[:500]:
                table.add_row(
                    self._cell(item, "run_id", "execution_id"),
                    self._cell(item, "status"),
                    self._cell(item, "provider"),
                    self._cell(item, "security_level"),
                    key=str(getattr(item, "path", "") or id(item)),
                )
            summary = (
                f"{len(visible)}/{len(self._items)} artifacts match filters — scores missing render as —"
                if len(visible) != len(self._items)
                else f"{len(self._items)} artifacts — scores missing render as —"
            )
            self.query_one("#results-summary", Static).update(summary)
        except Exception:
            pass

    @on(DataTable.RowSelected, "#results-table")
    def inspect_row(self, event: DataTable.RowSelected) -> None:
        self._show_detail(str(event.row_key.value) if event.row_key is not None else "")

    def _find_item(self, key: str) -> Any:
        for item in self._items:
            candidates = {str(getattr(item, attr, "") or "") for attr in
                          ("run_id", "execution_id", "identifier", "path")}
            if key in candidates:
                return item
        return self._items[0] if self._items else None

    def _load_artifact(self, item: Any) -> dict:
        try:
            payload = json.loads(Path(str(getattr(item, "path", "") or "")).read_text(encoding="utf-8"))
        except Exception:
            return {}
        return payload if isinstance(payload, dict) else {}

    def _same_config_count(self, item: Any) -> int:
        fingerprint = getattr(item, "config_fingerprint", None)
        if not fingerprint:
            return 0
        return sum(
            1 for other in self._items
            if other is not item and getattr(other, "config_fingerprint", None) == fingerprint
        )

    def _triage_fields(self, item: Any) -> list[tuple[str, str]]:
        """Redacted, triage-only fields for one artifact; never raw payloads."""
        raw = self._load_artifact(item)
        cfg = raw.get("config") if isinstance(raw.get("config"), dict) else {}
        failure = raw.get("failure") if isinstance(raw.get("failure"), dict) else {}

        def first(*keys: str) -> Any:
            for key in keys:
                for source in (raw, cfg):
                    value = source.get(key)
                    if value not in (None, "", [], {}):
                        return value
            return None

        def safe(value: Any) -> str:
            if value in (None, "", [], {}):
                return "—"
            return str(redact_secrets(value))[:300]

        failure_text = safe(
            failure.get("message") or failure.get("error") or raw.get("error")
            or raw.get("failure_class") or failure.get("failure_class")
        )
        fields: list[tuple[str, Any]] = [
            ("run", self._cell(item, "run_id", "execution_id")),
            ("status", first("status", "task_result")),
            ("provider / model", f"{safe(first('provider'))} / {safe(first('model'))}"),
            ("surface / level / mode",
             f"{safe(first('surface'))} / {safe(first('security_level', 'level'))} / "
             f"{safe(first('payload_mode'))}"),
            ("condition / target method / repeat",
             f"{safe(first('experiment_condition'))} / {safe(first('target_method'))} / "
             f"{safe(first('repeat_index'))}"),
            ("selected / viable method",
             f"{safe(first('selected_method'))} / {_joined(raw.get('viable_methods'))}"),
            ("method score", _score_text(raw, "method_score")),
            ("payload scores", _payload_text(raw)),
            ("exploitation / chain / output / composite",
             " / ".join(_score_text(raw, *keys)
                        for name, keys in _TRIAGE_SCORE_FIELDS if name != "method")),
            ("confirmed vulns / outcomes",
             f"{_joined(raw.get('confirmed_vulns'))} / {_joined(raw.get('achieved_outcomes'))}"),
            ("verifier decision", first("verifier_decision")),
            ("safety guardrail / containment / fallback",
             f"{_count_text(raw, 'guardrail_activation_count', 'guardrail_activations')} / "
             f"{_count_text(raw, 'containment_events')} / {_count_text(raw, 'fallback_events')}"),
            ("failure", failure_text),
            ("same-config executions", str(self._same_config_count(item))),
            ("artifact", str(getattr(item, "path", "") or "")),
            ("export", "Export JSON writes this triage summary; deep JSON/graphs stay in the web app"),
        ]
        return [(label, safe(value)) for label, value in fields]

    def _show_detail(self, key: str) -> None:
        item = self._find_item(key)
        if item is None:
            return
        text = "\n".join(f"{label}: {value}" for label, value in self._triage_fields(item))
        limit = int(DETAIL_RENDER_MAX_CHARS)
        body = text[:limit]
        max_lines = int(DETAIL_LOG_MAX_LINES)
        if len(body) != len(text) or len(body.splitlines()) > max_lines:
            body = "\n".join(body.splitlines()[:max_lines])
            body += (
                "\n— truncated: only triage fields are shown; deep JSON, graphs, and charts "
                "live in the web app —"
            )
        try:
            self.query_one("#results-detail", Static).update(body[:20000])
        except Exception:
            pass

    @on(Button.Pressed, "#results-export")
    def export_triage(self) -> None:
        records = []
        for item in self._visible_items():
            record = {"artifactId": self._cell(item, "run_id", "execution_id")}
            record.update({label: value for label, value in self._triage_fields(item)})
            records.append(record)
        try:
            path = self._output_dir() / "tui-results-export.json"
            path.write_text(json.dumps(records, indent=2, default=str), encoding="utf-8")
        except Exception as exc:
            self._set_status(f"Export failed: {type(exc).__name__}: {exc}")
            return
        self._set_status(f"Exported {len(records)} triage records → {path}")

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#results-status", Static).update(str(redact_secrets(text))[:300])
        except Exception:
            pass

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True
        self._closing_guard = True
        self._scan_generation += 1


class DoctorDrawer(BaseDrawer):
    def __init__(self) -> None:
        super().__init__()
        self._doctor_generation = 0
        self._tesis_closing = False
        self._closing_guard = False
        self._live_armed = False
        self._doctor_thread: Thread | None = None

    def compose(self) -> ComposeResult:
        yield Label("Doctor (Esc to close)", id="doctor-title")
        yield Static("Doctor checks — offline by default", id="doctor-summary", markup=False)
        yield Static("press R to run offline checks", id="doctor-results", markup=False)
        with Vertical(id="doctor-actions"):
            yield Button("Run offline checks", id="doctor-run")
            yield Button("Live checks (needs confirmation)", id="doctor-live")

    def on_mount(self) -> None:
        # Offline checks run on a daemon thread: opening Doctor must never block
        # the event loop. Results return through app.call_from_thread.
        self.run_offline_pressed()

    def on_unmount(self) -> None:
        self.prepare_shutdown()

    def _config(self) -> Any:
        return load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={})

    def _start_checks(self, live: bool) -> None:
        """Queue offline/live Doctor checks on one daemon worker."""
        self._doctor_generation += 1
        generation = self._doctor_generation
        self._doctor_thread = Thread(
            target=self._run_checks, args=(generation, live),
            name="tesis-doctor", daemon=True)
        self._doctor_thread.start()

    def _run_checks(self, generation: int, live: bool) -> None:
        """Worker thread: no widget access; rendering hops back via the app."""
        try:
            cfg = self._config()
            from tesis.doctor import run_doctor
            result = run_doctor(cfg, live=live)
        except Exception as exc:
            result = {"checks": [], "summary": {}, "error": _safe_config_error_text(exc)}
        if self._tesis_closing or generation != self._doctor_generation:
            return
        try:
            self.app.call_from_thread(self._render_result, result)
        except Exception:
            pass

    def _render_text(self, text: str) -> None:
        for selector in ("#doctor-results", "#doctor-summary"):
            try:
                self.query_one(selector, Static).update(str(redact_secrets(text))[:8000])
                return
            except Exception:
                continue

    def _render_result(self, result: Any) -> None:
        if not isinstance(result, dict):
            self._render_text(f"Doctor\n{redact_secrets(result)}")
            return
        checks = result.get("checks", []) if isinstance(result.get("checks"), list) else []
        lines = ["Doctor"]
        for check in checks:
            if not isinstance(check, dict):
                continue
            mark = {"passed": "✓", "failed": "×", "skipped": "○"}.get(
                str(check.get("status", "")), "•")
            lines.append(f"{mark} {check.get('category', '')}/{check.get('id', '')} "
                         f"{check.get('summary', '')}")
            details = str(check.get("details") or "").strip()
            if details:
                lines.append(f"  {details}"[:300])
            remediation = str(check.get("remediation") or "").strip()
            if remediation:
                lines.append(f"  Remediation: {remediation}"[:300])
        summary = result.get("summary", {})
        if isinstance(summary, dict):
            lines.append(f"Doctor summary: {summary.get('passed', 0)} passed, "
                         f"{summary.get('failed', 0)} failed, {summary.get('skipped', 0)} skipped")
        self._render_text("\n".join(lines))

    @on(Button.Pressed, "#doctor-run")
    def run_offline_pressed(self) -> None:
        self._live_armed = False
        self._start_checks(live=False)

    @on(Button.Pressed, "#doctor-live")
    def run_live_pressed(self) -> None:
        if not self._live_armed:
            self._live_armed = True
            self._render_text("Doctor\nLive checks hit the network. Press again to confirm.")
            return
        self._live_armed = False
        self._start_checks(live=True)

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True
        self._closing_guard = True
        self._doctor_generation += 1


class PlanDrawer(BaseDrawer):
    def __init__(self, config: Any = None) -> None:
        super().__init__()
        self.config = config
        self._tesis_closing = False
        self._plan_generation = 0

    def compose(self) -> ComposeResult:
        yield Label("Plan (Esc to close)", id="plan-title")
        with VerticalScroll(id="plan-scroll"):
            yield Static("loading…", id="plan-body", markup=False)

    def on_mount(self) -> None:
        cfg = self.config
        if cfg is None:
            try:
                cfg = load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={})
            except Exception as exc:
                self._set(f"config error        {_safe_config_error_text(exc)}")
                return
        try:
            fingerprint = config_fingerprint({
                "target_url": getattr(cfg, "target_url", ""),
                "provider": getattr(cfg, "provider", ""),
                "level": getattr(cfg, "level", ""),
            })
        except Exception:
            fingerprint = "—"
        rows = [
            ("target", _safe_url(getattr(cfg, "target_url", "—"))),
            ("provider", getattr(cfg, "provider", "—")),
            ("level", getattr(cfg, "level", "—")),
            ("surface", getattr(cfg, "surface", "—")),
            ("payload mode", getattr(cfg, "payload_mode", "—")),
            ("condition", getattr(cfg, "experiment_condition", "—")),
            ("target method", getattr(cfg, "target_method", None) or "—"),
            ("coordinates", _matrix_coordinate_count(cfg)),
            ("candidate budget", getattr(cfg, "candidate_budget", "—")),
            ("iterations", getattr(cfg, "iterations", "—")),
            ("output dir", getattr(cfg, "output_dir", "—")),
            ("models", getattr(cfg, "models", "—")),
            ("fingerprint", fingerprint),
        ]
        self._set("\n".join(f"{label:<18}{value}" for label, value in rows))

    def _set(self, text: str) -> None:
        try:
            self.query_one("#plan-body", Static).update(str(redact_secrets(text))[:8000])
        except Exception:
            pass

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True
        self._plan_generation += 1


class HelpDrawer(BaseDrawer):
    #: Help is one of the only two actions a too-small terminal still offers,
    #: so unlike every other drawer it stays open below the floor.
    ALLOW_BELOW_FLOOR = True

    def compose(self) -> ComposeResult:
        yield Label("Help (Esc to close)", id="help-title")
        with VerticalScroll(id="help-scroll"):
            yield Static("", id="help-body")

    def on_mount(self) -> None:
        rows = [
            f"{'NAVIGATION':<12}{navigation_hint()}",
            "",
            f"{'COMMAND':<12}{'KEYS':<10}SUMMARY",
        ]
        rows.extend(f"{'/' + spec.name:<12}{(spec.keys or '—'):<10}{spec.summary}" for spec in COMMANDS)
        try:
            self.query_one("#help-body", Static).update(str(redact_secrets("\n".join(rows)))[:8000])
        except Exception:
            pass


class AboutDrawer(BaseDrawer):
    def compose(self) -> ComposeResult:
        yield Label("About (Esc to close)", id="about-title")
        with VerticalScroll(id="about-scroll"):
            yield Static("", id="about-body")

    def on_mount(self) -> None:
        rows = [
            ("harness", "TESIS experiment harness — mission-control TUI"),
            ("purpose", "Configure/start, observe, inspect/export, cancel"),
            ("runs", "a started run is immutable"),
            ("scope", "authorized DVWA only; containment and redaction always on"),
            ("floor", "supported interactive size is 60x18"),
            ("companion", "deep JSON, AKG graphs, charts, and comparison live in the web app"),
        ]
        try:
            self.query_one("#about-body", Static).update(
                "\n".join(f"{label:<12}{text}" for label, text in rows)
            )
        except Exception:
            pass


# ---------------------------------------------------------------- mission control screen

_STAGE_GLYPH = {"queued": "○", "running": "●", "succeeded": "✓", "warning": "!", "failed": "×"}

_STATUS_GLYPH = {"ready": "○", "running": "●", "succeeded": "✓",
                 "degraded": "!", "failed": "×", "cancelled": "!"}

_RUN_STATUSES = ("ready", "running", "degraded", "succeeded", "failed", "cancelled")

_TOO_SMALL_FOOTER = "? help · q quit"

# Footer hints are contextual: idle advertises the start actions, an active run
# advertises inspection/navigation and cancellation. Both sets name registry
# commands and NAVIGATION_KEYS entries, so the footer can never advertise a key
# nothing binds; narrower terminals take the compact set instead of clipping.
_FOOTER_IDLE_CORE = ("run", "matrix")
_FOOTER_IDLE_EXTRA = ("plan", "doctor")
_FOOTER_IDLE_TAIL = ("help", "quit")
_FOOTER_IDLE_NAV = ("/",)
_FOOTER_ACTIVE_TAIL = ("cancel", "help")
_FOOTER_ACTIVE_NAV = ("1", "2", "3", "Tab/Shift+Tab", "Enter", "/")
_FOOTER_ACTIVE_NAV_COMPACT = ("Enter", "/")

# Concise pipeline labels for the narrow (60-79 column) layout, where the full
# canonical stage names plus detail no longer fit one row.
_NARROW_STAGE_LABELS = {
    "payload_candidate_builder": "candidates",
    "payload_validator": "validation",
    "chaining_router": "chain router",
}


def _cell(value: Any, fallback: str = "—") -> str:
    """One table cell: missing values stay visibly missing, never zero-filled."""
    text = "" if value is None else str(value).strip()
    return text[:40] if text else fallback


def _clip(value: Any, limit: int) -> str:
    """Single-row display value with an explicit ellipsis, never a silent cut."""
    text = "" if value is None else str(value).strip()
    if limit < 1:
        return ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _command_hints(names: tuple[str, ...]) -> list[str]:
    """Registry-derived ``key command`` hints; unbound commands contribute none."""
    return [
        f"{_COMMAND_INDEX[name].keys} {name}"
        for name in names
        if name in _COMMAND_INDEX and _COMMAND_INDEX[name].keys
    ]


def _nav_hint(keys: tuple[str, ...]) -> str:
    """Navigation hints for ``keys``, from the one NAVIGATION_KEYS list."""
    return " · ".join(f"{key} {label}" for key, label in NAVIGATION_KEYS if key in keys)


def _target_host(url: str) -> str:
    try:
        return str(urlsplit(url).hostname or "")
    except Exception:
        return ""


class MissionPane(Static):
    """A mission-control pane body that can hold keyboard focus.

    In the wide layout `1`/`2`/`3` and Tab/Shift+Tab move focus between the
    pipeline, coordinate, and evidence panes, so each pane body must be a
    focus target in its own right.
    """

    can_focus = True


class NoticeBody(VerticalScroll):
    """Scrollable, focusable notice body that reports scroll-position changes.

    ``scroll_y`` is reactive, so this one watcher covers wheel, keyboard, and
    programmatic scrolling; the screen turns the position into paused
    auto-follow. The body never takes focus on its own.
    """

    def __init__(self, on_scroll: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._on_scroll = on_scroll

    def watch_scroll_y(self, old_value: float, new_value: float) -> None:
        if self._on_scroll is not None:
            self._on_scroll()


class MissionControlScreen(Screen):
    BINDINGS = [
        # show=True bindings are rendered verbatim in the footer hint, so the
        # advertised keys are the keys this screen actually binds.
        Binding("1", "show_pipeline", "Pipeline", show=True),
        Binding("2", "show_coordinates", "Coordinates", show=True),
        Binding("3", "show_evidence", "Evidence", show=True),
        Binding("enter", "inspect", "Inspect", show=True, key_display="Enter"),
        Binding("/", "open_launcher", "Command", show=True),
        Binding("question_mark", "open_help", "Help", show=True, key_display="?"),
        Binding("ctrl+c", "cancel_or_exit", "Cancel", show=True, priority=True,
                key_display="Ctrl+C"),
        Binding("q", "quit_if_idle", "Quit", show=True),
        Binding("r", "launch_single", "Run", show=False),
        Binding("m", "launch_matrix", "Matrix", show=False),
        Binding("p", "open_plan", "Plan", show=False),
        Binding("d", "open_doctor", "Doctor", show=False),
        Binding(":", "open_launcher", "Command", show=False),
        Binding("ctrl+p", "open_launcher", "Palette", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.state = TuiRunState()
        self.cancel_token = CancellationToken()
        self._runtime_thread: Thread | None = None
        self._run_active = False
        self._cancel_requested = False
        self._event_queue: deque[RunEvent] = deque(maxlen=UI_PENDING_EVENT_MAX)
        self._event_lock = Lock()
        self._pending_dropped = 0
        self._tesis_closing = False
        self._journal_path: Path | None = None
        self._descriptor_active = False
        self._drawer_observers: list = []
        # Notice auto-follow: following the bottom, else paused with a count of
        # events the operator has not scrolled to yet.
        self._notice_following = True
        self._notice_new = 0
        self._notice_seen_version = 0

    @property
    def run_active(self) -> bool:
        return self._run_active

    # -- layout -----------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static("TESIS", id="context-bar")
        with Vertical(id="mission-body"):
            yield MissionPane("", id="pipeline-pane")
            yield DataTable(id="coordinate-pane")
            with Vertical(id="notice-pane"):
                yield Static("", id="notice-new-badge", markup=False, classes="notice-new-badge")
                with NoticeBody(self._notice_scroll_changed, id="notice-body"):
                    yield Static("", id="notice-text", markup=False)
            with Vertical(id="evidence-pane"):
                yield Static("", id="evidence-badge", classes="evidence-badge")
                yield MissionPane("", id="evidence-body")
        yield Static("", id="triage-line")
        yield Static("", id="size-notice")
        with Horizontal(id="status-strip"):
            yield Static("", id="status-rail")
            yield Static("", id="status-label")
        yield Static(self._footer_text(), id="context-footer")

    def _footer_text(self) -> str:
        """Contextual footer: start actions while idle, inspect/cancel while active.

        Every hint comes from its single source (``COMMANDS`` for command keys,
        ``NAVIGATION_KEYS`` for navigation), so the footer can never advertise a
        key nothing binds. The idle set fits from 80 columns, so it only drops to
        the compact set below that; the active set keeps its pane/navigation keys
        plus ``/ command``, cancel, and help, and only compact below 120 columns.
        """
        width, height = self._dims()
        if width < FLOOR_WIDTH or height < FLOOR_HEIGHT:
            # Below the floor only quit/help stay reachable.
            return _TOO_SMALL_FOOTER
        active = self._run_active or self.state.status in ("running", "degraded")
        if active:
            nav = _FOOTER_ACTIVE_NAV if width >= 120 else _FOOTER_ACTIVE_NAV_COMPACT
            hints = [_nav_hint(nav), *_command_hints(_FOOTER_ACTIVE_TAIL)]
            return " · ".join(hints)
        start = _FOOTER_IDLE_CORE if width < 80 else _FOOTER_IDLE_CORE + _FOOTER_IDLE_EXTRA
        hints = [
            *_command_hints(start),
            _nav_hint(_FOOTER_IDLE_NAV),
            *_command_hints(_FOOTER_IDLE_TAIL),
        ]
        return " · ".join(hints)

    def on_mount(self) -> None:
        try:
            table = self.query_one("#coordinate-pane", DataTable)
            table.add_columns("#", "status", "provider", "surface", "level",
                              "mode", "method", "findings", "elapsed")
            # Row cursor: Enter inspects a whole coordinate, never a single cell.
            table.cursor_type = "row"
        except Exception:
            pass
        self._update_responsive_layout()
        self._restore_default_focus()

    def on_resize(self, event: Any) -> None:
        try:
            self._update_responsive_layout()
        except Exception:
            pass

    def on_screen_resume(self) -> None:
        # Returning from the launcher or a drawer must land on a live surface,
        # never on a dead widget. Already-focused widgets are left alone.
        self._restore_default_focus()

    def _restore_default_focus(self) -> None:
        try:
            if self.app.focused is not None:
                return
            table = self.query_one("#coordinate-pane", DataTable)
            if table.display and table.can_focus:
                table.focus()
        except Exception:
            pass

    def _dims(self) -> tuple[int, int]:
        try:
            size = self.size
            return int(size.width), int(size.height)
        except Exception:
            return (120, 36)

    def _update_responsive_layout(self) -> None:
        """Apply exactly one size class and the matching pane visibility."""
        width, height = self._dims()
        if width < 60 or height < 18:
            mode = "too-small"
        elif width >= 120 and height >= 24:
            mode = "wide"
        elif width >= 80 and height >= 20:
            mode = "standard"
        else:
            mode = "narrow"
        for name in ("wide", "standard", "narrow", "too-small"):
            self.set_class(mode == name, name)
        try:
            body = self.query_one("#mission-body", Vertical)
            strip = self.query_one("#status-strip", Horizontal)
            notice = self.query_one("#size-notice", Static)
            footer = self.query_one("#context-footer", Static)
            pipeline = self.query_one("#pipeline-pane", Static)
            coordinates = self.query_one("#coordinate-pane", DataTable)
            evidence = self.query_one("#evidence-pane", Vertical)
            notices = self.query_one("#notice-pane", Vertical)
            triage = self.query_one("#triage-line", Static)
        except Exception:
            return
        too_small = mode == "too-small"
        body.display = not too_small
        strip.display = not too_small
        notice.display = too_small
        if too_small:
            notice.update(f"Terminal too small — need 60×18; current {width}×{height}")
        # Below the floor only quit/help stay reachable, so only they are hinted.
        footer.update(_TOO_SMALL_FOOTER if too_small else self._footer_text())
        for widget in (coordinates, evidence, notices):
            widget.display = mode == "wide"
        pipeline.display = not too_small
        triage.display = mode in ("standard", "narrow")
        self._render_all()

    # -- rendering ---------------------------------------------------

    def _render_all(self) -> None:
        self._render_regions(_DIRTY_REGIONS)

    def _render_regions(self, regions: frozenset[str] | set[str]) -> None:
        """Refresh only the widgets owned by the dirty ``regions``."""
        if "header" in regions:
            self._render_header()
        if "pipeline" in regions:
            self._render_pipeline()
        if "coordinates" in regions:
            self._render_coordinates()
        if "evidence" in regions:
            self._render_evidence()
        if "notices" in regions:
            self._render_notices()
        if regions & {"header", "pipeline", "coordinates"}:
            self._render_triage()

    def _update(self, selector: str, text: str) -> None:
        try:
            # A Text renderable keeps the pane literal: bracketed content such
            # as a redaction placeholder or event text is never read as markup.
            self.query_one(selector, Static).update(Text(text))
        except Exception:
            pass

    def _render_header(self) -> None:
        """Context bar, status strip, footer, and the run-status class toggles."""
        state = self.state
        fields = self._readiness_fields()
        if fields is None:
            context = "TESIS · unconfigured · — · —"
            artifacts = self._artifact_hint()
        else:
            context = (
                f"TESIS · {_clip(fields['target'], 48)} · {_clip(fields['condition'], 24)} · "
                f"{_clip(fields['provider'], 20)}/{_clip(fields['model'], 28)}"
            )
            artifacts = fields.get("artifacts") or self._artifact_hint()
        self._update("#context-bar", context)

        glyph = _STATUS_GLYPH.get(state.status, "○")
        progress = f" {state.completed}/{state.total}" if state.total else ""
        containment = (
            f"containment {state.containment_count}" if state.containment_count else "contained"
        )
        line = " · ".join((
            f"{glyph} {state.status.upper()}{progress}",
            containment,
            state.selected_method or "—",
            state.elapsed,
            _clip(artifacts, 60),
        ))
        self._update("#status-label", _clip(line, max(24, self._dims()[0] - 2)))
        self._update("#context-footer", self._footer_text())
        try:
            strip: Any = self.query_one("#status-strip")
        except Exception:
            strip = None
        for name in _RUN_STATUSES:
            active = state.status == name
            self.set_class(active, f"status-{name}")
            if strip is not None:
                strip.set_class(active, f"status-{name}")

    def _render_pipeline(self) -> None:
        state = self.state
        narrow = self._dims()[0] < 80
        rows = []
        for row in state.stages:
            glyph = _STAGE_GLYPH.get(row.status, "○")
            label = row.label or row.stage_id
            if narrow:
                label = _NARROW_STAGE_LABELS.get(row.stage_id, label)
            if row.stage_id == "method_agent" and state.selected_method:
                rows.append(f"{glyph} {label} · {state.selected_method}")
                continue
            detail = f" — {row.detail[:60]}" if row.detail else ""
            rows.append(f"{glyph} {label}{detail}")
        self._update("#pipeline-pane", "Pipeline\n" + "\n".join(rows))

    def _render_coordinates(self) -> None:
        try:
            table = self.query_one("#coordinate-pane", DataTable)
        except Exception:
            return
        # The pane and the coordinate drawer declare their own column sets, so
        # cells are matched by column label instead of assumed column order.
        labels = [str(column.label).strip().lower() for column in table.ordered_columns]
        table.clear()
        for index in sorted(self.state.coordinates):
            row = self.state.coordinates[index]
            cells = {
                "#": str(index),
                "index": str(index),
                "status": _cell(row.status),
                "provider": _cell(row.provider),
                "surface": _cell(row.surface),
                "level": _cell(row.level),
                "mode": _cell(row.mode),
                "method": _cell(row.selected_method or row.target_method),
                # A queued or in-flight coordinate has no finding count yet;
                # reporting 0 there would be a fabricated zero.
                "findings": (str(row.finding_count)
                             if str(row.status).lower() not in ("", "queued", "running")
                             else "—"),
                "elapsed": _cell(row.elapsed),
            }
            table.add_row(*[cells.get(label, "—") for label in labels], key=str(index))

    def _render_evidence(self) -> None:
        state = self.state
        self._update("#evidence-badge", f"evidence · {state.unseen_evidence} new")
        lines = [
            "Evidence",
            f"findings={len(state.confirmed_vulns)} outcomes={len(state.achieved_outcomes)} "
            f"verifier={state.verifier_decision or '—'}",
            f"guardrails={state.guardrail_count} containment={state.containment_count} "
            f"fallbacks={state.fallback_count}",
        ]
        # The latest failure summary is already redacted when it enters the
        # state; only the fields the failure actually carries are rendered.
        failure = _failure_mapping(state.failure)
        if failure:
            lines.append(
                f"failure={_clip(failure.get('failure_class') or '—', 40)} · "
                f"provider={_clip(failure.get('provider') or '—', 24)} · "
                f"request={_clip(failure.get('request_id') or '—', 40)}"
            )
            message = str(failure.get("message") or "").strip()
            remediation = str(failure.get("remediation") or "").strip()
            if message:
                lines.append(f"message={_clip(message, 160)}")
            if remediation:
                lines.append(f"remediation={_clip(remediation, 160)}")
        self._update("#evidence-body", "\n".join(lines))

    def _notice_scroll_changed(self) -> None:
        """Paused auto-follow: bottom resumes it, scrolling away pauses it.

        Called from the body's ``scroll_y`` watcher, so wheel, keyboard, and
        programmatic scrolling all take the same path. Focus is never touched,
        and a paused pane is never scrolled for the operator.
        """
        try:
            body = self.query_one("#notice-body", NoticeBody)
            following = bool(body.is_vertical_scroll_end)
        except Exception:
            return
        if following == self._notice_following:
            return
        self._notice_following = following
        if following:
            self._notice_new = 0
        self._render_notice_badge()

    def _render_notice_badge(self) -> None:
        text = f"{self._notice_new} new" if self._notice_new else (
            "following" if self._notice_following else "paused"
        )
        self._update("#notice-new-badge", text)

    def _render_notices(self) -> None:
        if self.state.status == "ready" and not self.state.notices:
            self._update("#notice-text", self._readiness_text())
            return
        version = self.state.notice_version
        if self._notice_following:
            self._notice_new = 0
        else:
            # A generation, not a length: the list stops growing at
            # NOTICE_MAX_ENTRIES while notices keep arriving.
            self._notice_new += max(0, version - self._notice_seen_version)
        self._notice_seen_version = version
        recent = self.state.notices[-NOTICE_PANE_MAX:]
        self._update("#notice-text", "Notices\n" + "\n".join(str(n)[:160] for n in recent))
        self._render_notice_badge()
        if self._notice_following:
            try:
                self.query_one("#notice-body", NoticeBody).scroll_end(animate=False)
            except Exception:
                pass

    def _readiness_text(self) -> str:
        """Idle body: everything an operator needs before starting a run."""
        lines = ["Ready — no run active"]
        fields = self._readiness_fields()
        if fields is None:
            lines.append("target      —")
            lines.append("config      invalid or unreadable (p for the resolved-config check)")
            lines.append("containment enforced — no target is contacted")
        else:
            lines.append(f"target      {fields['target'][:80]}")
            lines.append(f"condition   {fields['condition']} · method {fields['method']}")
            lines.append(f"provider    {fields['provider']} · model {fields['model']}")
            lines.append(f"coordinates {fields['coordinates']} default")
            lines.append("config      valid")
            host = _target_host(fields.get("raw_target", ""))
            lines.append(
                "containment enforced — DVWA scope only"
                + (f" · host {host}" if host else "")
            )
        lines.append("r run · m matrix · p plan · d doctor")
        return "\n".join(lines)

    def _readiness_fields(self) -> dict[str, str] | None:
        """Resolved readiness values, shared by the full and compact renderings."""
        config = self._resolved_config()
        if config is None:
            return None
        target = str(getattr(config, "target_url", "") or "—")
        provider = str(getattr(config, "provider", "") or "—")
        model = "—"
        models = getattr(config, "models", None)
        if isinstance(models, dict):
            profile = models.get(provider)
            model = str(getattr(profile, "model_name", "") or "—") if profile is not None else "—"
        return {
            "target": str(_sanitize_endpoint(target)),
            "raw_target": target,
            "condition": str(getattr(config, "experiment_condition", "") or "—"),
            "method": str(getattr(config, "target_method", "") or "orchestrator-selected"),
            "provider": provider,
            "model": model,
            "coordinates": str(self._default_coordinate_count(config)),
            "artifacts": str(getattr(config, "output_dir", "results") or "results"),
        }

    def _compact_readiness(self) -> str:
        """Idle readiness for the standard/narrow triage line (at most four rows).

        The wide layout shows the full summary in ``#notice-pane``; below that the
        body has room for one pane, so the same facts are folded into four rows.
        Each row is clipped to the cells the terminal actually has, because a row
        that wraps would push a later row out of the four-row cap.
        """
        available = max(24, self._dims()[0] - 1)
        fields = self._readiness_fields()
        if fields is None:
            return "\n".join(
                _clip(row, available) for row in (
                    "target      —",
                    "condition   invalid configuration",
                    "provider    — · coordinates — · config invalid",
                    "containment enforced · r run · m matrix · p plan · d doctor",
                )
            )
        method_tail = f" · method {fields['method']}"
        coords_tail = f" · coordinates {fields['coordinates']} · config valid"
        return "\n".join((
            _clip(f"target      {fields['target']}", available),
            _clip(f"condition   {fields['condition']}", max(8, available - len(method_tail))) + method_tail,
            _clip(f"provider    {fields['provider']}/{fields['model']}", max(8, available - len(coords_tail))) + coords_tail,
            _clip("containment enforced · r run · m matrix · p plan · d doctor", available),
        ))

    @staticmethod
    def _default_coordinate_count(config: Any) -> int:
        def axis(values: Any, single: Any) -> int:
            items = [v for v in (values or []) if v]
            return len(items) or (1 if single else 0)

        return (
            axis(getattr(config, "providers", None), getattr(config, "provider", None))
            * axis(getattr(config, "levels", None), getattr(config, "level", None))
            * axis(getattr(config, "surfaces", None), getattr(config, "surface", None))
            * axis(getattr(config, "payload_modes", None), getattr(config, "payload_mode", None))
            * max(1, int(getattr(config, "repeats", 1) or 1))
        )

    def _resolved_config(self) -> Any:
        try:
            return load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={})
        except Exception:
            return None

    def _render_triage(self) -> None:
        state = self.state
        if state.status == "ready" and not state.notices:
            # Idle: the triage line carries the same readiness summary the wide
            # layout shows in #notice-pane, folded to four rows.
            self._update("#triage-line", self._compact_readiness())
            return
        self._update(
            "#triage-line",
            f"Pipeline {sum(1 for r in state.stages if r.status == 'succeeded')}/{len(state.stages)} · "
            f"coords {state.completed}/{state.total or len(state.coordinates)} · "
            f"{state.status}",
        )

    def _artifact_hint(self) -> str:
        config = self._resolved_config()
        if config is None:
            return "results"
        return str(getattr(config, "output_dir", "results"))[:80]

    # -- runtime ------------------------------------------------------

    def start_run(self, config: Any, mode: str = "single") -> None:
        if self._run_active:
            return
        self.cancel_token = CancellationToken()
        self._cancel_requested = False
        self._run_active = True
        self._tesis_closing = False
        self.state.run_mode = "matrix" if mode == "matrix" else "single"
        self._render_regions(apply_run_event(self.state, RunEvent("run.started", message="run started")))
        self._journal_path = self._open_journal(config)
        self._open_descriptor(config)
        worker = Thread(target=self._run_blocking, args=(config, self.state.run_mode),
                        name="tesis-runtime", daemon=True)
        self._runtime_thread = worker
        worker.start()

    _start_run = start_run

    def _open_journal(self, config: Any) -> Path | None:
        try:
            output_dir = Path(str(getattr(config, "output_dir", "results")))
            output_dir.mkdir(parents=True, exist_ok=True)
            path = output_dir / "run-events.jsonl"
            path.touch(exist_ok=True)
            return path
        except Exception:
            return None

    def _open_descriptor(self, config: Any) -> None:
        try:
            from tesis.live_runtime import build_runtime_descriptor, write_descriptor
            descriptor = build_runtime_descriptor(config)
            write_descriptor(descriptor)
            self._descriptor_active = True
        except Exception:
            self._descriptor_active = False

    def _close_descriptor(self, status: str) -> None:
        if not self._descriptor_active:
            return
        try:
            from tesis.live_runtime import write_terminal_descriptor
            write_terminal_descriptor(status)
        except Exception:
            pass
        finally:
            self._descriptor_active = False

    def _run_blocking(self, config: Any, mode: str) -> None:
        token = self.cancel_token
        terminal_seen = False

        def forward(event: RunEvent) -> None:
            nonlocal terminal_seen
            if str(event.event_type or "") in _TERMINAL_EVENT_TYPES:
                terminal_seen = True
            self._post_event(event)

        class _Sink:
            def emit(self, event: RunEvent) -> None:
                forward(event)

        sink = _Sink()
        result_status = "cancelled" if token.is_cancelled else "succeeded"
        try:
            if mode == "matrix":
                providers = list(getattr(config, "providers", []) or [getattr(config, "provider", "gemini")])
                levels = list(getattr(config, "levels", []) or [getattr(config, "level", "low")])
                surfaces = list(getattr(config, "surfaces", []) or ["sqli"])
                payload_modes = list(getattr(config, "payload_modes", []) or ["hybrid"])
                _invoke_runner(run_provider_matrix, {
                    "target_url": config.target_url,
                    "providers": providers,
                    "security_levels": levels,
                    "surfaces": surfaces,
                    "payload_modes": payload_modes,
                    "repeats": int(getattr(config, "repeats", 1) or 1),
                    "output_dir": str(getattr(config, "output_dir", "results")),
                    "event_sink": sink,
                    "cancellation_token": token,
                    "execution_id": new_execution_id(),
                })
            else:
                models = getattr(config, "models", {}) or {}
                provider = str(getattr(config, "provider", "gemini"))
                model_config = models.get(provider) if isinstance(models, dict) else None
                if is_dataclass(model_config):
                    model_config = asdict(model_config)
                _invoke_runner(run_single_engagement, {
                    "target_url": config.target_url,
                    "security_level": str(getattr(config, "level", "low")),
                    "llm_provider": provider,
                    "surface": str(getattr(config, "surface", "sqli")),
                    "payload_mode": str(getattr(config, "payload_mode", "hybrid")),
                    "output_dir": str(getattr(config, "output_dir", "results")),
                    "model_config": model_config,
                    "event_sink": sink,
                    "cancellation_token": token,
                    "execution_id": new_execution_id(),
                })
            result_status = "cancelled" if token.is_cancelled else "succeeded"
        except Exception as exc:
            terminal_seen = True
            result_status = "failed"
            self._post_event(RunEvent("run.failed", message=f"{type(exc).__name__}: {exc}"))
        finally:
            if not terminal_seen:
                # Runners normally emit their own terminal event; one that
                # returns without it must still settle the operator state.
                prefix = "matrix" if mode == "matrix" else "run"
                if token.is_cancelled:
                    self._post_event(RunEvent(f"{prefix}.cancelled", message="Cancellation requested"))
                else:
                    self._post_event(RunEvent(f"{prefix}.finished", message=f"Experiment {result_status}"))
            self._run_active = False
            self._close_descriptor(result_status)
            self._append_journal_terminal(result_status)


    def _append_journal_terminal(self, status: str) -> None:
        if self._journal_path is None:
            return
        try:
            with open(self._journal_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({"event_type": f"run.{status}", "status": status}) + "\n")
        except Exception:
            pass

    def _post_event(self, event: RunEvent) -> None:
        should_drain = False
        with self._event_lock:
            if self._tesis_closing:
                return
            if len(self._event_queue) >= UI_PENDING_EVENT_MAX:
                self._pending_dropped += 1
                try:
                    self._event_queue.popleft()
                except IndexError:
                    pass
            self._event_queue.append(event)
            should_drain = True
        if should_drain:
            try:
                self.app.call_from_thread(self._drain_runtime_events)
            except Exception:
                pass

    def add_drawer_observer(self, observer: Any) -> None:
        if observer not in self._drawer_observers:
            self._drawer_observers.append(observer)

    def remove_drawer_observer(self, observer: Any) -> None:
        try:
            self._drawer_observers.remove(observer)
        except ValueError:
            pass

    def _notify_drawer_observers(self) -> None:
        for observer in list(self._drawer_observers):
            try:
                observer()
            except Exception:
                pass

    def _drain_runtime_events(self) -> None:
        with self._event_lock:
            pending = list(self._event_queue)
            self._event_queue.clear()
        if not pending:
            return
        dirty: set[str] = set()
        for event in pending:
            try:
                dirty.update(apply_run_event(self.state, event))
            except Exception:
                self.state.dropped_events += 1
        self._notify_drawer_observers()
        if not dirty:
            return
        try:
            self._render_regions(dirty)
        except Exception:
            pass

    def request_cancel(self) -> None:
        if self.cancel_token.cancel("user requested cancellation"):
            self._cancel_requested = True
        try:
            self._render_all()
        except Exception:
            pass

    def prepare_shutdown(self) -> None:
        with self._event_lock:
            self._tesis_closing = True
            self._event_queue.clear()
        try:
            self.cancel_token.cancel("TUI closed")
        except Exception:
            pass
        self._close_descriptor("cancelled")

    def on_unmount(self) -> None:
        self.prepare_shutdown()

    # -- actions -------------------------------------------------------

    def _floor_ok(self) -> bool:
        """Below the 60x18 floor only quit and help remain reachable."""
        return not self.has_class("too-small")

    def action_open_launcher(self) -> None:
        if not self._floor_ok():
            return
        try:
            self.app.push_screen(CommandLauncher())
        except Exception:
            pass

    def action_launch_single(self) -> None:
        if not self._floor_ok():
            return
        try:
            self.app.push_screen(LaunchDrawer(mode="single"))
        except Exception:
            pass

    def action_launch_matrix(self) -> None:
        if not self._floor_ok():
            return
        try:
            self.app.push_screen(LaunchDrawer(mode="matrix"))
        except Exception:
            pass

    def action_open_plan(self) -> None:
        if not self._floor_ok():
            return
        self._push_drawer(PlanDrawer())

    def action_open_doctor(self) -> None:
        if not self._floor_ok():
            return
        self._push_drawer(DoctorDrawer())

    def action_open_help(self) -> None:
        self._push_drawer(HelpDrawer())

    def action_show_pipeline(self) -> None:
        self._focus_pane("#pipeline-pane")

    def action_show_coordinates(self) -> None:
        self._focus_pane("#coordinate-pane", drawer=CoordinateDrawer)

    def action_show_evidence(self) -> None:
        self._focus_pane("#evidence-pane", "#evidence-body", drawer=EvidenceDrawer)

    def _focus_pane(self, pane_selector: str, focus_selector: str | None = None,
                    drawer: type[Screen] | None = None) -> None:
        """Focus a visible pane; when the pane is hidden, open its drawer.

        The wide layout shows all three panes, so 1/2/3 and Tab move focus
        between them there. Standard and narrow hide coordinates and evidence,
        so those keys open the full-height drawer instead of focusing nothing.
        """
        if self.has_class("too-small"):
            return
        try:
            pane = self.query_one(pane_selector)
        except Exception:
            pane = None
        if pane is not None and pane.display:
            try:
                target = pane if focus_selector is None else self.query_one(focus_selector)
                target.focus()
                return
            except Exception:
                pass
        if drawer is not None:
            self._push_drawer(drawer())

    def _push_drawer(self, drawer: Screen) -> None:
        """BaseDrawer decides its own panel width; the shell only pushes it."""
        try:
            self.app.push_screen(drawer)
        except Exception:
            pass

    def action_inspect(self) -> None:
        """Enter inspects the selected coordinate; nothing selected is a no-op."""
        if not self._floor_ok() or self.state.selected_coordinate is None:
            return
        self._push_drawer(CoordinateDrawer())

    @on(DataTable.RowSelected, "#coordinate-pane")
    def select_coordinate(self, event: DataTable.RowSelected) -> None:
        if not self._floor_ok():
            return
        try:
            self.state.selected_coordinate = int(str(event.row_key.value))
        except (TypeError, ValueError):
            return
        self._render_regions({"coordinates"})
        self._push_drawer(CoordinateDrawer())

    def action_quit_if_idle(self) -> None:
        if not self._run_active:
            self.app.exit()

    def action_cancel_or_exit(self) -> None:
        if self._run_active and not self._cancel_requested:
            self.request_cancel()
        else:
            self.app.exit()


# ---------------------------------------------------------------- app

class TesisApp(App[None]):
    """Mission-control terminal application for TESIS."""

    TITLE = "TESIS Experiment Harness"
    CSS_PATH = "tui.tcss"
    # Ctrl+P belongs to CommandLauncher; the stock palette would shadow it.
    ENABLE_COMMAND_PALETTE = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.register_theme(SHELL_MONO_THEME)
        if os.environ.get("NO_COLOR"):
            try:
                self.theme = SHELL_MONO_THEME_NAME
            except Exception:
                pass

    def exit(self, result: Any = None, return_code: int = 0, message: Any = None) -> None:
        if not getattr(self, "_tesis_shutdown_started", False):
            self._tesis_shutdown_started = True
            for screen in tuple(self.screen_stack):
                prepare = getattr(screen, "prepare_shutdown", None)
                if callable(prepare):
                    try:
                        prepare()
                    except Exception:
                        pass
            try:
                self.workers.cancel_all()
            except Exception:
                pass
        super().exit(result=result, return_code=return_code, message=message)

    def on_mount(self) -> None:
        self.push_screen(MissionControlScreen())

    def export_screenshot(self, *args: Any, **kwargs: Any) -> str:
        # Rich nbsp-encodes every space in exported SVGs, which makes the
        # text matrix unsearchable; decode back to plain spaces (single
        # spaces render identically; line widths are pinned by textLength).
        return super().export_screenshot(*args, **kwargs).replace("&#160;", " ")
def run_tui() -> None:
    TesisApp().run()


__all__ = [
    "AboutDrawer",
    "COMMANDS",
    "CONFIG_PATH",
    "CommandLauncher",
    "CommandSpec",
    "CoordinateDrawer",
    "CoordinateRow",
    "DETAIL_LOG_MAX_LINES",
    "DETAIL_RENDER_MAX_CHARS",
    "DoctorDrawer",
    "EvidenceDrawer",
    "FailureDrawer",
    "FailureSummary",
    "HelpDrawer",
    "LaunchDrawer",
    "MissionControlScreen",
    "PlanDrawer",
    "ResultsDrawer",
    "RunStatus",
    "SettingsDrawer",
    "StageRow",
    "StageStatus",
    "SHELL_MONO_THEME",
    "SHELL_MONO_THEME_NAME",
    "TesisApp",
    "TraceDrawer",
    "TuiRunState",
    "apply_run_event",
    "run_tui",
]
