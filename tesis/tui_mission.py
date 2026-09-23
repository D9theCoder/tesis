"""Live mission-control screen and runtime event surface for the terminal UI."""

from __future__ import annotations

import inspect
import json
from collections import deque
from dataclasses import asdict, is_dataclass
from pathlib import Path
from threading import Lock, Thread
from typing import Any
from urllib.parse import urlsplit

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Label, Static

from evaluation.multi_llm_runner import run_provider_matrix
from evaluation.runner import run_single_engagement
from tesis.artifact_repository import new_execution_id
from tesis.config_loader import load_and_resolve_config
from tesis.runtime_events import CancellationToken, RunEvent
import tesis.tui_commands as tui_commands
import tesis.tui_security as tui_security
import tesis.tui_state as tui_state


def _invoke_runner(runner: Any, kwargs: dict[str, Any]) -> Any:
    """Call single/matrix runners with only the kwargs they accept."""
    try:
        signature = inspect.signature(runner)
    except (TypeError, ValueError):
        return runner(**kwargs)
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values()):
        return runner(**kwargs)
    return runner(**{k: v for k, v in kwargs.items() if k in signature.parameters})



UI_PENDING_EVENT_MAX = 2_048
#: Most recent notices rendered in the scrollable pane; the bounded full stream
#: stays in the trace drawer.
NOTICE_PANE_MAX = 200



# ---------------------------------------------------------------- operator state contract


_DIRTY_REGIONS = frozenset({"header", "pipeline", "coordinates", "evidence", "notices"})

# Events that settle a run; a runner returning without one still needs a
# terminal state, so the runtime thread reconciles it (see _run_blocking).
_TERMINAL_EVENT_TYPES = frozenset({
    "run.finished", "run.failed", "run.cancelled", "run.error",
    "matrix.finished", "matrix.failed", "matrix.cancelled",
})

# Statuses that end a run. The elapsed clock stops once one is set, so a late
# event cannot keep extending a finished run.


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
        f"{tui_commands._COMMAND_INDEX[name].keys} {name}"
        for name in names
        if name in tui_commands._COMMAND_INDEX and tui_commands._COMMAND_INDEX[name].keys
    ]


def _nav_hint(keys: tuple[str, ...]) -> str:
    """Navigation hints for ``keys``, from the one NAVIGATION_KEYS list."""
    return " · ".join(
        f"{key} {label}" for key, label in tui_commands.NAVIGATION_KEYS if key in keys
    )


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
        self.state = tui_state.TuiRunState()
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
        if width < tui_commands.FLOOR_WIDTH or height < tui_commands.FLOOR_HEIGHT:
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
        failure = tui_security._failure_mapping(state.failure)
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
            "target": str(tui_security._sanitize_endpoint(target)),
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
            return load_and_resolve_config(config_path=str(tui_state.CONFIG_PATH), cli_args={})
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
        self._render_regions(tui_state.apply_run_event(self.state, RunEvent("run.started", message="run started")))
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
                dirty.update(tui_state.apply_run_event(self.state, event))
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
        from tesis.tui_commands import CommandLauncher

        if not self._floor_ok():
            return
        try:
            self.app.push_screen(CommandLauncher())
        except Exception:
            pass

    def action_launch_single(self) -> None:
        from tesis.tui_forms import LaunchDrawer

        if not self._floor_ok():
            return
        try:
            self.app.push_screen(LaunchDrawer(mode="single"))
        except Exception:
            pass

    def action_launch_matrix(self) -> None:
        from tesis.tui_forms import LaunchDrawer

        if not self._floor_ok():
            return
        try:
            self.app.push_screen(LaunchDrawer(mode="matrix"))
        except Exception:
            pass

    def action_open_plan(self) -> None:
        from tesis.tui_drawers import PlanDrawer

        if not self._floor_ok():
            return
        self._push_drawer(PlanDrawer())

    def action_open_doctor(self) -> None:
        from tesis.tui_drawers import DoctorDrawer

        if not self._floor_ok():
            return
        self._push_drawer(DoctorDrawer())

    def action_open_help(self) -> None:
        from tesis.tui_drawers import HelpDrawer

        self._push_drawer(HelpDrawer())

    def action_show_pipeline(self) -> None:
        self._focus_pane("#pipeline-pane")

    def action_show_coordinates(self) -> None:
        from tesis.tui_drawers import CoordinateDrawer

        self._focus_pane("#coordinate-pane", drawer=CoordinateDrawer)

    def action_show_evidence(self) -> None:
        from tesis.tui_drawers import EvidenceDrawer

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
        from tesis.tui_drawers import CoordinateDrawer

        if not self._floor_ok() or self.state.selected_coordinate is None:
            return
        self._push_drawer(CoordinateDrawer())

    @on(DataTable.RowSelected, "#coordinate-pane")
    def select_coordinate(self, event: DataTable.RowSelected) -> None:
        from tesis.tui_drawers import CoordinateDrawer

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
