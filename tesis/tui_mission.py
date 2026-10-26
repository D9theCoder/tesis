"""Live mission-control screen and runtime event surface for the terminal UI."""

from __future__ import annotations

import inspect
import json
from collections import deque
from dataclasses import replace
from pathlib import Path
from threading import Lock, Thread
from typing import Any
from urllib.parse import urlsplit

from rich.text import Text
from rich.cells import cell_len, set_cell_size
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, DataTable, Input, OptionList, Static, Tab, Tabs
from textual.widgets.option_list import Option

from evaluation.multi_llm_runner import run_provider_matrix
from evaluation.runner import run_single_engagement
from tesis.config_loader import load_and_resolve_config
from tesis.tui_config import TuiConfigCache
from tesis.runtime_events import CancellationToken, RunEvent
import tesis.tui_commands as tui_commands
import tesis.tui_security as tui_security
import tesis.tui_state as tui_state
from tesis.tui_widgets import KeyboardActions, KeyboardTable, KeyboardTabs, model_connection


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

_RUN_STATUSES = ("ready", "running", "degraded", "succeeded", "failed", "cancelled", "unknown")

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
_FOOTER_ACTIVE_NAV = ("1", "2", "3", "4", "Tab/Shift+Tab", "Enter", "/")
_FOOTER_ACTIVE_NAV_COMPACT = ("Enter", "/")

# Concise pipeline labels for the narrow (60-79 column) layout, where the full
# canonical stage names plus detail no longer fit one row.
_NARROW_STAGE_LABELS = {
    "payload_candidate_builder": "candidates",
    "payload_validator": "validation",
    "chaining_router": "chain router",
}

_STAGE_DESCRIPTIONS = {
    "recon": "Discover the DVWA target",
    "orchestrator": "Select the next method",
    "payload_candidate_builder": "Build payload candidates",
    "payload_validator": "Validate scope and provenance",
    "method_agent": "Execute and verify the method",
    "chaining_router": "Route confirmed outcomes",
    "scorer": "Score and write artifacts",
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
    return text if cell_len(text) <= limit else set_cell_size(text, limit - 1) + "…"


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
        Binding("4", "show_activity", "Activity", show=False),
        Binding("enter", "inspect", "Inspect", show=True, key_display="Enter"),
        Binding("escape", "overview", "Overview", show=False),
        Binding("/", "open_launcher", "Command", show=True),
        Binding("question_mark", "open_help", "Help", show=True, key_display="?"),
        Binding("ctrl+c", "cancel_or_exit", "Cancel", show=True, priority=True,
                key_display="Ctrl+C"),
        Binding("q", "quit_if_idle", "Quit", show=True),
        Binding("ctrl+q", "app.quit", "Force exit", show=False, priority=True),
        Binding("r", "launch_single", "Run", show=False),
        Binding("m", "launch_matrix", "Matrix", show=False),
        Binding("p", "open_plan", "Plan", show=False),
        Binding("d", "open_doctor", "Doctor", show=False),
        Binding("s", "open_settings", "Settings", show=False),
        Binding("v", "open_results", "Results", show=False),
        Binding("l", "open_trace", "Logs", show=False),
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
        self._run_result: dict[str, Any] | None = None
        self._run_config: Any = None
        self._artifact_root: Path | None = None
        self._drawer_observers: list = []
        # Notice auto-follow: following the bottom, else paused with a count of
        # events the operator has not scrolled to yet.
        self._notice_following = True
        self._notice_new = 0
        self._notice_seen_version = 0
        self._active_pane = "pipeline"
        self._layout_mode = ""
        self._coordinate_cursor: int | None = None
        self._config_cache = TuiConfigCache()
        self._layout_key: tuple | None = None
        self._coordinate_values: dict[int, tuple[str, ...]] = {}
        self._pending_regions: set[str] = set()
        self._render_timer: Any = None

    @property
    def run_active(self) -> bool:
        return self._run_active

    # -- layout -----------------------------------------------------

    def compose(self) -> ComposeResult:
        with Horizontal(id="header"):
            yield Static("TESIS", id="context-bar")
            yield Static("Ready", id="header-status")
        with Horizontal(id="workspace-nav"):
            yield KeyboardTabs(Tab("1 Pipeline", id="tab-pipeline"), Tab("2 Runs", id="tab-runs"),
                       Tab("3 Evidence", id="tab-evidence"), Tab("4 Activity", id="tab-activity"),
                       id="workspace-tabs")
            with KeyboardActions(id="workspace-actions"):
                yield Button("v Results", id="nav-results")
                yield Button("s Settings", id="nav-settings")
                yield Button("l Logs", id="nav-logs")
        with Vertical(id="mission-body"):
            with Vertical(id="pipeline-panel", classes="workspace-panel"):
                yield OptionList(id="pipeline-pane")
            with Vertical(id="coordinate-panel", classes="workspace-panel"):
                yield KeyboardTable(id="coordinate-pane", cursor_type="row", show_row_labels=False)
                yield Static("No runs yet\n\nPress r to configure a run or m to build a matrix.", id="coordinate-empty")
            with Horizontal(id="detail-panels"):
                with Vertical(id="notice-pane", classes="workspace-panel"):
                    yield Static("", id="notice-new-badge", markup=False, classes="notice-new-badge")
                    with NoticeBody(self._notice_scroll_changed, id="notice-body"):
                        yield Static("", id="notice-text", markup=False)
                with Vertical(id="evidence-pane", classes="workspace-panel"):
                    yield Static("", id="evidence-badge", classes="evidence-badge")
                    with VerticalScroll(id="evidence-body"):
                        yield Static("", id="evidence-text", markup=False)
        yield Static("", id="triage-line")
        yield Static("", id="size-notice")
        yield Input(placeholder="/ commands    r run    m matrix    p plan    ? help", id="mission-command")
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
        if width >= 120:
            hints.insert(0, "Tab focus · ↑/↓ select · Enter open")
        return " · ".join(hints)

    def on_mount(self) -> None:
        self._configure_coordinate_columns()
        self.query_one("#pipeline-panel").border_title = "Pipeline"
        self.query_one("#coordinate-panel").border_title = "Coordinates / Runs"
        self.query_one("#notice-pane").border_title = "Run details"
        self.query_one("#evidence-pane").border_title = "Evidence"
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
        if self.is_mounted:
            self._render_regions({"header", "notices"})

    def _restore_default_focus(self) -> None:
        try:
            if self.app.focused in self.focus_chain:
                return
            self._pane_target(self._active_pane).focus()
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
        layout_key = (width, height, None if mode == "wide" else self._active_pane)
        if layout_key == self._layout_key:
            return
        resized = self._layout_key is None or self._layout_key[:2] != layout_key[:2]
        self._layout_mode = mode
        for name in ("wide", "standard", "narrow", "too-small"):
            self.set_class(mode == name, name)
        try:
            body = self.query_one("#mission-body", Vertical)
            strip = self.query_one("#status-strip", Horizontal)
            notice = self.query_one("#size-notice", Static)
            footer = self.query_one("#context-footer", Static)
            pipeline = self.query_one("#pipeline-panel", Vertical)
            coordinates = self.query_one("#coordinate-panel", Vertical)
            evidence = self.query_one("#evidence-pane", Vertical)
            notices = self.query_one("#notice-pane", Vertical)
            triage = self.query_one("#triage-line", Static)
        except Exception:
            return
        self._layout_key = layout_key
        too_small = mode == "too-small"
        body.display = not too_small
        strip.display = not too_small
        notice.display = too_small
        if too_small:
            notice.update(f"Terminal too small\n\nNeed 60×18 · current {width}×{height}\nResize to continue.")
        # Below the floor only quit/help stay reachable, so only they are hinted.
        footer.update(_TOO_SMALL_FOOTER if too_small else self._footer_text())
        pipeline.display = mode == "wide" or (not too_small and self._active_pane == "pipeline")
        coordinates.display = mode == "wide" or (not too_small and self._active_pane == "runs")
        self.query_one("#detail-panels").display = mode == "wide" or (
            not too_small and self._active_pane in {"evidence", "activity"})
        evidence.display = mode == "wide" or self._active_pane == "evidence"
        notices.display = mode == "wide" or self._active_pane == "activity"
        self.query_one("#workspace-nav").display = not too_small
        self.query_one("#workspace-actions").display = width >= 145
        self.query_one("#mission-command").display = not too_small and height >= 22
        triage.display = mode in ("standard", "narrow")
        self._configure_coordinate_columns()
        if resized:
            self._render_all()
        focused = self.app.focused
        if focused is None or focused not in self.focus_chain:
            self._restore_default_focus()

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
            widget = self.query_one(selector, Static)
            content = Text(text)
            if widget.content != content:
                widget.update(content)
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
            context = f"TESIS  ·  DVWA  ·  {_clip(fields['target'], 42)}"
            if self._dims()[0] >= 120:
                context += f"  ·  {fields['provider']} / {fields['model']}"
            artifacts = fields.get("artifacts") or self._artifact_hint()
        context_text = Text(context)
        context_text.stylize("bold", 0, 5)
        self.query_one("#context-bar", Static).update(context_text)
        self._update("#header-status", f"{state.status.capitalize()}  {state.elapsed if state.status != 'ready' else ''}")

        progress = f"{state.completed}/{state.total} coordinates" if state.total else "No run active"
        containment = (
            f"containment {state.containment_count}" if state.containment_count else "contained"
        )
        line = " · ".join((
            progress,
            f"DVWA scope {containment}",
            state.selected_method or "—",
            _clip(artifacts, 60),
        ))
        self._update("#status-label", _clip(line, max(24, self._dims()[0] - 2)))
        self._update("#context-footer", self._footer_text())
        self.query_one("#nav-settings", Button).disabled = self._run_active
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
        options = self.query_one("#pipeline-pane", OptionList)
        initial_population = options.option_count == 0
        roomy = self._dims()[1] >= 34
        width = self._dims()[0]
        available = max(20, int((width - 3) * 0.28) - 4 if self._layout_mode == "wide" else width - 6)
        for index, row in enumerate(state.stages):
            label = row.label or row.stage_id.replace("_", " ")
            status = "pending" if row.status == "queued" else row.status
            if available < 40:
                label = _NARROW_STAGE_LABELS.get(row.stage_id, label)
            text = Text(f" {index + 1}  ")
            text.append(_clip(label, max(10, available - 6 - len(status))), style="bold")
            text.append(f"  {status}", style="dim" if row.status == "queued" else "bold")
            if roomy:
                detail = row.detail or _STAGE_DESCRIPTIONS.get(row.stage_id, "")
                if row.stage_id == "method_agent" and state.selected_method:
                    detail = state.selected_method
                text.append("\n    " + _clip(detail, available - 4), style="dim")
            if index < options.option_count:
                if options.get_option_at_index(index).prompt != text:
                    options.replace_option_prompt_at_index(index, text)
            else:
                options.add_option(Option(text, id=row.stage_id))
        if initial_population and options.option_count:
            options.action_first()
        self.query_one("#pipeline-panel").border_subtitle = f"{len(state.stages)} stages · Enter inspect"

    def _render_coordinates(self) -> None:
        try:
            table = self.query_one("#coordinate-pane", DataTable)
        except Exception:
            return
        # The pane and the coordinate drawer declare their own column sets, so
        # cells are matched by column label instead of assumed column order.
        labels = [str(column.label).strip().lower() for column in table.ordered_columns]
        column_keys = [column.key for column in table.ordered_columns]
        selected = table.cursor_row if self._coordinate_cursor is None else self._coordinate_cursor
        self._coordinate_cursor = None
        selected_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key if table.row_count else None
        scroll_x, scroll_y = table.scroll_x, table.scroll_y
        changed = False
        added = False
        for index in set(self._coordinate_values) - set(self.state.coordinates):
            table.remove_row(str(index))
            self._coordinate_values.pop(index)
            changed = True
        for index in sorted(self.state.coordinates):
            row = self.state.coordinates[index]
            cells = {
                "#": str(index),
                "index": str(index),
                "status": _cell(row.execution_status or row.status),
                "outcome": _cell(row.security_outcome),
                "provider": _cell(row.provider.split("__", 1)[0] if row.provider else None),
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
            values = tuple(cells.get(label, "—") for label in labels)
            previous = self._coordinate_values.get(index)
            if previous is None:
                table.add_row(*values, key=str(index))
                added = changed = True
            elif previous != values:
                for column, old, new in zip(column_keys, previous, values):
                    if old != new:
                        table.update_cell(str(index), column, new)
                changed = True
            self._coordinate_values[index] = values
        if added:
            table.sort(column_keys[0], key=int)
        if changed:
            if selected_key is not None and selected_key.value in {str(index) for index in self.state.coordinates}:
                selected = table.get_row_index(selected_key)
            table.move_cursor(row=min(selected, max(0, table.row_count - 1)), scroll=False)
            table.scroll_to(x=scroll_x, y=scroll_y, animate=False, force=True)
        self.query_one("#coordinate-empty").display = not bool(self.state.coordinates)
        self.query_one("#coordinate-panel").border_subtitle = f"{self.state.completed}/{self.state.total or len(self.state.coordinates)} completed"

    def _configure_coordinate_columns(self) -> None:
        width = self._dims()[0]
        available = int(width * 0.72) - 8 if self._layout_mode == "wide" else width - 8
        if available >= 134:
            columns = ("#", "status", "provider", "surface", "level", "mode", "method", "outcome", "findings", "elapsed")
        elif available >= 104:
            columns = ("#", "status", "provider", "surface", "level", "method", "outcome", "elapsed")
        elif available >= 78:
            columns = ("#", "status", "surface", "method", "outcome", "elapsed")
        else:
            columns = ("#", "status", "method", "outcome")
        table = self.query_one("#coordinate-pane", DataTable)
        if tuple(str(column.label) for column in table.ordered_columns) == columns:
            return
        widths = {"#": 2, "status": 10, "provider": 14, "surface": 12, "level": 5,
                  "mode": 10, "method": 21, "outcome": 14, "findings": 8, "elapsed": 7}
        if self._coordinate_cursor is None:
            self._coordinate_cursor = table.cursor_row
        table.clear(columns=True)
        self._coordinate_values.clear()
        for label in columns:
            table.add_column(label, width=widths[label])

    def _render_evidence(self) -> None:
        state = self.state
        self._update("#evidence-badge", f"{state.unseen_evidence} new" if state.unseen_evidence else "No new evidence")
        lines = [
            f"Execution   {state.execution_status or '—'}",
            f"Security    {state.security_outcome or '—'}",
            f"Reason      {(state.security_outcome_reason or {}).get('code', '—')}",
            f"Findings    {len(state.confirmed_vulns)}",
            f"Outcomes    {len(state.achieved_outcomes)}",
            f"Verifier    {state.verifier_decision or '—'}",
            f"Guardrails  {state.guardrail_count}",
            f"Containment {state.containment_count}",
            f"Fallbacks   {state.fallback_count}",
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
        self._update("#evidence-text", "\n".join(lines))

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
        lines = []
        fields = self._readiness_fields()
        if fields is None:
            lines.append("target      —")
            lines.append("config      invalid or unreadable (p for the resolved-config check)")
            lines.append("containment enforced — no target is contacted")
        else:
            lines.append(f"target      {fields['target'][:80]}")
            lines.append(f"condition   {fields['condition']} · method {fields['method']}")
            lines.append(f"provider    {fields['provider']}")
            lines.append(f"model       {fields['model']}")
            lines.append(f"API         {fields['protocol']}")
            lines.append(f"coordinates {fields['coordinates']} default")
            lines.append("config      valid")
            host = _target_host(fields.get("raw_target", ""))
            lines.append(
                "containment enforced — DVWA scope only"
                + (f" · host {host}" if host else "")
            )
        return "\n".join(lines)

    def _readiness_fields(self) -> dict[str, str] | None:
        """Resolved readiness values, shared by the full and compact renderings."""
        config = self._resolved_config()
        if config is None:
            return None
        target = str(getattr(config, "target_url", "") or "—")
        provider = str(getattr(config, "provider", "") or "—")
        connection = {"provider": provider, "model": "—", "protocol": "—"}
        models = getattr(config, "models", None)
        if isinstance(models, dict):
            profile = models.get(provider)
            if profile is not None:
                connection = model_connection(provider, profile)
        return {
            "target": str(tui_security._sanitize_endpoint(target)),
            "raw_target": target,
            "condition": str(getattr(config, "experiment_condition", "") or "—"),
            "method": str(getattr(config, "target_method", "") or "orchestrator-selected"),
            "provider": connection["provider"],
            "model": connection["model"],
            "protocol": connection["protocol"],
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
        if self._run_config is not None and self.state.status != "ready":
            return self._run_config
        try:
            return self._config_cache.resolve(loader=load_and_resolve_config)
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
        self._run_config = config
        self._tesis_closing = False
        self.state.run_mode = "matrix" if mode == "matrix" else "single"
        prefix = "matrix" if self.state.run_mode == "matrix" else "run"
        self._render_regions(tui_state.apply_run_event(self.state, RunEvent(f"{prefix}.started", message="run started")))
        self._journal_path = None
        self._run_result = None
        self._artifact_root = None
        worker = Thread(target=self._run_blocking, args=(config, self.state.run_mode),
                        name="tesis-runtime", daemon=True)
        self._runtime_thread = worker
        worker.start()

    _start_run = start_run

    def _run_blocking(self, config: Any, mode: str) -> None:
        from tesis.headless import run_resolved

        screen = self

        def forward(event: RunEvent) -> None:
            artifact_root = event.data.get("artifact_root")
            if artifact_root:
                self._journal_path = Path(artifact_root) / "runtime.events.jsonl"
            self._post_event(event)

        class _Sink:
            def emit(self, event: RunEvent) -> None:
                forward(event)

        try:
            _, self._run_result, self._artifact_root = run_resolved(
                replace(config, matrix=mode == "matrix"),
                event_sink=_Sink(), cancellation_token=self.cancel_token,
                single_runner=run_single_engagement, matrix_runner=run_provider_matrix,
            )
        except Exception as exc:
            prefix = "matrix" if mode == "matrix" else "run"
            self._post_event(RunEvent(f"{prefix}.failed", execution_id=self.state.execution_id,
                                     message=f"{type(exc).__name__}: {exc}"))
        finally:
            self._run_active = False

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
        if not dirty:
            return
        self._pending_regions.update(dirty)
        if self._render_timer is None:
            self._render_timer = self.set_timer(1 / 30, self._flush_render)

    def _flush_render(self) -> None:
        self._render_timer = None
        if self._tesis_closing:
            return
        regions, self._pending_regions = self._pending_regions, set()
        self._notify_drawer_observers()
        if regions:
            try:
                self._render_regions(regions)
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
        if self._render_timer is not None:
            self._render_timer.stop()
            self._render_timer = None
        self._pending_regions.clear()
        with self._event_lock:
            self._tesis_closing = True
            self._event_queue.clear()
        try:
            self.cancel_token.cancel("TUI closed")
        except Exception:
            pass

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
        except Exception as exc:
            self.notify(f"Navigation failed ({type(exc).__name__}).", severity="error")

    def action_launch_single(self) -> None:
        from tesis.tui_forms import LaunchDrawer

        if not self._floor_ok() or self._run_active:
            return
        try:
            self._push_drawer(LaunchDrawer(mode="single"))
        except Exception as exc:
            self.notify(f"Navigation failed ({type(exc).__name__}).", severity="error")

    def action_launch_matrix(self) -> None:
        from tesis.tui_forms import LaunchDrawer

        if not self._floor_ok() or self._run_active:
            return
        try:
            self._push_drawer(LaunchDrawer(mode="matrix"))
        except Exception as exc:
            self.notify(f"Navigation failed ({type(exc).__name__}).", severity="error")

    def action_open_plan(self) -> None:
        from tesis.tui_drawers import PlanDrawer

        if not self._floor_ok() or self._run_active:
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

    def action_open_settings(self) -> None:
        from tesis.tui_forms import SettingsDrawer

        if self._floor_ok() and not self._run_active:
            self._push_drawer(SettingsDrawer())

    def action_open_results(self) -> None:
        from tesis.tui_drawers import ResultsDrawer

        if self._floor_ok():
            self._push_drawer(ResultsDrawer())

    def action_open_trace(self) -> None:
        from tesis.tui_drawers import TraceDrawer

        if self._floor_ok():
            self._push_drawer(TraceDrawer())

    @on(Button.Pressed, "#nav-results, #nav-settings, #nav-logs")
    def open_workspace_action(self, event: Button.Pressed) -> None:
        actions = {"nav-results": self.action_open_results,
                   "nav-settings": self.action_open_settings, "nav-logs": self.action_open_trace}
        actions[event.button.id]()

    @on(Input.Changed, "#mission-command")
    def open_composer(self, event: Input.Changed) -> None:
        if event.value.strip() and self._floor_ok():
            from tesis.tui_commands import CommandLauncher

            event.input.value = ""
            self.app.push_screen(CommandLauncher(query=event.value))

    @on(Tabs.TabActivated, "#workspace-tabs")
    def workspace_tab_changed(self, event: Tabs.TabActivated) -> None:
        pane = (event.tab.id or "tab-pipeline").removeprefix("tab-")
        if pane == self._active_pane:
            return
        self._active_pane = pane
        if self.is_mounted:
            self._update_responsive_layout()

    @on(KeyboardTabs.Confirmed, "#workspace-tabs")
    def enter_workspace_tab(self) -> None:
        self._activate_pane(self._active_pane)

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        pane = {"pipeline-pane": "pipeline", "coordinate-pane": "runs",
                "notice-body": "activity", "evidence-body": "evidence"}.get(event.widget.id or "")
        if pane is not None:
            self._active_pane = pane
            self.query_one("#workspace-tabs", Tabs).active = f"tab-{pane}"

    def action_overview(self) -> None:
        self._activate_pane("pipeline")

    def _pane_target(self, pane: str) -> Any:
        return self.query_one({"pipeline": "#pipeline-pane", "runs": "#coordinate-pane",
                               "evidence": "#evidence-body", "activity": "#notice-body"}[pane])

    def _activate_pane(self, pane: str) -> None:
        if not self._floor_ok():
            return
        self._active_pane = pane
        self.query_one("#workspace-tabs", Tabs).active = f"tab-{pane}"
        self._update_responsive_layout()
        self._pane_target(pane).focus()

    def action_show_pipeline(self) -> None:
        self._activate_pane("pipeline")

    def action_show_coordinates(self) -> None:
        self._activate_pane("runs")

    def action_show_evidence(self) -> None:
        self._activate_pane("evidence")

    def action_show_activity(self) -> None:
        self._activate_pane("activity")

    def _push_drawer(self, drawer: Screen) -> None:
        """BaseDrawer decides its own panel width; the shell only pushes it."""
        try:
            from tesis.tui_commands import open_workspace
            open_workspace(self.app, drawer)
        except Exception as exc:
            self.notify(f"Navigation failed ({type(exc).__name__}).", severity="error")

    def action_inspect(self) -> None:
        """Enter inspects the selected coordinate; nothing selected is a no-op."""
        from tesis.tui_drawers import CoordinateDrawer, EvidenceDrawer

        if not self._floor_ok():
            return
        focused = self.app.focused
        if isinstance(focused, Tabs):
            self._activate_pane(self._active_pane)
        elif focused is self.query_one("#evidence-body"):
            self._push_drawer(EvidenceDrawer())
        elif focused is self.query_one("#notice-body"):
            self.action_open_plan() if self.state.status == "ready" else self.action_open_trace()
        elif self.state.selected_coordinate is not None:
            self._push_drawer(CoordinateDrawer())

    @on(OptionList.OptionSelected, "#pipeline-pane")
    def inspect_stage(self, event: OptionList.OptionSelected) -> None:
        from tesis.tui_drawers import StageDrawer

        row = next((r for r in self.state.stages if r.stage_id == event.option.id), None)
        if row is not None:
            self._push_drawer(StageDrawer(row, self.state.selected_method))

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
        focused = self.app.focused
        if isinstance(focused, Input) and not focused.selection.is_empty:
            focused.action_copy()
            return
        if self._run_active and not self._cancel_requested:
            self.request_cancel()
        elif self._run_active:
            self.app.exit()
        else:
            self.notify("Idle. Use q to quit or Ctrl+Q to force exit.")
