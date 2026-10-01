"""Read-only inspection drawers for the terminal UI."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from threading import Thread
from typing import Any

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, DataTable, Input, Label, Select, Static

from tesis.artifact_repository import ArtifactRepository, config_fingerprint
from tesis.config_loader import load_and_resolve_config
from tesis.runtime_events import redact_secrets
from tesis.tui_commands import BaseDrawer
import tesis.tui_commands as tui_commands
import tesis.tui_security as tui_security
import tesis.tui_state as tui_state


DETAIL_LOG_MAX_LINES = 2_000
DETAIL_RENDER_MAX_CHARS = 500_000
TRACE_MAX_ENTRIES = 500


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
        from tesis.tui_mission import MissionControlScreen

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
        from tesis.tui_mission import _cell

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
        from tesis.tui_mission import _cell

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
        from tesis.tui_mission import MissionControlScreen

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
        self.failure: dict[str, Any] = tui_security._redact_mapping(tui_security._failure_mapping(failure))
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
        from tesis.tui_mission import MissionControlScreen

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
        self._selected_path: Path | None = None
        self._selected_item = None

    def compose(self) -> ComposeResult:
        yield Label("Results (Esc to close)", id="results-title")
        yield Static("—", id="results-summary", markup=False)
        with VerticalScroll(id="results-filter-scroll"):
            with Horizontal(id="results-filters", classes="filters"):
                yield Label("Filters", id="results-filters-label")
                for select_id, _ in self.FILTER_FIELDS:
                    yield Select([], prompt=select_id.removeprefix("filter-"), id=select_id,
                                 allow_blank=True)
        yield DataTable(id="results-table")
        with VerticalScroll(classes="drawer-body"):
            yield Static("Select a row and press Enter for triage detail", id="results-detail", markup=False)
        with Horizontal(id="results-actions"):
            yield Button("Export JSON", id="results-export")
            yield Button("Review payload evidence", id="results-review")
        yield Static("", id="results-status", markup=False)

    def on_mount(self) -> None:
        try:
            table = self.query_one("#results-table", DataTable)
            table.cursor_type = "row"
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
            cfg = load_and_resolve_config(config_path=str(tui_state.CONFIG_PATH), cli_args={})
            return Path(cfg.output_dir)
        except Exception:
            return tui_state.REPOSITORY_ROOT / "results"

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
            ("composite status", first("composite_score_status") or "historical/provisional"),
            ("thesis scoring", f"{safe(first('scoring_mode'))} / {safe(first('thesis_scoring_status'))}"),
            ("final payload / composite", f"{safe(first('Spayload_final'))} / {safe(first('Srun_final'))}"),
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
        self._selected_path = Path(str(getattr(item, "path", "")))
        self._selected_item = item
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

    @on(Button.Pressed, "#results-review")
    def review_evidence(self) -> None:
        if self._selected_path is None:
            self._set_status("Select a run and press Enter before reviewing")
            return
        raw = self._load_artifact(self._selected_item)
        path = Path(raw['source_path']) if raw.get('artifact_type') == 'thesis_score_receipt' and raw.get('source_path') else self._selected_path
        self.app.push_screen(ReviewDrawer(path, receipt_path=(
            self._selected_path if raw.get('artifact_type') == 'thesis_score_receipt' else None)))

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#results-status", Static).update(str(redact_secrets(text))[:300])
        except Exception:
            pass

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True
        self._closing_guard = True
        self._scan_generation += 1


class ReviewDrawer(BaseDrawer):
    """One saved execution, independent review workflows; all disk/model work off-thread."""

    class Loaded(Message):
        def __init__(self, queue, decisions, result):
            super().__init__()
            self.queue, self.decisions, self.result = queue, decisions, result

    class Failed(Message):
        def __init__(self, text):
            super().__init__()
            self.text = text

    def __init__(self, source: Path, *, receipt_path: Path | None = None) -> None:
        super().__init__()
        self.source = Path(source)
        self.receipt_path = receipt_path
        self.output_dir = receipt_path.parent if receipt_path is not None else None
        self.queue = None
        self.result = None
        self.decisions = []
        self._tesis_closing = False
        self._review_busy = False

    def compose(self) -> ComposeResult:
        yield Label("Payload evidence review (Esc to close)")
        with VerticalScroll(classes="drawer-body"):
            yield Static("Loading frozen evidence…", id="review-status", markup=False)
            yield Select([], prompt="Candidate", id="review-candidate")
            yield Static("", id="review-evidence", markup=False)
            yield Select([(str(i), i) for i in range(5)], prompt="Human grade 0–4", id="review-score")
            yield Input(placeholder="Reviewer ID", id="review-reviewer")
            yield Input(placeholder="Reason supported by the evidence", id="review-reason")
            yield Button("Save human grade", id="review-save", disabled=True)
            yield Button("Run configured AI evaluator", id="review-ai", disabled=True)

    def on_mount(self) -> None:
        self.load_review()

    def load_review(self) -> None:
        self._review_busy = True
        Thread(target=self._load_review, name="tesis-review-load", daemon=True).start()

    def _load_review(self) -> None:
        from evaluation.thesis_scoring import review_queue, finalize_reviews, load_review_decisions
        try:
            queue = review_queue(self.source)
            decisions = load_review_decisions(self.source, queue=queue, receipt_path=self.receipt_path)
            result = finalize_reviews(self.source, decisions, output_dir=self.output_dir)
            self.post_message(self.Loaded(queue, decisions, result))
        except Exception as exc:
            self.post_message(self.Failed(f"Review unavailable: {type(exc).__name__}: {exc}"))

    @on(Loaded)
    def review_loaded(self, event: Loaded) -> None:
        self._loaded(event.queue, event.decisions, event.result)

    @on(Failed)
    def review_failed(self, event: Failed) -> None:
        self._review_busy = False
        self._status(event.text)

    def _status(self, text: str) -> None:
        if not self._tesis_closing:
            self.query_one("#review-status", Static).update(str(redact_secrets(text)))

    def _loaded(self, queue, decisions, result) -> None:
        if self._tesis_closing:
            return
        self._review_busy = False
        self.queue, self.decisions, self.result = queue, decisions, result
        pending = [r for r in queue['candidates'] if r['status'] == 'pending_review']
        select = self.query_one("#review-candidate", Select)
        select.set_options([(f"{r['candidate_id']} · ceiling {r['proof_ceiling']}", r['candidate_id']) for r in pending])
        if pending:
            select.value = pending[0]['candidate_id']
        self.query_one("#review-save", Button).disabled = queue['selection'] == 'ai' or not pending
        self.query_one("#review-ai", Button).disabled = queue['selection'] == 'human' or not queue['evaluator'] or not pending
        self._status("\n".join([f"Selection: {queue['selection']} · {queue['rubric_version']} · source SHA256: {queue['source_sha256']}",
            f"Evidence pending: {queue['component_pending_reasons']}",
            *[f"{mode}: {info['status']} · Spayload={info['Spayload_final']} · Srun={info['Srun_final']} · {info['reason'] or ''}"
                for mode, info in result['workflows'].items()]]))
        self.show_candidate()

    @on(Select.Changed, "#review-candidate")
    def show_candidate(self) -> None:
        if not self.queue:
            return
        cid = self.query_one("#review-candidate", Select).value
        row = next((r for r in self.queue['candidates'] if r['candidate_id'] == cid), None)
        if row:
            evidence = {k: row[k] for k in ('candidate', 'proof_ceiling', 'evidence_refs', 'evidence')}
            self.query_one("#review-evidence", Static).update(json.dumps(redact_secrets(evidence), indent=2)[:20000])

    @on(Button.Pressed, "#review-save")
    def submit_grade(self) -> None:
        if not self.queue or self.queue['selection'] == 'ai':
            return
        from datetime import datetime, timezone
        from uuid import uuid4
        cid = self.query_one("#review-candidate", Select).value
        row = next((r for r in self.queue['candidates'] if r['candidate_id'] == cid), None)
        grade = self.query_one("#review-score", Select).value
        if row is None or grade is Select.NULL:
            self._status("Choose a candidate and grade")
            return
        previous = next((d for d in reversed(self.decisions) if d['candidate_id'] == cid and d['scoring_mode'] == 'human'), None)
        decision = {'decision_id': str(uuid4()), 'run_id': self.queue['run_id'],
            'source_sha256': self.queue['source_sha256'], 'rubric_version': self.queue['rubric_version'],
            'scoring_mode': 'human', 'candidate_id': cid, 'score': grade,
            'reviewer_id': self.query_one("#review-reviewer", Input).value,
            'reason': self.query_one("#review-reason", Input).value, 'review_version': 'human.v1',
            'timestamp': datetime.now(timezone.utc).isoformat(), 'evidence_refs': row['evidence_refs']}
        if previous:
            decision['supersedes'] = previous['decision_id']
        self.save_review([decision])

    @on(Button.Pressed, "#review-ai")
    def run_evaluator(self) -> None:
        if self.queue and self.queue['selection'] in {'ai', 'both'}:
            self.save_review([], evaluate=True)

    def save_review(self, additions, evaluate=False) -> None:
        if self._review_busy:
            self._status("Review work is still running")
            return
        self._review_busy = True
        Thread(target=self._save_review, args=(additions, evaluate), name="tesis-review-save", daemon=True).start()

    def _save_review(self, additions, evaluate=False) -> None:
        from evaluation.thesis_scoring import (
            evaluate_queue, review_queue, finalize_reviews, load_review_decisions,
            append_evaluator_decisions, save_evaluator_telemetry,
        )
        try:
            queue = review_queue(self.source)
            decisions = load_review_decisions(self.source, queue=queue, receipt_path=self.receipt_path)
            if evaluate:
                config = load_and_resolve_config(config_path=str(tui_state.CONFIG_PATH), cli_args={})
                judged = evaluate_queue(queue, config.scoring_evaluator)
                save_evaluator_telemetry(self.source, judged, output_dir=self.output_dir)
                decisions = append_evaluator_decisions(decisions, judged['decisions'])
            updated = decisions + additions
            result = finalize_reviews(self.source, updated, output_dir=self.output_dir)
            self.post_message(self.Loaded(queue, updated, result))
        except Exception as exc:
            self.post_message(self.Failed(f"Grade not saved: {type(exc).__name__}: {exc}"))

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True

    def on_unmount(self) -> None:
        self.prepare_shutdown()


class DoctorDrawer(BaseDrawer):
    BINDINGS = [
        Binding("escape", "back", "Stop and close", priority=True),
        Binding("r", "rerun", "Run again"),
        Binding("l", "services", "Check services"),
        Binding("d", "details", "Details"),
    ]

    _CHECK_NAMES = {
        "coverage.scope": ("Supported tests", "Check the supported test methods."),
        "akg.integrity": ("Attack map", "Check the attack map definitions."),
        "graph.compilation": ("Test workflow", "Check how the test steps connect."),
        "payload.static_seeds": ("Built-in test inputs", "Check the saved test inputs."),
        "containment.http": ("Target safety", "Check the allowed target address."),
        "config.profiles_roles": ("AI settings", "Review your models in Settings."),
        "config.credentials": ("API keys", "Add the missing API key in Settings."),
        "config.endpoints": ("Service addresses", "Check the DVWA and AI service addresses."),
        "config.load": ("Saved settings", "Check config.yaml, then try again."),
        "config.redaction": ("Keeping secrets private", "Review your saved API keys."),
        "environment.dependencies": ("Installed packages", "Run uv sync to install the required packages."),
        "output.writability": ("Saving results", "Check the results folder and available disk space."),
        "reasoning.controls": ("AI reasoning settings", "Review the reasoning settings for your models."),
        "live.dvwa.authentication": ("DVWA sign-in", "Check that DVWA is running and the login is correct."),
        "live.dvwa.levels": ("DVWA difficulty levels", "Check the security settings in DVWA."),
        "live.dvwa.surfaces": ("DVWA test pages", "Check that the required DVWA pages are available."),
        "live.model.orchestrator": ("Planning model", "Check the model, API key, and service connection."),
        "live.model.payload_generator": ("Payload model", "Check the model, API key, and service connection."),
    }

    def __init__(self) -> None:
        super().__init__()
        self._doctor_generation = 0
        self._tesis_closing = False
        self._live_armed = False
        self._doctor_worker = None
        self._doctor_process: asyncio.subprocess.Process | None = None
        self._report: dict | None = None
        self._show_details = False

    def compose(self) -> ComposeResult:
        yield Label("Doctor", id="doctor-title", classes="drawer-title")
        yield Static("Checking this computer…", id="doctor-summary", markup=False)
        yield Static("Local checks only. Service connections are not checked.", id="doctor-note", markup=False)
        with VerticalScroll(id="doctor-scroll", classes="drawer-body"):
            yield Static("Starting checks…", id="doctor-results", markup=False)
        with Horizontal(id="doctor-actions"):
            yield Button("Run again", id="doctor-run")
            yield Button("Check services", id="doctor-live")
            yield Button("Details", id="doctor-details", disabled=True)
        yield Static("R rerun · L services · D details · Esc stop/close", classes="drawer-hint")

    def on_mount(self) -> None:
        self.run_offline_pressed()

    def on_unmount(self) -> None:
        self.prepare_shutdown()

    def _stop_checks(self) -> None:
        process = self._doctor_process
        if process is not None and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        worker, self._doctor_worker = self._doctor_worker, None
        if worker is not None:
            worker.cancel()

    def _start_checks(self, live: bool) -> None:
        self._stop_checks()
        self._doctor_generation += 1
        self._report = None
        self.query_one("#doctor-details", Button).disabled = True
        self.query_one("#doctor-summary", Static).update("Checking services…" if live else "Checking this computer…")
        self.query_one("#doctor-note", Static).update(
            "Testing DVWA and AI connections. Esc stops these checks." if live else
            "Local checks only. Service connections are not checked."
        )
        self._render_text("This may take a moment. You can close this panel at any time.")
        self._doctor_worker = self._run_checks(self._doctor_generation, live)

    @work(group="doctor")
    async def _run_checks(self, generation: int, live: bool) -> None:
        # A separate process can be stopped even during a blocking provider call.
        # Capture both streams so SDK logging cannot overwrite the terminal UI.
        process = None
        try:
            command = [sys.executable, "-m", "tesis", "doctor", "--config", str(tui_state.CONFIG_PATH), "--json"]
            if live:
                command.append("--live")
            process = await asyncio.create_subprocess_exec(
                *command, cwd=str(tui_state.REPOSITORY_ROOT),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            self._doctor_process = process
            output, _logs = await process.communicate()
            result = json.loads(output)
            if not isinstance(result, dict) or "checks" not in result:
                raise ValueError("Doctor returned an unreadable report. Please try again.")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            result = {"error": tui_security._safe_config_error_text(exc)}
        finally:
            if process is not None:
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                await process.wait()
                if self._doctor_process is process:
                    self._doctor_process = None
        self._render_result(result, generation)

    def _render_text(self, text: str) -> None:
        self.query_one("#doctor-results", Static).update(str(redact_secrets(text)))

    def _render_result(self, result: dict, generation: int | None = None) -> None:
        if self._tesis_closing or (generation is not None and generation != self._doctor_generation):
            return
        self._report = result
        self.query_one("#doctor-details", Button).disabled = False
        if result.get("error"):
            self.query_one("#doctor-summary", Static).update("Checks couldn’t finish")
            self._render_text(str(result["error"]) if self._show_details else
                              "Try again. Open Details if this keeps happening.")
            return
        summary = result.get("summary", {})
        failed = summary.get("failed", 0)
        headline = f"{failed} check{'s need' if failed != 1 else ' needs'} attention" if failed else "Checks finished"
        counts = f"{summary.get('passed', 0)} passed"
        if summary.get("skipped", 0):
            counts += f" · {summary['skipped']} not checked"
        self.query_one("#doctor-summary", Static).update(f"{headline}\n{counts}")
        lines = []
        for check in result.get("checks", []):
            status = check.get("status", "skipped")
            name, advice = self._CHECK_NAMES.get(check.get("id"), (check.get("summary", "Check"), "Open Details for more information."))
            mark = {"passed": "OK", "failed": "Fix", "skipped": "Not checked"}.get(status, "Not checked")
            lines.append(f"{mark}  {name}")
            if status == "failed":
                lines.append(f"  {advice}")
            if self._show_details:
                lines.extend(f"  {check[key]}" for key in ("summary", "details", "remediation") if check.get(key))
                lines.append("")
        self._render_text("\n".join(lines))

    @on(Button.Pressed, "#doctor-run")
    def run_offline_pressed(self) -> None:
        self._live_armed = False
        self.query_one("#doctor-live", Button).label = "Check services"
        self._start_checks(live=False)

    @on(Button.Pressed, "#doctor-live")
    def run_live_pressed(self) -> None:
        if not self._live_armed:
            self._live_armed = True
            self.query_one("#doctor-live", Button).label = "Confirm checks"
            self.query_one("#doctor-note", Static).update("This contacts DVWA and your AI providers and may use credits. Press again to confirm.")
            return
        self._live_armed = False
        self.query_one("#doctor-live", Button).label = "Check services"
        self._start_checks(live=True)

    @on(Button.Pressed, "#doctor-details")
    def action_details(self) -> None:
        if self._report is not None:
            self._show_details = not self._show_details
            self.query_one("#doctor-details", Button).label = "Less detail" if self._show_details else "Details"
            self._render_result(self._report)

    def action_rerun(self) -> None:
        self.run_offline_pressed()

    def action_services(self) -> None:
        self.run_live_pressed()

    def action_back(self) -> None:
        self.prepare_shutdown()
        super().action_back()

    def prepare_shutdown(self) -> None:
        if self._tesis_closing:
            return
        self._tesis_closing = True
        self._doctor_generation += 1
        self._stop_checks()

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
                cfg = load_and_resolve_config(config_path=str(tui_state.CONFIG_PATH), cli_args={})
            except Exception as exc:
                self._set(f"config error        {tui_security._safe_config_error_text(exc)}")
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
            ("target", tui_security._safe_url(getattr(cfg, "target_url", "—"))),
            ("provider", getattr(cfg, "provider", "—")),
            ("level", getattr(cfg, "level", "—")),
            ("surface", getattr(cfg, "surface", "—")),
            ("payload mode", getattr(cfg, "payload_mode", "—")),
            ("condition", getattr(cfg, "experiment_condition", "—")),
            ("target method", getattr(cfg, "target_method", None) or "—"),
            ("coordinates", tui_state._matrix_coordinate_count(cfg)),
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
            f"{'NAVIGATION':<12}{tui_commands.navigation_hint()}",
            "",
            f"{'COMMAND':<12}{'KEYS':<10}SUMMARY",
        ]
        rows.extend(
            f"{'/' + spec.name:<12}{(spec.keys or '—'):<10}{spec.summary}"
            for spec in tui_commands.COMMANDS
        )
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
