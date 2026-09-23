"""Read-only inspection drawers for the terminal UI."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Thread
from typing import Any

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, DataTable, Label, Select, Static

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
        return load_and_resolve_config(config_path=str(tui_state.CONFIG_PATH), cli_args={})

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
            result = {"checks": [], "summary": {}, "error": tui_security._safe_config_error_text(exc)}
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
