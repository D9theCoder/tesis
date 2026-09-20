"""New opt-in run-console shell (Phase 0 + shell portion of Phase 1).

Legacy screens in :mod:`tesis.tui` are unchanged. This module owns only the
new presentation shell: typed operator intents, the slash-command registry,
pure runtime-event presentation, bounded activity view models, coordinate
helpers, failure/plan text views, and the persistent ``RunConsoleScreen``.

No runtime semantics live here. Command dispatch delegates to the existing
screens/actions via lazy imports so this module never creates an import
cycle with :mod:`tesis.tui`.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from itertools import product
from typing import Any, Callable, Mapping

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.command import DiscoveryHit, Hit, Hits, Provider
from textual.containers import Vertical
from textual.screen import ModalScreen, Screen
from textual.suggester import SuggestFromList
from textual.widgets import Input, Label, RichLog, Static

from llm.diagnostics import redact_diagnostic_text, sanitize_endpoint
from tesis.runtime_events import RunEvent, redact_secrets
from textual.theme import Theme

SHELL_MONO_THEME = Theme(
    name="tesis-mono",
    # Explicit hex monochrome: black surface, white text. Never ansi_* names:
    # builtin textual-ansi resolves to ansi_default, which exports as
    # black-on-black SVG (see docs/tui_shell_2026-09-20). Hex keeps the
    # NO_COLOR-compatible capture genuinely readable.
    primary="#FFFFFF",
    secondary="#B0B0B0",
    warning="#FFFFFF",
    error="#FFFFFF",
    success="#FFFFFF",
    accent="#FFFFFF",
    foreground="#FFFFFF",
    background="#000000",
    surface="#000000",
    panel="#111111",
    boost="#222222",
    dark=True,
)

SHELL_MONO_THEME_NAME = SHELL_MONO_THEME.name



TRANSCRIPT_MAX_ENTRIES = 500

COMPOSER_HISTORY_LIMIT = 100


@dataclass(frozen=True)
class OperatorIntent:
    """A typed operator request emitted by the shell."""

    name: str
    args: str = ""


@dataclass(frozen=True)
class CommandSpec:
    name: str
    title: str
    summary: str
    synonyms: tuple[str, ...] = ()
    disabled_reason: str | None = None

    @property
    def enabled(self) -> bool:
        return self.disabled_reason is None


COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec("run", "Configure and start a single experiment",
                "Open the existing single-run setup screen"),
    CommandSpec("matrix", "Configure and start a matrix",
                "Open the existing matrix setup screen"),
    CommandSpec("plan", "Preview the fully resolved execution plan",
                "Show resolved coordinates, models, budgets, and outputs"),
    CommandSpec("cancel", "Request graceful cancellation",
                "Cancel the active run when one is attached"),
    CommandSpec("coordinates", "Inspect/filter matrix coordinates",
                "Open the coordinate table overlay"),
    CommandSpec("failure", "Inspect the active or most recent failure",
                "Open the structured failure inspector"),
    CommandSpec("details", "Toggle expanded runtime details",
                "Expand or collapse transcript detail rows"),
    CommandSpec("doctor", "Run offline Doctor",
                "Open validation; live mode still requires explicit selection there",
                synonyms=("validate",)),
    CommandSpec("results", "Browse completed runs",
                "Open the existing recent-results screen"),
    CommandSpec("resume", "Resume a durable run",
                "Reserved until durable resume lands",
                disabled_reason="Resume is disabled: durable resume is not implemented yet."),
    CommandSpec("retry", "Retry a failed coordinate",
                "Reserved until safe targeted retry exists",
                disabled_reason="Retry is disabled: safe targeted retry is not implemented yet."),
    CommandSpec("model", "Choose effective provider/model settings",
                "Open settings for provider/model profiles"),
    CommandSpec("settings", "Edit validated configuration",
                "Open the existing settings screen"),
    CommandSpec("export", "Export the selected run/artifact",
                "Open results; export actions live on the result detail screen"),
    CommandSpec("info", "Show framework information",
                "Open the existing framework information screen"),
    CommandSpec("help", "Commands and keybindings",
                "Show commands and keybindings"),
    CommandSpec("quit", "Quit", "Exit safely"),
)
_COMMANDS_BY_NAME: dict[str, CommandSpec] = {c.name: c for c in COMMANDS}


def find_command(name: str) -> CommandSpec | None:
    return _COMMANDS_BY_NAME.get(name.lstrip("/").lower())


def suggest_commands(prefix: str) -> list[str]:
    """Return slash-command suggestions for a composer prefix."""
    needle = prefix.lstrip().lower()
    if not needle.startswith("/"):
        return []
    stem = needle[1:]
    return [f"/{c.name}" for c in COMMANDS if c.name.startswith(stem)]


def parse_composer_text(text: str) -> OperatorIntent | None:
    """Parse composer input into a typed intent; None when not a command."""
    stripped = text.strip()
    if not stripped.startswith("/"):
        return None
    parts = stripped[1:].split(None, 1)
    if not parts or not parts[0]:
        return None
    spec = find_command(parts[0])
    if spec is None:
        return None
    return OperatorIntent(name=spec.name, args=parts[1] if len(parts) > 1 else "")


def help_lines() -> list[str]:
    lines = ["Commands (same intents as Ctrl+P palette):"]
    for spec in COMMANDS:
        marker = "" if spec.enabled else " [disabled]"
        lines.append(f"  /{spec.name:<12} {spec.summary}{marker}")
    lines.append("")
    lines.append("Keys: / complete · Ctrl+P palette · ? help · Ctrl+O details · Esc back · Ctrl+C cancel")
    return lines


@dataclass(frozen=True)
class ActivityEntry:
    entry_id: str
    summary: str
    status: str = "queued"  # queued|active|completed|warning|failed
    detail_rows: tuple[str, ...] = ()
    timestamp: float = 0.0
    coordinate_id: str = ""
    node: str = ""
    kind: str = ""
    duration_ms: int | None = None
    token_usage: str | None = None
    failure_class: str | None = None
    expandable: bool = False
    default_expanded: bool = False


STATUS_GLYPH = {
    "queued": "○",
    "active": "●",
    "completed": "✓",
    "warning": "!",
    "failed": "×",
}


@dataclass
class ActivityTranscriptModel:
    """Bounded in-memory transcript; the artifact journal stays complete."""

    max_entries: int = TRANSCRIPT_MAX_ENTRIES
    _entries: deque[ActivityEntry] = field(default_factory=deque)

    def append(self, entry: ActivityEntry) -> None:
        self._entries.append(entry)
        while len(self._entries) > self.max_entries:
            self._entries.popleft()

    def __len__(self) -> int:
        return len(self._entries)

    def rows(self) -> list[str]:
        return [f"{STATUS_GLYPH.get(e.status, '○')} {e.summary}" for e in self._entries]


@dataclass(frozen=True)
class ContextHeaderModel:
    run_label: str = "no active run"
    status: str = "IDLE"
    progress: str = ""

    def render(self) -> str:
        parts = f"TESIS  {self.run_label}"
        right = "  ".join(p for p in (self.status, self.progress) if p)
        return f"{parts}   {right}" if right else parts


@dataclass(frozen=True)
class StatusLineModel:
    text: str = "Type / for commands or Ctrl+P for actions"

    def render(self) -> str:
        return self.text


_SECRET_DETAIL_KEYS = frozenset({
    "api_key", "secret", "token", "password", "authorization",
    "prompt", "prompts", "response", "messages", "message_body",
    "system_prompt", "generation_prompts",
})


def _safe_text(value: Any, *, limit: int = 220) -> str:
    return redact_diagnostic_text(redact_secrets(value), limit=limit)


def _status_for_event(event_type: str) -> str:
    if event_type.endswith(".failed") or event_type.endswith(".failure"):
        return "failed"
    if event_type.endswith(".cancelled"):
        return "warning"
    if event_type.endswith((".finished", ".completed", ".complete")):
        return "completed"
    if event_type.endswith((".started", ".running", ".active")):
        return "active"
    if "fallback" in event_type or "guardrail" in event_type or "containment" in event_type:
        return "warning"
    return "queued"


def present_event(event: RunEvent) -> list[ActivityEntry]:
    """Present one runtime event as zero or more activity entries (pure).

    Suppresses high-frequency ``llm.token`` and raw ``graph.state``
    snapshots; every other event maps to exactly one bounded, redacted
    entry. Never raises on malformed data.
    """
    try:
        etype = str(event.event_type or "")
    except Exception:
        return []
    if etype in {"llm.token", "graph.state"}:
        return []
    try:
        data = dict(event.data or {})
    except Exception:
        data = {}
    safe_data = redact_secrets(data)
    if not isinstance(safe_data, dict):
        safe_data = {}
    node = str(event.node or safe_data.get("node") or "")
    method = str(event.method or safe_data.get("method") or "")
    coordinate = str(
        safe_data.get("coordinate_id") or event.run_id or event.execution_id or ""
    )
    status = _status_for_event(etype)
    kind = etype.split(".")[0] if "." in etype else etype
    raw_message = str(event.message or "")
    summary_core = raw_message.strip() or etype
    label = node or method or kind or "run"
    summary = _safe_text(f"{label}: {summary_core}", limit=160)
    details: list[str] = []
    for key in ("provider", "model", "model_profile", "role", "reason",
                "next_agent", "selected_method", "failure_class", "error_type",
                "cause_type", "http_status", "status_code", "request_id",
                "parse_status", "call_id", "attempts", "elapsed_ms",
                "call_duration_ms", "queue_wait_ms", "structured_output_mode",
                "status", "completed", "total"):
        if key in safe_data and safe_data[key] not in (None, ""):
            if key.lower() in _SECRET_DETAIL_KEYS:
                continue
            details.append(f"{key}: {_safe_text(safe_data[key], limit=120)}")
    endpoint = safe_data.get("endpoint")
    if endpoint:
        clean = sanitize_endpoint(endpoint)
        details.append(f"endpoint: {clean or 'N/A'}")
    if method and node and method != node:
        details.insert(0, f"method: {_safe_text(method, limit=120)}")
    details = details[:12]
    duration = safe_data.get("elapsed_ms", safe_data.get("call_duration_ms"))
    try:
        duration_ms = int(duration) if duration is not None else None
    except (TypeError, ValueError):
        duration_ms = None
    usage = safe_data.get("provider_usage")
    token_usage = _safe_text(usage, limit=120) if usage else None
    failure_class = safe_data.get("failure_class")
    try:
        ts = float(event.timestamp or 0.0)
    except (TypeError, ValueError):
        ts = 0.0
    entry_id = f"{event.execution_id or 'run'}:{etype}:{ts:.3f}"
    return [ActivityEntry(
        entry_id=entry_id,
        summary=summary,
        status=status,
        detail_rows=tuple(details),
        timestamp=ts,
        coordinate_id=coordinate,
        node=node,
        kind=kind,
        duration_ms=duration_ms,
        token_usage=token_usage,
        failure_class=str(failure_class) if failure_class else None,
        expandable=bool(details),
        default_expanded=etype in {"run.failed", "llm.failed"},
    )]


@dataclass(frozen=True)
class CoordinateRow:
    coordinate_id: str
    provider: str = ""
    surface: str = ""
    level: str = ""
    mode: str = ""
    status: str = "queued"  # queued|active|completed|failed|cancelled|skipped
    detail: str = ""

    def render(self, narrow: bool = False) -> str:
        glyph = STATUS_GLYPH.get(
            {"completed": "completed", "failed": "failed", "active": "active",
             "cancelled": "warning", "skipped": "warning"}.get(self.status, "queued"),
            "○",
        )
        if narrow:
            return f"{glyph} {self.coordinate_id} {self.status}"
        base = f"{glyph} {self.coordinate_id}  {self.provider}/{self.level} {self.surface}/{self.mode}  {self.status}"
        return f"{base}  {self.detail}" if self.detail else base


@dataclass(frozen=True)
class CoordinateFilter:
    status: str = ""  # empty = all
    provider: str = ""
    surface: str = ""
    level: str = ""
    mode: str = ""
    failure_class: str = ""

    def matches(self, row: CoordinateRow, failure_class: str = "") -> bool:
        if self.status and row.status != self.status:
            return False
        if self.provider and row.provider != self.provider:
            return False
        if self.surface and row.surface != self.surface:
            return False
        if self.level and row.level != self.level:
            return False
        if self.mode and row.mode != self.mode:
            return False
        if self.failure_class and failure_class != self.failure_class:
            return False
        return True


def filter_coordinates(
    rows: list[CoordinateRow],
    filt: CoordinateFilter,
    failure_by_id: Mapping[str, str] | None = None,
) -> list[CoordinateRow]:
    failure_by_id = failure_by_id or {}
    return [r for r in rows if filt.matches(r, failure_by_id.get(r.coordinate_id, ""))]


def summarize_coordinates(rows: list[CoordinateRow]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.status] = counts.get(row.status, 0) + 1
    total = len(rows)
    done = sum(counts.get(k, 0) for k in ("completed", "failed", "cancelled", "skipped"))
    return {
        "total": total,
        "completed": counts.get("completed", 0),
        "failed": counts.get("failed", 0),
        "cancelled": counts.get("cancelled", 0),
        "skipped": counts.get("skipped", 0),
        "queued_or_active": total - done,
        "tokens": "N/A",  # honest: shell never invents token totals
        "cost": "N/A",
    }


def expand_coordinates(config: Any) -> list[CoordinateRow]:
    """Expand an EngagementConfig into deterministic coordinate rows (pure)."""
    try:
        matrix = bool(getattr(config, "matrix", False))
    except Exception:
        return []
    if not matrix:
        provider = str(getattr(config, "provider", "") or "")
        return [CoordinateRow(
            coordinate_id="single",
            provider=provider,
            surface=str(getattr(config, "surface", "") or ""),
            level=str(getattr(config, "level", "") or ""),
            mode=str(getattr(config, "payload_mode", "") or ""),
        )]
    providers = sorted(str(p) for p in (getattr(config, "providers", []) or []))
    levels = sorted(str(v) for v in (getattr(config, "levels", []) or []))
    surfaces = sorted(str(s) for s in (getattr(config, "surfaces", []) or []))
    modes = sorted(str(m) for m in (getattr(config, "payload_modes", []) or []))
    try:
        repeats = max(0, int(getattr(config, "repeats", 1) or 0))
    except (TypeError, ValueError):
        repeats = 0
    if not (providers and levels and surfaces and modes and repeats > 0):
        return []
    rows: list[CoordinateRow] = []
    for index, (provider, surface, level, mode, rep) in enumerate(
        product(providers, surfaces, levels, modes, range(repeats))
    ):
        rows.append(CoordinateRow(
            coordinate_id=f"{index:02d}-{provider}-{surface}-{level}-{mode}-r{rep}",
            provider=provider, surface=surface, level=level, mode=mode,
        ))
    return rows


def format_failure_lines(failure: Mapping[str, Any]) -> list[str]:
    """Render a canonical failure envelope as redacted label lines."""
    get = lambda key: failure.get(key)
    lines = [
        f"remediation: {_safe_text(get('remediation') or 'Check the provider profile and retry.', limit=300)}",
        f"failure class: {_safe_text(get('failure_class') or 'unknown', limit=120)}",
        f"provider: {_safe_text(get('provider') or 'N/A', limit=120)}",
        f"model: {_safe_text(get('model') or 'N/A', limit=160)}",
        f"profile: {_safe_text(get('model_profile') or 'N/A', limit=120)}",
        f"role: {_safe_text(get('role') or 'N/A', limit=80)}",
        f"run: {_safe_text(get('run_id') or 'N/A', limit=120)}",
        f"coordinate: {_safe_text(get('coordinate_id') or 'N/A', limit=160)}",
        f"call: {_safe_text(get('call_id') or 'N/A', limit=160)}",
        f"endpoint: {sanitize_endpoint(get('endpoint')) or 'N/A'}",
        f"attempts: {get('attempts') if get('attempts') is not None else 'N/A'}  "
        f"max retries: {get('max_retries') if get('max_retries') is not None else 'N/A'}  "
        f"timeout: {get('timeout_s') if get('timeout_s') is not None else 'N/A'}  "
        f"elapsed: {get('elapsed_ms') if get('elapsed_ms') is not None else 'N/A'}",
        f"http status: {get('http_status') if get('http_status') is not None else 'N/A'}  "
        f"request id: {_safe_text(get('request_id') or 'N/A', limit=120)}",
        f"parse status: {_safe_text(get('parse_status') or 'N/A', limit=80)}",
        f"message: {_safe_text(get('message') or 'provider call failed', limit=400)}",
    ]
    return lines


def build_plan_preview(config: Any) -> list[str]:
    """Build resolved plan lines from a loaded EngagementConfig (pure-ish)."""
    from tesis.artifact_repository import config_fingerprint
    from tesis.live_runtime import safe_target_scope

    lines: list[str] = []
    try:
        matrix = bool(getattr(config, "matrix", False))
    except Exception:
        return ["plan unavailable: invalid configuration"]
    lines.append("Run matrix" if matrix else "Run single experiment")
    lines.append("")
    lines.append(f"Condition: {getattr(config, 'experiment_condition', 'N/A')}")
    if matrix:
        lines.append(f"Providers: {', '.join(getattr(config, 'providers', []) or ['N/A'])}")
        lines.append(f"Surfaces: {', '.join(getattr(config, 'surfaces', []) or ['N/A'])}")
        lines.append(f"Levels: {', '.join(getattr(config, 'levels', []) or ['N/A'])}")
        lines.append(f"Methods: {getattr(config, 'target_method', None) or 'all applicable'}")
        lines.append(f"Modes: {', '.join(getattr(config, 'payload_modes', []) or ['N/A'])}")
        lines.append(f"Repeats: {getattr(config, 'repeats', 'N/A')}")
    else:
        lines.append(f"Provider: {getattr(config, 'provider', 'N/A')}")
        lines.append(f"Surface: {getattr(config, 'surface', 'N/A')}")
        lines.append(f"Level: {getattr(config, 'level', 'N/A')}")
        lines.append(f"Method: {getattr(config, 'target_method', None) or 'automatic'}")
        lines.append(f"Mode: {getattr(config, 'payload_mode', 'N/A')}")
    runtime = getattr(config, "llm_runtime", None)
    try:
        max_conc = getattr(runtime, "max_concurrency", 1) if runtime is not None else 1
        scope = getattr(runtime, "cache_scope", "none") if runtime is not None else "none"
    except Exception:
        max_conc, scope = 1, "none"
    lines.append(f"Budgets: candidates={getattr(config, 'candidate_budget', 'N/A')} "
                 f"iterations={getattr(config, 'iterations', 'N/A')} "
                 f"concurrency={max_conc} cache={scope}")
    lines.append(f"Target scope: {safe_target_scope(str(getattr(config, 'target_url', '')))}")
    lines.append(f"Output: {getattr(config, 'output_dir', 'N/A')}")
    try:
        import dataclasses
        fingerprint = config_fingerprint(dataclasses.asdict(config))
    except Exception:
        fingerprint = "N/A"
    lines.append(f"Config fingerprint: {fingerprint}")
    rows = expand_coordinates(config)
    lines.append("")
    if not rows:
        lines.append("0 coordinates: select at least one provider, surface, level, mode, and repeat.")
    else:
        lines.append(f"{len(rows)} coordinates (estimate: model calls vary by method flow):")
        for row in rows[:40]:
            lines.append(f"  {row.coordinate_id}")
        if len(rows) > 40:
            lines.append(f"  … and {len(rows) - 40} more (full list in artifact manifest)")
    lines.append("")
    lines.append("Estimated calls: 2-4 per coordinate (estimate, never a guarantee)")
    return lines


def dispatch_intent(screen: Screen, intent: OperatorIntent) -> str:
    """Route an intent to an existing screen/overlay. Returns a status line."""
    spec = find_command(intent.name)
    if spec is not None and not spec.enabled:
        return spec.disabled_reason or f"/{spec.name} is disabled"
    if intent.name == "run":
        from tesis.tui import RunSetupScreen
        screen.app.push_screen(RunSetupScreen(matrix=False))
        return "Opened single-run setup"
    if intent.name == "matrix":
        from tesis.tui import RunSetupScreen
        screen.app.push_screen(RunSetupScreen(matrix=True))
        return "Opened matrix setup"
    if intent.name == "plan":
        try:
            from tesis.config_loader import load_and_resolve_config
            from tesis.tui import CONFIG_PATH
            cfg = load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={})
            lines = build_plan_preview(cfg)
        except Exception as exc:
            from tesis.tui import _safe_config_error_text
            lines = ["Plan unavailable:", _safe_config_error_text(exc)]
        screen.app.push_screen(PlanPreviewScreen(lines))
        return "Opened resolved plan preview"
    if intent.name == "cancel":
        cancel = getattr(screen, "request_shell_cancel", None)
        if callable(cancel):
            return str(cancel())
        legacy_cancel = getattr(screen, "request_cancel", None)
        if callable(legacy_cancel):
            legacy_cancel()
            return "Cancellation requested — waiting for the active operation to return"
        return "Nothing running — composer is idle"
    if intent.name == "coordinates":
        rows = list(getattr(screen, "coordinate_rows", []) or [])
        filt = getattr(screen, "coordinate_filter", CoordinateFilter())
        if not isinstance(filt, CoordinateFilter):
            filt = CoordinateFilter()
        screen.app.push_screen(CoordinateOverlayScreen(rows, filt))
        return f"Opened coordinates ({len(rows)} rows)"
    if intent.name == "failure":
        failure = getattr(screen, "last_failure", None)
        lines = format_failure_lines(failure) if isinstance(failure, Mapping) else [
            "No active failure.",
            "Run an experiment or wait for a provider error to inspect it here.",
        ]
        screen.app.push_screen(FailureInspectorScreen(lines))
        return "Opened failure inspector"
    if intent.name == "details":
        toggle = getattr(screen, "toggle_details", None)
        if callable(toggle):
            return str(toggle())
        return "Details toggled"
    if intent.name == "doctor":
        from tesis.tui import ValidationScreen
        screen.app.push_screen(ValidationScreen())
        return "Opened validation (Doctor offline by default)"
    if intent.name == "results":
        from tesis.tui import RecentResultsScreen
        screen.app.push_screen(RecentResultsScreen())
        return "Opened recent results"
    if intent.name == "model":
        from tesis.tui import SettingsScreen
        screen.app.push_screen(SettingsScreen())
        return "Opened settings for provider/model profiles"
    if intent.name == "settings":
        from tesis.tui import SettingsScreen
        screen.app.push_screen(SettingsScreen())
        return "Opened settings"
    if intent.name == "export":
        from tesis.tui import RecentResultsScreen
        screen.app.push_screen(RecentResultsScreen())
        return "Opened results; use Export on a result detail screen"
    if intent.name == "info":
        from tesis.tui import FrameworkInfoScreen
        screen.app.push_screen(FrameworkInfoScreen())
        return "Opened framework information"
    if intent.name == "help":
        screen.app.push_screen(ShellHelpScreen())
        return "Opened help"
    if intent.name == "quit":
        screen.app.exit()
        return "Exiting"
    return f"Unknown command: /{intent.name}"


class TesisShellProvider(Provider):
    """Palette provider sourcing every action from the command registry."""

    def _callback(self, spec_name: str) -> Callable[[], None]:
        screen = self.screen

        def _run() -> None:
            dispatch_intent(screen, OperatorIntent(name=spec_name))

        return _run

    async def discover(self) -> Hits:
        for spec in COMMANDS:
            yield DiscoveryHit(spec.title, self._callback(spec.name), help=spec.summary)

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        for spec in COMMANDS:
            haystack = f"{spec.title} /{spec.name} {' '.join(spec.synonyms)}"
            if (match := matcher.match(haystack)) > 0:
                yield Hit(
                    match,
                    matcher.highlight(spec.title),
                    self._callback(spec.name),
                    help=f"/{spec.name} — {spec.summary}",
                )


class _OverlayBase(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss_overlay", "Close", show=True)]

    def __init__(self, lines: list[str], title: str) -> None:
        super().__init__()
        self._lines = list(lines)
        self._title = title

    def compose(self) -> ComposeResult:
        with Vertical(classes="shell-overlay"):
            yield Label(self._title, classes="shell-overlay-title")
            yield Static("\n".join(self._lines) or "(empty)", classes="shell-overlay-body")
            yield Label("Esc closes", classes="shell-overlay-hint")

    def action_dismiss_overlay(self) -> None:
        self.dismiss(None)


class ShellHelpScreen(_OverlayBase):
    def __init__(self) -> None:
        super().__init__(help_lines(), "Run console help")


class PlanPreviewScreen(_OverlayBase):
    def __init__(self, lines: list[str]) -> None:
        super().__init__(lines, "Resolved plan preview")


class FailureInspectorScreen(_OverlayBase):
    def __init__(self, lines: list[str]) -> None:
        super().__init__(lines, "Failure inspector")


class CoordinateOverlayScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "dismiss_overlay", "Close", show=True)]

    def __init__(self, rows: list[CoordinateRow], filt: CoordinateFilter) -> None:
        super().__init__()
        self._rows = list(rows)
        self._filter = filt

    def compose(self) -> ComposeResult:
        with Vertical(classes="shell-overlay"):
            yield Label("Coordinates", classes="shell-overlay-title")
            shown = filter_coordinates(self._rows, self._filter)
            summary = summarize_coordinates(shown)
            yield Static(
                f"{summary['completed']}/{summary['total']} done · "
                f"failed {summary['failed']} · tokens {summary['tokens']}",
                classes="shell-overlay-hint",
            )
            body = "\n".join(r.render() for r in shown[:60]) or "No coordinates match the filter."
            if len(shown) > 60:
                body += f"\n… and {len(shown) - 60} more"
            yield Static(body, classes="shell-overlay-body")
            yield Label("Esc closes", classes="shell-overlay-hint")

    def action_dismiss_overlay(self) -> None:
        self.dismiss(None)


class RunConsoleScreen(Screen):
    """Opt-in persistent shell. Transcript starts empty and bounded."""

    CSS_PATH = "tui_shell.tcss"
    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("ctrl+c", "cancel_runtime", "Cancel", show=True, priority=True),
        Binding("question_mark", "show_help", "Help", show=True),
        Binding("ctrl+o", "toggle_details", "Details", show=True),
        Binding("ctrl+t", "show_coordinates", "Coordinates", show=True),
        Binding("ctrl+f", "show_failure", "Failure", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.transcript_model = ActivityTranscriptModel()
        self.header_model = ContextHeaderModel()
        self.status_model = StatusLineModel()
        self.details_expanded = False
        self.coordinate_rows: list[CoordinateRow] = []
        self.coordinate_filter = CoordinateFilter()
        self.last_failure: dict[str, Any] | None = None
        self.composer_history: list[str] = []
        self._history_cursor = 0
        self._history_draft = ""

    def compose(self) -> ComposeResult:
        yield Label(self.header_model.render(), id="console-header")
        yield Static("", id="console-coords")
        yield RichLog(markup=False, max_lines=TRANSCRIPT_MAX_ENTRIES,
                      id="console-transcript")
        yield Static("No activity yet. Type / for commands.", id="console-empty")
        yield Input(
            placeholder="Type / for commands or Ctrl+P for actions",
            id="console-composer",
            suggester=SuggestFromList([f"/{c.name}" for c in COMMANDS],
                                      case_sensitive=False),
        )
        yield Static(self.status_model.render(), id="console-status")
        yield Static("/ complete · Ctrl+P actions · ? help · Ctrl+O details", id="console-hints")

    def on_mount(self) -> None:
        self.query_one("#console-composer", Input).focus()
        try:
            from tesis.config_loader import load_and_resolve_config
            from tesis.tui import CONFIG_PATH
            self.coordinate_rows = expand_coordinates(
                load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={}))
        except Exception:
            self.coordinate_rows = []
        self._apply_layout(self.size.width)
        self._render_coords()

    def on_resize(self, event: Any) -> None:
        self._apply_layout(event.size.width)

    def _apply_layout(self, width: int) -> None:
        # Single centralized layout policy: exactly one mode class.
        self.set_class(width < 80, "narrow")
        self.set_class(80 <= width < 120, "standard")
        self.set_class(width >= 120, "wide")
        self._render_coords()

    def _render_coords(self) -> None:
        try:
            widget = self.query_one("#console-coords", Static)
        except Exception:
            return
        if not self.has_class("wide"):
            widget.update("")
            return
        shown = filter_coordinates(self.coordinate_rows, self.coordinate_filter)[:8]
        if not shown:
            widget.update("coords: none — /coordinates for the full table")
            return
        summary = summarize_coordinates(self.coordinate_rows)
        head = f"coords {summary['completed']}/{summary['total']} done · failed {summary['failed']}"
        widget.update(head + "\n" + "\n".join(r.render() for r in shown))

    @on(Input.Submitted, "#console-composer")
    def submit_composer(self, event: Input.Submitted) -> None:
        text = event.value
        event.input.value = ""
        if text.strip():
            self._remember_composer_text(text.strip())
        intent = parse_composer_text(text)
        if intent is None:
            if text.strip():
                self._set_status(f"Not a command: {text.strip()[:60]} — type /help")
            return
        self._set_status(dispatch_intent(self, intent))

    def _remember_composer_text(self, text: str) -> None:
        self.composer_history.append(text)
        del self.composer_history[:-COMPOSER_HISTORY_LIMIT]
        self._history_cursor = len(self.composer_history)
        self._history_draft = ""

    def _step_composer_history(self, step: int) -> None:
        try:
            composer = self.query_one("#console-composer", Input)
        except Exception:
            return
        if step < 0 and self._history_cursor == len(self.composer_history):
            self._history_draft = composer.value
        target = self._history_cursor + step
        target = max(0, min(len(self.composer_history), target))
        self._history_cursor = target
        composer.value = (
            self.composer_history[target] if target < len(self.composer_history)
            else self._history_draft
        )

    def on_key(self, event: Any) -> None:
        focused = getattr(self, "focused", None)
        try:
            composer = self.query_one("#console-composer", Input)
        except Exception:
            return
        if focused is not composer or not self.composer_history:
            return
        key = getattr(event, "key", "")
        # Plain Up/Down only: keep text entry and suggester behavior intact.
        if key == "up":
            event.prevent_default()
            self._step_composer_history(-1)
        elif key == "down":
            event.prevent_default()
            self._step_composer_history(1)

    def push_transcript_event(self, event: RunEvent) -> None:
        for entry in present_event(event):
            self.transcript_model.append(entry)
            try:
                log = self.query_one("#console-transcript", RichLog)
                log.write(f"{STATUS_GLYPH.get(entry.status, '○')} {entry.summary}")
                if self.details_expanded:
                    for row in entry.detail_rows:
                        log.write(f"  {row}")
                self.query_one("#console-empty", Static).update("")
            except Exception:
                pass
        failure = None
        try:
            failure = (event.data or {}).get("failure")
        except Exception:
            failure = None
        if isinstance(failure, Mapping) and failure:
            self.last_failure = dict(failure)

    def toggle_details(self) -> str:
        self.details_expanded = not self.details_expanded
        state = "expanded" if self.details_expanded else "collapsed"
        self._set_status(f"Details {state}")
        return f"Details {state}"

    def _find_run_controller(self) -> Any | None:
        """Return the nearest stacked screen owning legacy cancel behavior."""
        try:
            stack = list(getattr(self.app, "screen_stack", []) or [])
        except Exception:
            return None
        for other in reversed(stack):
            if other is self:
                continue
            if getattr(other, "completed", False):
                continue
            cancel = getattr(other, "request_cancel", None)
            if callable(cancel):
                return other
        return None

    def request_shell_cancel(self) -> str:
        controller = self._find_run_controller()
        if controller is not None:
            controller.request_cancel()
            self._set_status("Cancellation requested — waiting for the active operation to return")
            return "Cancellation requested — waiting for the active operation to return"
        self._set_status("Nothing running — composer is idle")
        return "Nothing running — composer is idle"

    def action_show_help(self) -> None:
        composer = self.query_one("#console-composer", Input)
        if not composer.value.strip():
            self.app.push_screen(ShellHelpScreen())

    def action_back(self) -> None:
        if len(self.app.screen_stack) > 1:
            self.app.pop_screen()

    def action_cancel_runtime(self) -> None:
        self._set_status(self.request_shell_cancel())

    def action_toggle_details(self) -> None:
        self.toggle_details()

    def action_show_coordinates(self) -> None:
        self._set_status(dispatch_intent(self, OperatorIntent(name="coordinates")))

    def action_show_failure(self) -> None:
        self._set_status(dispatch_intent(self, OperatorIntent(name="failure")))

    def _set_status(self, text: str) -> None:
        self.status_model = StatusLineModel(text=text)
        try:
            self.query_one("#console-status", Static).update(text)
        except Exception:
            pass


__all__ = [
    "COMMANDS",
    "COMPOSER_HISTORY_LIMIT",
    "ActivityEntry",
    "ActivityTranscriptModel",
    "CommandSpec",
    "ContextHeaderModel",
    "CoordinateFilter",
    "CoordinateOverlayScreen",
    "CoordinateRow",
    "FailureInspectorScreen",
    "OperatorIntent",
    "PlanPreviewScreen",
    "RunConsoleScreen",
    "SHELL_MONO_THEME",
    "SHELL_MONO_THEME_NAME",
    "ShellHelpScreen",
    "StatusLineModel",
    "TRANSCRIPT_MAX_ENTRIES",
    "TesisShellProvider",
    "build_plan_preview",
    "dispatch_intent",
    "expand_coordinates",
    "filter_coordinates",
    "find_command",
    "format_failure_lines",
    "help_lines",
    "parse_composer_text",
    "present_event",
    "suggest_commands",
    "summarize_coordinates",
]
