"""Full-screen Textual interface for configuring and observing TESIS runs."""

from __future__ import annotations

import dataclasses
import inspect
import json
import logging
import tempfile
from collections import deque
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from threading import Lock, Thread
from time import monotonic
from typing import Any

import httpx
from rich.syntax import Syntax
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.message import Message
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    OptionList,
    ProgressBar,
    RichLog,
    Select,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)
from textual.widgets.option_list import Option

from core.graph_builder import RUNTIME_AGENT_HANDLERS, RUNTIME_AGENT_NODE_NAMES
from core.state import new_default_state
from evaluation.multi_llm_runner import run_provider_matrix
from evaluation.runner import run_single_engagement
from tesis.artifact_repository import ArtifactMetadata, ArtifactRepository
from tesis.artifact_layout import allocate_artifact_layout
from tesis.config_loader import (
    ConfigError,
    dump_yaml_config,
    load_and_resolve_config,
    load_yaml_config,
    parse_yaml_config,
    save_yaml_config,
)
from tesis.config_fields import (
    EXPERIMENT_CONDITIONS,
    LOG_VERBOSITY_CHOICES,
    METHOD_CHOICES,
    PAYLOAD_MODE_CHOICES,
    PROVIDER_CHOICES,
    SECURITY_LEVEL_CHOICES,
    SURFACE_CHOICES,
)
from tesis.model_config import EngagementConfig, ModelConfig
from tesis.runtime_events import CallbackEventSink, CancellationToken, RunEvent, redact_secrets


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPOSITORY_ROOT / "config.yaml"

# Rendering every provider token as its own Textual message and RichLog row can
# overwhelm terminal emulators.  Keep UI refreshes comfortably below terminal
# frame rates while the runner continues to retain the canonical event stream.
UI_EVENT_FLUSH_INTERVAL = 0.075
UI_EVENT_BATCH_SIZE = 256
UI_PENDING_EVENT_MAX = 2_048
UI_INGRESS_TOKEN_CHARS = 4_096
STREAM_LOG_MAX_LINES = 500
TRACE_LOG_MAX_LINES = 2_000
TRACE_BUFFER_MAX_ENTRIES = 1_000
TRACE_BUFFER_MAX_CHARS = 1_000_000
DETAIL_LOG_MAX_LINES = 2_000
DETAIL_RENDER_MAX_CHARS = 500_000
DETAIL_MATRIX_MAX_ROWS = 1_000


def _coalesce_dashboard_events(events: list[RunEvent]) -> list[RunEvent]:
    """Combine adjacent token events without changing non-token event order."""

    coalesced: list[RunEvent] = []
    token_batch: list[RunEvent] = []

    def flush_tokens() -> None:
        if not token_batch:
            return
        first = token_batch[0]
        data = dict(first.data)
        data["ui_chunk_count"] = len(token_batch)
        coalesced.append(RunEvent(
            event_type="llm.token",
            timestamp=first.timestamp,
            execution_id=first.execution_id,
            run_id=first.run_id,
            node=first.node,
            method=first.method,
            candidate=first.candidate,
            message="".join(str(event.message or "") for event in token_batch),
            data=data,
        ))
        token_batch.clear()

    for event in events:
        if event.event_type == "llm.token":
            if token_batch:
                previous = token_batch[-1]
                previous_call = previous.data.get("call_id")
                current_call = event.data.get("call_id")
                if (
                    previous.execution_id != event.execution_id
                    or previous.run_id != event.run_id
                    or previous_call != current_call
                ):
                    flush_tokens()
            token_batch.append(event)
        else:
            flush_tokens()
            coalesced.append(event)
    flush_tokens()
    return coalesced


def _model_dict(config: EngagementConfig, provider: str) -> dict[str, Any]:
    model = config.models.get(provider)
    return dataclasses.asdict(model) if model else {}


LLM_RUNTIME_ROLES = ("orchestrator", "payload_generator")
LLM_CACHE_SCOPE_CHOICES = (("Disabled", "none"), ("Run-local", "run"))
LLM_STRUCTURED_OUTPUT_CHOICES = (
    ("Automatic", "auto"),
    ("Native JSON schema", "native"),
    ("JSON prompt", "json_prompt"),
)


def _object_mapping(value: Any) -> dict[str, Any]:
    """Return a shallow mapping for a typed or YAML-shaped config object."""

    if isinstance(value, Mapping):
        return dict(value)
    if dataclasses.is_dataclass(value):
        try:
            return dataclasses.asdict(value)
        except TypeError:
            return {}
    if value is None:
        return {}
    result: dict[str, Any] = {}
    for name in (
        "max_concurrency",
        "cache_scope",
        "roles",
        "model_profile",
        "model_name",
        "temperature",
        "max_tokens",
        "structured_output",
    ):
        if hasattr(value, name):
            result[name] = getattr(value, name)
    return result


def _config_value(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _runtime_values(config: EngagementConfig) -> dict[str, Any]:
    """Normalize the optional typed LLM runtime block for UI consumers.

    EngagementConfig is intentionally allowed to evolve from a plain mapping
    to typed runtime/role dataclasses.  Keeping this conversion in the TUI
    avoids coupling screens to one representation and leaves old configs with
    the documented sequential/no-cache defaults.
    """

    runtime = getattr(config, "llm_runtime", None)
    raw_runtime = _object_mapping(runtime)
    raw_scope = raw_runtime.get("cache_scope")
    if raw_scope is None:
        raw_scope = "run" if bool(raw_runtime.get("cache_enabled", False)) else "none"
    scope = str(raw_scope or "none").strip().lower()
    if scope not in {choice[1] for choice in LLM_CACHE_SCOPE_CHOICES}:
        scope = "none"
    try:
        max_concurrency = int(raw_runtime.get("max_concurrency", 1))
    except (TypeError, ValueError):
        max_concurrency = 1
    roles_value = raw_runtime.get("roles") or {}
    roles: dict[str, dict[str, Any]] = {}
    for role in LLM_RUNTIME_ROLES:
        raw_role = _object_mapping(
            roles_value.get(role) if isinstance(roles_value, Mapping) else getattr(roles_value, role, None)
        )
        roles[role] = {
            "model_profile": raw_role.get("model_profile"),
            "model_name": raw_role.get("model_name"),
            "temperature": raw_role.get("temperature", 0.0),
            "max_tokens": raw_role.get("max_tokens"),
            "structured_output": raw_role.get("structured_output", "auto"),
        }
    return {
        "max_concurrency": max_concurrency,
        "cache_scope": scope,
        "roles": roles,
    }


def _effective_role_model(
    config: EngagementConfig,
    role: str,
    runtime_values: Mapping[str, Any] | None = None,
) -> str:
    """Format one role's effective profile/model without exposing secrets."""

    runtime = dict(runtime_values or _runtime_values(config))
    role_values = runtime["roles"].get(role, {})
    profile = str(role_values.get("model_profile") or "").strip()
    if not profile:
        profile = str(getattr(config, "provider", "") or "").strip() or "default"
        if bool(getattr(config, "matrix", False)):
            profile = "per-coordinate:" + profile
    lookup_profile = profile.split(":", 1)[-1] if profile.startswith("per-coordinate:") else profile
    model_name = str(role_values.get("model_name") or "").strip()
    if not model_name and lookup_profile:
        model_name = str(_model_dict(config, lookup_profile).get("model_name") or "").strip()
    return f"{profile}/{model_name or 'default'}"


def _llm_runtime_summary(
    config: EngagementConfig,
    runtime_values: Mapping[str, Any] | None = None,
) -> str:
    runtime = dict(runtime_values or _runtime_values(config))
    return (
        f"LLM orchestrator={_effective_role_model(config, 'orchestrator', runtime)}  "
        f"payload_generator={_effective_role_model(config, 'payload_generator', runtime)}  "
        f"cache={runtime['cache_scope']}  concurrency={runtime['max_concurrency']}"
    )


def _runtime_role_configs(config: EngagementConfig) -> dict[str, dict[str, Any]]:
    """Return serializable role settings suitable for runner kwargs."""

    return {
        role: dict(values)
        for role, values in _runtime_values(config)["roles"].items()
    }


def _model_configs(config: EngagementConfig) -> dict[str, dict[str, Any]]:
    """Return all provider profiles as plain mappings for runner boundaries."""

    return {
        name: dataclasses.asdict(value)
        for name, value in config.models.items()
    }


def _llm_runtime_kwargs(config: EngagementConfig) -> dict[str, Any]:
    """Build runtime kwargs while retaining names used by direct callers."""

    runtime = _runtime_values(config)
    role_configs = _runtime_role_configs(config)
    runtime_config = {
        "max_concurrency": runtime["max_concurrency"],
        "cache_scope": runtime["cache_scope"],
        "roles": role_configs,
    }
    return {
        "llm_max_concurrency": runtime["max_concurrency"],
        "llm_cache_scope": runtime["cache_scope"],
        "llm_cache": runtime["cache_scope"] != "none",
        "llm_cache_enabled": runtime["cache_scope"] != "none",
        "role_configs": role_configs,
        "llm_role_configs": role_configs,
        "llm_runtime_config": runtime_config,
    }


def _set_config_value(container: Any, key: str, value: Any) -> None:
    if isinstance(container, Mapping):
        container[key] = value
    else:
        setattr(container, key, value)


def _apply_runtime_values(config: EngagementConfig, values: Mapping[str, Any]) -> None:
    """Apply typed-form controls to a resolved EngagementConfig in place."""

    runtime = getattr(config, "llm_runtime", None)
    if runtime is None:
        runtime = {"max_concurrency": 1, "cache_scope": "none", "roles": {}}
        _set_config_value(config, "llm_runtime", runtime)
    _set_config_value(runtime, "max_concurrency", int(values["max_concurrency"]))
    _set_config_value(runtime, "cache_scope", str(values["cache_scope"]))
    roles = _config_value(runtime, "roles")
    if roles is None:
        roles = {}
        _set_config_value(runtime, "roles", roles)
    for role in LLM_RUNTIME_ROLES:
        role_values = dict(values.get("roles", {}).get(role, {}))
        role_config = (
            roles.get(role) if isinstance(roles, Mapping) else getattr(roles, role, None)
        )
        if role_config is None:
            role_config = {}
            if isinstance(roles, Mapping):
                roles[role] = role_config
            else:
                setattr(roles, role, role_config)
        for key, value in role_values.items():
            if isinstance(role_config, Mapping):
                if value is None or value == "":
                    role_config.pop(key, None)
                else:
                    role_config[key] = value
            else:
                setattr(role_config, key, value)


def _runtime_form_values(screen: Screen, *, prefix: str = "") -> dict[str, Any]:
    """Read runtime controls from either RunSetupScreen or SettingsScreen."""

    def input_value(name: str) -> str:
        return screen.query_one(f"#{prefix}{name}", Input).value.strip()

    def select_value(name: str, default: str) -> str:
        return _select_value(screen, f"#{prefix}{name}", default)

    max_concurrency = int(input_value("llm-max-concurrency") or "1")
    if not 1 <= max_concurrency <= 4:
        raise ValueError("llm max concurrency must be between 1 and 4")
    cache_scope = select_value("llm-cache-scope", "none")
    roles: dict[str, dict[str, Any]] = {}
    for role, stem in (("orchestrator", "orchestrator"), ("payload_generator", "payload")):
        roles[role] = {
            "model_profile": input_value(f"{stem}-model-profile") or None,
            "model_name": input_value(f"{stem}-model") or None,
        }
    return {
        "max_concurrency": max_concurrency,
        "cache_scope": cache_scope,
        "roles": roles,
    }


def _runtime_cli_overrides(values: Mapping[str, Any]) -> dict[str, Any]:
    """Expose the same names as headless flags for config-loader versions."""

    result: dict[str, Any] = {
        "llm_max_concurrency": values["max_concurrency"],
        "llm_cache_scope": values["cache_scope"],
        "llm_cache": values["cache_scope"] != "none",
    }
    roles = values.get("roles", {})
    for role, stem in (("orchestrator", "orchestrator"), ("payload_generator", "payload")):
        role_values = roles.get(role, {})
        if role_values.get("model_profile"):
            result[f"{stem}_model_profile"] = role_values["model_profile"]
        if role_values.get("model_name"):
            result[f"{stem}_model"] = role_values["model_name"]
    return result


def _invoke_runner(runner: Any, kwargs: dict[str, Any]) -> Any:
    """Call old/new runners without breaking legacy direct signatures."""

    try:
        signature = inspect.signature(runner)
    except (TypeError, ValueError):
        return runner(**kwargs)
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values()):
        return runner(**kwargs)
    accepted = {
        key: value
        for key, value in kwargs.items()
        if key in signature.parameters
    }
    return runner(**accepted)


def _select_value(screen: Screen, selector: str, default: str) -> str:
    value = screen.query_one(selector, Select).value
    return default if value is Select.BLANK else str(value)


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
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            payload[index] = _restore_yaml_secrets(item, preserved)
    elif isinstance(payload, str) and payload in preserved:
        return preserved[payload]
    return payload


class Tips(Static):
    def __init__(self, text: str) -> None:
        super().__init__(f"{text}  •  Tab complete trace", classes="tips")


class BaseTesisScreen(Screen):
    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("ctrl+c", "cancel_runtime", "Cancel", show=True, priority=True),
    ]

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_cancel_runtime(self) -> None:
        if hasattr(self, "request_cancel"):
            self.request_cancel()  # type: ignore[attr-defined]
        else:
            self.action_back()

    def on_resize(self, event) -> None:
        self.set_class(event.size.width < 100, "compact")


class MainMenuScreen(Screen):
    BINDINGS = [Binding("q", "quit", "Quit", show=True)]
    ITEMS = (
        ("single", "Run Single Experiment"),
        ("matrix", "Run Experiment Matrix"),
        ("settings", "Settings"),
        ("results", "Recent Results"),
        ("validate", "Validate Framework"),
        ("info", "Framework Information"),
        ("exit", "Exit"),
    )

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="menu-shell"):
            yield Label("TESIS", id="brand")
            yield Label("Autonomous DVWA Experiment Harness", id="subtitle")
            yield OptionList(*(Option(label, id=key) for key, label in self.ITEMS), id="main-menu")
        yield Tips("↑↓ navigate  Enter select  q exit")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#main-menu", OptionList).focus()

    @on(OptionList.OptionSelected, "#main-menu")
    def choose(self, event: OptionList.OptionSelected) -> None:
        choice = str(event.option.id)
        if choice == "single":
            self.app.push_screen(RunSetupScreen(matrix=False))
        elif choice == "matrix":
            self.app.push_screen(RunSetupScreen(matrix=True))
        elif choice == "settings":
            self.app.push_screen(SettingsScreen())
        elif choice == "results":
            self.app.push_screen(RecentResultsScreen())
        elif choice == "validate":
            self.app.push_screen(ValidationScreen())
        elif choice == "info":
            self.app.push_screen(FrameworkInfoScreen())
        elif choice == "exit":
            self.app.exit()

    def action_quit(self) -> None:
        self.app.exit()


class RunSetupScreen(BaseTesisScreen):
    def __init__(self, *, matrix: bool) -> None:
        super().__init__()
        self.matrix = matrix
        self.config: EngagementConfig | None = None

    def compose(self) -> ComposeResult:
        title = "Experiment Matrix" if self.matrix else "Single Experiment"
        yield Header(show_clock=True)
        with VerticalScroll(id="setup-scroll"):
            yield Label(title, classes="screen-title")
            yield Label("TARGET & IDENTITY", classes="section-title")
            yield Label("DVWA base URL")
            yield Input(id="target")
            with Grid(classes="form-grid"):
                yield Label("Experiment condition")
                yield Select(((v, v) for v in EXPERIMENT_CONDITIONS), id="condition")
                yield Label("Target method (optional)")
                yield Select((("Automatic", ""), *((v, v) for v in METHOD_CHOICES)), id="target-method")

            if self.matrix:
                yield Label("MATRIX COORDINATES", classes="section-title")
                with Grid(id="matrix-grid"):
                    with Vertical():
                        yield Label("Providers")
                        yield SelectionList[str](id="providers")
                    with Vertical():
                        yield Label("Security levels")
                        yield SelectionList[str](id="levels")
                    with Vertical():
                        yield Label("Surfaces")
                        yield SelectionList[str](id="surfaces")
                    with Vertical():
                        yield Label("Payload modes")
                        yield SelectionList[str](id="payload-modes")
                with Horizontal(classes="inline-form"):
                    yield Label("Repeats")
                    yield Input("1", type="integer", id="repeats")
                    yield Static("0 runs", id="run-total")
            else:
                yield Label("MODEL & METHOD", classes="section-title")
                with Grid(classes="form-grid"):
                    yield Label("Provider")
                    yield Select(((v, v) for v in PROVIDER_CHOICES), id="provider")
                    yield Label("Model")
                    yield Input(id="model")
                    yield Label("Security level")
                    yield Select(((v, v) for v in SECURITY_LEVEL_CHOICES), id="level")
                    yield Label("Surface")
                    yield Select(((v, v) for v in SURFACE_CHOICES), id="surface")
                    yield Label("Payload mode")
                    yield Select(((v, v) for v in PAYLOAD_MODE_CHOICES), id="payload-mode")

            yield Label("LLM RUNTIME", classes="section-title")
            with Grid(classes="form-grid"):
                yield Label("LLM max concurrency")
                yield Input("1", type="integer", id="llm-max-concurrency")
                yield Label("LLM cache scope")
                yield Select(LLM_CACHE_SCOPE_CHOICES, id="llm-cache-scope")
                yield Label("Orchestrator model profile")
                yield Input(id="orchestrator-model-profile")
                yield Label("Orchestrator model")
                yield Input(id="orchestrator-model")
                yield Label("Payload model profile")
                yield Input(id="payload-model-profile")
                yield Label("Payload model")
                yield Input(id="payload-model")

            yield Label("BUDGET & POLICY", classes="section-title")
            with Grid(classes="form-grid"):
                yield Label("Candidate budget")
                yield Input("5", type="integer", id="candidate-budget")
                yield Label("Maximum iterations")
                yield Input("30", type="integer", id="iterations")
                yield Label("Stopping policy")
                yield Select(((v, v) for v in ("impact", "coverage")), id="stop-policy")
                yield Label("Coverage target")
                yield Input("0.70", type="number", id="coverage-target")
                yield Label("Guardrail handling")
                yield Select(((v, v) for v in ("reactive", "proactive", "disabled")), id="guardrail-mode")
                yield Label("Output directory")
                yield Input("results", id="output-dir")
                yield Label("Log verbosity")
                yield Select(((v, v) for v in LOG_VERBOSITY_CHOICES), id="verbosity")
            with Horizontal(classes="checks"):
                yield Checkbox("Enriched reporting", id="enriched")
                yield Checkbox("Diagnostics", id="diagnose")
                yield Checkbox("Guardrail handling enabled", id="guardrail-enabled")
            yield Static("", id="setup-summary")
            yield Static("", id="setup-status")
            with Horizontal(classes="actions"):
                yield Button("Validate only", id="validate-only")
                yield Button("Start run", variant="primary", id="start-run")
        yield Tips("Esc back  Enter activate  Ctrl+C cancel")
        yield Footer()

    def on_mount(self) -> None:
        try:
            cfg = load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={})
        except ConfigError as exc:
            self.query_one("#setup-status", Static).update(f"Config error: {exc}")
            return
        self.config = cfg
        self.query_one("#target", Input).value = cfg.target_url
        self.query_one("#candidate-budget", Input).value = str(cfg.candidate_budget)
        self.query_one("#iterations", Input).value = str(cfg.iterations)
        self.query_one("#coverage-target", Input).value = str(cfg.coverage_target)
        self.query_one("#output-dir", Input).value = cfg.output_dir
        self.query_one("#stop-policy", Select).value = cfg.stop_policy
        self.query_one("#guardrail-mode", Select).value = cfg.evasion_mode
        self.query_one("#enriched", Checkbox).value = cfg.enriched_reporting
        self.query_one("#diagnose", Checkbox).value = cfg.diagnose
        self.query_one("#guardrail-enabled", Checkbox).value = cfg.evasion_enabled
        self.query_one("#condition", Select).value = cfg.experiment_condition
        self.query_one("#target-method", Select).value = cfg.target_method or ""
        self.query_one("#verbosity", Select).value = cfg.log_verbosity
        runtime = _runtime_values(cfg)
        self.query_one("#llm-max-concurrency", Input).value = str(runtime["max_concurrency"])
        self.query_one("#llm-cache-scope", Select).value = runtime["cache_scope"]
        for role, stem in (("orchestrator", "orchestrator"), ("payload_generator", "payload")):
            role_values = runtime["roles"][role]
            self.query_one(f"#{stem}-model-profile", Input).value = str(role_values.get("model_profile") or "")
            self.query_one(f"#{stem}-model", Input).value = str(role_values.get("model_name") or "")
        if self.matrix:
            self.query_one("#repeats", Input).value = str(cfg.repeats)
            self._fill_selection("#providers", PROVIDER_CHOICES, cfg.providers)
            self._fill_selection("#levels", SECURITY_LEVEL_CHOICES, cfg.levels)
            self._fill_selection("#surfaces", SURFACE_CHOICES, cfg.surfaces)
            self._fill_selection("#payload-modes", PAYLOAD_MODE_CHOICES, cfg.payload_modes)
            self.update_total()
        else:
            self.query_one("#provider", Select).value = cfg.provider
            self.query_one("#model", Input).value = _model_dict(cfg, cfg.provider).get("model_name", "")
            self.query_one("#level", Select).value = cfg.level
            self.query_one("#surface", Select).value = cfg.surface
            self.query_one("#payload-mode", Select).value = cfg.payload_mode
        self._update_runtime_summary(cfg)

    def _update_runtime_summary(
        self,
        config: EngagementConfig,
        runtime_values: Mapping[str, Any] | None = None,
    ) -> None:
        self.query_one("#setup-summary", Static).update(
            _llm_runtime_summary(config, runtime_values)
        )

    def _fill_selection(self, selector: str, choices: Any, selected: list[str]) -> None:
        widget = self.query_one(selector, SelectionList)
        for value in choices:
            widget.add_option((value, value, value in selected))

    @on(SelectionList.SelectedChanged)
    @on(Input.Changed, "#repeats")
    def update_total(self) -> None:
        if not self.matrix or not self.is_mounted:
            return
        counts = [len(self.query_one(selector, SelectionList).selected) for selector in (
            "#providers", "#levels", "#surfaces", "#payload-modes"
        )]
        try:
            repeats = max(0, int(self.query_one("#repeats", Input).value or "0"))
        except ValueError:
            repeats = 0
        total = repeats
        for count in counts:
            total *= count
        self.query_one("#run-total", Static).update(f"{total} runs")

    @on(Input.Changed, "#llm-max-concurrency")
    @on(Input.Changed, "#orchestrator-model-profile")
    @on(Input.Changed, "#orchestrator-model")
    @on(Input.Changed, "#payload-model-profile")
    @on(Input.Changed, "#payload-model")
    @on(Select.Changed, "#llm-cache-scope")
    def update_runtime_preview(self) -> None:
        if not self.is_mounted or self.config is None:
            return
        try:
            values = _runtime_form_values(self)
        except (NoMatches, ValueError):
            return
        self._update_runtime_summary(self.config, values)

    def resolved_config(self) -> EngagementConfig:
        cli_args: dict[str, Any] = {
            "target": self.query_one("#target", Input).value,
            "candidate_budget": int(self.query_one("#candidate-budget", Input).value),
            "iterations": int(self.query_one("#iterations", Input).value),
            "stop_policy": _select_value(self, "#stop-policy", "impact"),
            "coverage_target": float(self.query_one("#coverage-target", Input).value),
            "output_dir": self.query_one("#output-dir", Input).value,
            "enriched_reporting": str(self.query_one("#enriched", Checkbox).value).lower(),
            "diagnose": str(self.query_one("#diagnose", Checkbox).value).lower(),
            "evasion_enabled": str(self.query_one("#guardrail-enabled", Checkbox).value).lower(),
            "evasion_mode": _select_value(self, "#guardrail-mode", "reactive"),
        }
        runtime_values = _runtime_form_values(self)
        cli_args.update(_runtime_cli_overrides(runtime_values))
        if self.matrix:
            cli_args.update({
                "matrix": True,
                "providers": list(self.query_one("#providers", SelectionList).selected),
                "levels": list(self.query_one("#levels", SelectionList).selected),
                "surfaces": list(self.query_one("#surfaces", SelectionList).selected),
                "payload_modes": list(self.query_one("#payload-modes", SelectionList).selected),
                "repeats": int(self.query_one("#repeats", Input).value),
            })
        else:
            cli_args.update({
                "provider": _select_value(self, "#provider", "gemini"),
                "level": _select_value(self, "#level", "low"),
                "surface": _select_value(self, "#surface", "sqli"),
                "payload_mode": _select_value(self, "#payload-mode", "hybrid"),
            })
        config = load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args=cli_args)
        _apply_runtime_values(config, runtime_values)
        if not self.matrix:
            model_name = self.query_one("#model", Input).value.strip()
            if model_name:
                if config.provider in config.models:
                    config.models[config.provider].model_name = model_name
                else:
                    config.models[config.provider] = ModelConfig(
                        provider=config.provider,
                        api_key="",
                        model_name=model_name,
                    )
        self.config = config
        self._update_runtime_summary(config)
        return config

    @on(Button.Pressed, "#validate-only")
    def validate_only(self) -> None:
        try:
            cfg = self.resolved_config()
            total = ""
            if self.matrix:
                total = f" ({len(cfg.providers) * len(cfg.levels) * len(cfg.surfaces) * len(cfg.payload_modes) * cfg.repeats} runs)"
            self.query_one("#setup-status", Static).update(f"✓ Configuration valid{total}")
            self._update_runtime_summary(cfg)
        except (ConfigError, ValueError) as exc:
            self.query_one("#setup-status", Static).update(f"✗ {exc}")

    @on(Button.Pressed, "#start-run")
    def start_run(self) -> None:
        try:
            cfg = self.resolved_config()
        except (ConfigError, ValueError) as exc:
            self.query_one("#setup-status", Static).update(f"✗ {exc}")
            return
        condition = _select_value(self, "#condition", "linear_hybrid")
        method = _select_value(self, "#target-method", "") or None
        if not self.matrix:
            model_name = self.query_one("#model", Input).value.strip()
            if model_name:
                if cfg.provider in cfg.models:
                    cfg.models[cfg.provider].model_name = model_name
                else:
                    cfg.models[cfg.provider] = ModelConfig(
                        provider=cfg.provider,
                        api_key="",
                        model_name=model_name,
                    )
        self._update_runtime_summary(cfg)
        verbosity = _select_value(self, "#verbosity", "info")
        self.app.push_screen(RuntimeDashboardScreen(
            cfg,
            matrix=self.matrix,
            condition=condition,
            target_method=method,
            log_verbosity=verbosity,
        ))


class DashboardEvent(Message):
    def __init__(self, event: RunEvent) -> None:
        self.event = event
        super().__init__()


class DashboardFlushRequested(Message):
    """Wake the UI once after a background thread buffers runtime events."""


class DashboardSummary(Message):
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result
        super().__init__()


class RuntimeDashboardScreen(BaseTesisScreen):
    BINDINGS = BaseTesisScreen.BINDINGS + [Binding("tab", "toggle_trace", "Complete trace", show=True)]

    STAGES = (
        "recon", "orchestrator", "payload_candidate_builder", "payload_validator",
        "method_agent", "chaining_router", "scorer",
    )

    def __init__(
        self,
        config: EngagementConfig,
        *,
        matrix: bool,
        condition: str,
        target_method: str | None,
        log_verbosity: str = "info",
    ) -> None:
        super().__init__()
        self.config = config
        self.matrix = matrix
        self.condition = condition
        self.target_method = target_method
        self.log_verbosity = log_verbosity
        self.cancel_token = CancellationToken()
        self.trace_expanded = False
        self.started_clock = monotonic()
        self.connection_state = "pending"
        self.completed = False
        self.matrix_status_counts = {"success": 0, "error": 0, "cancelled": 0, "skipped": 0}
        self.known_secrets = [
            model.api_key for model in config.models.values() if model.api_key
        ]
        self._event_lock = Lock()
        self._pending_events: deque[RunEvent] = deque()
        self._event_flush_scheduled = False
        self._pending_events_dropped = 0
        self._pending_summary: dict[str, Any] | None = None
        self._trace_entries: deque[str] = deque()
        self._trace_chars = 0
        self._trace_dropped = 0
        self._trace_dirty = False
        self._tesis_closing = False
        self._runtime_thread: Thread | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Preparing runtime…", id="run-header")
        with Grid(id="dashboard-grid"):
            with Vertical(id="task-rail", classes="panel"):
                yield Label("TASKS", classes="panel-title")
                for stage in self.STAGES:
                    yield Static(f"○ {stage}", id=f"stage-{stage.replace('_', '-')}")
                yield ProgressBar(total=100, show_eta=False, id="matrix-progress")
                yield Static("", id="matrix-counts")
            with Vertical(id="conversation", classes="panel"):
                yield Label("MODEL STREAM", classes="panel-title")
                yield RichLog(
                    max_lines=STREAM_LOG_MAX_LINES,
                    markup=False,
                    wrap=True,
                    id="stream-log",
                )
                yield RichLog(
                    max_lines=TRACE_LOG_MAX_LINES,
                    markup=False,
                    wrap=True,
                    id="trace-log",
                    classes="hidden",
                )
            with Vertical(id="telemetry", classes="panel"):
                yield Label("TELEMETRY", classes="panel-title")
                yield Static("Waiting for state", id="telemetry-content")
                yield Label("CANDIDATES", classes="panel-title")
                yield Static("Generated 0 / 0\nQueue 0 / 0", id="candidate-content")
                yield Label("FAILURE", classes="panel-title")
                yield Static("No active failure", id="failure-content")
        yield Tips("Ctrl+C graceful cancel  Ctrl+C again close  Esc returns after completion")
        yield Footer()

    def on_mount(self) -> None:
        model = _model_dict(self.config, self.config.provider).get("model_name", "default")
        self.header_context = (
            f"{self.config.target_url}  │  {self.config.provider}/{model}  │  "
            f"{self.condition}  │  {self.config.surface}/{self.target_method or 'auto'}  │  {self.config.level}  │  "
            f"{_llm_runtime_summary(self.config)}"
        )
        self._update_header()
        self.set_interval(1.0, self._update_header)
        progress = self.query_one("#matrix-progress", ProgressBar)
        progress.display = self.matrix
        self._runtime_thread = Thread(
            target=self.run_experiment,
            name="tesis-runtime",
            daemon=True,
        )
        self._runtime_thread.start()

    def _post_event(self, event: RunEvent) -> None:
        should_schedule = False
        with self._event_lock:
            if self._tesis_closing:
                return
            if self._pending_events:
                previous = self._pending_events[-1]
                same_call = previous.data.get("call_id") == event.data.get("call_id")
                if (
                    previous.event_type == event.event_type == "llm.token"
                    and previous.execution_id == event.execution_id
                    and previous.run_id == event.run_id
                    and same_call
                    and len(str(previous.message or "")) + len(str(event.message or ""))
                    <= UI_INGRESS_TOKEN_CHARS
                ):
                    data = dict(previous.data)
                    data["ingress_chunk_count"] = (
                        int(previous.data.get("ingress_chunk_count", 1) or 1)
                        + int(event.data.get("ingress_chunk_count", 1) or 1)
                    )
                    self._pending_events[-1] = RunEvent(
                        event_type="llm.token",
                        timestamp=previous.timestamp,
                        execution_id=previous.execution_id,
                        run_id=previous.run_id,
                        node=previous.node,
                        method=previous.method,
                        candidate=previous.candidate,
                        message=f"{previous.message or ''}{event.message or ''}",
                        data=data,
                    )
                elif previous.event_type == event.event_type == "graph.state":
                    # State events are snapshots; only the newest queued snapshot
                    # is useful to the dashboard.
                    self._pending_events[-1] = event
                else:
                    self._enqueue_bounded_event(event)
            else:
                self._pending_events.append(event)
            if not self._event_flush_scheduled:
                self._event_flush_scheduled = True
                should_schedule = True
        if should_schedule:
            if not self.post_message(DashboardFlushRequested()):
                with self._event_lock:
                    self._event_flush_scheduled = False

    def _enqueue_bounded_event(self, event: RunEvent) -> None:
        if len(self._pending_events) < UI_PENDING_EVENT_MAX:
            self._pending_events.append(event)
            return

        droppable = next(
            (
                index for index, queued in enumerate(self._pending_events)
                if queued.event_type in {"llm.token", "graph.state"}
            ),
            None,
        )
        if droppable is not None:
            del self._pending_events[droppable]
            self._pending_events.append(event)
            self._pending_events_dropped += 1
            return

        critical = (
            event.event_type.endswith(".failed")
            or event.event_type.endswith(".cancelled")
            or event.event_type.endswith(".finished")
        )
        if critical:
            self._pending_events.popleft()
            self._pending_events.append(event)
        self._pending_events_dropped += 1

    @on(DashboardFlushRequested)
    def _schedule_event_flush(self) -> None:
        if not self._tesis_closing:
            self.set_timer(UI_EVENT_FLUSH_INTERVAL, self._flush_event_batch)

    def _flush_event_batch(self) -> None:
        events: list[RunEvent] = []
        with self._event_lock:
            while self._pending_events and len(events) < UI_EVENT_BATCH_SIZE:
                events.append(self._pending_events.popleft())
            has_more = bool(self._pending_events)
            if not has_more:
                self._event_flush_scheduled = False
            dropped = self._pending_events_dropped
            self._pending_events_dropped = 0

        if dropped:
            self._append_trace(
                f"UI backpressure omitted {dropped} superseded live events; "
                "the run artifact retains the canonical execution log."
            )

        for event in _coalesce_dashboard_events(events):
            self._consume_runtime_event(event)

        if has_more:
            self.set_timer(UI_EVENT_FLUSH_INTERVAL, self._flush_event_batch)
        elif self._pending_summary is not None:
            result = self._pending_summary
            self._pending_summary = None
            self.show_summary(result)

    def _queue_summary(self, result: dict[str, Any]) -> None:
        with self._event_lock:
            has_pending = bool(self._pending_events)
        if has_pending:
            self._pending_summary = result
        else:
            self.show_summary(result)

    def _update_header(self) -> None:
        if self.completed:
            return
        elapsed = int(monotonic() - self.started_clock)
        self.query_one("#run-header", Static).update(
            f"{self.header_context}  │  {elapsed // 60:02d}:{elapsed % 60:02d}  │  {self.connection_state}"
        )

    def run_experiment(self) -> None:
        logging.getLogger().setLevel(getattr(logging, self.log_verbosity.upper(), logging.INFO))
        sink = CallbackEventSink(self._post_event)
        layout = None
        artifacts: list[dict[str, Any]] = []
        result: Any = {"status": "error", "error": "run did not start"}
        common = {
            "target_url": self.config.target_url,
            "max_iterations": self.config.iterations,
            "candidate_budget": self.config.candidate_budget,
            "stop_policy": self.config.stop_policy,
            "coverage_target": self.config.coverage_target,
            "enriched_reporting": self.config.enriched_reporting,
            "diagnose": self.config.diagnose,
            "evasion_enabled": self.config.evasion_enabled,
            "evasion_mode": self.config.evasion_mode,
            "evasion_max_retries": self.config.evasion_max_retries,
            "evasion_cooldown_threshold": self.config.evasion_cooldown_threshold,
            "event_sink": sink,
            "cancellation_token": self.cancel_token,
            "experiment_condition": self.condition,
            "target_method": self.target_method,
        }
        common.update(_llm_runtime_kwargs(self.config))
        try:
            layout = allocate_artifact_layout(
                self.config.output_dir,
                "matrix" if self.matrix else "single-run",
            )
            common["output_dir"] = str(layout.root)
            if self.matrix:
                matrix_kwargs = {
                    **common,
                    "providers": self.config.providers,
                    "security_levels": self.config.levels,
                    "surfaces": self.config.surfaces,
                    "payload_modes": self.config.payload_modes,
                    "repeats": self.config.repeats,
                    "include_aggregate": True,
                    "run_output_dir_factory": layout.child_directory,
                    "model_configs": _model_configs(self.config),
                }
                artifacts, aggregate = _invoke_runner(run_provider_matrix, matrix_kwargs)
                result: Any = aggregate
            else:
                single_kwargs = {
                    **common,
                    "security_level": self.config.level,
                    "llm_provider": self.config.provider,
                    "surface": self.config.surface,
                    "payload_mode": self.config.payload_mode,
                    "model_config": _model_dict(self.config, self.config.provider),
                    "model_profiles": _model_configs(self.config),
                }
                result = _invoke_runner(run_single_engagement, single_kwargs)
        except Exception as exc:
            self._post_event(RunEvent(
                event_type="run.failed",
                message=f"{type(exc).__name__}: {exc}",
                data={"error_type": type(exc).__name__},
            ))
            result = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
        finally:
            if layout is not None:
                manifest_config = dataclasses.asdict(self.config)
                manifest_config.update({
                    "experiment_condition": self.condition,
                    "target_method": self.target_method,
                })
                try:
                    layout.write_manifest(
                        config=manifest_config,
                        artifacts=artifacts if self.matrix else ([result] if result else []),
                        aggregate=result if self.matrix and isinstance(result, dict) else None,
                        status=str(result.get("status", "unknown")) if isinstance(result, dict) else None,
                    )
                except Exception as exc:
                    self._post_event(RunEvent(
                        event_type="artifact.manifest.failed",
                        message=f"{type(exc).__name__}: {exc}",
                        data={"error_type": type(exc).__name__},
                    ))
        if not self._tesis_closing:
            self.post_message(DashboardSummary(result))

    @on(DashboardSummary)
    def receive_summary(self, message: DashboardSummary) -> None:
        self._queue_summary(message.result)

    @on(DashboardEvent)
    def consume_event(self, message: DashboardEvent) -> None:
        self._consume_runtime_event(message.event)

    def _append_trace(self, entry: str) -> None:
        if len(entry) > TRACE_BUFFER_MAX_CHARS:
            suffix = "\n… trace entry truncated for terminal stability"
            entry = entry[:TRACE_BUFFER_MAX_CHARS - len(suffix)] + suffix
        while self._trace_entries and (
            len(self._trace_entries) >= TRACE_BUFFER_MAX_ENTRIES
            or self._trace_chars + len(entry) > TRACE_BUFFER_MAX_CHARS
        ):
            self._trace_chars -= len(self._trace_entries.popleft())
            self._trace_dropped += 1
        self._trace_entries.append(entry)
        self._trace_chars += len(entry)
        self._trace_dirty = True
        if self.trace_expanded:
            self.query_one("#trace-log", RichLog).write(Text(entry), scroll_end=True)

    def _render_trace(self) -> None:
        if not self._trace_dirty:
            return
        trace = self.query_one("#trace-log", RichLog)
        trace.clear()
        if self._trace_dropped:
            trace.write(Text(
                f"… {self._trace_dropped} older trace entries omitted from the live terminal; "
                "the run artifact retains the execution log.",
                style="yellow",
            ))
        for entry in self._trace_entries:
            trace.write(Text(entry), scroll_end=False)
        trace.scroll_end(animate=False)
        self._trace_dirty = False

    def _consume_runtime_event(self, event: RunEvent) -> None:
        if event.event_type == "run.started":
            self.connection_state = "active"
        elif event.event_type in {"run.failed", "llm.failed"}:
            self.connection_state = "degraded"
        stamp = datetime.fromtimestamp(event.timestamp).strftime("%H:%M:%S")
        safe_message = str(redact_secrets(event.message or "", self.known_secrets))
        safe_data = redact_secrets(dict(event.data), self.known_secrets)
        safe_candidate = redact_secrets(event.candidate, self.known_secrets)
        if event.event_type == "llm.token":
            self.query_one("#stream-log", RichLog).write(safe_message)
        else:
            self._append_trace(f"{stamp}  {event.event_type}  {safe_message}")
            trace_data = dict(safe_data)
            if event.event_type == "llm.completed":
                # The full response is already the event message; avoid rendering
                # and retaining a second identical copy in the live trace.
                trace_data.pop("response", None)
            if trace_data:
                self._append_trace(json.dumps(trace_data, indent=2, default=str))
            if event.event_type == "llm.completed" and safe_data.get("streaming"):
                self.query_one("#stream-log", RichLog).write(f"{stamp}  Model call completed")
            elif event.event_type in {"llm.completed", "llm.failed", "run.started", "run.finished", "run.cancelled"}:
                self.query_one("#stream-log", RichLog).write(f"{stamp}  {safe_message}")

        node = event.node or str(event.data.get("node", ""))
        if node in self.STAGES:
            stage_status = (
                "failure" if event.event_type.endswith("failed")
                else "fallback" if "fallback" in event.event_type
                else "success" if event.event_type.endswith("completed")
                else "running"
            )
            self._set_stage(node, stage_status)
        if node in RUNTIME_AGENT_NODE_NAMES:
            method_status = (
                "failure" if event.event_type.endswith("failed")
                else "success" if event.event_type.endswith("completed")
                else "running"
            )
            self._set_stage("method_agent", method_status)
        if event.event_type == "graph.state":
            self._update_telemetry(dict(event.data))
        if event.event_type.startswith("matrix."):
            completed = int(event.data.get("completed", 0) or 0)
            total = int(event.data.get("total", 0) or 0)
            if event.event_type == "matrix.run.finished":
                status = str(event.data.get("status", "unknown"))
                if status in self.matrix_status_counts:
                    self.matrix_status_counts[status] += 1
            if total:
                self.query_one("#matrix-progress", ProgressBar).update(progress=completed / total * 100)
            self.query_one("#matrix-counts", Static).update(
                f"{completed}/{total}\n"
                f"success {self.matrix_status_counts['success']}  error {self.matrix_status_counts['error']}\n"
                f"cancelled {self.matrix_status_counts['cancelled']}  skipped {self.matrix_status_counts['skipped']}"
            )
        if (
            event.event_type.endswith("failed")
            or "error" in event.event_type
            or "containment" in event.event_type
            or "fallback" in event.event_type
        ):
            affected = event.method or safe_candidate or event.node or "run"
            self.query_one("#failure-content", Static).update(
                f"[red]{event.event_type}[/]\n{safe_message}\nAffected: {affected}\n"
                f"Continuing: {event.event_type not in {'run.failed', 'run.cancelled'}}"
            )

    def _set_stage(self, stage: str, status: str) -> None:
        icon = {"running": "◉", "success": "✓", "failure": "✗", "fallback": "↪"}.get(status, "○")
        selector = f"#stage-{stage.replace('_', '-')}"
        try:
            self.query_one(selector, Static).update(f"{icon} {stage}")
        except NoMatches:
            pass

    def _update_telemetry(self, state: dict[str, Any]) -> None:
        method = state.get("selected_method") or "—"
        findings = state.get("confirmed_vulns") or []
        outcomes = state.get("achieved_outcomes") or []
        path = state.get("akg_path") or []
        self.query_one("#telemetry-content", Static).update(
            f"Method  {method}\nIteration  {state.get('iteration_count', 0)}/{self.config.iterations}\n"
            f"Findings  {len(findings)}\nOutcomes  {len(outcomes)}\nAKG  {' → '.join(path) or '—'}\n"
            f"Guardrails  {state.get('guardrail_count', 0)}  Fallbacks  {state.get('fallback_count', 0)}\n"
            f"Verifier  {state.get('latest_verifier') or '—'}"
        )
        failures = state.get("validation_failures") or {}
        failure_text = ", ".join(f"{reason}={count}" for reason, count in failures.items()) or "none"
        self.query_one("#candidate-content", Static).update(
            f"Generated budget  {state.get('generated_candidates', 0)} / {state.get('generation_budget', 0)}\n"
            f"Generation remaining  {state.get('generation_remaining', 0)}\n"
            f"Execution queue  {state.get('tried_candidates', 0)} tried / {state.get('accepted_candidates', 0)} accepted\n"
            f"Rejected  {failure_text}"
        )

    def show_summary(self, result: dict[str, Any]) -> None:
        self.completed = True
        status = result.get("status", "complete")
        totals = result.get("totals", {})
        if totals:
            summary = "  ".join(f"{key.replace('_runs', '')}: {value}" for key, value in totals.items())
        else:
            summary = (
                f"method={result.get('selected_method') or '—'}  "
                f"score={result.get('composite_score', 0)}  "
                f"duration={result.get('timing', {}).get('duration_ms', 0)}ms"
            )
        self.query_one("#run-header", Static).update(f"{status.upper()}  │  {summary}  │  Esc returns")
        for stage in self.STAGES:
            self._set_stage(stage, "success" if status == "success" else ("failure" if status == "error" else "fallback"))

    def request_cancel(self) -> None:
        if self.cancel_token.cancel():
            self.query_one("#failure-content", Static).update(
                "[yellow]Cancellation requested[/]\nWaiting for the active LLM or HTTP operation to return.\n"
                "Press Ctrl+C again to close the TUI immediately."
            )
        else:
            self.app.exit()

    def prepare_shutdown(self) -> None:
        """Cancel work and release buffers without joining the runtime thread."""
        self.cancel_token.cancel("TUI closed")
        with self._event_lock:
            self._tesis_closing = True
            self._pending_events.clear()
            self._event_flush_scheduled = False
            self._pending_events_dropped = 0
        self._pending_summary = None
        self._trace_entries.clear()
        self._trace_chars = 0

    def on_unmount(self) -> None:
        self.prepare_shutdown()

    def action_back(self) -> None:
        if not self.completed:
            self.request_cancel()
            return
        self.app.pop_screen()

    def action_toggle_trace(self) -> None:
        self.trace_expanded = not self.trace_expanded
        self.query_one("#stream-log", RichLog).set_class(self.trace_expanded, "hidden")
        self.query_one("#trace-log", RichLog).set_class(not self.trace_expanded, "hidden")
        if self.trace_expanded:
            self._render_trace()


class SettingsScreen(BaseTesisScreen):
    def __init__(self) -> None:
        super().__init__()
        self.literal_warning_acknowledged = False
        self.preserved_secret_placeholders: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="settings-shell"):
            yield Label("Settings", classes="screen-title")
            with TabbedContent():
                with TabPane("Typed", id="typed-settings"):
                    with VerticalScroll():
                        yield Label("TARGET & MODEL", classes="section-title")
                        with Grid(classes="form-grid"):
                            yield Label("Target URL")
                            yield Input(id="settings-target")
                            yield Label("Default provider")
                            yield Select(((v, v) for v in PROVIDER_CHOICES), id="settings-provider")
                            yield Label("Model name")
                            yield Input(id="settings-model")
                            yield Label("Base URL")
                            yield Input(id="settings-base-url")
                            yield Label("Temperature")
                            yield Input(type="number", id="settings-temperature")
                            yield Label("Timeout (seconds)")
                            yield Input(type="integer", id="settings-timeout")
                            yield Label("API key (blank preserves)")
                            yield Input(password=True, id="settings-api-key")
                        yield Label("EXPERIMENT DEFAULTS", classes="section-title")
                        with Grid(classes="form-grid"):
                            yield Label("Security level")
                            yield Select(((v, v) for v in SECURITY_LEVEL_CHOICES), id="settings-level")
                            yield Label("Surface")
                            yield Select(((v, v) for v in SURFACE_CHOICES), id="settings-surface")
                            yield Label("Payload mode")
                            yield Select(((v, v) for v in PAYLOAD_MODE_CHOICES), id="settings-payload-mode")
                            yield Label("Candidate budget")
                            yield Input(type="integer", id="settings-budget")
                            yield Label("Iterations")
                            yield Input(type="integer", id="settings-iterations")
                            yield Label("Repeats")
                            yield Input(type="integer", id="settings-repeats")
                            yield Label("Output directory")
                            yield Input(id="settings-output")
                        yield Label("POLICY, REPORTING & GUARDRAILS", classes="section-title")
                        with Grid(classes="form-grid"):
                            yield Label("Stop policy")
                            yield Select(((v, v) for v in ("impact", "coverage")), id="settings-stop")
                            yield Label("Coverage target")
                            yield Input(type="number", id="settings-coverage")
                            yield Label("Report format")
                            yield Select(((v, v) for v in ("json", "markdown", "both")), id="settings-report")
                            yield Label("Guardrail mode")
                            yield Select(((v, v) for v in ("reactive", "proactive", "disabled")), id="settings-guardrail-mode")
                            yield Label("Guardrail retries")
                            yield Input(type="integer", id="settings-guardrail-retries")
                            yield Label("Cooldown threshold")
                            yield Input(type="integer", id="settings-cooldown")
                        with Horizontal(classes="checks"):
                            yield Checkbox("Enriched reporting", id="settings-enriched")
                            yield Checkbox("Diagnostics", id="settings-diagnose")
                            yield Checkbox("Guardrail handling", id="settings-guardrail-enabled")
                        yield Label("LLM RUNTIME", classes="section-title")
                        with Grid(classes="form-grid"):
                            yield Label("LLM max concurrency")
                            yield Input("1", type="integer", id="settings-llm-max-concurrency")
                            yield Label("LLM cache scope")
                            yield Select(LLM_CACHE_SCOPE_CHOICES, id="settings-llm-cache-scope")
                            yield Label("Orchestrator model profile")
                            yield Input(id="settings-orchestrator-model-profile")
                            yield Label("Orchestrator model")
                            yield Input(id="settings-orchestrator-model")
                            yield Label("Orchestrator temperature")
                            yield Input(type="number", id="settings-orchestrator-temperature")
                            yield Label("Orchestrator max tokens")
                            yield Input(type="integer", id="settings-orchestrator-max-tokens")
                            yield Label("Orchestrator structured output")
                            yield Select(LLM_STRUCTURED_OUTPUT_CHOICES, id="settings-orchestrator-structured-output")
                            yield Label("Payload model profile")
                            yield Input(id="settings-payload-model-profile")
                            yield Label("Payload model")
                            yield Input(id="settings-payload-model")
                            yield Label("Payload temperature")
                            yield Input(type="number", id="settings-payload-temperature")
                            yield Label("Payload max tokens")
                            yield Input(type="integer", id="settings-payload-max-tokens")
                            yield Label("Payload structured output")
                            yield Select(LLM_STRUCTURED_OUTPUT_CHOICES, id="settings-payload-structured-output")
                with TabPane("Advanced YAML", id="raw-settings"):
                    yield TextArea(language="yaml", id="yaml-editor")
            yield Static("", id="settings-status")
            with Horizontal(classes="actions"):
                yield Button("Reload", id="settings-reload")
                yield Button("Save validated config", variant="primary", id="settings-save")
        yield Tips("Esc back  Ctrl+S is reserved; use Save")
        yield Footer()

    def on_mount(self) -> None:
        self.reload()

    @on(Button.Pressed, "#settings-reload")
    def reload(self) -> None:
        try:
            raw = CONFIG_PATH.read_text(encoding="utf-8")
            parsed = load_yaml_config(CONFIG_PATH)
            resolved = load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={})
            masked, self.preserved_secret_placeholders = _mask_yaml_secrets(parsed)
            self.query_one("#yaml-editor", TextArea).text = (
                dump_yaml_config(masked) if self.preserved_secret_placeholders else raw
            )
            self.query_one("#settings-target", Input).value = str(parsed.get("target_url", ""))
            provider = str(parsed.get("provider") or parsed.get("default_llm_provider") or "gemini")
            self.query_one("#settings-provider", Select).value = provider
            self.query_one("#settings-output", Input).value = str(parsed.get("output_dir", "results"))
            self.query_one("#settings-level", Select).value = resolved.level
            self.query_one("#settings-surface", Select).value = resolved.surface
            self.query_one("#settings-payload-mode", Select).value = resolved.payload_mode
            self.query_one("#settings-budget", Input).value = str(resolved.candidate_budget)
            self.query_one("#settings-iterations", Input).value = str(resolved.iterations)
            self.query_one("#settings-repeats", Input).value = str(resolved.repeats)
            self.query_one("#settings-stop", Select).value = resolved.stop_policy
            self.query_one("#settings-coverage", Input).value = str(resolved.coverage_target)
            self.query_one("#settings-report", Select).value = resolved.report_format
            self.query_one("#settings-guardrail-mode", Select).value = resolved.evasion_mode
            self.query_one("#settings-guardrail-retries", Input).value = str(resolved.evasion_max_retries)
            self.query_one("#settings-cooldown", Input).value = str(resolved.evasion_cooldown_threshold)
            self.query_one("#settings-enriched", Checkbox).value = resolved.enriched_reporting
            self.query_one("#settings-diagnose", Checkbox).value = resolved.diagnose
            self.query_one("#settings-guardrail-enabled", Checkbox).value = resolved.evasion_enabled
            model_values = _model_dict(resolved, provider)
            self.query_one("#settings-model", Input).value = model_values.get("model_name", "")
            self.query_one("#settings-base-url", Input).value = model_values.get("base_url") or ""
            self.query_one("#settings-temperature", Input).value = str(model_values.get("temperature", 0.0))
            self.query_one("#settings-timeout", Input).value = str(model_values.get("timeout", 60))
            self.query_one("#settings-api-key", Input).value = ""
            runtime = _runtime_values(resolved)
            self.query_one("#settings-llm-max-concurrency", Input).value = str(runtime["max_concurrency"])
            self.query_one("#settings-llm-cache-scope", Select).value = runtime["cache_scope"]
            for role, stem in (("orchestrator", "orchestrator"), ("payload_generator", "payload")):
                role_values = runtime["roles"][role]
                self.query_one(f"#settings-{stem}-model-profile", Input).value = str(role_values.get("model_profile") or "")
                self.query_one(f"#settings-{stem}-model", Input).value = str(role_values.get("model_name") or "")
                self.query_one(f"#settings-{stem}-temperature", Input).value = str(role_values.get("temperature", 0.0))
                max_tokens = role_values.get("max_tokens")
                self.query_one(f"#settings-{stem}-max-tokens", Input).value = "" if max_tokens is None else str(max_tokens)
                structured_output = str(role_values.get("structured_output") or "auto")
                self.query_one(f"#settings-{stem}-structured-output", Select).value = (
                    structured_output if structured_output in {choice[1] for choice in LLM_STRUCTURED_OUTPUT_CHOICES}
                    else "auto"
                )
            self.query_one("#settings-status", Static).update("Loaded config.yaml")
        except (OSError, ConfigError) as exc:
            self.query_one("#settings-status", Static).update(f"✗ {exc}")

    @on(Select.Changed, "#settings-provider")
    def settings_provider_changed(self, event: Select.Changed) -> None:
        if event.value is Select.BLANK:
            return
        try:
            payload = parse_yaml_config(self.query_one("#yaml-editor", TextArea).text)
            provider = str(event.value)
            entry = payload.get("models", {}).get(provider, {})
            self.query_one("#settings-model", Input).value = str(entry.get("model_name", ""))
            self.query_one("#settings-base-url", Input).value = str(entry.get("base_url") or "")
            self.query_one("#settings-temperature", Input).value = str(entry.get("temperature", 0.0))
            self.query_one("#settings-timeout", Input).value = str(entry.get("timeout", 60))
            self.query_one("#settings-api-key", Input).value = ""
        except (ConfigError, AttributeError):
            return

    @on(Button.Pressed, "#settings-save")
    def save(self) -> None:
        try:
            payload = parse_yaml_config(self.query_one("#yaml-editor", TextArea).text)
            _restore_yaml_secrets(payload, self.preserved_secret_placeholders)
            payload["target_url"] = self.query_one("#settings-target", Input).value
            provider = _select_value(self, "#settings-provider", "gemini")
            payload["provider"] = provider
            payload["output_dir"] = self.query_one("#settings-output", Input).value
            payload["level"] = _select_value(self, "#settings-level", "low")
            payload["surface"] = _select_value(self, "#settings-surface", "sqli")
            payload["payload_mode"] = _select_value(self, "#settings-payload-mode", "hybrid")
            payload["candidate_budget"] = int(self.query_one("#settings-budget", Input).value)
            payload["iterations"] = int(self.query_one("#settings-iterations", Input).value)
            payload["repeats"] = int(self.query_one("#settings-repeats", Input).value)
            payload["stop_policy"] = _select_value(self, "#settings-stop", "impact")
            payload["coverage_target"] = float(self.query_one("#settings-coverage", Input).value)
            payload["report_format"] = _select_value(self, "#settings-report", "both")
            payload["enriched_reporting"] = self.query_one("#settings-enriched", Checkbox).value
            payload["diagnose"] = self.query_one("#settings-diagnose", Checkbox).value
            payload["evasion_enabled"] = self.query_one("#settings-guardrail-enabled", Checkbox).value
            payload["evasion_mode"] = _select_value(self, "#settings-guardrail-mode", "reactive")
            payload["evasion_max_retries"] = int(self.query_one("#settings-guardrail-retries", Input).value)
            payload["evasion_cooldown_threshold"] = int(self.query_one("#settings-cooldown", Input).value)
            literal_secret = self.query_one("#settings-api-key", Input).value
            model_name = self.query_one("#settings-model", Input).value
            base_url = self.query_one("#settings-base-url", Input).value.strip()
            temperature = float(self.query_one("#settings-temperature", Input).value)
            timeout = int(self.query_one("#settings-timeout", Input).value)
            models = payload.setdefault("models", {})
            if model_name:
                models.setdefault(provider, {})["model_name"] = model_name
            models.setdefault(provider, {})["temperature"] = temperature
            models.setdefault(provider, {})["timeout"] = timeout
            if base_url:
                models.setdefault(provider, {})["base_url"] = base_url
            else:
                models.setdefault(provider, {}).pop("base_url", None)
            if literal_secret:
                models.setdefault(provider, {})["api_key"] = literal_secret

            runtime_payload = payload.setdefault("llm_runtime", {})
            if not isinstance(runtime_payload, Mapping):
                raise ConfigError("llm_runtime must be a mapping")
            max_concurrency = int(self.query_one("#settings-llm-max-concurrency", Input).value)
            if not 1 <= max_concurrency <= 4:
                raise ConfigError("llm max concurrency must be between 1 and 4")
            runtime_payload["max_concurrency"] = max_concurrency
            runtime_payload["cache_scope"] = _select_value(
                self, "#settings-llm-cache-scope", "none"
            )
            roles_payload = runtime_payload.setdefault("roles", {})
            if not isinstance(roles_payload, Mapping):
                raise ConfigError("llm_runtime.roles must be a mapping")
            for role, stem in (("orchestrator", "orchestrator"), ("payload_generator", "payload")):
                role_payload = roles_payload.setdefault(role, {})
                if not isinstance(role_payload, Mapping):
                    raise ConfigError(f"llm_runtime.roles.{role} must be a mapping")
                profile = self.query_one(f"#settings-{stem}-model-profile", Input).value.strip()
                model_override = self.query_one(f"#settings-{stem}-model", Input).value.strip()
                temperature = float(self.query_one(f"#settings-{stem}-temperature", Input).value)
                max_tokens_value = self.query_one(f"#settings-{stem}-max-tokens", Input).value.strip()
                structured_output = _select_value(
                    self, f"#settings-{stem}-structured-output", "auto"
                )
                if profile:
                    role_payload["model_profile"] = profile
                else:
                    role_payload.pop("model_profile", None)
                if model_override:
                    role_payload["model_name"] = model_override
                else:
                    role_payload.pop("model_name", None)
                role_payload["temperature"] = temperature
                if max_tokens_value:
                    role_payload["max_tokens"] = int(max_tokens_value)
                else:
                    role_payload.pop("max_tokens", None)
                role_payload["structured_output"] = structured_output

            if _contains_literal_secret(payload) and not self.literal_warning_acknowledged:
                self.literal_warning_acknowledged = True
                self.query_one("#settings-status", Static).update(
                    "⚠ Literal secret will be stored in config.yaml. Prefer ${ENV_VAR}; press Save again to confirm."
                )
                return

            with tempfile.NamedTemporaryFile("w", suffix=".yaml", encoding="utf-8", delete=True) as temp:
                temp.write(dump_yaml_config(payload))
                temp.flush()
                load_and_resolve_config(config_path=temp.name, cli_args={})
            save_yaml_config(CONFIG_PATH, payload)
            masked, self.preserved_secret_placeholders = _mask_yaml_secrets(payload)
            self.query_one("#yaml-editor", TextArea).text = (
                dump_yaml_config(masked)
                if self.preserved_secret_placeholders
                else CONFIG_PATH.read_text(encoding="utf-8")
            )
            self.query_one("#settings-api-key", Input).value = ""
            self.literal_warning_acknowledged = False
            self.query_one("#settings-status", Static).update("✓ config.yaml validated and saved")
        except (ConfigError, OSError, ValueError) as exc:
            self.query_one("#settings-status", Static).update(f"✗ Not saved: {exc}")


class ResultsScanned(Message):
    def __init__(self, generation: int, items: list[ArtifactMetadata], error: str | None = None) -> None:
        self.generation = generation
        self.items = items
        self.error = error
        super().__init__()


class RecentResultsScreen(BaseTesisScreen):
    def __init__(self) -> None:
        super().__init__()
        self.repository: ArtifactRepository | None = None
        self.rows: dict[str, ArtifactMetadata] = {}
        self.fingerprint_groups: dict[str, list[ArtifactMetadata]] = {}
        self._scan_generation = 0
        self._tesis_closing = False
        self._scan_thread: Thread | None = None
        self._queued_scan: tuple[str | None, str | None, str | None, str | None, str | None] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="results-shell"):
            yield Label("Recent Results", classes="screen-title")
            with Horizontal(classes="filters"):
                yield Select((("All statuses", ""), *((v, v) for v in ("success", "error", "cancelled", "skipped"))), id="filter-status")
                yield Select((("All providers", ""), *((v, v) for v in PROVIDER_CHOICES)), id="filter-provider")
                yield Select((("All surfaces", ""), *((v, v) for v in SURFACE_CHOICES)), id="filter-surface")
                yield Select((("All levels", ""), *((v, v) for v in SECURITY_LEVEL_CHOICES)), id="filter-level")
                yield Select((("All modes", ""), *((v, v) for v in PAYLOAD_MODE_CHOICES)), id="filter-mode")
                yield Button("Apply", id="apply-filters")
            yield DataTable(cursor_type="row", zebra_stripes=True, id="results-table")
            yield Static("", id="results-status")
        yield Tips("↑↓ select  Enter details  Esc back")
        yield Footer()

    def on_mount(self) -> None:
        try:
            cfg = load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={})
            self.repository = ArtifactRepository(Path(cfg.output_dir))
        except ConfigError:
            self.repository = ArtifactRepository(REPOSITORY_ROOT / "results")
        table = self.query_one("#results-table", DataTable)
        table.add_columns("When", "Status", "Provider", "Surface", "Level", "Mode", "Identity")
        self.refresh_rows()

    @on(Button.Pressed, "#apply-filters")
    def refresh_rows(self) -> None:
        if self.repository is None:
            return
        status = _select_value(self, "#filter-status", "") or None
        provider = _select_value(self, "#filter-provider", "") or None
        surface = _select_value(self, "#filter-surface", "") or None
        level = _select_value(self, "#filter-level", "") or None
        mode = _select_value(self, "#filter-mode", "") or None
        self.query_one("#results-status", Static).update("Scanning artifacts…")
        scan_args = (status, provider, surface, level, mode)
        if self._scan_thread is not None and self._scan_thread.is_alive():
            self._queued_scan = scan_args
            self.query_one("#results-status", Static).update("Current scan finishing; latest filters queued…")
            return
        self._start_scan(scan_args)

    def _start_scan(
        self,
        scan_args: tuple[str | None, str | None, str | None, str | None, str | None],
    ) -> None:
        self._scan_generation += 1
        generation = self._scan_generation
        self._scan_thread = Thread(
            target=self._scan_rows,
            args=(generation, *scan_args),
            name="tesis-result-scan",
            daemon=True,
        )
        self._scan_thread.start()

    def _scan_rows(
        self,
        generation: int,
        status: str | None,
        provider: str | None,
        surface: str | None,
        level: str | None,
        mode: str | None,
    ) -> None:
        if self.repository is None:
            return
        try:
            items = self.repository.scan(
                status=status,
                provider=provider,
                surface=surface,
                security_level=level,
                payload_mode=mode,
                retain_raw=False,
            )
            message = ResultsScanned(generation, items)
        except Exception as exc:
            message = ResultsScanned(generation, [], f"{type(exc).__name__}: {exc}")
        if not self._tesis_closing:
            self.post_message(message)

    @on(ResultsScanned)
    def receive_scan(self, message: ResultsScanned) -> None:
        if message.generation != self._scan_generation:
            return
        self._scan_thread = None
        if self._queued_scan is not None:
            scan_args = self._queued_scan
            self._queued_scan = None
            self._start_scan(scan_args)
            return
        if message.error:
            self.query_one("#results-status", Static).update(f"Unable to scan artifacts: {message.error}")
            return
        self._display_rows(message.items)

    def on_unmount(self) -> None:
        self._tesis_closing = True
        self._scan_generation += 1
        self._queued_scan = None

    def _display_rows(self, items: list[ArtifactMetadata]) -> None:
        if self.repository is None:
            return
        table = self.query_one("#results-table", DataTable)
        table.clear()
        self.rows.clear()
        self.fingerprint_groups = self.repository.group_by_config_fingerprint(items)
        duplicate_counts = {key: len(group) for key, group in self.fingerprint_groups.items()}
        for index, item in enumerate(items):
            row_key = f"artifact-{index}"
            self.rows[row_key] = item
            same = duplicate_counts.get(item.config_fingerprint or "", 0)
            marker = f"SAME CONFIG ×{same}" if same > 1 else item.execution_id or item.run_id
            table.add_row(
                datetime.fromtimestamp(item.sort_timestamp).strftime("%Y-%m-%d %H:%M") if item.sort_timestamp else "—",
                item.status,
                item.provider,
                item.surface,
                item.security_level,
                item.payload_mode,
                marker,
                key=row_key,
            )
        self.query_one("#results-status", Static).update(f"{len(items)} readable artifacts; malformed files ignored")

    @on(DataTable.RowSelected, "#results-table")
    def open_result(self, event: DataTable.RowSelected) -> None:
        item = self.rows.get(str(event.row_key.value))
        if item:
            peers = self.fingerprint_groups.get(item.config_fingerprint or "", [])
            self.app.push_screen(ResultDetailScreen(item, same_config=peers))


class ArtifactLoaded(Message):
    def __init__(self, artifact: dict[str, Any], error: str | None = None) -> None:
        self.artifact = artifact
        self.error = error
        super().__init__()


class ResultDetailScreen(BaseTesisScreen):
    def __init__(self, metadata: ArtifactMetadata, *, same_config: list[ArtifactMetadata] | None = None) -> None:
        super().__init__()
        self.metadata = metadata
        self.same_config = same_config or []
        self.matrix_rows: dict[str, dict[str, Any]] = {}
        self.artifact: dict[str, Any] = {}
        self.rendered_tabs: set[str] = set()
        self._tesis_closing = False

    def compose(self) -> ComposeResult:
        tabs = ("Overview", "Scores", "Methods", "Payloads", "Evidence", "AKG", "Safety", "Trace", "Matrix", "Raw")
        yield Header(show_clock=True)
        with Vertical(id="detail-shell"):
            yield Label(f"Result: {self.metadata.execution_id or self.metadata.run_id}", classes="screen-title")
            with TabbedContent(id="result-tabs"):
                for label in tabs:
                    tab_id = label.lower()
                    with TabPane(label, id=f"result-tab-{tab_id}"):
                        if label == "Matrix":
                            yield DataTable(cursor_type="row", zebra_stripes=True, id="matrix-runs-table")
                        else:
                            yield RichLog(
                                max_lines=DETAIL_LOG_MAX_LINES,
                                markup=False,
                                wrap=True,
                                id=f"detail-{tab_id}",
                            )
            with Horizontal(classes="actions"):
                yield Button("Export JSON", id="export-json")
                yield Button("Export Markdown", id="export-markdown")
                yield Button("Export terminal", id="export-terminal")
            yield Static("", id="export-status")
        yield Tips("←→ tabs  Esc back")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#matrix-runs-table", DataTable)
        table.add_columns("Status", "Provider", "Surface", "Level", "Mode", "Execution")
        self.query_one("#export-status", Static).update("Loading artifact…")
        Thread(
            target=self._load_artifact,
            name="tesis-artifact-load",
            daemon=True,
        ).start()

    def _load_artifact(self) -> None:
        try:
            if self.metadata.raw and not self.metadata.is_matrix:
                payload: Any = dict(self.metadata.raw)
            else:
                with self.metadata.path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            if isinstance(payload, list):
                artifact = {"status": "unknown", "runs": payload}
            elif isinstance(payload, dict):
                artifact = payload
            else:
                artifact = {"error": "Artifact root is not a JSON mapping or list"}
            message = ArtifactLoaded(artifact)
        except Exception as exc:
            message = ArtifactLoaded({}, f"{type(exc).__name__}: {exc}")
        if not self._tesis_closing:
            self.post_message(message)

    @on(ArtifactLoaded)
    def receive_artifact(self, message: ArtifactLoaded) -> None:
        self._artifact_loaded(message.artifact, message.error)

    def _artifact_loaded(self, artifact: dict[str, Any], error: str | None) -> None:
        self.artifact = artifact
        self.rendered_tabs.clear()
        self.query_one("#export-status", Static).update(f"Unable to load artifact: {error}" if error else "")
        tabs = self.query_one("#result-tabs", TabbedContent)
        pane = tabs.active_pane
        label = pane.id.removeprefix("result-tab-") if pane and pane.id else "overview"
        self._render_tab(label)

    def on_unmount(self) -> None:
        self._tesis_closing = True

    @on(TabbedContent.TabActivated, "#result-tabs")
    def activate_result_tab(self, event: TabbedContent.TabActivated) -> None:
        pane_id = event.pane.id or "result-tab-overview"
        self._render_tab(pane_id.removeprefix("result-tab-"))

    def _render_tab(self, label: str) -> None:
        if not self.artifact or label in self.rendered_tabs:
            return
        if label == "matrix":
            self._populate_matrix_table()
            self.rendered_tabs.add(label)
            return
        selector = f"#detail-{label}"
        try:
            widget = self.query_one(selector, RichLog)
        except NoMatches:
            return
        data = self.artifact if label == "raw" else self._tab_payload(label)
        rendered = json.dumps(data, indent=2, default=str)
        if len(rendered) > DETAIL_RENDER_MAX_CHARS:
            rendered = (
                rendered[:DETAIL_RENDER_MAX_CHARS]
                + "\n… live view truncated for terminal stability; Export JSON retains the complete artifact."
            )
        widget.clear()
        widget.write(Text(rendered))
        self.rendered_tabs.add(label)

    def _populate_matrix_table(self) -> None:
        table = self.query_one("#matrix-runs-table", DataTable)
        table.clear()
        self.matrix_rows.clear()
        runs = self.artifact.get("runs", [])
        for index, run in enumerate(runs[:DETAIL_MATRIX_MAX_ROWS] if isinstance(runs, list) else []):
            if not isinstance(run, dict):
                continue
            key = f"matrix-run-{index}"
            self.matrix_rows[key] = run
            config = run.get("config", {})
            table.add_row(
                str(run.get("status", "unknown")),
                str(run.get("provider") or config.get("provider", "—")),
                str(run.get("surface") or config.get("surface", "—")),
                str(run.get("security_level") or config.get("security_level", "—")),
                str(run.get("payload_mode") or config.get("payload_mode", "—")),
                str(run.get("execution_id") or run.get("run_id", "—")),
                key=key,
            )
        if isinstance(runs, list) and len(runs) > DETAIL_MATRIX_MAX_ROWS:
            self.query_one("#export-status", Static).update(
                f"Showing first {DETAIL_MATRIX_MAX_ROWS} of {len(runs)} matrix runs; exports remain complete."
            )

    @on(DataTable.RowSelected, "#matrix-runs-table")
    def drill_into_matrix_run(self, event: DataTable.RowSelected) -> None:
        run = self.matrix_rows.get(str(event.row_key.value))
        if not run:
            return
        config = run.get("config", {})
        metadata = ArtifactMetadata(
            path=self.metadata.path,
            execution_id=run.get("execution_id"),
            run_id=run.get("run_id"),
            status=str(run.get("status", "unknown")),
            provider=run.get("provider") or config.get("provider"),
            surface=run.get("surface") or config.get("surface"),
            security_level=run.get("security_level") or config.get("security_level"),
            payload_mode=run.get("payload_mode") or config.get("payload_mode"),
            config_fingerprint=run.get("config_fingerprint"),
            artifact_kind="single",
            raw=run,
        )
        self.app.push_screen(ResultDetailScreen(metadata))

    def _tab_payload(self, label: str) -> Any:
        state = self.artifact.get("final_state", {})
        if label == "overview":
            return {
                "status": self.artifact.get("status"),
                "config": self.artifact.get("config"),
                "timing": self.artifact.get("timing"),
                "same_config_executions": [
                    peer.execution_id or peer.run_id for peer in self.same_config
                ] if len(self.same_config) > 1 else [],
            }
        if label == "scores":
            return {key: value for key, value in self.artifact.items() if "score" in key}
        if label == "methods":
            return {"selected": self.artifact.get("selected_method"), "viable": state.get("viable_methods"), "findings": state.get("confirmed_vulns")}
        if label == "payloads":
            return {"validation": state.get("payload_validation_results"), "provenance": state.get("payload_provenance")}
        if label == "evidence":
            return {"responses": self.artifact.get("response_evidence"), "verifier": self.artifact.get("verifier_decision")}
        if label == "akg":
            return {"path": self.artifact.get("akg_path"), "outcomes": state.get("achieved_outcomes")}
        if label == "safety":
            return {"guardrails": state.get("guardrail_activations"), "fallbacks": state.get("fallback_events"), "containment": state.get("containment_events")}
        if label == "trace":
            return {"events": self.artifact.get("execution_log"), "error": self.artifact.get("error")}
        if label == "matrix":
            return {
                "totals": self.artifact.get("totals"),
                "by_provider": self.artifact.get("by_provider"),
                "by_provider_level": self.artifact.get("by_provider_level"),
                "constituent_runs": [
                    {
                        "execution_id": run.get("execution_id"),
                        "run_id": run.get("run_id"),
                        "status": run.get("status"),
                        "config": run.get("config"),
                    }
                    for run in self.artifact.get("runs", [])
                    if isinstance(run, dict)
                ],
            }
        return {}

    @on(Button.Pressed, "#export-json, #export-markdown, #export-terminal")
    def export(self, event: Button.Pressed) -> None:
        export_dir = self.metadata.path.parent.parent / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        identity = self.metadata.execution_id or self.metadata.run_id or "artifact"
        if event.button.id == "export-json":
            path = export_dir / f"{identity}.json"
            path.write_text(json.dumps(self.artifact, indent=2, default=str), encoding="utf-8")
        elif event.button.id == "export-markdown":
            path = export_dir / f"{identity}.md"
            path.write_text(f"# {identity}\n\n```json\n{json.dumps(self._tab_payload('overview'), indent=2)}\n```\n", encoding="utf-8")
        else:
            path = export_dir / f"{identity}.txt"
            path.write_text(json.dumps(self._tab_payload("overview"), indent=2), encoding="utf-8")
        self.query_one("#export-status", Static).update(f"Exported {path}")


class ValidationLine(Message):
    def __init__(self, generation: int, text: str) -> None:
        self.generation = generation
        self.text = text
        super().__init__()


class ValidationScreen(BaseTesisScreen):
    def __init__(self) -> None:
        super().__init__()
        self._validation_generation = 0
        self._tesis_closing = False
        self._validation_thread: Thread | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="validation-shell"):
            yield Label("Validate Framework", classes="screen-title")
            yield Select(((v, v) for v in RUNTIME_AGENT_NODE_NAMES), id="validation-agent")
            with Horizontal(classes="actions"):
                yield Button("Configuration", id="validate-config")
                yield Button("Target reachability", id="validate-target")
                yield Button("Selected method agent", id="validate-agent")
                yield Button("All registered agents", id="validate-all")
            yield RichLog(markup=True, id="validation-log")
        yield Tips("Choose scope  Enter run  Esc back")
        yield Footer()

    @on(Button.Pressed, "#validate-config")
    def validate_config(self) -> None:
        try:
            load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={})
            self.query_one("#validation-log", RichLog).write("[green]✓ Configuration valid[/]")
        except ConfigError as exc:
            self.query_one("#validation-log", RichLog).write(f"[red]✗ {exc}[/]")

    @on(Button.Pressed, "#validate-target")
    def validate_target(self) -> None:
        self.run_validation("target")

    @on(Button.Pressed, "#validate-agent")
    def validate_agent(self) -> None:
        self.run_validation(_select_value(self, "#validation-agent", RUNTIME_AGENT_NODE_NAMES[0]))

    @on(Button.Pressed, "#validate-all")
    def validate_all(self) -> None:
        self.run_validation("all")

    def run_validation(self, scope: str) -> None:
        if self._validation_thread is not None and self._validation_thread.is_alive():
            self.query_one("#validation-log", RichLog).write(
                "[yellow]A validation is already running; wait for it to finish or leave this screen.[/]"
            )
            return
        self._validation_generation += 1
        generation = self._validation_generation
        self._validation_thread = Thread(
            target=self._run_validation,
            args=(generation, scope),
            name="tesis-validation",
            daemon=True,
        )
        self._validation_thread.start()

    def _validation_line(self, generation: int, text: str) -> None:
        if not self._tesis_closing:
            self.post_message(ValidationLine(generation, text))

    def _run_validation(self, generation: int, scope: str) -> None:
        try:
            cfg = load_and_resolve_config(config_path=str(CONFIG_PATH), cli_args={})
            if scope == "target":
                response = httpx.get(cfg.target_url, timeout=5, follow_redirects=False)
                self._validation_line(generation, f"Target: HTTP {response.status_code}")
                return
            names = list(RUNTIME_AGENT_NODE_NAMES) if scope == "all" else [scope]
            for name in names:
                if self._tesis_closing or generation != self._validation_generation:
                    return
                state = {**new_default_state(), "target_url": cfg.target_url, "security_level": cfg.level}
                try:
                    result = RUNTIME_AGENT_HANDLERS[name](state)
                    findings = len(result.get("confirmed_vulns", []))
                    self._validation_line(generation, f"[green]✓ {name}[/] findings={findings}")
                except Exception as exc:
                    self._validation_line(generation, f"[red]✗ {name}[/] {type(exc).__name__}: {exc}")
        except Exception as exc:
            self._validation_line(generation, f"[red]✗ {type(exc).__name__}: {exc}[/]")

    @on(ValidationLine)
    def receive_validation_line(self, message: ValidationLine) -> None:
        if message.generation == self._validation_generation:
            self.query_one("#validation-log", RichLog).write(message.text)

    def on_unmount(self) -> None:
        self._tesis_closing = True
        self._validation_generation += 1


class FrameworkInfoScreen(BaseTesisScreen):
    def compose(self) -> ComposeResult:
        from core.graph_builder import RUNTIME_AGENT_NODE_NAMES

        topology = [
            "START → recon → orchestrator → payload_candidate_builder → payload_validator",
            "→ selected method agent → chaining_router → orchestrator | payload_candidate_builder | scorer → END",
        ]
        payload = {
            "schema_version": "tui.v1",
            "providers": list(PROVIDER_CHOICES),
            "surfaces": list(SURFACE_CHOICES),
            "methods": list(RUNTIME_AGENT_NODE_NAMES),
            "security_levels": list(SECURITY_LEVEL_CHOICES),
            "graph_topology": topology,
        }
        yield Header(show_clock=True)
        with Vertical(id="info-shell"):
            yield Label("Framework Information", classes="screen-title")
            yield RichLog(id="info-log")
        yield Tips("Esc back")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#info-log", RichLog).write(
            Syntax(json.dumps({
                "schema_version": "tui.v1",
                "providers": list(PROVIDER_CHOICES),
                "surfaces": list(SURFACE_CHOICES),
                "methods": list(RUNTIME_AGENT_NODE_NAMES),
                "security_levels": list(SECURITY_LEVEL_CHOICES),
                "graph_topology": (
                    "START → recon → orchestrator → payload_candidate_builder → payload_validator "
                    "→ method agent → chaining_router → orchestrator|payload_candidate_builder|scorer → END"
                ),
            }, indent=2), "json", word_wrap=True)
        )


class TesisApp(App[None]):
    """Keyboard-first terminal application for TESIS."""

    TITLE = "TESIS Experiment Harness"
    CSS = """
    Screen { background: #071018; color: #d7e3ea; }
    Header { background: #0b1b26; color: #70e1f5; }
    Footer { background: #0b1b26; }
    MainMenuScreen { align-horizontal: center; }
    .tips { dock: bottom; height: 1; background: #0d222e; color: #85a8b6; padding: 0 2; }
    .screen-title { text-style: bold; color: #70e1f5; height: 2; padding: 0 1; }
    .section-title, .panel-title { color: #44c7db; text-style: bold; margin-top: 1; }
    #menu-shell { width: 64; height: auto; max-height: 30; margin: 3 0; border: round #1c6073; padding: 1 3; }
    #brand { text-align: center; text-style: bold; color: #70e1f5; height: 2; }
    #subtitle { text-align: center; color: #7f9da8; margin-bottom: 1; }
    #main-menu { height: 16; border: none; }
    #setup-scroll, #settings-shell, #results-shell, #detail-shell, #validation-shell, #info-shell { padding: 1 2 3 2; }
    .form-grid { grid-size: 2; grid-columns: 1fr 2fr; grid-gutter: 0 1; height: auto; }
    .form-grid Label { height: 3; content-align: left middle; }
    .form-grid Input, .form-grid Select { height: 3; }
    #matrix-grid { grid-size: 4; grid-columns: 1fr 1fr 1fr 1fr; height: 13; grid-gutter: 1; }
    SelectionList { height: 10; border: round #173f4d; }
    .inline-form, .checks, .actions, .filters { height: 4; align-vertical: middle; }
    .inline-form Input { width: 10; margin: 0 2; }
    .checks Checkbox { margin-right: 2; }
    .actions Button { margin-right: 1; }
    #setup-summary { min-height: 2; color: #9de9f5; }
    #setup-status, #settings-status, #results-status, #export-status { min-height: 2; color: #e6c66b; }
    #settings-shell TabbedContent { height: 1fr; }
    #yaml-editor { height: 1fr; border: round #1c6073; }
    #dashboard-grid { grid-size: 3; grid-columns: 28 1fr 34; grid-gutter: 1; height: 1fr; padding: 1; }
    .panel { border: round #1c6073; padding: 0 1; }
    #run-header { height: 2; background: #0d222e; color: #9de9f5; padding: 0 2; }
    #stream-log, #trace-log { height: 1fr; }
    .hidden { display: none; }
    #matrix-progress { height: 2; margin-top: 1; }
    #results-table { height: 1fr; border: round #1c6073; }
    .filters Select { width: 1fr; margin-right: 1; }
    #detail-shell TabbedContent { height: 1fr; }
    #validation-log, #info-log { height: 1fr; border: round #1c6073; }
    .compact #dashboard-grid { grid-size: 1; grid-columns: 1fr; grid-rows: 12 1fr 16; }
    .compact #matrix-grid { grid-size: 2; grid-columns: 1fr 1fr; height: 25; }
    """

    def exit(
        self,
        result: None = None,
        return_code: int = 0,
        message: Any = None,
    ) -> None:
        """Cancel app work and release screen buffers before stopping the loop."""
        if not getattr(self, "_tesis_shutdown_started", False):
            self._tesis_shutdown_started = True
            for screen in tuple(self.screen_stack):
                prepare = getattr(screen, "prepare_shutdown", None)
                if callable(prepare):
                    prepare()
            self.workers.cancel_all()
        super().exit(result=result, return_code=return_code, message=message)

    def on_mount(self) -> None:
        self.push_screen(MainMenuScreen())


def run_tui() -> None:
    TesisApp().run()


__all__ = ["CONFIG_PATH", "TesisApp", "run_tui"]
