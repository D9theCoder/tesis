"""Configuration and launch forms for the terminal UI."""

from __future__ import annotations

import re
from threading import Thread
from typing import Any, Literal

from textual import on
from textual.message import Message
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    ContentSwitcher,
    Input,
    Label,
    OptionList,
    Select,
    SelectionList,
    Static,
    TextArea,
)

from tesis.config_fields import (
    ALL_FIELD_SPECS,
    FieldSpec,
    field_choice_label,
    get_config_value,
    payload_mode_label,
    set_config_value,
)
from tesis.config_loader import (
    dump_yaml_config,
    load_and_resolve_config,
    load_yaml_config,
)
from tesis.tui_commands import BaseDrawer
from tesis.tui_auth import ChatGPTAuth
from tesis.tui_config import DraftConfigCache, TuiConfigCache
from tesis.tui_reasoning import ReasoningControl
from llm.reasoning import model_efforts
from textual.widgets.option_list import Option
from tesis.tui_choices import ChoiceSelect
from tesis.tui_rows import ControlRow
from tesis.tui_widgets import (
    KeyboardActions, PaletteInput, SettingField, SettingValueRow, TextCheckbox, TextSelectionList,
    execution_summary, key_hints, model_connection, summary_rows,
)
import tesis.tui_security as tui_security
import tesis.tui_state as tui_state


_LAUNCH_SCOPE_FIELDS: tuple[str, ...] = ("target_url", "experiment_condition", "target_method", "scoring_mode")
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
_LAUNCH_PROFILE_LABELS = {
    "provider": "Primary provider / model",
    "model_profile": "Model profile for both roles (optional)",
    "providers": "Provider / model profiles",
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
    "scoring_mode": "scoring_mode",
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




class LaunchDrawer(BaseDrawer):
    """Guided launch: Scope → Coordinates → Runtime → Review.

    Every step renders native controls bound to the existing config fields;
    Review resolves through the same loader the headless CLI uses and is the
    only step that offers Start. Started requests are frozen until terminal.
    """

    STEPS = ("Scope", "Coordinates", "Runtime", "Review")
    BINDINGS = [Binding("ctrl+f8", "next_step", "Next", show=False),
                Binding("ctrl+f7", "previous_step", "Previous", show=False)]

    def __init__(self, mode: Literal["single", "matrix"] = "single") -> None:
        super().__init__()
        self.mode: Literal["single", "matrix"] = mode if mode in ("single", "matrix") else "single"
        self._tesis_closing = False
        self._step = 0
        self._step_focus: dict[int, Any] = {}
        self._confirmed_fields: set[str] = set()
        self._frozen = None
        self._config_cache = TuiConfigCache()
        self._preview_timer: Any = None
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
            parsed = self._config_cache.raw(loader=load_yaml_config)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _field_control(self, path: str, config: dict, resolved: Any) -> Any:
        spec = self._field_specs[path]
        field_id = _launch_field_id(path)
        choices = [str(value) for value in spec.choice_values(config)]
        value = _launch_field_value(resolved, path)
        label = _LAUNCH_GUARDRAIL_LABELS.get(path, spec.label)
        from tesis.provider_registry import model_profile_labels
        profile_labels = model_profile_labels(config) if path in {"provider", "providers", "model_profile"} else {}
        if spec.kind == "select" or (choices and spec.value_type is str and not spec.multiple):
            current = None if value in (None, "") else str(value)
            unavailable = current is not None and current not in choices
            if unavailable:
                choices.append(current)
            labels = profile_labels if path in {"provider", "providers", "model_profile"} else {}
            return ChoiceSelect([(f"{choice} (saved; unavailable)" if unavailable and choice == current else labels.get(choice) or field_choice_label(spec, choice), choice) for choice in choices],
                          value=current if current is not None else Select.NULL,
                          allow_blank=True, prompt=label, id=field_id)
        if spec.multiple or spec.kind == "multi_select":
            selected = {str(item) for item in (value or [])}
            labels = profile_labels if path in {"provider", "providers", "model_profile"} else {}
            return TextSelectionList(*[(labels.get(choice) or field_choice_label(spec, choice), choice, choice in selected) for choice in choices],
                                 id=field_id)
        if spec.value_type is bool or spec.kind == "boolean":
            return TextCheckbox(label, value=bool(value), id=field_id)
        if path == "target_url":
            # The configured endpoint may carry userinfo/query/fragment secrets,
            # so the widget is seeded masked and the raw value never reaches it.
            self._target_seed = tui_security._safe_url(value) if value not in (None, "") else ""
            self._target_display = self._target_seed
            return Input(value=self._target_seed, placeholder=label, id=field_id)
        return Input(value="" if value in (None, "") else str(value),
                     placeholder=label, id=field_id)

    def _yield_step(self, paths: tuple[str, ...], config: dict, resolved: Any) -> None:
        for path in paths:
            if path in self._field_specs:
                label = _LAUNCH_PROFILE_LABELS.get(path, _LAUNCH_GUARDRAIL_LABELS.get(path, self._field_specs[path].label))
                control = self._field_control(path, config, resolved)
                from tesis.tui_rows import ControlRow
                yield ControlRow(label, control, self._field_specs[path].description, spec=self._field_specs[path])

    def compose(self) -> ComposeResult:
        config = self._raw_config()
        try:
            resolved = self._resolved_config()
        except Exception:
            resolved = None
        yield Label("Run experiment" if self.mode == "single" else "Build experiment matrix", id="launch-title", classes="drawer-title")
        yield Static("", id="launch-step-indicator", markup=False)
        with ContentSwitcher(initial="launch-step-scope", id="launch-steps"):
            with VerticalScroll(id="launch-step-scope", classes="launch-step"):
                yield from self._yield_step(_LAUNCH_SCOPE_FIELDS, config, resolved)
            with VerticalScroll(id="launch-step-coordinates", classes="launch-step"):
                yield from self._yield_step(_LAUNCH_COORDINATE_FIELDS, config, resolved)
                if self.mode == "matrix":
                    yield from self._yield_step(_LAUNCH_MATRIX_FIELDS, config, resolved)
                yield Static("", id="launch-model-connection", markup=False)
                yield Label("ChatGPT / Codex model ID (optional override)", id="launch-codex-model-label", classes="field-label")
                yield ControlRow('ChatGPT / Codex model ID (optional override)', Input(placeholder="Use the saved model or enter an exact model ID", id="launch-codex-model"))
                yield Label("Reasoning effort", classes="field-label")
                yield ReasoningControl(id="launch-reasoning-effort", modes=(
                    ("Keep per-role reasoning settings", "preserve"),
                    ("Inherit profile effort for both roles", "inherit"),
                ))
            with VerticalScroll(id="launch-step-runtime", classes="launch-step"):
                primary = ("candidate_budget", "iterations", "stop_policy", "output_dir", "report_format")
                yield from self._yield_step(primary, config, resolved)
                yield Button("Advanced runtime & model roles", id="launch-advanced-open")
                with Collapsible(title="Advanced runtime & model roles (Esc returns)", collapsed=True, id="launch-advanced"):
                    yield from self._yield_step(tuple(path for path in _LAUNCH_RUNTIME_FIELDS if path not in primary), config, resolved)
                    runtime = getattr(resolved, "llm_runtime", None)
                    roles = getattr(runtime, "roles", {}) or {}
                    concurrency = getattr(runtime, "max_concurrency", None)
                    from tesis.provider_registry import model_profile_labels
                    labels = model_profile_labels(config)
                    profiles = [(labels.get(name, name), name) for name in self._profile_names(config)]
                    for role in ("orchestrator", "payload_generator"):
                        saved = _role_attr(roles, role, "model_profile")
                        if saved and saved not in {name for _, name in profiles}:
                            profiles.append((f"{saved} (saved; unavailable)", saved))
                    profile_names = {name for _, name in profiles}
                    yield Label("LLM concurrency (1-4)", classes="field-label")
                    yield ControlRow('LLM concurrency (1-4)', Input(value="" if concurrency in (None, "") else str(concurrency),
                                placeholder="LLM max concurrency (1-4)",
                                id="launch-llm-concurrency"), spec=FieldSpec("llm_runtime.max_concurrency", label="LLM concurrency", value_type=int, min_value=1, max_value=4))
                    yield ControlRow('LLM cache within run', TextCheckbox("LLM cache within run",
                                   value=bool(getattr(runtime, "cache_enabled", False)),
                                   id="launch-llm-cache"))
                    yield Static("; ".join(
                        f"{name}: {getattr(settings, 'reasoning_effort', None) or 'inherit profile'}"
                        for name, settings in roles.items()
                    ), markup=False, id="launch-role-reasoning")
                    orchestrator = _role_attr(roles, "orchestrator", "model_profile")
                    payload_role = _role_attr(roles, "payload_generator", "model_profile")
                    yield Label("Orchestrator model profile", classes="field-label")
                    yield ControlRow('Orchestrator model profile', ChoiceSelect(profiles,
                                 value=orchestrator if orchestrator in profile_names else Select.NULL,
                                 allow_blank=True, prompt="orchestrator model profile",
                                 id="launch-orchestrator-profile"))
                    yield Label("Payload generator model profile", classes="field-label")
                    yield ControlRow('Payload generator model profile', ChoiceSelect(profiles,
                                 value=payload_role if payload_role in profile_names else Select.NULL,
                                 allow_blank=True, prompt="payload model profile",
                                 id="launch-payload-profile"))
            with VerticalScroll(id="launch-step-review", classes="launch-step"):
                yield Static("", id="launch-review", markup=False)
        with KeyboardActions(id="launch-nav"):
            yield Button("Back", id="launch-back")
            yield Button("Next", id="launch-next")
            yield Button("Start", id="launch-start")
            yield Button("Close", id="launch-close")
        yield Static(key_hints(("Ctrl+F7/F8", "previous / next"), ("Enter", "edit row"), ("Esc", "previous / back")), classes="drawer-hint")

    @on(ControlRow.Confirmed)
    def launch_field_confirmed(self, event: ControlRow.Confirmed) -> None:
        event.stop()
        self._confirmed_fields.add(event.row.control_widget.id or "")

    @on(ReasoningControl.Changed)
    def launch_capability_changed(self) -> None:
        control = self.query_one("#launch-reasoning-effort", ReasoningControl)
        reason = control.blocking_reason
        self.query_one("#launch-start", Button).disabled = bool(reason)
        if self._step == 3:
            self._render_review()
            if reason:
                self.query_one("#launch-review", Static).update(f"Start blocked: {reason}")

    def _profile_names(self, config: dict) -> tuple[str, ...]:
        try:
            return tuple(self._field_specs["model_profile"].choice_values(config))
        except Exception:
            return ()

    def on_mount(self) -> None:
        self._configure_launch_reasoning()
        self._goto_step(0)
        self._initial_args = self._cli_args()

    @on(Select.Changed, "#launch-field-provider, #launch-field-model-profile, #launch-orchestrator-profile, #launch-payload-profile")
    @on(SelectionList.SelectedChanged, "#launch-field-providers")
    @on(Input.Changed, "#launch-codex-model")
    def launch_profile_changed(self) -> None:
        if self.is_mounted:
            self._configure_launch_reasoning()
            self._schedule_preview()

    def _configure_launch_reasoning(self) -> None:
        from dataclasses import asdict
        from tesis.provider_registry import expanded_model_sections
        try:
            cfg = self._resolved_config()
            raw = self._raw_config()
            sections = expanded_model_sections(raw)
            primary = cfg.models.get(cfg.model_profile or cfg.provider)
            codex = primary is not None and primary.provider == "openai_codex_auth"
            self.query_one("#row-launch-codex-model").display = codex
            self.query_one("#launch-codex-model-label").display = codex
            profiles, catalogs = [], []
            for coordinate in (cfg.providers if self.mode == "matrix" else [cfg.provider]):
                for role in cfg.llm_runtime.roles.values():
                    profile_id = role.model_profile or cfg.model_profile or coordinate
                    profile = cfg.models.get(profile_id)
                    if profile is None:
                        continue
                    section = asdict(profile)
                    section["model_name"] = role.model_name or profile.model_name
                    if section not in profiles:
                        profiles.append(section)
                        metadata = sections.get(profile_id) if section["model_name"] == profile.model_name else None
                        catalogs.append(model_efforts(raw, section["model_name"], metadata))
            efforts = ([x for x in catalogs[0] if all(x in values for values in catalogs)]
                       if catalogs and all(values is not None for values in catalogs) else None)
            self.query_one("#launch-reasoning-effort", ReasoningControl).configure(profiles, efforts)
        except Exception:
            self.query_one("#launch-reasoning-effort", ReasoningControl).configure([], None)

    def _schedule_preview(self) -> None:
        if self._preview_timer is not None:
            self._preview_timer.stop()
        self._preview_timer = self.set_timer(0.15, self._refresh_preview)

    def _refresh_preview(self) -> None:
        self._preview_timer = None
        if self._tesis_closing:
            return
        if self._step == 1:
            self._render_model_connection()
        elif self._step == 3:
            self._render_review()

    def _render_model_connection(self) -> None:
        try:
            cfg = self._resolved_config()
            profile_id = cfg.model_profile or cfg.provider
            info = model_connection(profile_id, cfg.models.get(profile_id))
            self.query_one("#launch-model-connection", Static).update(summary_rows([
                ("Provider", info["provider"]), ("Model", info["model"]),
                ("API protocol", info["protocol"]),
            ]))
        except Exception as exc:
            self.query_one("#launch-model-connection", Static).update(tui_security._safe_config_error_text(exc))

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
        if self.is_mounted:
            control = self.query_one("#launch-reasoning-effort", ReasoningControl)
            if control.mode == "inherit":
                args["llm_runtime"] = {"roles": {role: {"reasoning_effort": None}
                    for role in ("orchestrator", "payload_generator")}}
            elif control.mode != "preserve":
                args["reasoning_effort"] = control.value
            from tesis.provider_registry import expanded_model_sections
            sections = expanded_model_sections(self._raw_config())
            primary = args.get("model_profile") or args.get("provider") or self._raw_config().get("provider")
            override = self.query_one("#launch-codex-model", Input).value.strip()
            if override and any(c.isspace() or ord(c) < 32 for c in override):
                raise ValueError("Model ID must not contain spaces or control characters.")
            if override and sections.get(primary, {}).get("provider", primary) == "openai_codex_auth":
                for role, key, profile_key in (("orchestrator", "orchestrator_model", "orchestrator_model_profile"),
                                               ("payload_generator", "payload_model", "payload_model_profile")):
                    selected_profile = args.get(profile_key) or (((self._raw_config().get("llm_runtime") or {}).get("roles") or {}).get(role) or {}).get("model_profile") or primary
                    if sections.get(selected_profile, {}).get("provider", selected_profile) == "openai_codex_auth":
                        args[key] = override
        try:
            args["llm_cache"] = bool(self.query_one("#launch-llm-cache", Checkbox).value)
        except Exception:
            pass
        if "launch-field-model-profile" in self._confirmed_fields and self.query_one("#launch-field-model-profile", Select).value is Select.NULL:
            args["model_profile"] = ""
        for identifier, role in (("launch-orchestrator-profile", "orchestrator"), ("launch-payload-profile", "payload_generator")):
            if identifier in self._confirmed_fields and self.query_one(f"#{identifier}", Select).value is Select.NULL:
                args.setdefault("llm_runtime", {}).setdefault("roles", {}).setdefault(role, {})["model_profile"] = None
        for path, spec in self._field_specs.items():
            identifier = _launch_field_id(path)
            if spec.value_type is bool and identifier in self._confirmed_fields:
                if self.query_one(f"#{identifier}", Checkbox).value is False:
                    args[_LAUNCH_CLI_KEYS.get(path, path)] = "false"
        if self.mode == "matrix":
            args["matrix"] = True
        return args

    def _resolved_config(self, *, fresh: bool = False) -> Any:
        return self._config_cache.resolve(self._cli_args(), loader=load_and_resolve_config, fresh=fresh)

    # -- navigation --------------------------------------------------

    def on_descendant_focus(self, event: Any) -> None:
        super().on_descendant_focus()
        page = self.query_one(f"#launch-step-{self.STEPS[self._step].casefold()}")
        if page in event.widget.ancestors:
            self._step_focus[self._step] = event.widget

    def _goto_step(self, index: int) -> None:
        old_page = self.query_one(f"#launch-step-{self.STEPS[self._step].casefold()}")
        if self.app.focused is not None and old_page in self.app.focused.ancestors:
            self._step_focus[self._step] = self.app.focused
        self._step = max(0, min(index, len(self.STEPS) - 1))
        try:
            self.query_one("#launch-steps", ContentSwitcher).current = (
                f"launch-step-{self.STEPS[self._step].casefold()}"
            )
        except Exception:
            pass
        if self._step == len(self.STEPS) - 1:
            self._render_review()
            self.launch_capability_changed()
        elif self._step == 1:
            self._render_model_connection()
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
        page = self.query_one(f"#launch-step-{self.STEPS[self._step].casefold()}")
        descendants = set(page.walk_children())
        controls = [widget for widget in self.focus_chain if widget in descendants]
        remembered = self._step_focus.get(self._step)
        if remembered in controls:
            remembered.focus()
        elif controls:
            controls[0].focus()
        elif self._step == len(self.STEPS) - 1:
            # Review never arms Start just by changing steps.
            self.query_one("#launch-back", Button).focus()

    def action_next_step(self) -> None:
        self.next_step()

    def action_previous_step(self) -> None:
        self.previous_step()

    def action_back(self) -> None:
        advanced = self.query_one("#launch-advanced", Collapsible)
        if self._step == 2 and not advanced.collapsed:
            advanced.collapsed = True
            for child in self.query_one("#launch-step-runtime").children:
                child.display = True
            self.query_one("#launch-advanced-open", Button).focus()
        elif self._step:
            self.previous_step()
        else:
            super().action_back()

    @on(Button.Pressed, "#launch-advanced-open")
    def open_advanced(self) -> None:
        self.query_one("#launch-advanced", Collapsible).collapsed = False
        self.query_one("#launch-advanced").add_class("launch-advanced-page")
        self.query_one("#launch-advanced-open").display = False
        for child in self.query_one("#launch-step-runtime").children:
            if child.id != "launch-advanced":
                child.display = False
        controls = [widget for widget in self.focus_chain if self.query_one("#launch-advanced") in widget.ancestors]
        if controls:
            controls[0].focus()

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
        masked = tui_security._safe_url(typed)
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
        if self.is_mounted and self._step == 3:
            self._schedule_preview()

    def _render_review(self) -> None:
        try:
            cfg = self._resolved_config()
            text = execution_summary(cfg, mode=self.mode)
        except Exception as exc:
            text = f"Configuration needs attention\n{tui_security._safe_config_error_text(exc)}"
        self.query_one("#launch-review", Static).update(text)

    @on(Button.Pressed, "#launch-close")
    def close_drawer(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#launch-start")
    def start_from_review(self) -> None:
        from tesis.tui_mission import MissionControlScreen

        if self._frozen is not None or self._step != 3:
            return
        try:
            model_id = self.query_one("#launch-codex-model", Input).value.strip()
            if model_id and any(c.isspace() or ord(c) < 32 for c in model_id):
                raise ValueError("Model ID must not contain spaces or control characters.")
            self._configure_launch_reasoning()
            self.query_one("#launch-reasoning-effort", ReasoningControl).ensure_ready()
            cfg = self._resolved_config(fresh=True)
        except Exception as exc:
            try:
                self.query_one("#launch-review", Static).update(
                    f"Review\nconfig error: {tui_security._safe_config_error_text(exc)}"
                )
            except Exception:
                pass
            return
        self._frozen = cfg
        mission = next(
            (s for s in reversed(self.app.screen_stack) if isinstance(s, MissionControlScreen)), None
        )
        if mission is None:
            self.app.pop_screen()
            return
        # Launch may have been opened from Plan or another inspection dialog.
        # Reveal the live monitor before starting, removing every setup layer.
        with self.app.batch_update():
            while self.app.screen is not mission:
                self.app.pop_screen()
            mission.start_run(cfg, mode=self.mode)

    def prepare_navigation(self) -> bool:
        if self._cli_args() != getattr(self, "_initial_args", {}):
            self.notify("Setup has unsaved edits. Use Close to discard before changing workspace.")
            return False
        return True

    def prepare_shutdown(self) -> None:
        if self._preview_timer is not None:
            self._preview_timer.stop()
            self._preview_timer = None
        self._tesis_closing = True

    def on_unmount(self) -> None:
        self.prepare_shutdown()


class ChatGPTModelsLoaded(Message):
    """Thread-safe delivery without blocking the worker on the UI loop."""

    def __init__(self, generation: int, profile: str, account: str,
                 models: list[dict[str, Any]], error: str | None):
        super().__init__()
        self.generation = generation
        self.profile = profile
        self.account = account
        self.models = models
        self.error = error


class SettingsSaved(Message):
    def __init__(self, generation: int, payload: dict[str, Any], error: str | None):
        super().__init__()
        self.generation, self.payload, self.error = generation, payload, error


class SettingsDrawer(BaseDrawer):
    """Full-window categories with one scrollable section and fixed Save controls."""

    SECTIONS = (
        ("target", "Target & defaults"), ("model", "API providers"),
        ("chatgpt", "ChatGPT accounts"), ("llm", "LLM runtime"),
        ("evaluator", "AI evaluator"), ("policy", "Policy & output"),
        ("yaml", "Advanced YAML"),
    )
    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=False, priority=True),
        Binding("ctrl+f6", "categories", "Categories", show=False),
        Binding("ctrl+f4", "edit_yaml", "Advanced YAML", show=False),
        Binding("up", "setting_focus(-1)", show=False, priority=True),
        Binding("down", "setting_focus(1)", show=False, priority=True),
        Binding("home", "setting_boundary(0)", show=False),
        Binding("end", "setting_boundary(-1)", show=False),
        Binding("left", "focus_categories", show=False, priority=True),
        Binding("right", "content", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.preserved_secret_placeholders: dict[str, str] = {}
        self.literal_warning_acknowledged = False
        self._tesis_closing = False
        self._settings_generation = 0
        self._model_generation = 0
        self._catalog_binding: tuple[str, str] | None = None
        self._pending_api_keys: dict[str, str] = {}
        self._saving = False
        self._loaded_ok = False
        self._saved_text = ""
        self._discard_armed = False
        self._content_focus = None
        self._evaluator_display_info: dict[str, str] = {}
        self._evaluator_supports_tokens = True
        self._config_cache = TuiConfigCache()
        self._draft_cache = DraftConfigCache()
        self._draft_timer: Any = None
        self._evaluator_sync_key: tuple[str, bool] | None = None
        self._evaluator_has_choices = False
        self._evaluator_valid = False
        self._evaluator_preview_text: str | None = None
        self._evaluator_reasoning_key: Any = None
        self._chatgpt_models: dict[str, dict] = {}
        self._chatgpt_account_value: str | None = None
        self._form_baselines: dict[str, Any] = {}
        self._section_returns: dict[str, Any] = {}
        self._settings_values: dict[str, Any] = {}
        self._account_detail = False
        self._browsing_categories = False
        self._settings_profile_id = ""

    def compose(self) -> ComposeResult:
        yield Label("Settings", id="settings-title", classes="drawer-title")
        with Horizontal(id="settings-workspace"):
            yield OptionList(*(Option(label, id=section) for section, label in self.SECTIONS), id="settings-categories")
            with ContentSwitcher(initial="settings-section-target", id="settings-content"):
                with VerticalScroll(id="settings-section-target", classes="settings-section"):
                    yield Label("Target & defaults", classes="section-heading")
                    yield Static("Default DVWA target and experiment settings used by Run and Matrix setup.", classes="section-note", markup=False)
                    yield Static("", id="settings-target-error", markup=False)
                    with Vertical(id="settings-target-body", classes="settings-card"):
                        yield SettingValueRow("Target URL", "Base URL of the authorized DVWA target.", id="setting-target")
                        yield SettingValueRow("Provider / model", "Saved provider and model profile used by default.", id="setting-primary-model")
                        yield SettingValueRow("Security level", "Configured DVWA protection level.", id="setting-level")
                        yield SettingValueRow("Surface", "Vulnerability surface for the default run.", id="setting-surface")
                        yield SettingValueRow("Payload mode", "Controls static seeds and constrained LLM candidates.", id="setting-payload-mode")
                        yield SettingValueRow("Condition", "Experiment condition for the default run.", id="setting-condition")
                        yield SettingValueRow("Target method", "An empty value leaves method selection to the orchestrator.", id="setting-method")
                    with Vertical(id="settings-target-actions", classes="settings-card"):
                        yield ChoiceSelect([], prompt="Choose default provider / model", id="settings-default-provider")
                        yield Button("Apply default model to draft", id="settings-default-apply")
                        yield Button("Edit defaults in YAML", id="settings-edit-target", classes="edit-yaml")
                        yield Static("Edit the default settings in the masked configuration draft.", classes="setting-description", markup=False)
                with VerticalScroll(id="settings-section-model", classes="settings-section"):
                    yield Label("API providers", classes="section-heading")
                    with Vertical(id="settings-model-body", classes="settings-card"):
                        yield SettingValueRow("Active provider", id="setting-provider")
                        yield SettingValueRow("Active model", id="setting-model")
                        yield SettingValueRow("API protocol", id="setting-protocol")
                    with KeyboardActions(classes="compact-actions"):
                        yield Button("Add provider", id="settings-api-add")
                        yield Button("Edit provider / models", id="settings-api-edit", disabled=True)
                    yield ChoiceSelect([], prompt="Saved API providers", id="settings-api-provider", classes="row-value-storage")
                    yield PaletteInput(placeholder="Search providers", id="settings-provider-query", list_selector="#settings-provider-list")
                    yield OptionList(id="settings-provider-list")
                    yield Static("Choose a provider to inspect its API protocol and models.", id="settings-provider-details", markup=False)
                with VerticalScroll(id="settings-section-chatgpt", classes="settings-section"):
                    yield Label("ChatGPT accounts", classes="section-heading")
                    yield Static("Sign in with ChatGPT, then select the saved profile in Run or Matrix to use it.", classes="section-note", markup=False)
                    try:
                        raw = self._config_cache.raw(loader=load_yaml_config)
                    except Exception:
                        raw = {}
                    if not isinstance(raw, dict):
                        raw = {}
                    configured_models = raw.get("models") or {}
                    if not isinstance(configured_models, dict):
                        configured_models = {}
                    profiles = {name: value for name, value in configured_models.items()
                                if isinstance(value, dict) and value.get("provider", name) == "openai_codex_auth"}
                    if not profiles:
                        name = "openai_codex_auth"
                        suffix = 2
                        while name in configured_models:
                            name = f"openai_codex_auth_{suffix}"
                            suffix += 1
                        profiles = {name: {}}
                    selected = next(iter(profiles))
                    profile = profiles[selected]
                    extra = profile.get("extra") if isinstance(profile.get("extra"), dict) else {}
                    account = profile.get("account", extra.get("account", "default"))
                    yield PaletteInput(placeholder="Search account profiles", id="settings-account-query", list_selector="#settings-account-list")
                    yield OptionList(*(Option(f"{name} / {entry.get('account', (entry.get('extra') or {}).get('account', 'default'))}", id=name)
                                       for name, entry in profiles.items()), id="settings-account-list")
                    with Vertical(id="settings-chatgpt-detail"):
                        yield Label("Model profile", classes="field-label")
                        yield ControlRow('Model profile', ChoiceSelect([(name, name) for name in profiles], value=selected,
                                     allow_blank=False, id="settings-chatgpt-profile"))
                        yield Label("Local account label", classes="field-label")
                        yield ControlRow('Local account label', Input(value=str(account), placeholder="Local ChatGPT account label", id="settings-chatgpt-account"))
                        yield ChatGPTAuth(str(account), id="settings-chatgpt-auth")
                        yield Static("Sign in, then refresh OpenAI models or enter an exact model ID.", markup=False, id="settings-chatgpt-status")
                        yield Button("Refresh models", id="settings-chatgpt-refresh")
                        yield ControlRow('OpenAI model', ChoiceSelect([], prompt="Available OpenAI models", disabled=True, id="settings-chatgpt-model"))
                        yield ControlRow('Manual model ID', Input(placeholder="Or enter an exact ChatGPT / Codex model ID", id="settings-chatgpt-manual"))
                        yield Label("Reasoning effort", classes="field-label")
                        yield ReasoningControl(id="settings-chatgpt-reasoning")
                        yield Button("Use selected model", id="settings-chatgpt-apply", disabled=True)
                with VerticalScroll(id="settings-section-llm", classes="settings-section"):
                    yield Label("LLM runtime", classes="section-heading")
                    with Vertical(id="settings-llm-body", classes="settings-card"):
                        yield SettingValueRow("Concurrency", "Maximum concurrent LLM calls.", id="setting-concurrency")
                        yield SettingValueRow("Cache scope", "Reuse of successful responses within one run.", id="setting-cache")
                        for role, label in (("orchestrator", "Orchestrator"), ("payload_generator", "Payload generator")):
                            yield SettingValueRow(label, id=f"setting-role-{role.replace('_', '-')}")
                    yield Button("Edit runtime in YAML", id="settings-edit-runtime", classes="edit-yaml")
                with Horizontal(id="settings-section-evaluator", classes="settings-section"):
                    with VerticalScroll(id="settings-evaluator-form", classes="settings-form-body"):
                        yield Label("AI evaluator", classes="section-heading")
                        yield Static("Configure independent payload review using a saved provider and model.", classes="section-note", markup=False)
                        with Vertical(id="settings-evaluator-model-card", classes="settings-card"):
                            yield SettingField("Payload review", ChoiceSelect([("Human", "human"), ("AI", "ai"), ("Human and AI", "both")], value="human", allow_blank=False, id="settings-scoring-mode"), "Who reviews payload evidence.")
                            yield SettingField("Provider / model", ChoiceSelect([], prompt="Choose a saved model", id="settings-evaluator-provider"), "Use a registered API or ChatGPT model profile.")
                            yield Static("", id="settings-evaluator-details", markup=False)
                            yield SettingField("Codex model ID", Input(placeholder="Use saved model or enter exact ID", id="settings-evaluator-model"), "Optional independent ChatGPT / Codex model selection.", id="settings-evaluator-model-row")
                            yield Label("Reasoning effort", classes="field-label")
                            yield ReasoningControl(id="settings-evaluator-reasoning")
                        with Vertical(id="settings-evaluator-limits-card", classes="settings-card"):
                            for name, label, value, description in (
                                ("attempts", "Review attempts", "2", "Maximum attempts per payload (1-3)."),
                                ("tokens", "Output token limit", "1024", "Independent evaluator token budget (1-16384)."),
                                ("timeout", "Request timeout", "60", "Seconds per evaluator request (1-120)."),
                            ):
                                yield SettingField(label, Input(value=value, type="integer", id=f"settings-evaluator-{name}"), description, label_id=f"settings-evaluator-{name}-label")
                        yield Button("Apply evaluator to draft", id="settings-evaluator-apply", disabled=True)
                        yield Static("Apply stages the draft. Save persists it. Existing reviews keep their frozen evaluator.", markup=False, id="settings-evaluator-status")
                    with VerticalScroll(id="settings-evaluator-context", classes="settings-context"):
                        yield Label("Draft evaluator", classes="section-heading")
                        yield Static("", id="settings-evaluator-preview", markup=False)
                        yield Label("Review behavior", classes="section-heading")
                        yield Static("Evaluator settings are independent of the run's model roles.\n\nApply updates the draft. Save settings to persist it. Saved reviews retain their frozen evaluator.", classes="section-note", markup=False)
                with VerticalScroll(id="settings-section-policy", classes="settings-section"):
                    yield Label("Policy & output", classes="section-heading")
                    with Vertical(id="settings-policy-body", classes="settings-card"):
                        for key, label in (("budget", "Candidate budget"), ("iterations", "Iterations"), ("stop-policy", "Stop policy"),
                                           ("coverage", "Coverage target"), ("output", "Output directory"), ("format", "Report format"),
                                           ("diagnostics", "Diagnostics"), ("enriched", "Enriched reporting"),
                                           ("guardrail", "Guardrail handling"), ("retry", "Guardrail retry"),
                                           ("retries", "Maximum retries"), ("cooldown", "Cooldown threshold")):
                            yield SettingValueRow(label, id=f"setting-{key}")
                    yield Button("Edit policy in YAML", id="settings-edit-policy", classes="edit-yaml")
                with Vertical(id="settings-section-yaml", classes="settings-section"):
                    yield Label("Advanced YAML", classes="section-heading")
                    yield Static("Secrets are masked. Comments and unknown fields are preserved.", classes="section-note", markup=False)
                    yield TextArea("", id="yaml-editor", tab_behavior="focus")
        yield Static("", id="settings-status", markup=False)
        with KeyboardActions(id="settings-actions"):
            yield Button("Save settings", id="settings-save", variant="primary")
            yield Button("Close", id="settings-close")
            yield Static("", id="settings-draft-state", markup=False)
        yield Static(key_hints(("Ctrl+F6", "categories"), ("Ctrl+F4", "YAML"), ("Tab", "focus"), ("Ctrl+S", "save"), ("Esc", "back")), classes="drawer-hint")

    def on_mount(self) -> None:
        self._apply_settings_layout()
        self.query_one("#settings-chatgpt-detail").display = False
        for selector, title in (("settings-target-body", "Target configuration"), ("settings-target-actions", "Actions"),
                                 ("settings-model-body", "Current model"), ("settings-llm-body", "Runtime defaults"),
                                 ("settings-policy-body", "Execution & output"),
                                 ("settings-evaluator-model-card", "Review model"), ("settings-evaluator-limits-card", "Evaluator limits")):
            self.query_one(f"#{selector}").border_title = title
        self._render_sections()
        try:
            raw = tui_state.CONFIG_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            self.query_one("#settings-save", Button).disabled = True
            self._set_status(f"Not saved: cannot read config ({type(exc).__name__})")
            return
        try:
            parsed = self._config_cache.raw(loader=load_yaml_config)
            masked, self.preserved_secret_placeholders = tui_security._mask_yaml_secrets(parsed)
            masked = tui_security._mask_url_credentials(masked, self.preserved_secret_placeholders)
            self.query_one("#yaml-editor", TextArea).text = (
                dump_yaml_config(masked) if masked != parsed else raw
            )
        except Exception as exc:
            self.query_one("#settings-save", Button).disabled = True
            self.query_one("#yaml-editor", TextArea).text = "# Fix the YAML syntax in config.yaml, then reopen Settings.\n"
            self._saved_text = self.query_one("#yaml-editor", TextArea).text
            self._set_status(f"Not saved: {tui_security._safe_config_error_text(exc)}")
            return
        self._refresh_api_providers()
        self._refresh_evaluator()
        self._refresh_default_provider()
        self._sync_saved_chatgpt_model()
        self._saved_text = self.query_one("#yaml-editor", TextArea).text
        self._loaded_ok = True
        self._remember_forms()
        if self.app.size.width < 120:
            self.query_one("#settings-categories").display = False
            self.query_one("#settings-content").display = True
            self._focus_content_pane()
        else:
            self.query_one("#settings-categories", OptionList).focus()

    @on(OptionList.OptionHighlighted, "#settings-categories")
    def highlight_section(self, event: OptionList.OptionHighlighted) -> None:
        switcher = self.query_one("#settings-content", ContentSwitcher)
        page = self.query_one(f"#{switcher.current}")
        if self.app.focused is not None and page in self.app.focused.ancestors:
            self._section_returns[str(switcher.current)] = self.app.focused
        switcher.current = f"settings-section-{event.option.id}"
        title = dict(self.SECTIONS).get(str(event.option.id), str(event.option.id))
        self.query_one("#settings-title", Label).update(f"Settings / {title}")
        self._content_focus = self._section_returns.get(str(switcher.current))

    @on(OptionList.OptionSelected, "#settings-categories")
    def enter_section(self) -> None:
        self._browsing_categories = False
        if self.app.size.width < 120:
            self.query_one("#settings-categories").display = False
            self.query_one("#settings-content").display = True
        self._focus_content_pane()

    def on_resize(self, event: Any) -> None:
        if self.is_mounted:
            self._apply_settings_layout()

    def _apply_settings_layout(self) -> None:
        width = self.app.size.width
        categories = self.query_one("#settings-categories")
        if self._loaded_ok and width < 120 and not self.has_class("settings-single") and self.focused is categories:
            self._browsing_categories = True
        self.set_class(width < 115, "settings-stacked")
        self.set_class(width < 120, "settings-single")
        if width >= 120:
            categories.display = True
            self.query_one("#settings-content").display = True
        else:
            categories.display = self._browsing_categories
            self.query_one("#settings-content").display = not self._browsing_categories
        context = self.query_one("#settings-evaluator-context")
        if width < 160 and self.app.focused is context:
            self._focus_content_pane()
        context.display = width >= 160

    def on_descendant_focus(self, event: Any) -> None:
        super().on_descendant_focus()
        current = self.query_one("#settings-content", ContentSwitcher).current
        if current:
            page = self.query_one(f"#{current}")
            if page in event.widget.ancestors:
                self._browsing_categories = False
                self._section_returns[str(current)] = event.widget
                self._content_focus = event.widget

    def _focus_content_pane(self) -> None:
        current = self.query_one("#settings-content", ContentSwitcher).current
        page = self.query_one(f"#{current}")
        descendants = set(page.walk_children())
        focus_chain = self.focus_chain
        if self._content_focus in focus_chain and self._content_focus in descendants:
            self._content_focus.focus()
            return
        rows = [row for row in page.query(SettingValueRow) if row in focus_chain]
        if rows:
            rows[0].focus()
            return
        controls = [widget for widget in focus_chain if widget in descendants]
        editable = [widget for widget in controls if isinstance(widget, (Input, Select, Button, TextArea, Checkbox, SelectionList))]
        if editable:
            editable[0].focus()
        elif controls:
            controls[0].focus()

    def action_categories(self) -> None:
        self._browsing_categories = True
        categories = self.query_one("#settings-categories", OptionList)
        current = self.query_one("#settings-content", ContentSwitcher).current
        page = self.query_one(f"#{current}")
        if self.app.focused is not None and page in self.app.focused.ancestors:
            self._section_returns[str(current)] = self.app.focused
            self._content_focus = self.app.focused
        categories.display = True
        if self.app.size.width < 120:
            self.query_one("#settings-content").display = False
        categories.focus()

    def check_action(self, action: str, parameters: tuple[Any, ...]) -> bool | None:
        if action == "focus_categories":
            if self.has_class("too-small"):
                return False
            if isinstance(self.focused, Button):
                actions = next((parent for parent in self.focused.ancestors if isinstance(parent, KeyboardActions)), None)
                buttons = [button for button in actions.query(Button) if button in self.focus_chain] if actions else []
                return not buttons or self.focused is buttons[0]
            return isinstance(self.focused, (SettingValueRow, OptionList))
        if action == "setting_focus":
            return not self.has_class("too-small") and isinstance(self.focused, (SettingValueRow, Button, Select, Input, Checkbox)) and not isinstance(self.focused, PaletteInput)
        if action == "setting_boundary":
            return not self.has_class("too-small") and isinstance(self.focused, (SettingValueRow, Button, Select, Checkbox))
        if action == "content":
            return not self.has_class("too-small") and self.focused is self.query_one("#settings-categories")
        return super().check_action(action, parameters)

    def _setting_focus_chain(self) -> list[Any]:
        current = self.query_one("#settings-content", ContentSwitcher).current
        page = self.query_one(f"#{current}")
        return [widget for widget in self.focus_chain
                if isinstance(widget, (SettingValueRow, Button, Select, Input, Checkbox, TextArea, OptionList))
                and (page in widget.ancestors or widget.id in {"settings-save", "settings-close"})]

    def action_setting_focus(self, direction: int) -> None:
        controls = self._setting_focus_chain()
        if self.focused in controls:
            index = max(0, min(len(controls) - 1, controls.index(self.focused) + direction))
            controls[index].focus()

    def action_setting_boundary(self, index: int) -> None:
        controls = self._setting_focus_chain()
        if controls:
            controls[index].focus()

    def action_content(self) -> None:
        self.enter_section()

    def action_focus_categories(self) -> None:
        self.action_categories()

    @on(Button.Pressed, ".edit-yaml")
    def edit_yaml_pressed(self) -> None:
        self.action_edit_yaml()

    def action_edit_yaml(self) -> None:
        self._browsing_categories = False
        self.query_one("#settings-categories", OptionList).highlighted = len(self.SECTIONS) - 1
        self.query_one("#settings-content", ContentSwitcher).current = "settings-section-yaml"
        if self.app.size.width < 120:
            self.query_one("#settings-categories").display = False
            self.query_one("#settings-content").display = True
        self.query_one("#yaml-editor", TextArea).focus()

    def action_save(self) -> None:
        self.save_settings()

    def action_back(self) -> None:
        if self._saving:
            self._set_status("Saving settings…")
            return
        if self.query_one(ChatGPTAuth).signing_out:
            self._set_status("Finishing sign-out. Local credentials are cleared after the revocation attempt.")
            return
        if self.query_one(ChatGPTAuth).busy:
            self.query_one(ChatGPTAuth).cancel_login()
            return
        if self.app.size.width < 120 and not self.query_one("#settings-content").display:
            self.enter_section()
            return
        if self._account_detail:
            self._account_detail = False
            self.query_one("#settings-chatgpt-detail").display = False
            self.query_one("#settings-account-list").display = True
            self.query_one("#settings-account-query").display = True
            self.query_one("#settings-title", Label).update("Settings / ChatGPT accounts")
            self.filter_accounts()
            self.query_one("#settings-account-query", Input).focus()
            return
        dirty = self.query_one("#yaml-editor", TextArea).text != self._saved_text or self._forms_dirty()
        if dirty and not self._discard_armed:
            self._discard_armed = True
            self._set_status("Unsaved changes. Ctrl+S saves; Esc again discards.")
            return
        super().action_back()

    @on(ReasoningControl.Changed)
    def settings_capability_changed(self, event: ReasoningControl.Changed) -> None:
        reason = event.control.blocking_reason
        if event.control.id == "settings-evaluator-reasoning":
            self.query_one("#settings-evaluator-apply", Button).disabled = self._saving or bool(reason)
        elif event.control.id == "settings-chatgpt-reasoning":
            self.query_one("#settings-chatgpt-apply", Button).disabled = self._saving or bool(reason)
        if reason:
            self._set_status(reason)

    @on(ControlRow.Confirmed)
    def field_confirmed(self, event: ControlRow.Confirmed) -> None:
        event.stop()
        identifier = event.row.control_widget.id or ""
        if event.save:
            self.call_after_refresh(self.save_settings)
        elif identifier.startswith("settings-evaluator-") or identifier == "settings-scoring-mode":
            self.call_after_refresh(self.apply_evaluator)
        elif identifier.startswith("settings-chatgpt-") and identifier != "settings-chatgpt-profile":
            self.call_after_refresh(self.apply_chatgpt_model)

    def _form_state(self, group: str) -> tuple[Any, ...]:
        prefixes = {"evaluator": ("settings-evaluator-", "settings-scoring-mode"),
                    "chatgpt": ("settings-chatgpt-account", "settings-chatgpt-manual", "settings-chatgpt-model", "settings-chatgpt-reasoning"),
                    "default": ("settings-default-provider",)}[group]
        return tuple((widget.id, widget.value) for widget in self.query("Input, Select")
                     if widget.id and any(widget.id.startswith(prefix) for prefix in prefixes))

    def _remember_forms(self, group: str | None = None) -> None:
        for name in ([group] if group else ["evaluator", "chatgpt", "default"]):
            self._form_baselines[name] = self._form_state(name)

    def _forms_dirty(self, group: str | None = None) -> bool:
        return any(self._form_state(name) != state for name, state in self._form_baselines.items()
                   if group is None or name == group)

    @on(Input.Changed)
    @on(Select.Changed)
    def mark_form_edits(self) -> None:
        if self._loaded_ok and not self._saving:
            self._discard_armed = False
            dirty = self._forms_dirty() or self.query_one("#yaml-editor", TextArea).text != self._saved_text
            self.query_one("#settings-draft-state", Static).update("Unsaved changes" if dirty else "Saved")

    def cancel_local_operation(self) -> bool:
        if self.query_one("#settings-chatgpt-refresh", Button).disabled and not self._saving:
            self._model_generation += 1
            self.query_one("#settings-chatgpt-refresh", Button).disabled = False
            self.query_one("#settings-chatgpt-status", Static).update("Model refresh canceled locally. Late responses will be ignored.")
            if not self.query_one("#settings-chatgpt-manual", Input).value:
                self._sync_saved_chatgpt_model()
            return True
        if self._saving:
            self._set_status("Saving settings. Wait for the atomic save to finish.")
            return True
        return False

    def prepare_navigation(self) -> bool:
        if self._saving or self.query_one(ChatGPTAuth).busy:
            self._set_status("Finish or cancel the local operation before leaving Settings.")
            return False
        if self.query_one("#yaml-editor", TextArea).text != self._saved_text or self._forms_dirty():
            self._set_status("Unsaved changes. Save or explicitly discard with Back before changing workspace.")
            return False
        return True

    @on(Button.Pressed, "#settings-close")
    def close_settings(self) -> None:
        self.action_back()

    @on(TextArea.Changed, "#yaml-editor")
    def evaluator_yaml_changed(self) -> None:
        if self.is_mounted and not self._saving:
            self._discard_armed = False
            dirty = self.query_one("#yaml-editor", TextArea).text != self._saved_text
            self.query_one("#settings-draft-state", Static).update("Unsaved changes" if dirty else "Saved")
            if self._draft_timer is not None:
                self._draft_timer.stop()
            self._draft_timer = self.set_timer(0.2, self._refresh_draft_views)

    def _refresh_draft_views(self) -> None:
        self._draft_timer = None
        if not self._tesis_closing and not self._saving:
            self._refresh_api_providers()
            self._refresh_evaluator()
            self._refresh_default_provider()
            self._render_draft_rows()

    def _render_draft_rows(self) -> None:
        try:
            payload = self._draft_cache.read(self.query_one("#yaml-editor", TextArea).text)
            for key, path in self.ROW_FIELDS.items():
                if key == "primary-model":
                    sections, labels = self._draft_cache.profiles(self.query_one("#yaml-editor", TextArea).text)
                    value = labels.get(payload.get("provider"), payload.get("provider"))
                else:
                    spec = ALL_FIELD_SPECS[path]
                    value = get_config_value(payload, spec, self._settings_values.get(key, spec.default))
                    if spec.kind == "url":
                        value = tui_security._safe_url(value)
                self._set_setting_value(key, value)
            for key, path in (("concurrency", "llm_runtime.max_concurrency"), ("cache", "llm_runtime.cache_scope")):
                self._set_setting_value(key, get_config_value(payload, path, self._settings_values.get(key)))
        except Exception as exc:
            self._set_status(f"Draft needs attention: {tui_security._safe_config_error_text(exc)}")

    def _refresh_default_provider(self) -> None:
        if self._loaded_ok and self._forms_dirty("default"):
            return
        try:
            text = self.query_one("#yaml-editor", TextArea).text
            payload = self._draft_cache.read(text)
            sections, labels = self._draft_cache.profiles(text)
            picker = self.query_one("#settings-default-provider", Select)
            selected = payload.get("provider")
            options = [(labels[name], name) for name, section in sections.items() if section.get("model_name")]
            if selected and selected not in {value for _, value in options}:
                options.insert(0, (f"{selected} (saved; unavailable)", selected))
            picker.set_options(options)
            picker.value = selected if selected else Select.NULL
            if self._loaded_ok:
                self._remember_forms("default")
        except Exception:
            pass

    @on(Button.Pressed, "#settings-default-apply")
    def apply_default_provider(self) -> bool:
        try:
            editor = self.query_one("#yaml-editor", TextArea)
            payload = self._draft_cache.edit(editor.text)
            selected = self.query_one("#settings-default-provider", Select).value
            if selected is Select.NULL:
                raise ValueError("Choose a saved provider / model first.")
            payload["provider"] = str(selected)
            editor.text = dump_yaml_config(payload)
            self._set_status("Default model applied to draft. Save Settings to keep it.")
            self._remember_forms("default")
            return True
        except Exception as exc:
            self._set_status(tui_security._safe_config_error_text(exc))
            return False

    def _refresh_evaluator(self) -> None:
        if self._loaded_ok and self._forms_dirty("evaluator"):
            return
        picker = self.query_one("#settings-evaluator-provider", Select)
        text = self.query_one("#yaml-editor", TextArea).text
        key = (text, self._saving)
        if key == self._evaluator_sync_key:
            picker.disabled = not self._evaluator_has_choices or self._saving
            self.query_one("#settings-evaluator-apply", Button).disabled = self._saving or not self._evaluator_valid
            self._show_evaluator_connection()
            return
        self._evaluator_sync_key = key
        try:
            payload = self._draft_cache.read(text)
            sections, labels = self._draft_cache.profiles(text)
            choices = [(labels[name] if labels[name] != name else f"{name} / {section['model_name']}", name)
                       for name, section in sections.items() if section.get("model_name")]
            evaluator = payload.get("scoring_evaluator") or {}
            selected = evaluator.get("model_profile") or evaluator.get("provider")
            if (not evaluator.get("model_profile") and evaluator.get("model")) or selected not in {value for _, value in choices}:
                matches = [name for name, section in sections.items()
                           if section.get("provider", name) == evaluator.get("provider")
                           and section.get("model_name") == evaluator.get("model")]
                selected = matches[0] if len(matches) == 1 else selected or Select.NULL
            if selected is not Select.NULL and selected not in {value for _, value in choices}:
                choices.insert(0, (f"{selected} (saved; unavailable)", selected))
            picker.set_options(choices)
            self._evaluator_has_choices = bool(choices)
            self._evaluator_valid = True
            picker.value = selected if selected in {value for _, value in choices} else Select.NULL
            picker.disabled = not choices
            self.query_one("#settings-scoring-mode", Select).value = payload.get("scoring_mode", "human")
            for selector, key, default in (("attempts", "max_attempts", 2), ("tokens", "max_tokens", 1024),
                                           ("timeout", "timeout", 60)):
                self.query_one(f"#settings-evaluator-{selector}", Input).value = str(evaluator.get(key, default))
            self.query_one("#settings-evaluator-apply", Button).disabled = self._saving
            self._show_evaluator_connection()
            if self._loaded_ok:
                self._remember_forms("evaluator")
        except Exception as exc:
            self._evaluator_has_choices = False
            self._evaluator_valid = False
            picker.disabled = True
            self.query_one("#settings-evaluator-apply", Button).disabled = True
            self.query_one("#settings-evaluator-details", Static).update(
                f"Cannot load evaluator choices: {tui_security._safe_config_error_text(exc)}")

    @on(Select.Changed, "#settings-evaluator-provider")
    def evaluator_provider_changed(self) -> None:
        self._show_evaluator_connection()

    @on(Input.Changed, "#settings-evaluator-model")
    def evaluator_model_changed(self) -> None:
        if self.is_mounted:
            self._show_evaluator_connection()

    def _show_evaluator_connection(self) -> None:
        selected = self.query_one("#settings-evaluator-provider", Select).value
        details = self.query_one("#settings-evaluator-details", Static)
        self._evaluator_display_info = {}
        self._evaluator_supports_tokens = True
        try:
            if selected is Select.NULL:
                details.update("Choose a saved API provider or ChatGPT model.")
            else:
                sections, _ = self._draft_cache.profiles(self.query_one("#yaml-editor", TextArea).text)
                profile = sections[str(selected)]
                info = model_connection(str(selected), profile)
                self._evaluator_display_info = info
                self._evaluator_supports_tokens = info["adapter"] != "openai_codex_auth"
                self.query_one("#settings-evaluator-model-row").display = not self._evaluator_supports_tokens
                profile = self._probe_profile(profile)
                override = self.query_one("#settings-evaluator-model", Input).value.strip()
                if override and any(c.isspace() or ord(c) < 32 for c in override):
                    raise ValueError("Model ID must not contain spaces or control characters.")
                if override and not self._evaluator_supports_tokens:
                    if override != profile["model_name"]:
                        profile.pop("reasoning_efforts", None)
                    profile["model_name"] = override
                    info["model"] = override
                payload = self._draft_cache.read(self.query_one("#yaml-editor", TextArea).text)
                key = (str(selected), profile)
                control = self.query_one("#settings-evaluator-reasoning", ReasoningControl)
                current = payload.get("scoring_evaluator") or {}
                initial = current.get("reasoning_effort") if current.get("provider") == selected else None
                control.configure([profile], model_efforts(payload, profile["model_name"], profile),
                                  value=initial, reset=key != self._evaluator_reasoning_key)
                self._evaluator_reasoning_key = key
                endpoint = tui_security._safe_url(profile.get("base_url") or "provider default")
                details.update(summary_rows([("API protocol", info["protocol"]), ("Endpoint", endpoint)]))
        except Exception:
            details.update("The selected model is unavailable. Choose another saved model.")
            self.query_one("#settings-evaluator-reasoning", ReasoningControl).configure([], None)
            self._evaluator_reasoning_key = None
        if selected is Select.NULL:
            self.query_one("#settings-evaluator-reasoning", ReasoningControl).configure([], None)
            self.query_one("#settings-evaluator-model-row").display = False
        tokens = self.query_one("#settings-evaluator-tokens", Input)
        tokens.disabled = self._saving or not self._evaluator_supports_tokens
        self.query_one("#settings-evaluator-tokens-label", Label).update("Output token limit")
        self.query_one("#settings-evaluator-tokens-description", Static).update(
            "Independent evaluator token budget (1-8192)." if self._evaluator_supports_tokens
            else "Unsupported by ChatGPT sign-in; this limit is not sent."
        )
        self._refresh_evaluator_preview()

    @on(Select.Changed, "#settings-scoring-mode")
    @on(Input.Changed, "#settings-evaluator-attempts, #settings-evaluator-tokens, #settings-evaluator-timeout")
    def evaluator_preview_changed(self) -> None:
        if self.is_mounted:
            self._refresh_evaluator_preview()

    def _refresh_evaluator_preview(self) -> None:
        info = self._evaluator_display_info
        mode = str(self.query_one("#settings-scoring-mode", Select).value)
        values = []
        for key, label in (("attempts", "Attempts"), ("timeout", "Timeout (s)"), ("tokens", "Output tokens")):
            value = self.query_one(f"#settings-evaluator-{key}", Input).value or "—"
            if key == "tokens" and not self._evaluator_supports_tokens:
                value = "Unsupported"
            values.append((label, value))
        rows = [("Review", {"human": "Human", "ai": "AI", "both": "Human and AI"}.get(mode, "—")),
                ("Provider", info.get("provider")), ("Model", info.get("model")),
                ("API protocol", info.get("protocol")), *values]
        text = "\n\n".join(f"{label}\n{value or '—'}" for label, value in rows)
        if text != self._evaluator_preview_text:
            self._evaluator_preview_text = text
            self.query_one("#settings-evaluator-preview", Static).update(str(tui_security.redact_secrets(text)))

    @on(Button.Pressed, "#settings-evaluator-apply")
    def apply_evaluator(self) -> bool:
        from evaluation.thesis_scoring import validate_scoring_config
        from tesis.provider_registry import expanded_model_sections
        status = self.query_one("#settings-evaluator-status", Static)
        try:
            editor = self.query_one("#yaml-editor", TextArea)
            payload = self._draft_cache.edit(editor.text)
            selected = self.query_one("#settings-evaluator-provider", Select).value
            mode = str(self.query_one("#settings-scoring-mode", Select).value)
            evaluator = dict(payload.get("scoring_evaluator") or {})
            if selected is Select.NULL:
                if mode != "human":
                    raise ValueError("Choose a saved provider and model for AI review.")
            else:
                sections = expanded_model_sections(payload)
                if str(selected) not in sections:
                    raise ValueError("The selected saved model is unavailable. Choose another model.")
                profile = sections[str(selected)]
                self._show_evaluator_connection()
                control = self.query_one("#settings-evaluator-reasoning", ReasoningControl)
                control.ensure_ready()
                override = self.query_one("#settings-evaluator-model", Input).value.strip()
                if profile.get("provider", str(selected)) == "openai_codex_auth" and override and override != profile["model_name"]:
                    from tesis.provider_registry import model_profile_id
                    from copy import deepcopy
                    selected = model_profile_id(str(selected), override)
                    profile = deepcopy(profile)
                    profile["model_name"] = override
                    profile.pop("reasoning_efforts", None)
                    payload["models"] = dict(payload.get("models") or {})
                    payload["models"][selected] = profile
                for key in ("provider", "adapter", "model", "model_profile", "base_url", "api_key", "use_responses_api", "account", "reasoning_effort"):
                    evaluator.pop(key, None)
                evaluator["provider"] = str(selected)
                if control.value is not None:
                    evaluator["reasoning_effort"] = control.value
                for selector, key in (("attempts", "max_attempts"), ("tokens", "max_tokens"), ("timeout", "timeout")):
                    evaluator[key] = int(self.query_one(f"#settings-evaluator-{selector}", Input).value)
                validate_scoring_config(mode, {**evaluator, "model": profile["model_name"]})
            payload.update(scoring_mode=mode, scoring_evaluator=evaluator)
            editor.text = dump_yaml_config(payload)
            status.update("Evaluator applied to the draft. Save Settings to keep it.")
            self._remember_forms("evaluator")
            return True
        except Exception as exc:
            status.update(f"Evaluator not applied: {tui_security._safe_config_error_text(exc)}")
            return False

    def _refresh_api_providers(self) -> None:
        try:
            payload = self._draft_cache.read(self.query_one("#yaml-editor", TextArea).text)
            entries = payload.get("api_providers") or {}
            picker = self.query_one("#settings-api-provider", Select)
            selected = picker.value
            picker.set_options([
                (str(entry.get("display_name") or name), name) for name, entry in entries.items()
            ])
            if selected in entries:
                picker.value = selected
            elif entries:
                picker.value = next(iter(entries))
            self.query_one("#settings-api-edit", Button).disabled = not bool(entries) or self._saving
            self._filter_provider_rows()
        except Exception:
            self.query_one("#settings-api-edit", Button).disabled = True

    @on(Input.Changed, "#settings-provider-query")
    def _filter_provider_rows(self) -> None:
        payload = self._draft_cache.read(self.query_one("#yaml-editor", TextArea).text)
        entries = payload.get("api_providers") or {}
        options = self.query_one("#settings-provider-list", OptionList)
        selected = options.get_option_at_index(options.highlighted).id if options.highlighted is not None else None
        query = self.query_one("#settings-provider-query", Input).value.casefold().strip()
        options.clear_options()
        keys = []
        for name, entry in entries.items():
            label = f"{entry.get('display_name') or name} / {name}"
            if query in label.casefold():
                options.add_option(Option(label, id=name))
                keys.append(name)
        options.highlighted = keys.index(selected) if selected in keys else 0 if keys else None

    @on(Input.Submitted, "#settings-provider-query")
    @on(OptionList.OptionSelected, "#settings-provider-list")
    def enter_provider_row(self) -> None:
        options = self.query_one("#settings-provider-list", OptionList)
        if options.highlighted is not None:
            self.query_one("#settings-api-provider", Select).value = options.get_option_at_index(options.highlighted).id
            self.edit_api_provider()

    @on(Select.Changed, "#settings-api-provider")
    def show_api_provider(self) -> None:
        from tesis.provider_registry import API_PROTOCOLS

        try:
            payload = self._draft_cache.read(self.query_one("#yaml-editor", TextArea).text)
            selected = self.query_one("#settings-api-provider", Select).value
            entry = (payload.get("api_providers") or {}).get(str(selected))
            if not entry:
                return
            text = summary_rows([
                ("API protocol", API_PROTOCOLS.get(entry.get("protocol"), "—")),
                ("Endpoint", tui_security._safe_url(entry.get("base_url") or "—")),
                ("Models", ", ".join(entry.get("models") or []) or "None selected"),
                ("Credential", "Configured" if entry.get("api_key") else "Not configured"),
            ])
            self.query_one("#settings-provider-details", Static).update(text)
        except Exception:
            self.query_one("#settings-provider-details", Static).update("Provider unavailable in this draft.")

    @on(Button.Pressed, "#settings-api-add, #settings-api-edit")
    def edit_api_provider(self, event: Button.Pressed | None = None) -> None:
        from tesis.tui_providers import ProviderDrawer
        try:
            payload = self._draft_cache.edit(self.query_one("#yaml-editor", TextArea).text)
            payload = tui_security._restore_yaml_secrets(payload, self.preserved_secret_placeholders)
            entries = payload.get("api_providers") or {}
            selected = self.query_one("#settings-api-provider", Select).value
            editing = event is None or event.button.id == "settings-api-edit"
            if editing and selected is Select.NULL:
                self._set_status("Select an API provider to edit.")
                return
            provider_id = str(selected) if editing else ""
            self.app.push_screen(ProviderDrawer(config_path=tui_state.CONFIG_PATH, entries=entries,
                                               provider_id=provider_id, pending_keys=self._pending_api_keys,
                                               reasoning_catalog=payload.get("reasoning_catalog")),
                                 self._apply_api_provider)
        except Exception as exc:
            self._set_status(f"Cannot edit provider: {tui_security._safe_config_error_text(exc)}")

    def _apply_api_provider(self, draft: Any) -> None:
        if draft is None:
            return
        try:
            editor = self.query_one("#yaml-editor", TextArea)
            payload = self._draft_cache.edit(editor.text)
            payload.setdefault("api_providers", {})[draft.provider_id] = draft.entry
            editor.text = dump_yaml_config(payload)
            self._pending_api_keys.update(draft.keys)
            self._refresh_api_providers()
            self.query_one("#settings-api-provider", Select).value = draft.provider_id
            self._set_status(f"Updated {draft.provider_id}. Save settings to keep these changes.")
        except Exception as exc:
            self._set_status(f"Provider not applied: {tui_security._safe_config_error_text(exc)}")

    ROW_FIELDS = {
        "target": "target_url", "level": "level", "surface": "surface", "payload-mode": "payload_mode",
        "condition": "experiment_condition", "method": "target_method", "primary-model": "provider",
        "budget": "candidate_budget", "iterations": "iterations", "stop-policy": "stop_policy",
        "coverage": "coverage_target", "output": "output_dir", "format": "report_format",
        "diagnostics": "diagnose", "enriched": "enriched_reporting", "guardrail": "evasion.mode",
        "retry": "evasion.enabled", "retries": "evasion.max_retries", "cooldown": "evasion.cooldown_threshold",
    }

    @on(SettingValueRow.Activated)
    def edit_setting_row(self, event: SettingValueRow.Activated) -> None:
        from tesis.tui_choices import ChoicePicker
        from tesis.tui_editors import FieldEditor
        key = str(event.row.id).removeprefix("setting-")
        try:
            editor = self.query_one("#yaml-editor", TextArea)
            payload = self._draft_cache.edit(editor.text)
            path = self.ROW_FIELDS.get(key)
            if path:
                spec = ALL_FIELD_SPECS[path]
            elif key == "concurrency":
                spec = FieldSpec("llm_runtime.max_concurrency", label="Concurrency", value_type=int, min_value=1, max_value=4)
            elif key == "cache":
                spec = FieldSpec("llm_runtime.cache_scope", label="Cache scope", choices=("none", "run"))
            elif key.startswith("role-"):
                role = key.removeprefix("role-").replace("-", "_")
                profiles, labels = self._draft_cache.profiles(editor.text)
                spec = FieldSpec(f"llm_runtime.roles.{role}.model_profile", label=f"{role} model profile", allow_none=True,
                                 choices=lambda _: tuple(profiles))
            else:
                if key in {"provider", "model", "protocol"}:
                    self.edit_api_provider()
                return
            fallback = None if key.startswith("role-") else self._settings_profile_id if key == "primary-model" else self._settings_values.get(key)
            value = get_config_value(payload, spec, fallback)
            if key == "target":
                restored = tui_security._restore_yaml_secrets(payload, self.preserved_secret_placeholders)
                value = get_config_value(restored, spec)
            choices = spec.choice_values(payload)
            def stage(result: Any) -> None:
                if result is None:
                    return
                try:
                    draft = self._draft_cache.edit(editor.text)
                    set_config_value(draft, spec, result[0])
                    if spec.kind == "url" and result[0]:
                        sanitized = tui_security._safe_url(result[0])
                        self.preserved_secret_placeholders[sanitized] = result[0]
                    masked = tui_security._mask_url_credentials(draft, self.preserved_secret_placeholders)
                    editor.text = dump_yaml_config(masked)
                    self._set_setting_value(key, tui_security._safe_url(result[0]) if spec.kind == "url" else result[0])
                    self._set_status("Value staged. Ctrl+S saves Settings.")
                    if len(result) > 1 and result[1]:
                        self.save_settings()
                except Exception as exc:
                    self._set_status(tui_security._safe_config_error_text(exc))
            if spec.value_type is bool:
                choices = (False, True)
            if choices:
                options = [(str(choice), choice) for choice in choices]
                if spec.allow_none:
                    options.insert(0, ("Inherit / unset", None))
                if value not in [item for _, item in options]:
                    options.insert(0, (f"{value} (saved; unavailable)", value))
                self.app.push_screen(ChoicePicker(options, current=value, title=spec.label), stage)
            else:
                self.app.push_screen(FieldEditor(spec, value, payload), stage)
        except Exception as exc:
            self._set_status(tui_security._safe_config_error_text(exc))

    def on_key(self, event: Any) -> None:
        if not isinstance(self.app.focused, (SettingValueRow, OptionList)) or not event.character or not event.character.isprintable() or event.character.isspace():
            return
        list_queries = {"settings-provider-list": "settings-provider-query", "settings-account-list": "settings-account-query"}
        query_id = list_queries.get(self.app.focused.id)
        if query_id:
            field = self.query_one(f"#{query_id}", Input)
            field.focus()
            field.value += event.character
            event.stop()
            event.prevent_default()
            return
        from tesis.tui_choices import ChoicePicker
        rows = [(f"{section}: {row._setting_label}", str(row.id))
                for section, _ in self.SECTIONS for row in self.query(f"#settings-section-{section} SettingValueRow")
                if row.id not in {"setting-provider", "setting-model", "setting-protocol", "row-settings-chatgpt-profile"}
                and not (str(row.id).endswith("-custom") and not row.display)]
        def selected(result: Any) -> None:
            if result is None:
                return
            row = self.query_one(f"#{result[0]}")
            page = next(parent for parent in row.ancestors if parent.has_class("settings-section"))
            self.query_one("#settings-content", ContentSwitcher).current = page.id
            section = str(page.id).removeprefix("settings-section-")
            self.query_one("#settings-categories", OptionList).highlighted = [key for key, _ in self.SECTIONS].index(section)
            self.enter_section()
            if self.query_one("#settings-chatgpt-detail") in row.ancestors:
                self.enter_account()
            row.focus()
        picker = ChoicePicker(rows, title="Search settings")
        self.app.push_screen(picker, selected)
        picker.call_after_refresh(lambda: setattr(picker.query_one(Input), "value", event.character))
        event.stop()
        event.prevent_default()

    def _set_setting_value(self, key: str, value: Any) -> None:
        self._settings_values[key] = value
        if key == "payload-mode" and value not in (None, ""):
            text = payload_mode_label(value)
        else:
            text = "—" if value in (None, "") else str(value)
        self.query_one(f"#setting-{key}-value", Static).update(str(tui_security.redact_secrets(text)))

    def _render_sections(self) -> None:
        """Populate structured setting rows with approved configuration fields."""
        error = self.query_one("#settings-target-error", Static)
        try:
            cfg = self._config_cache.resolve(loader=load_and_resolve_config)
        except Exception as exc:
            error.update(tui_security._safe_config_error_text(exc))
            error.display = True
            return
        error.display = False
        runtime = getattr(cfg, "llm_runtime", None)
        roles = getattr(runtime, "roles", {}) or {}
        profile_id = getattr(cfg, "model_profile", None) or getattr(cfg, "provider", "")
        self._settings_profile_id = profile_id
        models = getattr(cfg, "models", {}) or {}
        connection = model_connection(profile_id, models.get(profile_id))
        values = {
            "target": tui_security._safe_url(cfg.target_url),
            "primary-model": f"{connection['provider']} / {connection['model']}",
            "level": cfg.level,
            "surface": cfg.surface,
            "payload-mode": cfg.payload_mode,
            "condition": cfg.experiment_condition,
            "method": cfg.target_method,
            "provider": connection["provider"],
            "model": connection["model"],
            "protocol": connection["protocol"],
            "concurrency": getattr(runtime, "max_concurrency", None),
            "cache": getattr(runtime, "cache_scope", None),
            "budget": cfg.candidate_budget,
            "iterations": cfg.iterations,
            "stop-policy": cfg.stop_policy,
            "coverage": cfg.coverage_target,
            "output": cfg.output_dir,
            "format": cfg.report_format,
            "diagnostics": "Enabled" if cfg.diagnose else "Disabled",
            "enriched": "Enabled" if cfg.enriched_reporting else "Disabled",
            "guardrail": cfg.evasion_mode,
            "retry": "Enabled" if cfg.evasion_enabled else "Disabled",
            "retries": cfg.evasion_max_retries,
            "cooldown": cfg.evasion_cooldown_threshold,
        }
        for key, value in values.items():
            self._set_setting_value(key, value)
        for role in ("orchestrator", "payload_generator"):
            settings = roles.get(role)
            role_profile = getattr(settings, "model_profile", None) or profile_id
            info = model_connection(role_profile, models.get(role_profile))
            model_name = getattr(settings, "model_name", None) or info["model"]
            effort = getattr(settings, "reasoning_effort", None) or info["reasoning"]
            self._set_setting_value(f"role-{role.replace('_', '-')}",
                                    f"{info['provider']} / {model_name}\n{info['protocol']} · reasoning {effort}")

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#settings-status", Static).update(str(tui_security.redact_secrets(text)))
        except Exception:
            pass

    def _clear_model_catalog(self) -> None:
        self._model_generation += 1
        self._catalog_binding = None
        self._chatgpt_models = {}
        picker = self.query_one("#settings-chatgpt-model", Select)
        picker.set_options([])
        picker.disabled = True
        self.query_one("#settings-chatgpt-apply", Button).disabled = True
        self.query_one("#settings-chatgpt-refresh", Button).disabled = False

    @on(Input.Changed, "#settings-account-query")
    def filter_accounts(self) -> None:
        options = self.query_one("#settings-account-list", OptionList)
        selected = options.get_option_at_index(options.highlighted).id if options.highlighted is not None else None
        query = self.query_one("#settings-account-query", Input).value.casefold().strip()
        profiles = self.query_one("#settings-chatgpt-profile", Select)._options
        raw = self._draft_cache.read(self.query_one("#yaml-editor", TextArea).text)
        options.clear_options()
        ids = []
        for _, name in profiles:
            if name is Select.NULL:
                continue
            entry = (raw.get("models") or {}).get(name) or {}
            account = entry.get("account", (entry.get("extra") or {}).get("account", "default"))
            label = f"{name} / {account}"
            if query in label.casefold():
                options.add_option(Option(label, id=str(name)))
                ids.append(name)
        options.highlighted = ids.index(selected) if selected in ids else 0 if ids else None

    @on(Input.Submitted, "#settings-account-query")
    @on(OptionList.OptionSelected, "#settings-account-list")
    def enter_account(self) -> None:
        options = self.query_one("#settings-account-list", OptionList)
        if options.highlighted is None:
            return
        name = options.get_option_at_index(options.highlighted).id
        current = self.query_one("#settings-chatgpt-profile", Select).value
        if name != current and self._forms_dirty("chatgpt"):
            self._set_status("Finish the current account/model edit before choosing another profile.")
            return
        self.query_one("#settings-chatgpt-profile", Select).value = name
        self._account_detail = True
        self.query_one("#settings-account-query").display = False
        options.display = False
        self.query_one("#settings-chatgpt-detail").display = True
        self.query_one("#settings-title", Label).update(f"Settings / ChatGPT accounts / {name}")
        self.query_one("#row-settings-chatgpt-account").focus()

    @on(Input.Changed, "#settings-chatgpt-account")
    def chatgpt_account_changed(self) -> None:
        account = self.query_one("#settings-chatgpt-account", Input).value.strip()
        if account == self._chatgpt_account_value:
            return
        self._chatgpt_account_value = account
        self.query_one(ChatGPTAuth).set_account(account)
        self._clear_model_catalog()
        self.query_one("#settings-chatgpt-manual", Input).value = ""
        self._configure_chatgpt_reasoning()
        self.query_one("#settings-chatgpt-status", Static).update("Account changed. Refresh OpenAI models.")

    @on(Select.Changed, "#settings-chatgpt-profile")
    def chatgpt_profile_changed(self, event: Select.Changed) -> None:
        if event.value is Select.NULL:
            return
        self._clear_model_catalog()
        try:
            raw = self._draft_cache.read(self.query_one("#yaml-editor", TextArea).text) or {}
            profile = raw.get("models", {}).get(str(event.value), {})
            account = profile.get("account", (profile.get("extra") or {}).get("account", "default"))
            self.query_one("#settings-chatgpt-account", Input).value = str(account)
            self._sync_saved_chatgpt_model()
            if self._loaded_ok:
                self._remember_forms("chatgpt")
        except Exception:
            pass

    def _probe_profile(self, profile: dict) -> dict:
        from copy import deepcopy
        from tesis.provider_settings import resolved_provider_key
        result = tui_security._restore_yaml_secrets(deepcopy(profile), self.preserved_secret_placeholders)
        if result.get("api_key"):
            result["api_key"] = resolved_provider_key(result, tui_state.CONFIG_PATH, self._pending_api_keys)
        return result

    def _sync_saved_chatgpt_model(self) -> None:
        try:
            payload = self._draft_cache.read(self.query_one("#yaml-editor", TextArea).text)
            name = str(self.query_one("#settings-chatgpt-profile", Select).value)
            profile = (payload.get("models") or {}).get(name) or {}
            account = str(profile.get("account", (profile.get("extra") or {}).get("account", "default")))
            self._chatgpt_account_value = account
            self.query_one("#settings-chatgpt-account", Input).value = account
            self.query_one(ChatGPTAuth).set_account(account)
            model = profile.get("model_name")
            picker = self.query_one("#settings-chatgpt-model", Select)
            picker.set_options([(model, model)] if model else [])
            picker.value = model if model else Select.NULL
            picker.disabled = not bool(model)
            self._catalog_binding = (name, account) if model else None
            self._chatgpt_models = {model: profile} if model else {}
            self.query_one("#settings-chatgpt-apply", Button).disabled = not bool(model)
            self._configure_chatgpt_reasoning(reset=True)
        except Exception:
            pass

    @on(ChatGPTAuth.Changed)
    def chatgpt_auth_changed(self, message: ChatGPTAuth.Changed) -> None:
        message.stop()
        self._clear_model_catalog()
        self._sync_auth_controls()
        self.query_one("#settings-chatgpt-status", Static).update(
            "Account action in progress..." if self.query_one(ChatGPTAuth).busy else
            "Refresh OpenAI models after signing in."
        )

    def _sync_auth_controls(self) -> None:
        busy = self.query_one(ChatGPTAuth).busy
        for selector in ("#settings-chatgpt-account", "#settings-chatgpt-profile", "#settings-chatgpt-refresh"):
            self.query_one(selector).disabled = busy or self._saving

    @on(Select.Changed, "#settings-chatgpt-model")
    @on(Input.Changed, "#settings-chatgpt-manual")
    def chatgpt_model_changed(self) -> None:
        self._configure_chatgpt_reasoning(reset=True)

    def _configure_chatgpt_reasoning(self, *, reset: bool = False) -> None:
        try:
            payload = self._draft_cache.read(self.query_one("#yaml-editor", TextArea).text)
            name = str(self.query_one("#settings-chatgpt-profile", Select).value)
            account = self.query_one("#settings-chatgpt-account", Input).value.strip()
            manual = self.query_one("#settings-chatgpt-manual", Input).value.strip()
            selected = self.query_one("#settings-chatgpt-model", Select).value
            model = manual or (str(selected) if selected is not Select.NULL and self._catalog_binding == (name, account) else "")
            profile = dict((payload.get("models") or {}).get(name) or {})
            profile.update(provider="openai_codex_auth", model_name=model, extra={"account": account})
            metadata = self._chatgpt_models.get(model) or {}
            self.query_one("#settings-chatgpt-reasoning", ReasoningControl).configure(
                [profile] if model else [], model_efforts(payload, model, metadata),
                value=profile.get("reasoning_effort"), reset=reset)
            self.query_one("#settings-chatgpt-apply", Button).disabled = not model or self._saving
        except Exception:
            pass

    @on(Button.Pressed, "#settings-chatgpt-refresh")
    def refresh_chatgpt_models(self) -> None:
        if self.query_one(ChatGPTAuth).busy:
            return
        self._catalog_preferred_model = self.query_one("#settings-chatgpt-model", Select).value
        self._clear_model_catalog()
        profile = str(self.query_one("#settings-chatgpt-profile", Select).value)
        account = self.query_one("#settings-chatgpt-account", Input).value.strip()
        self.query_one("#settings-chatgpt-status", Static).update("Loading models from OpenAI…")
        self.query_one("#settings-chatgpt-refresh", Button).disabled = True
        Thread(target=self._fetch_chatgpt_models, args=(self._model_generation, profile, account),
               daemon=True, name="tesis-chatgpt-models").start()

    def _fetch_chatgpt_models(self, generation: int, profile: str, account: str) -> None:
        from llm.siwc.oauth import SIWCSession
        from llm.siwc.storage import SIWCError
        models = []
        error = None
        try:
            models = SIWCSession().list_models(account)
        except SIWCError as exc:
            error = str(exc)
        except Exception:
            error = "Unable to load the OpenAI model catalog. Retry or check auth status."
        if not self._tesis_closing:
            self.post_message(ChatGPTModelsLoaded(generation, profile, account, models, error))

    @on(ChatGPTModelsLoaded)
    def chatgpt_models_loaded(self, message: ChatGPTModelsLoaded) -> None:
        self._chatgpt_models_ready(message.generation, message.profile, message.account,
                                  message.models, message.error)

    def _chatgpt_models_ready(self, generation: int, profile: str, account: str,
                             models: list[dict[str, Any]], error: str | None) -> None:
        if self._tesis_closing or generation != self._model_generation or not self.is_mounted:
            return
        status = self.query_one("#settings-chatgpt-status", Static)
        self.query_one("#settings-chatgpt-refresh", Button).disabled = False
        if error:
            status.update(str(tui_security.redact_secrets(error)))
            return
        picker = self.query_one("#settings-chatgpt-model", Select)
        self._chatgpt_models = {model["slug"]: model for model in models}
        # Preserve OpenAI's ordering and display names. There is no model allowlist.
        preferred = getattr(self, "_catalog_preferred_model", Select.NULL)
        choices = [(f"{model['display_name']} / OpenAI / {model['slug']}", model["slug"]) for model in models]
        if preferred is not Select.NULL and preferred not in self._chatgpt_models:
            choices.insert(0, (f"{preferred} (saved; unavailable in catalog)", preferred))
        picker.set_options(choices)
        picker.disabled = not choices
        if choices:
            picker.value = preferred if preferred in {value for _, value in choices} else choices[0][1]
        self.query_one("#settings-chatgpt-apply", Button).disabled = not models
        self._catalog_binding = (profile, account)
        self._configure_chatgpt_reasoning(reset=True)
        status.update(f"{len(models)} models available for {account}. Select a model, then save Settings."
                      if models else "OpenAI returned no visible models for this account.")

    @on(Button.Pressed, "#settings-chatgpt-apply")
    def apply_chatgpt_model(self) -> bool:
        manual = self.query_one("#settings-chatgpt-manual", Input).value.strip()
        model = manual or self.query_one("#settings-chatgpt-model", Select).value
        if not manual and (self._catalog_binding is None or model is Select.NULL):
            return False
        profile_name = str(self.query_one("#settings-chatgpt-profile", Select).value)
        account = self.query_one("#settings-chatgpt-account", Input).value.strip()
        try:
            if any(c.isspace() or ord(c) < 32 for c in str(model)):
                raise ValueError("Model ID must not contain spaces or control characters.")
            self._configure_chatgpt_reasoning()
            control = self.query_one("#settings-chatgpt-reasoning", ReasoningControl)
            control.ensure_ready()
            editor = self.query_one("#yaml-editor", TextArea)
            payload = self._draft_cache.edit(editor.text)
            if not isinstance(payload, dict):
                raise ValueError("Config must be a YAML mapping")
            payload["models"] = dict(payload.get("models") or {})
            profile = payload["models"].setdefault(profile_name, {})
            profile.update(provider="openai_codex_auth", model_name=str(model))
            profile["reasoning_effort"] = control.value
            profile["extra"] = {**(profile.get("extra") or {}), "account": account}
            profile.pop("account", None)
            metadata = self._chatgpt_models.get(str(model)) or {}
            profile.pop("reasoning_efforts", None)
            if "reasoning_efforts" in metadata:
                profile["reasoning_efforts"] = metadata["reasoning_efforts"]
            # This picker never switches the experiment's primary provider.
            editor.text = dump_yaml_config(payload)
            self._refresh_evaluator()
            self._refresh_default_provider()
            self._set_status(f"Updated models.{profile_name}. Save Settings to keep the selected model.")
            self._remember_forms("chatgpt")
            return True
        except Exception as exc:
            self._set_status(f"Model not applied: {tui_security._safe_config_error_text(exc)}")
            return False

    @on(Button.Pressed, "#settings-save")
    def save_settings(self) -> None:
        if self._saving:
            return
        if not self._loaded_ok:
            self._set_status("Settings could not be loaded. Fix config.yaml and reopen Settings.")
            return
        for group, apply in (("chatgpt", self.apply_chatgpt_model), ("default", self.apply_default_provider),
                             ("evaluator", self.apply_evaluator)):
            if self._forms_dirty(group) and not apply():
                self._set_status(f"Not saved: finish the {group} edit. Check the field status for details.")
                return
        self._settings_generation += 1
        try:
            text = self.query_one("#yaml-editor", TextArea).text
        except Exception as exc:
            self._set_status(f"Not saved: {type(exc).__name__}")
            return
        try:
            payload = self._draft_cache.edit(text)
        except Exception as exc:
            self._set_status(f"Not saved: invalid YAML ({tui_security._safe_config_error_text(exc)})")
            return
        if not isinstance(payload, dict):
            self._set_status("Not saved: config must be a mapping")
            return
        if tui_security._contains_literal_secret(payload):
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
        payload = tui_security._restore_yaml_secrets(payload, self.preserved_secret_placeholders)
        self._saving = True
        self._set_save_controls(True)
        self._set_status("Saving config and provider credentials...")
        generation = self._settings_generation
        path = tui_state.CONFIG_PATH
        keys = dict(self._pending_api_keys)

        def save() -> None:
            from tesis.provider_settings import save_provider_settings
            error = None
            try:
                save_provider_settings(path, payload, keys)
            except Exception as exc:
                error = tui_security._safe_config_error_text(exc)
            if not self._tesis_closing:
                self.post_message(SettingsSaved(generation, payload, error))

        Thread(target=save, daemon=True, name="tesis-settings-save").start()

    def _set_save_controls(self, disabled: bool) -> None:
        for row in self.query(SettingValueRow):
            row.disabled = disabled
        for selector in ("#settings-provider-list", "#settings-account-list", "#settings-provider-query", "#settings-account-query"):
            self.query_one(selector).disabled = disabled
        for selector in ("#settings-save", "#settings-api-add", "#settings-api-edit", "#yaml-editor",
                         "#settings-chatgpt-apply", "#settings-evaluator-apply", "#settings-evaluator-provider",
                         "#settings-scoring-mode", "#settings-evaluator-attempts", "#settings-evaluator-tokens",
                         "#settings-evaluator-timeout", "#settings-evaluator-model", "#settings-evaluator-reasoning",
                         "#settings-chatgpt-reasoning", "#settings-chatgpt-manual", "#settings-chatgpt-profile",
                         "#settings-chatgpt-account", "#settings-default-provider", "#settings-default-apply"):
            self.query_one(selector).disabled = disabled
        if not disabled:
            self._refresh_api_providers()
            self._refresh_evaluator()
            self.query_one("#settings-chatgpt-apply", Button).disabled = (
                not self.query_one("#settings-chatgpt-manual", Input).value.strip() and (
                    self._catalog_binding is None or self.query_one("#settings-chatgpt-model", Select).disabled)
            )
        self.query_one(ChatGPTAuth).disabled = disabled
        self._sync_auth_controls()

    @on(SettingsSaved)
    def settings_saved(self, message: SettingsSaved) -> None:
        if self._tesis_closing or message.generation != self._settings_generation:
            return
        self._saving = False
        self._set_save_controls(False)
        if message.error:
            self._set_status(f"Not saved: {message.error}")
            return
        try:
            masked, self.preserved_secret_placeholders = tui_security._mask_yaml_secrets(message.payload)
            masked = tui_security._mask_url_credentials(masked, self.preserved_secret_placeholders)
            self.query_one("#yaml-editor", TextArea).text = dump_yaml_config(masked)
        except Exception:
            pass
        self.literal_warning_acknowledged = False
        self._pending_api_keys.clear()
        self._refresh_api_providers()
        self._refresh_evaluator()
        self._render_sections()
        self._saved_text = self.query_one("#yaml-editor", TextArea).text
        self._remember_forms()
        self.query_one("#settings-draft-state", Static).update("Saved")
        self._discard_armed = False
        self._set_status("Saved config.")

    def prepare_shutdown(self) -> None:
        if self._draft_timer is not None:
            self._draft_timer.stop()
            self._draft_timer = None
        self._tesis_closing = True
        self._settings_generation += 1
        self._model_generation += 1
        self._pending_api_keys.clear()
        for auth in self.query(ChatGPTAuth):
            auth.prepare_shutdown()

    def on_unmount(self) -> None:
        self.prepare_shutdown()
