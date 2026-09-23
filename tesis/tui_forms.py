"""Configuration and launch forms for the terminal UI."""

from __future__ import annotations

import os
import re
import tempfile
from typing import Any, Literal

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    ContentSwitcher,
    Input,
    Label,
    Select,
    SelectionList,
    Static,
    TextArea,
)

from tesis.artifact_repository import config_fingerprint
from tesis.config_fields import ALL_FIELD_SPECS, REASONING_EFFORT_CHOICES
from tesis.config_loader import (
    dump_yaml_config,
    load_and_resolve_config,
    load_yaml_config,
    parse_yaml_config,
    save_yaml_config,
)
from tesis.tui_commands import BaseDrawer
import tesis.tui_security as tui_security
import tesis.tui_state as tui_state


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
            parsed = load_yaml_config(tui_state.CONFIG_PATH)
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
            self._target_seed = tui_security._safe_url(value) if value not in (None, "") else ""
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
        return load_and_resolve_config(config_path=str(tui_state.CONFIG_PATH), cli_args=self._cli_args())

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
                f"mode={self.mode} coordinates={tui_state._matrix_coordinate_count(cfg)}\n"
                f"target={tui_security._safe_url(cfg.target_url)}\n"
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
            text = f"Review\nconfig error: {tui_security._safe_config_error_text(exc)}"
        try:
            self.query_one("#launch-review", Static).update(str(tui_security.redact_secrets(text))[:8000])
        except Exception:
            pass

    @on(Button.Pressed, "#launch-close")
    def close_drawer(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#launch-start")
    def start_from_review(self) -> None:
        from tesis.tui_mission import MissionControlScreen

        if self._frozen is not None:
            return
        try:
            cfg = self._resolved_config()
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
            raw = tui_state.CONFIG_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            self._set_status(f"Not saved: cannot read config ({type(exc).__name__})")
            return
        try:
            parsed = load_yaml_config(tui_state.CONFIG_PATH)
            masked, self.preserved_secret_placeholders = tui_security._mask_yaml_secrets(parsed)
            masked = tui_security._mask_url_credentials(masked, self.preserved_secret_placeholders)
            self.query_one("#yaml-editor", TextArea).text = (
                dump_yaml_config(masked) if masked != parsed else raw
            )
        except Exception as exc:
            try:
                self.query_one("#yaml-editor", TextArea).text = raw
            except Exception:
                pass
            self._set_status(f"Not saved: {tui_security._safe_config_error_text(exc)}")

    def _set_section(self, selector: str, lines: list[str]) -> None:
        try:
            self.query_one(selector, Static).update(str(tui_security.redact_secrets("\n".join(lines)))[:4000])
        except Exception:
            pass

    def _render_sections(self) -> None:
        """Summarize the resolved config; credentials are never rendered."""
        try:
            cfg = load_and_resolve_config(config_path=str(tui_state.CONFIG_PATH), cli_args={})
        except Exception as exc:
            self._set_section("#settings-target-body", [tui_security._safe_config_error_text(exc)])
            return
        runtime = getattr(cfg, "llm_runtime", None)
        roles = getattr(runtime, "roles", {}) or {}
        self._set_section("#settings-target-body", [
            f"target: {tui_security._safe_url(getattr(cfg, 'target_url', '—'))}",
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
            self.query_one("#settings-status", Static).update(str(tui_security.redact_secrets(text)))
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
            save_yaml_config(tui_state.CONFIG_PATH, payload)
        except Exception as exc:
            self._set_status(f"Not saved: {tui_security._safe_config_error_text(exc)}")
            return
        try:
            masked, self.preserved_secret_placeholders = tui_security._mask_yaml_secrets(payload)
            masked = tui_security._mask_url_credentials(masked, self.preserved_secret_placeholders)
            self.query_one("#yaml-editor", TextArea).text = dump_yaml_config(masked)
        except Exception:
            pass
        self.literal_warning_acknowledged = False
        self._set_status("Saved config.")

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True
        self._settings_generation += 1
