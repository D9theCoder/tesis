"""Configuration and launch forms for the terminal UI."""

from __future__ import annotations

import re
from threading import Thread
from typing import Any, Literal

from textual import on
from textual.message import Message
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
)
from tesis.tui_commands import BaseDrawer
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
        from tesis.provider_registry import model_profile_labels
        profile_labels = model_profile_labels(config) if path in {"provider", "providers", "model_profile"} else {}
        if spec.kind == "select" or (choices and spec.value_type is str and not spec.multiple):
            current = None if value in (None, "") else str(value)
            if current is not None and current not in choices:
                # An off-registry value degrades to blank rather than crashing;
                # leaving it untouched keeps the configured value on submit.
                current = None
            return Select([(profile_labels.get(choice, choice), choice) for choice in choices],
                          value=current if current is not None else Select.NULL,
                          allow_blank=True, prompt=label, id=field_id)
        if spec.multiple or spec.kind == "multi_select":
            selected = {str(item) for item in (value or [])}
            return SelectionList(*[(profile_labels.get(choice, choice), choice, choice in selected) for choice in choices],
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
                    from tesis.provider_registry import model_profile_labels
                    labels = model_profile_labels(config)
                    profiles = [(labels.get(name, name), name) for name in self._profile_names(config)]
                    profile_names = {name for _, name in profiles}
                    yield Input(value="" if concurrency in (None, "") else str(concurrency),
                                placeholder="LLM max concurrency (1-4)",
                                id="launch-llm-concurrency")
                    yield Checkbox("LLM cache within run",
                                   value=bool(getattr(runtime, "cache_enabled", False)),
                                   id="launch-llm-cache")
                    yield Static("; ".join(
                        f"{name}: {getattr(settings, 'reasoning_effort', None) or 'inherit profile'}"
                        for name, settings in roles.items()
                    ), markup=False, id="launch-role-reasoning")
                    yield Select([
                        ("Keep per-role reasoning settings", "preserve"),
                        ("Inherit profile effort for both roles", "inherit"),
                        *[(choice, choice) for choice in REASONING_EFFORT_CHOICES],
                    ], value="preserve", allow_blank=False, id="launch-reasoning-effort")
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
            if key == "reasoning_effort":
                if raw == "preserve":
                    continue
                if raw == "inherit":
                    args["llm_runtime"] = {"roles": {
                        role: {"reasoning_effort": None}
                        for role in ("orchestrator", "payload_generator")
                    }}
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
                f"scoring={cfg.scoring_mode} rubric={cfg.scoring_rubric_version} "
                f"ranking={cfg.scoring_profile.get('profile_id', 'unavailable')} "
                f"evaluator={cfg.scoring_evaluator.get('model', 'not configured')}\n"
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


class ChatGPTModelsLoaded(Message):
    """Thread-safe delivery without blocking the worker on the UI loop."""

    def __init__(self, generation: int, profile: str, account: str,
                 models: list[dict[str, str]], error: str | None):
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

    def compose(self) -> ComposeResult:
        yield Label("Settings — config sections (Esc to close)", id="settings-title")
        with Collapsible(title="Target & defaults", collapsed=True, id="settings-section-target"):
            yield Static("", id="settings-target-body", markup=False)
        with Collapsible(title="Model profile", collapsed=True, id="settings-section-model"):
            yield Static("", id="settings-model-body", markup=False)
            yield Label("API providers and models")
            yield Button("Add API provider", id="settings-api-add")
            yield Select([], prompt="Saved API providers", id="settings-api-provider")
            yield Button("Edit provider / models", id="settings-api-edit", disabled=True)
            yield Label("ChatGPT subscription models")
            try:
                raw = load_yaml_config(tui_state.CONFIG_PATH)
            except Exception:
                raw = {}
            configured_models = raw.get("models")
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
            yield Select([(name, name) for name in profiles], value=selected,
                         allow_blank=False, id="settings-chatgpt-profile")
            yield Input(value=str(account), placeholder="Saved ChatGPT account label",
                        id="settings-chatgpt-account")
            yield Static("Connect an account first: python -m tesis auth login --account default",
                         markup=False, id="settings-chatgpt-status")
            yield Button("Refresh OpenAI models", id="settings-chatgpt-refresh")
            yield Select([], prompt="Available OpenAI models", disabled=True,
                         id="settings-chatgpt-model")
            yield Button("Use selected model", id="settings-chatgpt-apply", disabled=True)
        with Collapsible(title="LLM runtime", collapsed=True, id="settings-section-llm"):
            yield Static("", id="settings-llm-body", markup=False)
        with Collapsible(title="AI evaluator", collapsed=True, id="settings-section-evaluator"):
            yield Label("Payload review")
            yield Select([("Human", "human"), ("AI", "ai"), ("Human and AI", "both")],
                         value="human", allow_blank=False, id="settings-scoring-mode")
            yield Label("Evaluator provider / model")
            yield Select([], prompt="Choose a saved provider and model", id="settings-evaluator-provider")
            yield Static("", id="settings-evaluator-details", markup=False)
            yield Label("Maximum review attempts (1-3)")
            yield Input(value="2", type="integer", id="settings-evaluator-attempts")
            yield Label("Output token limit (1-8192)")
            yield Input(value="1024", type="integer", id="settings-evaluator-tokens")
            yield Label("Request timeout in seconds (1-120)")
            yield Input(value="60", type="integer", id="settings-evaluator-timeout")
            yield Button("Apply evaluator", id="settings-evaluator-apply", disabled=True)
            yield Static("Apply updates the draft. Save Settings to keep it. Existing reviews retain their frozen evaluator.",
                         markup=False, id="settings-evaluator-status")
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
        self._refresh_api_providers()
        self._refresh_evaluator()

    @on(TextArea.Changed, "#yaml-editor")
    def evaluator_yaml_changed(self) -> None:
        if self.is_mounted and not self._saving:
            self._refresh_evaluator()

    def _refresh_evaluator(self) -> None:
        from tesis.provider_registry import expanded_model_sections, model_profile_labels
        picker = self.query_one("#settings-evaluator-provider", Select)
        try:
            payload = parse_yaml_config(self.query_one("#yaml-editor", TextArea).text)
            sections = expanded_model_sections(payload)
            labels = model_profile_labels(payload)
            choices = [(labels[name] if labels[name] != name else f"{name} / {section['model_name']}", name)
                       for name, section in sections.items() if section.get("model_name")]
            evaluator = payload.get("scoring_evaluator") or {}
            selected = evaluator.get("model_profile") or evaluator.get("provider")
            if (not evaluator.get("model_profile") and evaluator.get("model")) or selected not in {value for _, value in choices}:
                matches = [name for name, section in sections.items()
                           if section.get("provider", name) == evaluator.get("provider")
                           and section.get("model_name") == evaluator.get("model")]
                selected = matches[0] if len(matches) == 1 else Select.NULL
            picker.set_options(choices)
            picker.value = selected if selected in {value for _, value in choices} else Select.NULL
            picker.disabled = not choices
            self.query_one("#settings-scoring-mode", Select).value = payload.get("scoring_mode", "human")
            for selector, key, default in (("attempts", "max_attempts", 2), ("tokens", "max_tokens", 1024),
                                           ("timeout", "timeout", 60)):
                self.query_one(f"#settings-evaluator-{selector}", Input).value = str(evaluator.get(key, default))
            self.query_one("#settings-evaluator-apply", Button).disabled = self._saving
            self._show_evaluator_connection()
        except Exception as exc:
            picker.disabled = True
            self.query_one("#settings-evaluator-apply", Button).disabled = True
            self.query_one("#settings-evaluator-details", Static).update(
                f"Cannot load evaluator choices: {tui_security._safe_config_error_text(exc)}")

    @on(Select.Changed, "#settings-evaluator-provider")
    def evaluator_provider_changed(self) -> None:
        self._show_evaluator_connection()

    def _show_evaluator_connection(self) -> None:
        from tesis.provider_registry import API_PROTOCOLS, expanded_model_sections
        selected = self.query_one("#settings-evaluator-provider", Select).value
        details = self.query_one("#settings-evaluator-details", Static)
        if selected is Select.NULL:
            details.update("Choose an evaluator model. Add providers and models in Model profile.")
            return
        try:
            payload = parse_yaml_config(self.query_one("#yaml-editor", TextArea).text)
            profile = expanded_model_sections(payload)[str(selected)]
            adapter = profile.get("provider", str(selected))
            protocol = "anthropic" if adapter == "claude" else adapter
            if adapter in {"openai", "openai_compatible"}:
                responses = (profile.get("extra") or {}).get("use_responses_api", profile.get("use_responses_api"))
                if responses is not None:
                    protocol = "openai" if responses else "openai_compatible"
            endpoint = tui_security._safe_url(profile.get("base_url") or "provider default")
            text = f"API format: {API_PROTOCOLS.get(protocol, adapter)}\nEndpoint: {endpoint}"
            if adapter == "openai_codex_auth":
                text = "API format: ChatGPT sign-in Responses\nTemperature and output-token limits are unsupported."
            details.update(text)
        except Exception:
            details.update("The selected evaluator model is unavailable. Choose another saved model.")

    @on(Button.Pressed, "#settings-evaluator-apply")
    def apply_evaluator(self) -> None:
        from evaluation.thesis_scoring import validate_scoring_config
        from tesis.provider_registry import expanded_model_sections
        status = self.query_one("#settings-evaluator-status", Static)
        try:
            editor = self.query_one("#yaml-editor", TextArea)
            payload = parse_yaml_config(editor.text)
            selected = self.query_one("#settings-evaluator-provider", Select).value
            mode = str(self.query_one("#settings-scoring-mode", Select).value)
            evaluator = dict(payload.get("scoring_evaluator") or {})
            if selected is Select.NULL:
                if mode != "human":
                    raise ValueError("Choose a saved provider and model for AI review.")
            else:
                profile = expanded_model_sections(payload)[str(selected)]
                for key in ("provider", "adapter", "model", "model_profile", "base_url", "api_key", "use_responses_api"):
                    evaluator.pop(key, None)
                evaluator["provider"] = str(selected)
                for selector, key in (("attempts", "max_attempts"), ("tokens", "max_tokens"), ("timeout", "timeout")):
                    evaluator[key] = int(self.query_one(f"#settings-evaluator-{selector}", Input).value)
                validate_scoring_config(mode, {**evaluator, "model": profile["model_name"]})
            payload.update(scoring_mode=mode, scoring_evaluator=evaluator)
            editor.text = dump_yaml_config(payload)
            status.update("Evaluator applied to the draft. Save Settings to keep it.")
        except Exception as exc:
            status.update(f"Evaluator not applied: {tui_security._safe_config_error_text(exc)}")

    def _refresh_api_providers(self) -> None:
        try:
            payload = parse_yaml_config(self.query_one("#yaml-editor", TextArea).text)
            entries = payload.get("api_providers") or {}
            self.query_one("#settings-api-provider", Select).set_options([
                (str(entry.get("display_name") or name), name) for name, entry in entries.items()
            ])
            self.query_one("#settings-api-edit", Button).disabled = not bool(entries)
        except Exception:
            self.query_one("#settings-api-edit", Button).disabled = True

    @on(Button.Pressed, "#settings-api-add, #settings-api-edit")
    def edit_api_provider(self, event: Button.Pressed) -> None:
        from tesis.tui_providers import ProviderDrawer
        try:
            payload = parse_yaml_config(self.query_one("#yaml-editor", TextArea).text)
            payload = tui_security._restore_yaml_secrets(payload, self.preserved_secret_placeholders)
            entries = payload.get("api_providers") or {}
            selected = self.query_one("#settings-api-provider", Select).value
            if event.button.id == "settings-api-edit" and selected is Select.NULL:
                self._set_status("Select an API provider to edit.")
                return
            provider_id = str(selected) if event.button.id == "settings-api-edit" else ""
            self.app.push_screen(ProviderDrawer(config_path=tui_state.CONFIG_PATH, entries=entries,
                                               provider_id=provider_id, pending_keys=self._pending_api_keys),
                                 self._apply_api_provider)
        except Exception as exc:
            self._set_status(f"Cannot edit provider: {tui_security._safe_config_error_text(exc)}")

    def _apply_api_provider(self, draft: Any) -> None:
        if draft is None:
            return
        try:
            editor = self.query_one("#yaml-editor", TextArea)
            payload = parse_yaml_config(editor.text)
            payload.setdefault("api_providers", {})[draft.provider_id] = draft.entry
            editor.text = dump_yaml_config(payload)
            self._pending_api_keys.update(draft.keys)
            self._refresh_api_providers()
            self.query_one("#settings-api-provider", Select).value = draft.provider_id
            self._set_status(f"Updated {draft.provider_id}. Save Settings to persist the provider, models, and .env key.")
        except Exception as exc:
            self._set_status(f"Provider not applied: {tui_security._safe_config_error_text(exc)}")

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
            key_state = ("SIWC account " + str(model.extra.get("account", "default"))
                         if model.provider == "openai_codex_auth"
                         else "api key " + ("set" if getattr(model, "api_key", "") else "—"))
            model_lines.append(
                f"{name}: {getattr(model, 'model_name', '—') or '—'} · {key_state}"
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

    def _clear_model_catalog(self) -> None:
        self._model_generation += 1
        self._catalog_binding = None
        picker = self.query_one("#settings-chatgpt-model", Select)
        picker.set_options([])
        picker.disabled = True
        self.query_one("#settings-chatgpt-apply", Button).disabled = True
        self.query_one("#settings-chatgpt-refresh", Button).disabled = False

    @on(Input.Changed, "#settings-chatgpt-account")
    def chatgpt_account_changed(self) -> None:
        self._clear_model_catalog()
        self.query_one("#settings-chatgpt-status", Static).update("Account changed. Refresh OpenAI models.")

    @on(Select.Changed, "#settings-chatgpt-profile")
    def chatgpt_profile_changed(self, event: Select.Changed) -> None:
        if event.value is Select.NULL:
            return
        self._clear_model_catalog()
        try:
            raw = parse_yaml_config(self.query_one("#yaml-editor", TextArea).text) or {}
            profile = raw.get("models", {}).get(str(event.value), {})
            account = profile.get("account", (profile.get("extra") or {}).get("account", "default"))
            self.query_one("#settings-chatgpt-account", Input).value = str(account)
        except Exception:
            pass

    @on(Button.Pressed, "#settings-chatgpt-refresh")
    def refresh_chatgpt_models(self) -> None:
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
                             models: list[dict[str, str]], error: str | None) -> None:
        if self._tesis_closing or generation != self._model_generation or not self.is_mounted:
            return
        status = self.query_one("#settings-chatgpt-status", Static)
        self.query_one("#settings-chatgpt-refresh", Button).disabled = False
        if error:
            status.update(str(tui_security.redact_secrets(error)))
            return
        picker = self.query_one("#settings-chatgpt-model", Select)
        # Preserve OpenAI's ordering and display names. There is no model allowlist.
        picker.set_options([(model["display_name"], model["slug"]) for model in models])
        picker.disabled = not models
        self.query_one("#settings-chatgpt-apply", Button).disabled = not models
        self._catalog_binding = (profile, account)
        status.update(f"{len(models)} models available for {account}. Select a model, then save Settings."
                      if models else "OpenAI returned no visible models for this account.")

    @on(Button.Pressed, "#settings-chatgpt-apply")
    def apply_chatgpt_model(self) -> None:
        model = self.query_one("#settings-chatgpt-model", Select).value
        if self._catalog_binding is None or model is Select.NULL:
            return
        profile_name, account = self._catalog_binding
        try:
            editor = self.query_one("#yaml-editor", TextArea)
            payload = parse_yaml_config(editor.text)
            if not isinstance(payload, dict):
                raise ValueError("Config must be a YAML mapping")
            profile = payload.setdefault("models", {}).setdefault(profile_name, {})
            profile.update(provider="openai_codex_auth", model_name=str(model))
            profile.setdefault("extra", {})["account"] = account
            profile.pop("account", None)
            # This picker never switches the experiment's primary provider.
            editor.text = dump_yaml_config(payload)
            self._set_status(f"Updated models.{profile_name}. Save Settings to keep the selected model.")
        except Exception as exc:
            self._set_status(f"Model not applied: {tui_security._safe_config_error_text(exc)}")

    @on(Button.Pressed, "#settings-save")
    def save_settings(self) -> None:
        if self._saving:
            return
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
        for selector in ("#settings-save", "#settings-api-add", "#settings-api-edit", "#yaml-editor",
                         "#settings-chatgpt-apply", "#settings-evaluator-apply", "#settings-evaluator-provider",
                         "#settings-scoring-mode", "#settings-evaluator-attempts", "#settings-evaluator-tokens",
                         "#settings-evaluator-timeout"):
            self.query_one(selector).disabled = disabled
        if not disabled:
            self._refresh_api_providers()
            self._refresh_evaluator()
            self.query_one("#settings-chatgpt-apply", Button).disabled = (
                self._catalog_binding is None or self.query_one("#settings-chatgpt-model", Select).disabled
            )

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
        self._set_status("Saved config.")

    def prepare_shutdown(self) -> None:
        self._tesis_closing = True
        self._settings_generation += 1
        self._model_generation += 1
        self._pending_api_keys.clear()

    def on_unmount(self) -> None:
        self.prepare_shutdown()
