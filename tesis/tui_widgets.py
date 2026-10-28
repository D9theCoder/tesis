"""Small keyboard primitives shared by the experiment harness screens."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from rich.text import Text
from rich.segment import Segment
from rich.style import Style
from textual.app import ComposeResult
from textual.binding import Binding
from textual.content import Content
from textual.containers import Grid, Horizontal, Vertical
from textual.message import Message
from textual.strip import Strip
from textual.widget import Widget
from textual.widgets import Button, Checkbox, DataTable, Input, Label, SelectionList, Static, Tab, Tabs
from textual.widgets.option_list import OptionDoesNotExist

from tesis.config_fields import payload_mode_label


class SettingValueRow(Vertical, can_focus=True):
    """A compact row. Enter opens a typed editor owned by the calling workspace."""

    BINDINGS = [Binding("enter", "edit", "Edit"), Binding("space", "edit", "Edit"),
                Binding("up", "row(-1)", show=False), Binding("down", "row(1)", show=False)]

    class Activated(Message):
        def __init__(self, row: SettingValueRow) -> None:
            super().__init__()
            self.row = row

    def action_edit(self) -> None:
        self.post_message(self.Activated(self))

    def action_row(self, direction: int) -> None:
        rows = [row for row in self.screen.query(SettingValueRow) if row in self.screen.focus_chain]
        if self in rows:
            rows[(rows.index(self) + direction) % len(rows)].focus()

    def on_click(self) -> None:
        self.focus()
        self.action_edit()

    def __init__(self, label: str, description: str = "", *, id: str) -> None:
        super().__init__(id=id, classes="setting-summary-row")
        self._setting_label = label
        self._setting_description = description

    def compose(self) -> ComposeResult:
        with Horizontal(classes="setting-value-line"):
            yield Static(self._setting_label, classes="setting-key", markup=False)
            yield Static(":", classes="setting-separator", markup=False)
            yield Static("—", id=f"{self.id}-value", classes="setting-value", markup=False)
        if self._setting_description:
            yield Static(self._setting_description, classes="setting-description", markup=False)


class SettingField(Grid):
    """Aligned label, editable control, and explanation for settings forms."""

    def __init__(self, label: str, control: Widget, description: str, *, label_id: str | None = None,
                 id: str | None = None) -> None:
        super().__init__(classes="settings-form-row", id=id)
        self._field_label, self._field_control = label, control
        self._field_description, self._label_id = description, label_id

    def compose(self) -> ComposeResult:
        from tesis.tui_rows import ControlRow
        # Labels/descriptions keep their public identities for dynamic capability text.
        yield Label(self._field_label, id=self._label_id, classes="form-row-label row-value-storage")
        yield ControlRow(self._field_label, self._field_control, self._field_description)
        yield Static(self._field_description, id=f"{self._field_control.id}-description" if self._field_control.id else None,
                     classes="form-row-description row-value-storage", markup=False)


class TextCheckbox(Checkbox):
    """A plain text toggle that retains native Checkbox values and events."""

    def render(self) -> Content:
        return Content.assemble(
            ("[*]" if self.value else "[-]", self.get_visual_style("toggle--button")),
            " ", self.label.stylize_before(self.get_visual_style("toggle--label")),
        )


class TextSelectionList(SelectionList):
    """Native multiple selection with the same bracket markers as checkboxes."""

    def render_line(self, y: int) -> Strip:
        line = super().render_line(y)
        index = self.scroll_offset.y + y
        try:
            option = self.get_option_at_index(index)
        except OptionDoesNotExist:
            return line
        content = line.crop(4)
        style = next(iter(content), Segment("")).style or self.rich_style
        style += Style(meta={"option": index})
        marker = "[*] " if option.value in self.selected else "[-] "
        return Strip.join([Strip([Segment(marker, style)]), content])


class KeyboardActions(Horizontal):
    """Arrow navigation inside an action row; Tab keeps its normal focus order."""

    BINDINGS = [Binding("left", "horizontal(-1)", show=False), Binding("right", "horizontal(1)", show=False),
                Binding("up", "vertical(-1)", show=False), Binding("down", "vertical(1)", show=False)]

    def check_action(self, action: str, parameters: tuple[Any, ...]) -> bool | None:
        if action in {"horizontal", "vertical"}:
            return self.layout.name == action
        return super().check_action(action, parameters)

    def action_horizontal(self, direction: int) -> None:
        self.action_move(direction)

    def action_vertical(self, direction: int) -> None:
        self.action_move(direction)

    def action_move(self, direction: int) -> None:
        buttons = [button for button in self.query(Button) if button in self.screen.focus_chain]
        if buttons:
            current = buttons.index(self.app.focused) if self.app.focused in buttons else 0
            buttons[(current + direction) % len(buttons)].focus()


class KeyboardTabs(Tabs):
    """Enter opens the selected context; Home/End select boundary tabs."""

    class Confirmed(Message):
        def __init__(self, tabs: KeyboardTabs) -> None:
            super().__init__()
            self.tabs = tabs

        @property
        def control(self) -> KeyboardTabs:
            return self.tabs

    BINDINGS = [
        Binding("enter", "confirm", show=False),
        Binding("home", "boundary(0)", show=False),
        Binding("end", "boundary(-1)", show=False),
    ]

    def action_confirm(self) -> None:
        self.post_message(self.Confirmed(self))

    def action_boundary(self, index: int) -> None:
        tabs = [tab for tab in self.query(Tab) if not tab.disabled and tab.display]
        if tabs:
            self.active = tabs[index].id or ""


class KeyboardTable(DataTable):
    """Home and End select boundary rows, including in horizontally wide tables."""

    BINDINGS = [
        Binding("home", "first_row", "First row", show=False),
        Binding("end", "last_row", "Last row", show=False),
    ]

    def action_first_row(self) -> None:
        self.move_cursor(row=0)

    def action_last_row(self) -> None:
        self.move_cursor(row=max(0, self.row_count - 1))


class PaletteInput(Input):
    """Keep typing focus while forwarding list navigation to the palette."""

    BINDINGS = [Binding("space", "palette_toggle", show=False, priority=True), *[
        Binding(key, f"palette_move('{action}')", show=False)
        for key, action in (
            ("up", "cursor_up"), ("down", "cursor_down"),
            ("pageup", "page_up"), ("pagedown", "page_down"),
            ("home", "first"), ("end", "last"),
        )
    ]]

    def __init__(self, *args: Any, list_selector: str = "#launcher-list", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.list_selector = list_selector

    def check_action(self, action: str, parameters: tuple[Any, ...]) -> bool | None:
        if action == "palette_toggle":
            return bool(getattr(self.screen, "multiple", False))
        return super().check_action(action, parameters)

    def action_palette_toggle(self) -> None:
        toggle = getattr(self.screen, "toggle", None)
        if toggle is not None:
            toggle()
        else:
            self.screen.query_one(self.list_selector).action_toggle_model()

    async def action_palette_move(self, action: str) -> None:
        options = self.screen.query_one(self.list_selector)
        if isinstance(options, DataTable):
            action = {"first": "first_row", "last": "last_row"}.get(action, action)
        await options.run_action(action)


def key_hints(*pairs: tuple[str, str]) -> Text:
    """Compact key labels with consistent emphasis and literal descriptions."""
    text = Text()
    for index, (key, description) in enumerate(pairs):
        if index:
            text.append("   ")
        text.append(key, style="bold")
        text.append(f" {description}")
    return text


def summary_rows(rows: list[tuple[str, object]], label_width: int = 16) -> Text:
    """Render an allowlisted summary without interpreting values as markup."""
    text = Text()
    for index, (label, value) in enumerate(rows):
        if index:
            text.append("\n")
        if not label:
            text.append(str(value), style="bold")
        else:
            text.append(f"{label:<{label_width}} ", style="dim")
            text.append(str(value) if value not in (None, "") else "—")
    return text


def model_connection(profile_id: str, model: Any) -> dict[str, str]:
    """Only display approved model fields, never the credential-bearing repr."""
    def value(name: str, default: Any = None) -> Any:
        return model.get(name, default) if isinstance(model, Mapping) else getattr(model, name, default)

    # Legacy model sections use their profile key as the adapter, just as the
    # canonical configuration loader does when `provider` is omitted.
    adapter = str(value("provider", profile_id) or "—")
    extra = value("extra") or {}
    if adapter == "openai_codex_auth":
        protocol = "ChatGPT Responses"
    elif adapter in {"openai", "openai_compatible"}:
        responses = extra.get("use_responses_api", value("use_responses_api"))
        protocol = ("OpenAI Responses" if responses is True else
                    "OpenAI Chat Completions" if responses is False else "OpenAI SDK default")
    else:
        protocol = {"claude": "Anthropic Messages", "gemini": "Google Generative AI"}.get(adapter, adapter)
    return {
        "adapter": adapter,
        "provider": "codex" if adapter == "openai_codex_auth" else profile_id.split("__", 1)[0] if profile_id else adapter,
        "model": str(value("model_name") or value("model") or "—"),
        "protocol": protocol,
        "reasoning": str(value("reasoning_effort") or "default"),
    }


def execution_summary(config: Any, *, mode: str = "single", details: bool = False) -> Text:
    """Shared Plan/Review presentation, restricted to nonsecret scalar fields."""
    from tesis.artifact_repository import config_fingerprint
    from tesis.tui_security import _safe_url, redact_secrets
    from tesis.tui_state import _matrix_coordinate_count

    models = getattr(config, "models", {}) or {}
    profile_id = getattr(config, "model_profile", None) or getattr(config, "provider", "")
    model = models.get(profile_id)
    connection = model_connection(profile_id, model)
    rows: list[tuple[str, object]] = [
        ("Target", _safe_url(getattr(config, "target_url", "—"))),
        ("Condition", getattr(config, "experiment_condition", "—")),
        ("Method", getattr(config, "target_method", None) or "orchestrator-selected"),
        ("Surface / level", f"{config.surface} / {config.level}"),
        ("Payload mode", payload_mode_label(config.payload_mode)),
        ("Chapter 3 block", getattr(config, "experiment_block", "selection")),
        ("Readiness / controls", "decided at execution · fail-closed · offline dry run only"),
    ]
    if mode == "matrix":
        profile_names = config.providers or [config.provider]
        profile_labels = []
        for name in profile_names:
            info = model_connection(name, models.get(name))
            profile_labels.append(name if details else f"{info['provider']} / {info['model']}")
        rows.extend([
            ("Coordinates", f"{_matrix_coordinate_count(config)} · {config.repeats} repeat(s)"),
            ("Surfaces", ", ".join(config.surfaces or [config.surface])),
            ("Levels", ", ".join(config.levels or [config.level])),
            ("Payload modes", ", ".join(config.payload_modes or [config.payload_mode])),
            ("Model profiles", ", ".join(profile_labels)),
        ])
    rows.extend([
        ("", "\nModel & runtime"),
        ("Provider", connection["provider"]), ("Model", connection["model"]),
        ("API protocol", connection["protocol"]),
    ])
    runtime = getattr(config, "llm_runtime", None)
    for role, settings in (getattr(runtime, "roles", {}) or {}).items():
        explicit_profile = getattr(settings, "model_profile", None)
        role_profile = explicit_profile or profile_id
        role_model = models.get(role_profile)
        info = model_connection(role_profile, role_model)
        effort = getattr(settings, "reasoning_effort", None) or info["reasoning"]
        model_name = getattr(settings, "model_name", None) or info["model"]
        inherited_matrix_profile = mode == "matrix" and not explicit_profile
        selection = "coordinate profile" if inherited_matrix_profile else f"{info['provider']} / {model_name}"
        if inherited_matrix_profile:
            effort = getattr(settings, "reasoning_effort", None) or "profile default"
        rows.append((role.replace("_", " ").capitalize(), f"{selection} · {effort}"))
        if details:
            rows.extend([("Role profile", "per coordinate" if inherited_matrix_profile else role_profile),
                         ("Role API", "per coordinate" if inherited_matrix_profile else info["protocol"]),
                         ("Output tokens", "per coordinate" if inherited_matrix_profile and getattr(settings, "max_tokens_default", False)
                          else "unsupported" if info["protocol"] == "ChatGPT Responses"
                          else getattr(settings, "max_tokens", None) or "profile default"),
                         ("Structured output", getattr(settings, "structured_output", "auto"))])
    rows.extend([
        ("Concurrency", getattr(runtime, "max_concurrency", "—")),
        ("Cache", getattr(runtime, "cache_scope", "none")),
        ("", "\nLimits & output"),
        ("Budget", f"{config.candidate_budget} candidates · {config.iterations} iterations"),
        ("Stop policy", config.stop_policy),
        ("Scoring", f"{config.scoring_mode} · {config.scoring_rubric_version}"),
    ])
    evaluator = getattr(config, "scoring_evaluator", {}) or {}
    if config.scoring_mode in {"ai", "both"}:
        evaluator_id = evaluator.get("model_profile") or evaluator.get("provider", "")
        evaluator_model = models.get(evaluator_id)
        if evaluator_model is None or evaluator.get("adapter"):
            evaluator_model = {**evaluator, "provider": evaluator.get("adapter") or evaluator.get("provider")}
        info = model_connection(evaluator_id, evaluator_model)
        rows.append(("Evaluator", f"{info['provider']} / {evaluator.get('model') or info['model']}"))
        rows.append(("Evaluator API", info["protocol"]))
    rows.append(("Output", f"{config.output_dir} · {config.report_format}"))
    fingerprint = config_fingerprint(config)
    rows.append(("Fingerprint", fingerprint if details else fingerprint[:23] + "…"))
    if details:
        rows.extend([("Profile ID", profile_id),
                     ("Endpoint", _safe_url(getattr(model, "base_url", None) or "provider default")),
                     ("Reasoning", connection["reasoning"]),
                     ("Coverage target", getattr(config, "coverage_target", "—")),
                     ("Guardrail handling", getattr(config, "evasion_mode", "—")),
                     ("Guardrail retries", getattr(config, "evasion_max_retries", "—"))])
    # Keep typography after redacting each allowlisted value.
    return summary_rows([
        (label, str(redact_secrets(str(value))) if value is not None else None)
        for label, value in rows
    ], label_width=19)
