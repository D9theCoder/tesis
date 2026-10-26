"""Bounded typed field editor; confirmed values are returned into the owner draft."""
from __future__ import annotations

from typing import Any
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import Button, Input, Label, Static

from tesis.config_fields import FieldSpec
from tesis.tui_commands import BaseDrawer
from tesis.tui_security import _safe_config_error_text, _safe_url
from tesis.tui_widgets import KeyboardActions


class FieldEditor(BaseDrawer):
    BINDINGS = [Binding("ctrl+s", "stage_save", "Stage and save", priority=True)]

    def action_stage_save(self) -> None:
        self.stage(save=True)

    def __init__(self, spec: FieldSpec, value: Any, config: dict) -> None:
        super().__init__()
        self.spec, self.value, self.config = spec, value, config
        self._raw_url: str | None = None
        self._url_display = ""
        self.seed = _safe_url(value) if spec.kind == "url" and value else str(value) if value is not None else ""
        self._url_display = self.seed

    def compose(self) -> ComposeResult:
        yield Label(self.spec.label, markup=False)
        with VerticalScroll(classes="drawer-body"):
            yield Static(self.spec.description, markup=False)
            yield Input(value=self.seed, password=self.spec.secret, id="field-value")
            yield Static("", id="field-error", markup=False)
        with KeyboardActions():
            yield Button("Stage value", id="field-stage", variant="primary")
            yield Button("Cancel", id="field-cancel")
        yield Static("Edit: native caret keys · Enter stage · Esc cancel", classes="drawer-hint", markup=False)

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    @on(Input.Changed)
    def mask_endpoint(self, event: Input.Changed) -> None:
        if self.spec.kind != "url" or event.value == self._url_display:
            return
        self._raw_url = event.value
        self._url_display = _safe_url(event.value)
        event.input.value = self._url_display

    @on(Input.Submitted)
    @on(Button.Pressed, "#field-stage")
    def stage(self, event: Any = None, *, save: bool = False) -> None:
        try:
            text = self.query_one(Input).value
            if self.spec.kind == "url" and self._raw_url is not None:
                value = self._raw_url
            else:
                value = self.value if text == self.seed else self.spec.coerce(text, config=self.config)
            value = self.spec.validate(value, config=self.config)
        except (ValueError, TypeError) as exc:
            self.query_one("#field-error", Static).update(_safe_config_error_text(exc))
            return
        self.dismiss((value, save))

    @on(Button.Pressed, "#field-cancel")
    def action_back(self) -> None:
        self.dismiss(None)

    def prepare_navigation(self) -> bool:
        self.query_one("#field-error", Static).update("Stage or Cancel this edit before changing workspace.")
        return False
