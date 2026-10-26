"""Selectable value rows with private editors and stable native field identities."""
from __future__ import annotations

from typing import Any
from textual import on
from textual.app import ComposeResult
from textual.message import Message
from textual.containers import Vertical
from textual.widgets import Checkbox, Input, Select, SelectionList, Static

from tesis.config_fields import FieldSpec
from tesis.tui_choices import ChoicePicker
from tesis.tui_editors import FieldEditor
from tesis.tui_security import _redact_text, _safe_url
from tesis.tui_widgets import SettingValueRow


class ControlRow(SettingValueRow):
    """Keep field state in its original widget; only its active editor takes keys."""

    class Confirmed(Message):
        def __init__(self, row: ControlRow, save: bool = False):
            super().__init__()
            self.row, self.save = row, save

    def __init__(self, label: str, control: Any, description: str = "", *, spec: FieldSpec | None = None):
        super().__init__(label, description, id=f"row-{control.id}")
        self.control_widget = control
        self.spec = spec or FieldSpec(str(control.id), label=label,
                                     value_type=int if isinstance(control, Input) and control.type == "integer" else str,
                                     secret=isinstance(control, Input) and control.password,
                                     kind="url" if isinstance(control, Input) and "url" in str(control.id) else "text",
                                     allow_none=True)

    def compose(self) -> ComposeResult:
        yield from super().compose()
        with Vertical(classes="row-value-storage"):
            yield self.control_widget

    def on_mount(self) -> None:
        self.refresh_value()

    @on(Input.Changed)
    @on(Select.Changed)
    @on(Checkbox.Changed)
    @on(SelectionList.SelectedChanged)
    def field_changed(self) -> None:
        self.refresh_value()

    def refresh_value(self) -> None:
        control = self.control_widget
        if isinstance(control, SelectionList):
            value = ", ".join(str(item) for item in control.selected) or "None selected"
        elif isinstance(control, Select):
            value = next((str(label) for label, item in control._options if item == control.value), "Unset / inherit")
        elif isinstance(control, Checkbox):
            value = "Enabled" if control.value else "Disabled"
        else:
            value = control.value
        if isinstance(control, Input) and control.password:
            value = "Configured" if value else "Unchanged / unset"
        self.query_one(f"#{self.id}-value", Static).update(_redact_text(_safe_url(value) if "://" in str(value) else value))

    def action_edit(self) -> None:
        control = self.control_widget
        if control.disabled:
            self.notify("This field is unavailable in the current context.")
            return
        def staged(result: Any) -> None:
            if result is not None:
                if isinstance(control, SelectionList):
                    control.deselect_all()
                    for item in result[0]:
                        control.select(item)
                elif isinstance(control, Input):
                    control.value = "" if result[0] is None else str(result[0])
                else:
                    control.value = result[0]
                self.refresh_value()
                self.post_message(self.Confirmed(self, len(result) > 1 and result[1]))
            self.focus()
        if isinstance(control, Select):
            options = [("Unset / inherit" if value is Select.NULL else str(label), value) for label, value in control._options]
            self.app.push_screen(ChoicePicker(options, current=control.value, title=self._setting_label), staged)
        elif isinstance(control, SelectionList):
            options = [(str(control.get_option_at_index(index).prompt), control.get_option_at_index(index).value)
                       for index in range(control.option_count)]
            self.app.push_screen(ChoicePicker(options, current=control.selected, title=self._setting_label, multiple=True), staged)
        elif isinstance(control, Checkbox):
            self.app.push_screen(ChoicePicker([("Disabled", False), ("Enabled", True)], current=control.value,
                                             title=self._setting_label), staged)
        else:
            self.app.push_screen(FieldEditor(self.spec, control.value, {}), staged)
