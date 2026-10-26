"""Short filter child page shared by saved and live coordinate browsing."""
from textual import on
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Button, Label, Select, Static

from tesis.tui_choices import ChoiceSelect
from tesis.tui_commands import BaseDrawer
from tesis.tui_rows import ControlRow
from tesis.tui_widgets import KeyboardActions


class FilterPage(BaseDrawer):
    def __init__(self, fields, values, active):
        super().__init__()
        self.fields, self.values, self.active = fields, values, active

    def compose(self) -> ComposeResult:
        yield Label("Filters")
        with VerticalScroll(classes="drawer-body"):
            for identifier, attr in self.fields:
                choices = self.values[attr]
                selected = self.active.get(attr) or Select.NULL
                if selected is not Select.NULL and selected not in choices:
                    choices = [selected, *choices]
                yield ControlRow(attr.replace("_", " ").title(), ChoiceSelect([(str(value), value) for value in choices],
                    value=selected, id=identifier, allow_blank=True))
        with KeyboardActions():
            yield Button("Apply filters", id="filters-apply", variant="primary")
            yield Button("Clear filters", id="filters-clear")
            yield Button("Cancel", id="filters-cancel")
        yield Static("Browse: Enter edit · Tab Apply / Clear · Esc cancel", classes="drawer-hint", markup=False)

    @on(Button.Pressed, "#filters-apply")
    def apply(self):
        self.dismiss({attr: value for identifier, attr in self.fields
                      if (value := self.query_one(f"#{identifier}", Select).value) is not Select.NULL})

    @on(Button.Pressed, "#filters-clear")
    def clear(self):
        self.dismiss({})

    @on(Button.Pressed, "#filters-cancel")
    def action_back(self):
        self.dismiss(None)
