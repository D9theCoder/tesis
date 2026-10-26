"""Persistent-query choice sheets, preserving native Select values and messages."""
from __future__ import annotations

from typing import Any

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, OptionList, Select, Static
from textual.widgets.option_list import Option

from tesis.tui_widgets import KeyboardActions, PaletteInput


class ChoicePicker(ModalScreen):
    """A private selection draft. Cancel never mutates the calling control."""

    BINDINGS = [Binding("escape", "cancel", "Cancel"),
                Binding("ctrl+c", "interrupt", "Copy / cancel", priority=True),
                Binding("ctrl+q", "app.quit", "Force exit", priority=True),
                Binding("space", "toggle", "Toggle", priority=True),
                Binding("f1", "help", "Help")]

    def __init__(self, choices: list[tuple[Any, Any]], *, current: Any = Select.NULL,
                 title: str = "Choose value", multiple: bool = False) -> None:
        super().__init__()
        self._title_text = title
        self.choices = choices
        self.current = current
        self.multiple = multiple
        self.selected = set(current) if multiple else set()
        self.filtered_choices: list[tuple[Any, Any]] = list(choices)
        self._highlight = current if not multiple else None

    def compose(self) -> ComposeResult:
        yield Static("Terminal too small. Minimum 60x18. Resize to resume.\nF1 Help · Esc cancel · Ctrl+Q force exit",
                     id="choice-size-notice", markup=False)
        with Vertical(id="choice-sheet"):
            yield Label(self.title_text, id="choice-title", markup=False)
            yield PaletteInput(placeholder="Search choices", id="choice-query", list_selector="#choice-list")
            yield OptionList(id="choice-list")
            yield Static("", id="choice-count", markup=False)
            with KeyboardActions():
                if self.multiple:
                    yield Button("Apply selection", id="choice-apply", variant="primary")
                yield Button("Cancel", id="choice-cancel")
            yield Static("Multi-select: Space toggles · Tab actions · Esc discards" if self.multiple else
                         "Pick: type to filter · ↑/↓ move · Enter confirm · Esc cancel", markup=False)

    @property
    def title_text(self) -> str:
        return getattr(self, "_title_text", "Choose value")

    def on_mount(self) -> None:
        self.refilter("")
        self._apply_size_floor()
        if not self.has_class("too-small"):
            self.query_one(Input).focus()

    def on_resize(self) -> None:
        if self.is_mounted:
            self._apply_size_floor()

    def _apply_size_floor(self) -> None:
        small = self.app.size.width < 60 or self.app.size.height < 18
        was_small = self.has_class("too-small")
        self.set_class(small, "too-small")
        if small:
            self.set_focus(None)
        elif was_small:
            self.call_after_refresh(self.query_one(Input).focus)

    def action_help(self) -> None:
        from tesis.tui_drawers import HelpDrawer
        self.app.push_screen(HelpDrawer())

    def refilter(self, query: str) -> None:
        options = self.query_one("#choice-list", OptionList)
        if options.highlighted is not None and options.highlighted < len(self.filtered_choices):
            self._highlight = self.filtered_choices[options.highlighted][1]
        words = query.casefold().split()
        self.filtered_choices = [(label, value) for label, value in self.choices
                        if all(word in f"{label} {value}".casefold() for word in words)]
        options.clear_options()
        for index, (label, value) in enumerate(self.filtered_choices):
            marker = ("[*] " if value in self.selected else "[-] ") if self.multiple else (
                "> " if value == self.current else "  ")
            display = str(label)
            if value is Select.NULL:
                display = "Unset / inherit"
            elif value is not None and str(value) not in display and not isinstance(value, bool):
                display += f" / {value}"
            options.add_option(Option(Text(marker + display), id=str(index)))
        values = [value for _, value in self.filtered_choices]
        options.highlighted = values.index(self._highlight) if self._highlight in values else (0 if values else None)
        self.query_one("#choice-count", Static).update(
            f"{len(values)}/{len(self.choices)} choices" if values else "No matching choices; refine your query.")

    @on(Input.Changed, "#choice-query")
    def filter_query(self, event: Input.Changed) -> None:
        self.refilter(event.value)

    @on(Input.Submitted, "#choice-query")
    @on(OptionList.OptionSelected, "#choice-list")
    def confirm(self) -> None:
        index = self.query_one(OptionList).highlighted
        if index is None or index >= len(self.filtered_choices):
            return
        value = self.filtered_choices[index][1]
        if self.multiple:
            self.query_one("#choice-apply", Button).focus()
        else:
            self.dismiss((value,))

    def toggle(self) -> None:
        index = self.query_one(OptionList).highlighted
        if index is None:
            return
        value = self.filtered_choices[index][1]
        self.selected.symmetric_difference_update({value})
        self.refilter(self.query_one(Input).value)

    def check_action(self, action: str, parameters: tuple[Any, ...]) -> bool | None:
        if self.has_class("too-small") and action not in {"cancel", "interrupt", "help"}:
            return False
        if action == "toggle":
            return self.multiple and not isinstance(self.focused, Button)
        return super().check_action(action, parameters)

    def action_toggle(self) -> None:
        self.toggle()

    @on(Button.Pressed, "#choice-apply")
    def apply(self) -> None:
        self.dismiss(([value for _, value in self.choices if value in self.selected],))

    @on(Button.Pressed, "#choice-cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_interrupt(self) -> None:
        focused = self.focused
        if isinstance(focused, Input) and not focused.selection.is_empty:
            focused.action_copy()
        else:
            self.action_cancel()


class ChoiceSelect(Select):
    """Select-compatible row that opens a visible-query sheet instead of a dropdown."""

    def _watch_expanded(self, expanded: bool) -> None:
        if not expanded or not self.is_mounted:
            return
        self.expanded = False
        picker = ChoicePicker(list(self._options), current=self.value)
        picker._title_text = str(self.prompt or self.id or "Choose value")
        self.app.push_screen(picker, self._picked)

    def _picked(self, result: Any) -> None:
        if result is not None:
            self.value = result[0]
        if self.is_mounted:
            self.focus()
