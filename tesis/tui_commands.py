"""Command registry and shared drawer shell for the terminal UI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Input, Label, OptionList, Static, TextArea
from textual.widgets.option_list import Option

from tesis.tui_widgets import PaletteInput, SettingValueRow, key_hints


# ---------------------------------------------------------------- command registry

@dataclass
class CommandSpec:
    name: str
    title: str
    summary: str
    keys: str = ""
    enabled_when: str = "always"


# ``keys`` is the launcher's advertised shortcut for a command, and is only set
# when MissionControlScreen really binds that key (see
# test_registry_keys_are_dispatchable_and_pane_keys_agree). Commands without a
# global key leave it empty and stay reachable through the launcher and help.
COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec("run", "Run single", "Guided single-coordinate launch", "ctrl+r", "idle"),
    CommandSpec("matrix", "Run matrix", "Guided experiment-matrix launch", "ctrl+alt+m", "idle"),
    CommandSpec("plan", "Plan", "Preview resolved config and fingerprint", "ctrl+o", "idle"),
    CommandSpec("cancel", "Cancel", "Request graceful cancellation", "ctrl+c", "active"),
    CommandSpec("coordinates", "Coordinates", "Inspect live coordinate rows", "alt+2", "always"),
    CommandSpec("evidence", "Evidence", "Inspect verified findings and outcomes", "alt+3", "always"),
    CommandSpec("failure", "Failure", "Inspect latest failure summary", "", "always"),
    CommandSpec("activity", "Activity", "Focus run details and recent activity", "alt+4", "always"),
    CommandSpec("trace", "Trace", "Bounded redacted event stream", "ctrl+l", "always"),
    CommandSpec("doctor", "Doctor", "Configuration and target checks", "ctrl+d", "always"),
    CommandSpec("results", "Results", "Browse saved experiments and reviews", "ctrl+v", "always"),
    CommandSpec("settings", "Settings", "Configure target, models, runtime and output", "ctrl+s", "idle"),
    CommandSpec("export", "Export", "Export triage summary as JSON", "", "always"),
    CommandSpec("about", "About", "Harness and runtime summary", "", "always"),
    CommandSpec("help", "Help", "Command registry and keys", "ctrl+f1", "always"),
    CommandSpec("quit", "Quit", "Exit the TUI", "ctrl+q", "idle"),
)

_COMMAND_INDEX = {spec.name: spec for spec in COMMANDS}

# Keys the screen binds that are not registry commands. The footer hint and the
# help drawer both render this one list, so pane navigation is described once.
NAVIGATION_KEYS: tuple[tuple[str, str], ...] = (
    ("alt+1", "pipeline"),
    ("alt+2", "coordinates"),
    ("alt+3", "evidence"),
    ("alt+4", "activity"),
    ("Tab/Shift+Tab", "focus"),
    ("Enter", "inspect"),
    ("ctrl+p", "command"),
    ("↑/↓", "select"),
    ("←/→", "tabs"),
    ("PgUp/PgDn", "scroll"),
    ("Home/End", "first/last"),
    ("Esc", "back"),
)


def navigation_hint() -> str:
    """Global navigation keys, rendered identically in the footer and help."""
    return " · ".join(f"{key} {label}" for key, label in NAVIGATION_KEYS)


#: Supported interactive floor. Below it the shell shows only the size notice
#: and the quit/help hints.
FLOOR_WIDTH = 60
FLOOR_HEIGHT = 18


def _below_floor(screen: Screen) -> bool:
    try:
        size = screen.app.size
    except Exception:
        return False
    return size.width < FLOOR_WIDTH or size.height < FLOOR_HEIGHT


def _dismisses_below_floor(screen: Screen) -> bool:
    """Pop an overlay that is not allowed below the floor; report if dismissed.

    Idempotent: a mount and a resize can both arrive for the same screen, and a
    second pop would take the screen underneath with it.
    """
    if getattr(screen, "ALLOW_BELOW_FLOOR", False):
        return False
    if isinstance(screen, BaseDrawer):
        # Keep the workspace instance and draft through a temporary resize.
        screen.set_class(_below_floor(screen), "too-small")
        return False
    if not _below_floor(screen):
        return False
    try:
        if screen.app.screen is screen:
            screen.app.pop_screen()
    except Exception:
        pass
    return True


def keyboard_context(screen: Screen) -> str:
    focused = screen.focused
    from tesis.tui_auth import ChatGPTAuth
    if any(auth.busy for auth in screen.query(ChatGPTAuth)):
        return "Busy: Ctrl+C cancel sign-in · Esc back · Ctrl+Alt+Q force exit"
    from tesis.tui_reasoning import ReasoningControl
    if any(control._checking for control in screen.query(ReasoningControl)):
        return "Busy: Ctrl+C cancel support check · Esc back · Ctrl+Alt+Q force exit"
    if getattr(screen, "_saving", False):
        return "Busy: saving configuration · Ctrl+Alt+Q force exit"
    if getattr(screen, "_review_busy", False):
        return "Busy: reviewing frozen evidence · wait to go Back"
    if any(button.disabled for button in screen.query("#provider-fetch, #settings-chatgpt-refresh")):
        return "Busy: loading model catalog · Ctrl+C cancel · Esc back"
    if isinstance(focused, PaletteInput):
        if getattr(screen, "multiple", False):
            return "Multi-select: type filter · ↑↓ move · Space toggle · Enter details"
        return "Search: type filters · ↑/↓ results · Enter choose · Esc cancel"
    if isinstance(focused, (Input, TextArea)):
        if type(screen).__name__ == "FieldEditor":
            return "Edit: Enter stage · Esc cancel"
        return "Edit: native caret keys · Ctrl+C copy selection · Tab next · Esc back"
    if isinstance(focused, SettingValueRow):
        owner = type(screen).__name__
        if owner == "SettingsDrawer" and screen.app.size.width < 80:
            return "↑↓ fields · ← categories · Enter edit · Ctrl+S save"
        if owner == "SettingsDrawer":
            return "Browse: ↑/↓ fields · ← categories / → content · Enter edit · Ctrl+S save · Esc back"
        if owner == "LaunchDrawer":
            return "Browse: ↑/↓ rows · Enter edit · Ctrl+F7/F8 previous / next · Esc back"
        if type(focused).__name__ == "GradeRow":
            return "Grade: Alt+0-4 stage grade · Tab reason / Save · Esc candidate list"
        return "Browse: ↑/↓ rows · Enter edit · Tab actions · Esc back"
    if type(screen).__name__ == "LaunchDrawer":
        return "Review: Tab to Start · Ctrl+F7 previous · Esc back" if screen._step == 3 else "Setup: Ctrl+F7/F8 previous / next · Enter edit · Esc back"
    if type(screen).__name__ == "SettingsDrawer":
        return "Browse: ↑/↓ select · ← categories / → content · Ctrl+F4 YAML · Ctrl+S save · Esc back"
    return "Browse: ↑/↓ select · Enter activate · Tab focus · Esc back · Ctrl+Alt+Q force exit"


def interrupt_context(screen: Screen) -> None:
    """Copy, cancel the local operation, then cancel an experiment; never discard."""
    focused = screen.app.focused
    if isinstance(focused, (Input, TextArea)) and not focused.selection.is_empty:
        focused.action_copy()
        return
    from tesis.tui_auth import ChatGPTAuth
    for auth in screen.query(ChatGPTAuth):
        if auth.busy:
            if auth.signing_out:
                screen.notify("Finishing sign-out before returning to account settings.")
            else:
                auth.cancel_login()
            return
    from tesis.tui_reasoning import ReasoningControl
    for control in screen.query(ReasoningControl):
        if control.cancel_support_check():
            return
    cancel = getattr(screen, "cancel_local_operation", None)
    if cancel is not None and cancel():
        return
    from tesis.tui_mission import MissionControlScreen
    mission = next((item for item in screen.app.screen_stack if isinstance(item, MissionControlScreen)), None)
    if mission is not None and mission.run_active:
        mission.action_cancel_or_exit()
    else:
        screen.notify("Idle. Esc goes back; Ctrl+Q quits; Ctrl+Alt+Q forces exit.")


def request_quit(screen: Screen) -> None:
    """Ordinary quit respects active experiments and every outgoing draft."""
    from tesis.tui_mission import MissionControlScreen

    stack = screen.app.screen_stack
    if any(isinstance(item, MissionControlScreen) and item.run_active for item in stack):
        screen.notify("Run active. Ctrl+C cancels; Ctrl+Alt+Q forces exit.")
        return
    for item in reversed(stack):
        prepare = getattr(item, "prepare_navigation", None)
        if prepare is not None and not prepare():
            return
    screen.app.exit()


def open_workspace(app: Any, screen: Screen) -> None:
    """One instance of each root, with outgoing dirty children given first refusal."""
    existing = next((item for item in app.screen_stack if type(item) is type(screen)), None)
    if existing is app.screen:
        return
    roots = {"SettingsDrawer", "LaunchDrawer", "ResultsDrawer"}
    if existing is None and type(screen).__name__ not in roots:
        app.push_screen(screen)
        return
    from tesis.tui_mission import MissionControlScreen

    mission = next((item for item in app.screen_stack if isinstance(item, MissionControlScreen)), None)
    while len(app.screen_stack) > 1 and app.screen is not existing and app.screen is not mission:
        current = app.screen
        prepare = getattr(current, "prepare_navigation", None)
        if prepare is not None and not prepare():
            return
        app.pop_screen()
    if existing is None:
        app.push_screen(screen)


# ---------------------------------------------------------------- drawers

class BaseDrawer(Screen):
    """Centered inspection dialog, or a full-window settings surface.

    Public class names remain compatible with existing callers. Screens own
    their focus chain, so Tab stays inside the active dialog and popping it
    restores the previous context. Help remains available below the size floor.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=False),
        Binding("ctrl+p", "open_launcher", "Commands", show=False),
        Binding("ctrl+f1", "open_help", "Help", show=False),
        Binding("ctrl+c", "cancel_or_exit", "Copy / cancel", show=False, priority=True),
        Binding("ctrl+q", "quit", "Quit", show=False, priority=True),
        Binding("ctrl+alt+q", "force_exit", "Force exit", show=False, priority=True),
    ]

    #: Set on a drawer that is allowed to stay open below the 60x18 floor.
    ALLOW_BELOW_FLOOR = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        compose = cls.__dict__.get("compose")
        if compose is not None:
            def composed(self: Screen, _compose: Any = compose) -> ComposeResult:
                try:
                    self.set_class(self.app.size.width < 80, "drawer-full")
                except Exception:
                    pass
                yield Static("Terminal too small. Minimum 60x18. Resize to resume.\nCtrl+F1 Help · Esc Back · Ctrl+Q quit · Ctrl+Alt+Q force exit",
                             id="drawer-size-notice", markup=False)
                with Vertical(classes="drawer"):
                    yield from _compose(self)

            composed.__name__ = "compose"
            cls.compose = composed  # type: ignore[method-assign]

        # Wrap the subclass handlers so the floor rule is applied once, here,
        # instead of in every drawer.
        on_mount = cls.__dict__.get("on_mount")

        def mounted(self: Screen) -> None:
            if _dismisses_below_floor(self):
                return
            if on_mount is not None:
                on_mount(self)
            titles = self.query(".drawer Label")
            if titles:
                titles.first().add_class("drawer-title")

        mounted.__name__ = "on_mount"
        cls.on_mount = mounted  # type: ignore[method-assign]

        on_resize = cls.__dict__.get("on_resize")

        def resized(self: Screen, event: Any) -> None:
            if _dismisses_below_floor(self):
                return
            self.set_class(self.app.size.width < 80, "drawer-full")
            if on_resize is not None:
                on_resize(self, event)

        resized.__name__ = "on_resize"
        cls.on_resize = resized  # type: ignore[method-assign]

    def check_action(self, action: str, parameters: tuple[Any, ...]) -> bool | None:
        if self.has_class("too-small") and action not in {"back", "open_help", "cancel_or_exit", "quit", "force_exit", "app.force_exit"}:
            return False
        return super().check_action(action, parameters)

    def on_descendant_focus(self) -> None:
        for hint in self.query(".drawer-hint"):
            hint.update(keyboard_context(self))

    def action_back(self) -> None:
        if self.app.screen is self:
            self.app.pop_screen()

    def action_open_launcher(self) -> None:
        self.app.push_screen(CommandLauncher())

    def action_open_help(self) -> None:
        from tesis.tui_drawers import HelpDrawer

        if not isinstance(self, HelpDrawer):
            self.app.push_screen(HelpDrawer())

    def action_cancel_or_exit(self) -> None:
        interrupt_context(self)

    def action_force_exit(self) -> None:
        self.app.exit()

    def action_quit(self) -> None:
        request_quit(self)


class CommandLauncher(Screen):
    """Bottom-anchored command list above a compact text composer.

    Ctrl+P opens this registry-backed surface, so the
    footer hint, the help drawer, and typed dispatch never disagree.
    """

    BINDINGS = [Binding("escape", "back", "Back", show=False),
                Binding("ctrl+c", "cancel_or_exit", "Copy / cancel", show=False, priority=True),
                Binding("ctrl+q", "quit", "Quit", show=False, priority=True),
                Binding("ctrl+alt+q", "app.force_exit", "Force exit", show=False, priority=True)]

    def __init__(self, query: str = "") -> None:
        super().__init__()
        self._filtered: list[CommandSpec] = list(COMMANDS)
        self._query = query

    def compose(self) -> ComposeResult:
        with Vertical(id="command-launcher"):
            yield OptionList(*(self._option(spec) for spec in COMMANDS), id="launcher-list")
            yield Static("No matching commands", id="launcher-empty")
            yield PaletteInput(value=self._query, placeholder="/ Type a command", id="launcher-input")
            yield Label(key_hints(("↑/↓", "select"), ("Enter", "run"), ("Tab", "focus"), ("Esc", "close")), id="launcher-title")

    def on_mount(self) -> None:
        if _dismisses_below_floor(self):
            return
        self._refilter(self._query)
        try:
            self.query_one("#launcher-input", Input).focus()
        except Exception:
            pass

    def _run_active(self) -> bool:
        mission = self._mission()
        return bool(mission is not None and mission.run_active)

    def _enabled(self, spec: CommandSpec) -> bool:
        if spec.enabled_when == "idle":
            return not self._run_active()
        if spec.enabled_when == "active":
            return self._run_active()
        return True

    def _option(self, spec: CommandSpec) -> Option:
        enabled = self._enabled(spec)
        text = Text(f"  /{spec.name:<14}")
        text.append(spec.summary)
        if spec.keys:
            text.append(f"  {spec.keys}", style="dim")
        if not enabled:
            reason = "run active" if spec.enabled_when == "idle" else "no active run"
            text.append(f"  ({reason})", style="dim")
        return Option(text, id=spec.name, disabled=not enabled)

    def _refilter(self, text: str) -> None:
        needle = text.strip().lower().lstrip("/")
        self._filtered = [s for s in COMMANDS if needle in s.name or needle in s.summary.lower()]
        try:
            options = self.query_one("#launcher-list", OptionList)
            options.clear_options()
            for spec in self._filtered:
                options.add_option(self._option(spec))
            options.action_first()
            self.query_one("#launcher-empty").display = not self._filtered
        except Exception:
            pass

    @on(Input.Changed, "#launcher-input")
    def filter_commands(self, event: Input.Changed) -> None:
        self._refilter(event.value)

    @on(Input.Submitted, "#launcher-input")
    def dispatch_typed(self, event: Input.Submitted) -> None:
        options = self.query_one("#launcher-list", OptionList)
        if options.highlighted is not None:
            self._dispatch(str(options.get_option_at_index(options.highlighted).id))

    def action_cancel_or_exit(self) -> None:
        interrupt_context(self)

    def action_quit(self) -> None:
        request_quit(self)

    @on(OptionList.OptionSelected, "#launcher-list")
    def dispatch_selected(self, event: OptionList.OptionSelected) -> None:
        self._dispatch(str(event.option.id))

    def _dispatch(self, name: str) -> None:
        spec = _COMMAND_INDEX.get(str(name))
        if spec is None or not self._enabled(spec):
            return
        app = self.app
        app.pop_screen()

        def push(screen: Screen) -> None:
            try:
                open_workspace(app, screen)
            except Exception as exc:
                app.notify(f"Navigation failed ({type(exc).__name__}).", severity="error")

        if name in ("run", "matrix"):
            from tesis.tui_forms import LaunchDrawer

            push(LaunchDrawer(mode="single" if name == "run" else "matrix"))
        elif name == "plan":
            from tesis.tui_drawers import PlanDrawer

            push(PlanDrawer())
        elif name == "cancel":
            mission = self._mission()
            if mission is not None:
                mission.request_cancel()
                self._return_to_mission()
        elif name == "coordinates":
            from tesis.tui_drawers import CoordinateDrawer

            push(CoordinateDrawer())
        elif name == "evidence":
            from tesis.tui_drawers import EvidenceDrawer

            push(EvidenceDrawer())
        elif name == "failure":
            from tesis.tui_drawers import FailureDrawer

            mission = self._mission()
            push(FailureDrawer(getattr(getattr(mission, "state", None), "failure", None)))
        elif name == "trace":
            from tesis.tui_drawers import TraceDrawer

            push(TraceDrawer())
        elif name == "activity":
            mission = self._mission()
            if mission is not None:
                self._return_to_mission()
                mission.action_show_activity()
        elif name == "doctor":
            from tesis.tui_drawers import DoctorDrawer

            push(DoctorDrawer())
        elif name in ("results", "export"):
            from tesis.tui_drawers import ResultsDrawer

            push(ResultsDrawer())
        elif name == "settings":
            from tesis.tui_forms import SettingsDrawer

            push(SettingsDrawer())
        elif name == "about":
            from tesis.tui_drawers import AboutDrawer

            push(AboutDrawer())
        elif name == "help":
            from tesis.tui_drawers import HelpDrawer

            push(HelpDrawer())
        elif name == "quit":
            request_quit(app.screen)

    def _return_to_mission(self) -> None:
        """Cancelling is observed on the mission surface, not inside a stale modal."""
        mission = self._mission()
        if mission is None:
            return
        while self.app.screen is not mission:
            current = self.app.screen
            prepare = getattr(current, "prepare_navigation", None)
            if prepare is not None and not prepare():
                return
            self.app.pop_screen()

    def _mission(self) -> MissionControlScreen | None:
        from tesis.tui_mission import MissionControlScreen

        for screen in self.app.screen_stack:
            if isinstance(screen, MissionControlScreen):
                return screen
        return None

    def action_back(self) -> None:
        # Focus restoration is owned by MissionControlScreen.on_screen_resume,
        # which knows which surface is the live default.
        self.app.pop_screen()
