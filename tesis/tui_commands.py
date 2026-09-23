"""Command registry and shared drawer shell for the terminal UI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Input, Label, OptionList
from textual.widgets.option_list import Option


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
# global key leave it empty and stay reachable through the launcher and `?`.
COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec("run", "Run single", "Guided single-coordinate launch", "r", "idle"),
    CommandSpec("matrix", "Run matrix", "Guided experiment-matrix launch", "m", "idle"),
    CommandSpec("plan", "Plan", "Preview resolved config and fingerprint", "p", "idle"),
    CommandSpec("cancel", "Cancel", "Request graceful cancellation", "ctrl+c", "active"),
    CommandSpec("coordinates", "Coordinates", "Inspect live coordinate rows", "2", "always"),
    CommandSpec("evidence", "Evidence", "Inspect verified findings and outcomes", "3", "always"),
    CommandSpec("failure", "Failure", "Inspect latest failure summary", "", "always"),
    CommandSpec("trace", "Trace", "Bounded redacted event stream", "", "always"),
    CommandSpec("doctor", "Doctor", "Configuration and target checks", "d", "always"),
    CommandSpec("results", "Results", "Scan and triage saved artifacts", "", "always"),
    CommandSpec("settings", "Settings", "Edit config YAML with secret masking", "", "idle"),
    CommandSpec("export", "Export", "Export triage summary as JSON", "", "always"),
    CommandSpec("about", "About", "Harness and runtime summary", "", "always"),
    CommandSpec("help", "Help", "Command registry and keys", "?", "always"),
    CommandSpec("quit", "Quit", "Exit the TUI", "q", "idle"),
)

_COMMAND_INDEX = {spec.name: spec for spec in COMMANDS}

# Keys the screen binds that are not registry commands. The footer hint and the
# help drawer both render this one list, so pane navigation is described once.
NAVIGATION_KEYS: tuple[tuple[str, str], ...] = (
    ("1", "pipeline"),
    ("2", "coordinates"),
    ("3", "evidence"),
    ("Tab/Shift+Tab", "focus"),
    ("Enter", "inspect"),
    ("/", "command"),
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
    if getattr(screen, "ALLOW_BELOW_FLOOR", False) or not _below_floor(screen):
        return False
    try:
        if screen.app.screen is screen:
            screen.app.pop_screen()
    except Exception:
        pass
    return True


# ---------------------------------------------------------------- drawers

class BaseDrawer(Screen):
    """Shared drawer shell.

    A Textual ``Screen`` is always laid out at the full terminal size, so the
    docked panel has to be an inner container: every drawer's composed content
    is wrapped in one ``.drawer`` panel, which is what makes it a 76-cell
    right-docked surface at 80+ columns and a full-screen surface below 80.
    The wrapping happens here so no drawer has to repeat the shell.

    Below the supported 60x18 floor the shell renders nothing but the size
    notice, so an overlay must not stay on top of it: a drawer dismisses itself
    on mount or on resize below the floor. Help is the documented exception,
    because it is one of the only two actions a too-small terminal still has.
    """

    BINDINGS = [Binding("escape", "back", "Back", show=True)]

    #: Set on a drawer that is allowed to stay open below the 60x18 floor.
    ALLOW_BELOW_FLOOR = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        compose = cls.__dict__.get("compose")
        if compose is not None:
            def composed(self: Screen, _compose: Any = compose) -> ComposeResult:
                # Below 80 columns the panel takes the whole screen; at 80 and
                # above it stays the 76-cell right-docked panel.
                try:
                    self.set_class(self.app.size.width < 80, "drawer-full")
                except Exception:
                    pass
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

        mounted.__name__ = "on_mount"
        cls.on_mount = mounted  # type: ignore[method-assign]

        on_resize = cls.__dict__.get("on_resize")

        def resized(self: Screen, event: Any) -> None:
            if _dismisses_below_floor(self):
                return
            if on_resize is not None:
                on_resize(self, event)

        resized.__name__ = "on_resize"
        cls.on_resize = resized  # type: ignore[method-assign]

    def action_back(self) -> None:
        self.app.pop_screen()


class CommandLauncher(Screen):
    """Bottom-anchored command modal; the only chrome border in the shell.

    ``/``, ``:``, and Ctrl+P all open this same registry-backed surface, so the
    footer hint, the help drawer, and typed dispatch never disagree.
    """

    BINDINGS = [Binding("escape", "back", "Back", show=True)]

    def __init__(self) -> None:
        super().__init__()
        self._filtered: list[CommandSpec] = list(COMMANDS)

    def compose(self) -> ComposeResult:
        with Vertical(id="command-launcher"):
            yield Label("Command — type to filter, Enter to dispatch, Esc to close", id="launcher-title")
            yield Input(placeholder="command", id="launcher-input")
            yield OptionList(*(self._option(spec) for spec in COMMANDS), id="launcher-list")

    def on_mount(self) -> None:
        if _dismisses_below_floor(self):
            return
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
        text = f"/{spec.name} — {spec.summary}"
        if not enabled:
            reason = "run active — cancel first" if spec.enabled_when == "idle" else "no active run"
            text = f"{text}  [disabled: {reason}]"
        return Option(text, id=spec.name, disabled=not enabled)

    def _refilter(self, text: str) -> None:
        needle = text.strip().lower().lstrip("/")
        self._filtered = [s for s in COMMANDS if needle in s.name or needle in s.summary.lower()] or list(COMMANDS)
        try:
            options = self.query_one("#launcher-list", OptionList)
            options.clear_options()
            for spec in self._filtered:
                options.add_option(self._option(spec))
        except Exception:
            pass

    @on(Input.Changed, "#launcher-input")
    def filter_commands(self, event: Input.Changed) -> None:
        self._refilter(event.value)

    @on(Input.Submitted, "#launcher-input")
    def dispatch_typed(self, event: Input.Submitted) -> None:
        # Only an exact command name dispatches; anything else is a filter term,
        # so a typo can never fire a neighbouring command.
        needle = event.value.strip().lower().lstrip("/")
        match = next((s for s in COMMANDS if s.name == needle), None)
        if match is not None:
            self._dispatch(match.name)

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
                app.push_screen(screen)
            except Exception:
                pass

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
            try:
                mission = self._mission()
                if mission is None or not mission.run_active:
                    app.exit()
            except Exception:
                pass

    def _return_to_mission(self) -> None:
        """Cancelling is observed on the mission surface, not inside a stale modal."""
        mission = self._mission()
        if mission is None:
            return
        for _ in range(4):
            stack = self.app.screen_stack
            if not stack or stack[-1] is mission:
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
