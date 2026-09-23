"""Stable public import facade for the mission-control Textual interface."""

from __future__ import annotations

import inspect
import os
from typing import Any

from rich.text import Text
from textual.app import App
from textual.theme import Theme

from tesis.tui_commands import COMMANDS, CommandLauncher, CommandSpec
from tesis.tui_drawers import (
    AboutDrawer,
    CoordinateDrawer,
    DETAIL_LOG_MAX_LINES,
    DETAIL_RENDER_MAX_CHARS,
    DoctorDrawer,
    EvidenceDrawer,
    FailureDrawer,
    HelpDrawer,
    PlanDrawer,
    ResultsDrawer,
    TraceDrawer,
)
from tesis.tui_forms import LaunchDrawer, SettingsDrawer
from tesis.tui_mission import MissionControlScreen
from tesis.tui_state import (
    CONFIG_PATH,
    REPOSITORY_ROOT,
    CoordinateRow,
    FailureSummary,
    RunStatus,
    StageRow,
    StageStatus,
    TuiRunState,
    apply_run_event,
)


# ---------------------------------------------------------------- themes

def _build_mono_theme() -> Theme:
    """Build the hex-monochrome theme against the installed Textual API."""
    params = inspect.signature(Theme).parameters
    defaults: dict[str, Any] = {
        "name": "tesis-mono",
        "primary": "#FFFFFF",
        "secondary": "#B0B0B0",
        "accent": "#FFFFFF",
        "foreground": "#FFFFFF",
        "background": "#000000",
        "success": "#FFFFFF",
        "error": "#FFFFFF",
        "warning": "#FFFFFF",
        "surface": "#000000",
        "panel": "#000000",
        "boost": "#FFFFFF",
        "dark": True,
    }
    return Theme(**{key: value for key, value in defaults.items() if key in params})


SHELL_MONO_THEME = _build_mono_theme()
SHELL_MONO_THEME_NAME = SHELL_MONO_THEME.name


# ---------------------------------------------------------------- app

class TesisApp(App[None]):
    """Mission-control terminal application for TESIS."""

    TITLE = "TESIS Experiment Harness"
    CSS_PATH = "tui.tcss"
    # Ctrl+P belongs to CommandLauncher; the stock palette would shadow it.
    ENABLE_COMMAND_PALETTE = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.register_theme(SHELL_MONO_THEME)
        if os.environ.get("NO_COLOR"):
            try:
                self.theme = SHELL_MONO_THEME_NAME
            except Exception:
                pass

    def exit(self, result: Any = None, return_code: int = 0, message: Any = None) -> None:
        if not getattr(self, "_tesis_shutdown_started", False):
            self._tesis_shutdown_started = True
            for screen in tuple(self.screen_stack):
                prepare = getattr(screen, "prepare_shutdown", None)
                if callable(prepare):
                    try:
                        prepare()
                    except Exception:
                        pass
            try:
                self.workers.cancel_all()
            except Exception:
                pass
        super().exit(result=result, return_code=return_code, message=message)

    def on_mount(self) -> None:
        self.push_screen(MissionControlScreen())

    def export_screenshot(self, *args: Any, **kwargs: Any) -> str:
        # Rich nbsp-encodes every space in exported SVGs, which makes the
        # text matrix unsearchable; decode back to plain spaces (single
        # spaces render identically; line widths are pinned by textLength).
        return super().export_screenshot(*args, **kwargs).replace("&#160;", " ")


def run_tui() -> None:
    TesisApp().run()


__all__ = [
    "AboutDrawer",
    "COMMANDS",
    "CONFIG_PATH",
    "CommandLauncher",
    "CommandSpec",
    "CoordinateDrawer",
    "CoordinateRow",
    "DETAIL_LOG_MAX_LINES",
    "DETAIL_RENDER_MAX_CHARS",
    "DoctorDrawer",
    "EvidenceDrawer",
    "FailureDrawer",
    "FailureSummary",
    "HelpDrawer",
    "LaunchDrawer",
    "MissionControlScreen",
    "PlanDrawer",
    "ResultsDrawer",
    "RunStatus",
    "SettingsDrawer",
    "StageRow",
    "StageStatus",
    "SHELL_MONO_THEME",
    "SHELL_MONO_THEME_NAME",
    "TesisApp",
    "TraceDrawer",
    "TuiRunState",
    "apply_run_event",
    "run_tui",
]
