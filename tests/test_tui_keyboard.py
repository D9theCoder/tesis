"""Focused keyboard/draft checks. No runner, provider, or DVWA execution."""
import asyncio

import pytest
from textual.app import App
from textual.binding import Binding
from textual.widgets import Button, TextArea

from tesis import tui_state
from tesis.config_loader import save_yaml_config
from tesis.tui_choices import ChoicePicker
from tesis.tui_commands import open_workspace, request_quit
from tesis.tui_forms import SettingsDrawer


class WidgetApp(App):
    CSS_PATH = "../tesis/tui.tcss"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [Binding("ctrl+q", "quit", priority=False)]

    def action_quit(self):
        request_quit(self.screen)

    def action_force_exit(self):
        self.exit()


@pytest.fixture
def mission_shell(monkeypatch):
    """Keep only the mission screen's identity and keyboard dispatch."""
    from tesis.tui_mission import MissionControlScreen
    monkeypatch.setattr(MissionControlScreen, "compose", lambda self: iter([Button("Mission", id="mission-anchor")]))
    monkeypatch.setattr(MissionControlScreen, "on_mount", lambda self: None)
    monkeypatch.setattr(MissionControlScreen, "on_resize", lambda *args: None)
    monkeypatch.setattr(MissionControlScreen, "on_screen_resume", lambda self: self.query_one(Button).focus())
    return MissionControlScreen


@pytest.fixture
def settings_path(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    monkeypatch.setattr(tui_state, "CONFIG_PATH", path)
    save_yaml_config(path, {"target_url": "http://localhost/dvwa", "provider": "saved",
                           "models": {"saved": {"provider": "openai", "model_name": "offline"}},
                           "scoring_mode": "ai", "scoring_evaluator": {"provider": "saved", "max_attempts": 2,
                                                                      "max_tokens": 1024, "timeout": 60}})
    return path


def test_quit_combinations_preserve_dirty_settings_and_active_runs(settings_path, mission_shell):
    async def scenario():
        app = WidgetApp()
        async with app.run_test() as pilot:
            mission = mission_shell()
            app.push_screen(mission)
            await pilot.pause()
            mission._run_active = True
            await pilot.press("ctrl+q")
            assert app.is_running and app.screen is mission
            mission._run_active = False
            open_workspace(app, SettingsDrawer())
            await pilot.pause()
            drawer = app.screen
            drawer.query_one("#yaml-editor", TextArea).text += "\n# unsaved\n"
            await pilot.press("ctrl+q")
            assert app.is_running and app.screen is drawer
            drawer.query_one("#setting-target").focus()
            await pilot.press("enter", "ctrl+q")
            assert app.is_running and app.screen is not drawer
            await pilot.press("escape")
            app.push_screen(ChoicePicker([("A", "a")]))
            await pilot.pause()
            await pilot.press("ctrl+q")
            assert app.is_running and isinstance(app.screen, ChoicePicker)
            await pilot.press("ctrl+alt+q")
            assert not app.is_running
    asyncio.run(scenario())
