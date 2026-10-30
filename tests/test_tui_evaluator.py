"""Isolated Settings widgets for the independent evaluator selection."""

import asyncio

import pytest
from textual.app import App
from textual.widgets import Input, Select, Static, TextArea

from tesis import tui_state
from tesis.config_loader import dump_yaml_config, load_yaml_config, save_yaml_config
from tesis.provider_registry import model_profile_id
from tesis.tui_forms import SettingsDrawer




class SettingsApp(App):
    CSS_PATH = "../tesis/tui.tcss"

    def on_mount(self):
        self.push_screen(SettingsDrawer())


@pytest.fixture
def evaluator_config(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    monkeypatch.setattr(tui_state, "CONFIG_PATH", path)
    monkeypatch.setenv("EVALUATOR_WIDGET_KEY", "offline-evaluator-secret")
    save_yaml_config(path, {
        "target_url": "http://localhost/dvwa", "provider": model_profile_id("gateway", "first"),
        "api_providers": {name: {"display_name": name, "protocol": protocol,
            "base_url": f"https://{name}.invalid/v1", "api_key": "${EVALUATOR_WIDGET_KEY}",
            "models": ["first", "second"]}
            for name, protocol in (("gateway", "openai_compatible"), ("responses", "openai"),
                                   ("messages", "anthropic"))},
        "scoring_mode": "ai", "scoring_evaluator": {
            "provider": model_profile_id("gateway", "first"),
            "max_attempts": 2, "max_tokens": 1024, "timeout": 60},
    })
    return path


async def wait_saved(pilot, drawer):
    for _ in range(100):
        await pilot.pause(0.01)
        if not drawer._saving:
            break
    assert str(drawer.query_one("#settings-status", Static).content) == "Saved config."


def test_invalid_limits_and_removed_models_do_not_change_the_saved_evaluator(evaluator_config):
    original = evaluator_config.read_bytes()

    async def scenario():
        app = SettingsApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = app.screen
            drawer.query_one("#settings-evaluator-tokens", Input).value = "0"
            drawer.apply_evaluator()
            assert "not applied" in str(drawer.query_one("#settings-evaluator-status", Static).content)
            assert evaluator_config.read_bytes() == original
            payload = load_yaml_config(evaluator_config)
            payload["api_providers"]["gateway"]["models"] = ["second"]
            drawer.query_one("#yaml-editor", TextArea).text = dump_yaml_config(payload)
            await pilot.pause(0.3)
            # Unconfirmed invalid edits and saved identities survive an unrelated YAML refresh.
            assert drawer.query_one("#settings-evaluator-provider", Select).value == model_profile_id("gateway", "first")
            assert drawer.query_one("#settings-evaluator-tokens", Input).value == "0"
            drawer.apply_evaluator()
            assert "unavailable" in str(drawer.query_one("#settings-evaluator-status", Static).content)
            await pilot.press("escape")
            assert evaluator_config.read_bytes() == original
    asyncio.run(scenario())
