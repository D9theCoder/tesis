"""Focused provider widgets: drafts, catalog selection, keyboard access, and saving."""

import asyncio

from textual.app import App
from textual.widgets import Input, Select

from tesis.tui_providers import ProviderDrawer


class ProviderApp(App):
    CSS_PATH = "../tesis/tui.tcss"

    def __init__(self, path, entries=None, provider_id=""):
        super().__init__()
        self.path, self.entries, self.provider_id = path, entries or {}, provider_id
        self.result = None

    def on_mount(self):
        self.push_screen(ProviderDrawer(config_path=self.path, entries=self.entries, provider_id=self.provider_id),
                         lambda result: setattr(self, "result", result))


def test_manual_effort_is_checked_before_provider_draft_can_be_applied(tmp_path, monkeypatch):
    from tesis.tui_reasoning import ReasoningControl
    calls = []
    monkeypatch.setattr("tesis.tui_reasoning.probe_reasoning", lambda profile, effort: calls.append((profile, effort)))
    entry = {"protocol": "openai_compatible", "base_url": "https://gateway.invalid/v1",
             "api_key": "offline-secret", "models": ["unknown"]}

    async def scenario():
        app = ProviderApp(tmp_path / "config.yaml", {"gateway": entry}, "gateway")
        async with app.run_test() as pilot:
            drawer = app.screen
            control = drawer.query_one("#provider-reasoning", ReasoningControl)
            control.query_one(Select).value = "custom"
            control.query_one(Input).value = "ultra"
            await pilot.pause()
            drawer.apply_provider()
            assert app.result is None
            assert not calls
            control.check_support()
            for _ in range(50):
                await pilot.pause(0.01)
                if control._checked:
                    break
            drawer.apply_provider()
            await pilot.pause()
            assert app.result.entry["model_options"]["unknown"]["reasoning_effort"] == "ultra"
            assert calls[0][0]["api_key"] == "offline-secret"
            assert calls[0][1] == "ultra"
    asyncio.run(scenario())
