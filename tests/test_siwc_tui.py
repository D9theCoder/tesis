"""Focused Settings widget tests with a stubbed OpenAI model catalog."""

import asyncio

import pytest
from textual.app import App
from textual.widgets import Button, Collapsible, Input, Select, Static, TextArea

from llm.siwc.oauth import SIWCSession
from llm.siwc.storage import SIWCError
from tesis import tui_state
from tesis.config_loader import load_yaml_config, parse_yaml_config
from tesis.tui_forms import SettingsDrawer


@pytest.fixture
def settings_config(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("target_url: http://localhost/dvwa\nprovider: openai_compatible\nmodels:\n"
                    "  openai_compatible:\n    provider: openai_compatible\n"
                    "    model_name: existing-model\n    api_key: ${ORIGINAL_KEY}\n"
                    "    base_url: https://example.invalid/v1\n", encoding="utf-8")
    monkeypatch.setattr(tui_state, "CONFIG_PATH", path)
    monkeypatch.setenv("ORIGINAL_KEY", "offline-fixture-key")
    return path


class SettingsApp(App):
    CSS_PATH = "../tesis/tui.tcss"

    def on_mount(self):
        self.push_screen(SettingsDrawer())


async def _wait_catalog(pilot, drawer):
    for _ in range(100):
        await pilot.pause(0.02)
        text = str(drawer.query_one("#settings-chatgpt-status", Static).content)
        if not text.startswith("Loading"):
            return
    raise AssertionError("The mocked model catalog did not complete")


@pytest.mark.parametrize("size", [(80, 24), (60, 18)])
def test_catalog_selection_updates_only_selected_profile_and_saves(settings_config, monkeypatch, size):
    calls = []

    def catalog(_self, account):
        calls.append(account)
        return [{"slug": "brand-new-model-z", "display_name": "Brand new Z"},
                {"slug": "brand-new-model-a", "display_name": "Brand new A"}]

    monkeypatch.setattr(SIWCSession, "list_models", catalog)

    async def scenario():
        app = SettingsApp()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            drawer = app.screen
            drawer.query_one("#settings-section-model", Collapsible).collapsed = False
            drawer.query_one("#settings-chatgpt-account", Input).value = "research"
            await pilot.pause()
            drawer.refresh_chatgpt_models()
            await _wait_catalog(pilot, drawer)
            picker = drawer.query_one("#settings-chatgpt-model", Select)
            assert not picker.disabled
            apply_button = drawer.query_one("#settings-chatgpt-apply", Button)
            apply_button.focus()
            apply_button.scroll_visible(animate=False)
            await pilot.pause()
            assert apply_button.region.overlaps(app.screen.region)
            picker.value = "brand-new-model-a"
            await pilot.pause()
            drawer.apply_chatgpt_model()
            edited = parse_yaml_config(drawer.query_one("#yaml-editor", TextArea).text)
            assert edited["models"]["openai_codex_auth"]["model_name"] == "brand-new-model-a"
            assert edited["models"]["openai_codex_auth"]["extra"]["account"] == "research"
            assert edited["provider"] == "openai_compatible"
            assert edited["models"]["openai_compatible"]["model_name"] == "existing-model"
            assert "openai_codex_auth" not in load_yaml_config(settings_config)["models"]
            save_button = drawer.query_one("#settings-save", Button)
            save_button.focus()
            save_button.scroll_visible(animate=False)
            await pilot.pause()
            assert save_button.region.overlaps(app.screen.region)
            drawer.save_settings()
            for _ in range(100):
                await pilot.pause(0.01)
                if not drawer._saving:
                    break
            saved = load_yaml_config(settings_config)
            assert saved["models"]["openai_codex_auth"]["model_name"] == "brand-new-model-a"
            assert saved["models"]["openai_compatible"]["api_key"] == "${ORIGINAL_KEY}"
            await pilot.press("escape")
            await pilot.pause()
    asyncio.run(scenario())
    assert calls == ["research"]


@pytest.mark.parametrize("catalog", [[], SIWCError("SIWC is signed out; run auth login")])
def test_empty_or_failed_catalog_does_not_offer_stale_models(settings_config, monkeypatch, catalog):
    def load(_self, _account):
        if isinstance(catalog, Exception):
            raise catalog
        return catalog
    monkeypatch.setattr(SIWCSession, "list_models", load)

    async def scenario():
        app = SettingsApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            drawer = app.screen
            drawer.refresh_chatgpt_models()
            await _wait_catalog(pilot, drawer)
            assert drawer.query_one("#settings-chatgpt-model", Select).disabled
            assert drawer.query_one("#settings-chatgpt-apply", Button).disabled
            text = str(drawer.query_one("#settings-chatgpt-status", Static).content)
            assert "signed out" in text if isinstance(catalog, Exception) else "no visible models" in text
            await pilot.press("escape")
            await pilot.pause()
    asyncio.run(scenario())


def test_changing_account_discards_old_catalog_and_late_worker_results(settings_config):
    async def scenario():
        app = SettingsApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            drawer = app.screen
            generation = drawer._model_generation
            drawer._chatgpt_models_ready(generation, "openai_codex_auth", "default",
                                        [{"slug": "old-account-only", "display_name": "Old account model"}], None)
            drawer.query_one("#settings-chatgpt-account", Input).value = "different"
            await pilot.pause()
            drawer._chatgpt_models_ready(generation, "openai_codex_auth", "default",
                                        [{"slug": "late-result", "display_name": "Stale"}], None)
            assert drawer.query_one("#settings-chatgpt-model", Select).disabled
            assert drawer._catalog_binding is None
            await pilot.press("escape")
            await pilot.pause()
    asyncio.run(scenario())
