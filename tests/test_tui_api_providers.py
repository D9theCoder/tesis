"""Focused provider widgets: drafts, catalog selection, keyboard access, and saving."""

import asyncio
from threading import Event

from dotenv import dotenv_values
import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Input, Select, SelectionList, Static, TextArea, OptionList

from tesis import tui_state
from tesis.config_fields import configured_provider_choices
from tesis.config_loader import load_yaml_config, parse_yaml_config, save_yaml_config
from tesis.provider_registry import model_profile_id, provider_key_variable
from tesis.tui_forms import LaunchDrawer, SettingsDrawer
from tesis.tui_providers import CatalogLoaded, ProviderDrawer


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


def test_launch_codex_model_and_reasoning_override_only_experiment_roles(tmp_path, monkeypatch):
    from tesis.tui_reasoning import ReasoningControl

    path = save_yaml_config(tmp_path / "config.yaml", {"target_url": "http://localhost/dvwa", "provider": "codex",
        "models": {"codex": {"provider": "openai_codex_auth", "model_name": "saved",
                              "extra": {"account": "research"}}},
        "reasoning_catalog": {"other": ["low", "high"]},
        "scoring_evaluator": {"provider": "codex", "max_attempts": 2, "max_tokens": 1024, "timeout": 60}})
    monkeypatch.setattr(tui_state, "CONFIG_PATH", path)

    class LaunchApp(App):
        CSS_PATH = "../tesis/tui.tcss"
        def on_mount(self):
            self.push_screen(LaunchDrawer())

    async def scenario():
        async with LaunchApp().run_test() as pilot:
            drawer = pilot.app.screen
            drawer._goto_step(1)
            drawer.query_one("#launch-codex-model", Input).value = "other"
            await pilot.pause()
            control = drawer.query_one("#launch-reasoning-effort", ReasoningControl)
            control.query_one(Select).value = "high"
            await pilot.pause()
            assert control.ensure_ready()
            config = drawer._resolved_config()
            assert all(role.model_name == "other" and role.reasoning_effort == "high"
                       for role in config.llm_runtime.roles.values())
            assert config.scoring_evaluator["model"] == "saved"
            assert load_yaml_config(path)["models"]["codex"]["model_name"] == "saved"
    asyncio.run(scenario())


def _fill(drawer):
    for name, value in {"provider-id": "my_gateway", "provider-url": "https://gateway.invalid/v1",
                        "provider-key": "private-widget-fixture"}.items():
        drawer.query_one(f"#{name}", Input).value = value


async def _wait_catalog(pilot, drawer):
    for _ in range(80):
        await pilot.pause(0.01)
        if not drawer.query_one("#provider-fetch", Button).disabled:
            return
    raise AssertionError("Mock catalog did not finish")


@pytest.mark.parametrize("size", [(120, 40), (80, 24), (60, 18)])
def test_form_fetch_select_ignore_manual_and_keyboard_apply_a_draft(tmp_path, monkeypatch, size):
    calls = []

    def catalog(**kwargs):
        calls.append(kwargs)
        return [{"id": "future-a", "display_name": "Future A"}, {"id": "future-b", "display_name": "Future B"}]

    monkeypatch.setattr("tesis.tui_providers.fetch_models", catalog)

    async def scenario():
        app = ProviderApp(tmp_path / "config.yaml")
        async with app.run_test(size=size) as pilot:
            drawer = app.screen
            _fill(drawer)
            await pilot.pause()
            drawer.fetch_catalog()
            await _wait_catalog(pilot, drawer)
            table = drawer.query_one("#provider-models", DataTable)
            assert table.row_count == 2
            table.focus()
            table.scroll_visible(animate=False)
            await pilot.pause()
            await pilot.press("space")
            assert drawer._selected == {"future-a"}
            drawer.select_shown()
            drawer.query_one("#provider-filter", Input).value = "future-b"
            await pilot.pause()
            drawer.ignore_shown()
            drawer.query_one("#provider-manual", Input).value = "manual/model"
            drawer.add_model()
            await pilot.pause()
            button = drawer.query_one("#provider-apply", Button)
            assert button.region.bottom <= size[1]
            assert button.region.x >= 0
            button.focus()
            await pilot.press("enter")
            await pilot.pause()
            assert app.result.entry["models"] == ["future-a", "manual/model"]
            assert app.result.entry["display_name"] == "my_gateway"
            assert "private-widget-fixture" not in str(app.result.entry)
            assert list(app.result.keys.values()) == ["private-widget-fixture"]
            assert not (tmp_path / ".env").exists()
            assert not (tmp_path / "config.yaml").exists()
    asyncio.run(scenario())
    assert calls[0]["api_key"] == "private-widget-fixture"


def test_launch_selects_distinct_models_from_one_provider_without_protocol_collapse(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    models = [model_profile_id("gateway", model) for model in ("first", "second")]
    save_yaml_config(path, {"target_url": "http://localhost/dvwa", "provider": models[0],
        "api_providers": {"gateway": {"display_name": "My gateway", "base_url": "https://gateway.invalid/v1",
            "protocol": "openai_compatible", "api_key": "${LAUNCH_TEST_KEY}", "models": ["first", "second"]}}})
    monkeypatch.setenv("LAUNCH_TEST_KEY", "offline-launch-key")
    monkeypatch.setattr(tui_state, "CONFIG_PATH", path)

    class LaunchApp(App):
        CSS_PATH = "../tesis/tui.tcss"

        def on_mount(self):
            self.push_screen(LaunchDrawer(mode="matrix"))

    async def scenario():
        app = LaunchApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = app.screen
            drawer.query_one("#launch-field-provider", Select).value = models[1]
            picker = drawer.query_one("#launch-field-providers", SelectionList)
            picker.select_all()
            await pilot.pause()
            resolved = drawer._resolved_config()
            assert resolved.provider == models[1]
            assert set(resolved.providers) == set(models)
            assert {resolved.models[name].model_name for name in resolved.providers} == {"first", "second"}
            assert all(role.model_profile is None for role in resolved.llm_runtime.roles.values())
    asyncio.run(scenario())


def test_edit_keeps_saved_models_missing_from_catalog_and_drops_stale_results(tmp_path, monkeypatch):
    started, release = Event(), Event()
    entry = {"protocol": "openai", "base_url": "https://gateway.invalid/v1", "api_key": "existing-key",
             "models": ["saved-unlisted"]}

    def catalog(**_kwargs):
        started.set()
        release.wait(5)
        return [{"id": "stale-model", "display_name": "Stale"}]

    monkeypatch.setattr("tesis.tui_providers.fetch_models", catalog)

    async def scenario():
        app = ProviderApp(tmp_path / "config.yaml", {"existing": entry}, "existing")
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = app.screen
            assert drawer.query_one("#provider-key", Input).value == ""
            drawer.fetch_catalog()
            for _ in range(40):
                await pilot.pause(0.01)
                if started.is_set():
                    break
            assert started.is_set()
            generation = drawer._generation
            drawer.query_one("#provider-url", Input).value = "https://new.invalid/v1"
            await pilot.pause()
            drawer.catalog_loaded(CatalogLoaded(generation, [{"id": "stale-model", "display_name": "Stale"}], None))
            assert list(drawer._models) == ["saved-unlisted"]
            assert drawer._selected == {"saved-unlisted"}
            drawer.catalog_loaded(CatalogLoaded(drawer._generation, [{"id": "fresh", "display_name": "Fresh"}], None))
            assert list(drawer._models) == ["saved-unlisted", "fresh"]
            assert drawer._selected == {"saved-unlisted"}
            await pilot.press("escape")
            assert drawer._closed
            assert app.result is None
    try:
        asyncio.run(scenario())
    finally:
        release.set()


def test_settings_stages_key_until_save_then_exposes_all_models_in_launch_choices(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("target_url: http://localhost/dvwa\nprovider: gemini\nmodels:\n"
                    "  gemini:\n    provider: gemini\n    model_name: legacy-model\n    api_key: ${LEGACY_TEST_KEY}\n")
    monkeypatch.setattr(tui_state, "CONFIG_PATH", path)
    monkeypatch.setenv("LEGACY_TEST_KEY", "legacy-test-value")
    variable = provider_key_variable("my_gateway")
    monkeypatch.delenv(variable, raising=False)

    class SettingsApp(App):
        CSS_PATH = "../tesis/tui.tcss"

        def on_mount(self):
            self.push_screen(SettingsDrawer())

    async def scenario():
        app = SettingsApp()
        async with app.run_test(size=(80, 24)) as pilot:
            settings = app.screen
            settings.query_one("#settings-categories", OptionList).highlighted = 1
            settings.edit_api_provider(Button.Pressed(settings.query_one("#settings-api-add", Button)))
            await pilot.pause()
            drawer = app.screen
            assert isinstance(drawer, ProviderDrawer)
            _fill(drawer)
            for model in ["first-model", "second-model"]:
                drawer.query_one("#provider-manual", Input).value = model
                drawer.add_model()
            drawer.apply_provider()
            await pilot.pause()
            assert app.screen is settings
            staged = parse_yaml_config(settings.query_one("#yaml-editor", TextArea).text)
            assert staged["api_providers"]["my_gateway"]["api_key"] == f"${{{variable}}}"
            assert not path.with_name(".env").exists()
            settings.save_settings()
            for _ in range(100):
                await pilot.pause(0.01)
                if not settings._saving:
                    break
            assert str(settings.query_one("#settings-status", Static).content) == "Saved config."
            assert dotenv_values(path.with_name(".env"))[variable] == "private-widget-fixture"
            saved = load_yaml_config(path)
            assert "private-widget-fixture" not in path.read_text()
            assert saved["models"]["gemini"]["model_name"] == "legacy-model"
            assert set(configured_provider_choices(saved)) == {"gemini", model_profile_id("my_gateway", "first-model"),
                                                             model_profile_id("my_gateway", "second-model")}
    asyncio.run(scenario())
