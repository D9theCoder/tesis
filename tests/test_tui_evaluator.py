"""Isolated Settings widgets for the independent evaluator selection."""

import asyncio
from pathlib import Path

import pytest
from textual.app import App
from textual.widgets import Button, Input, Select, Static, TextArea, OptionList

from tesis import tui_state
from tesis.config_loader import dump_yaml_config, load_and_resolve_config, load_yaml_config, parse_yaml_config, save_yaml_config
from tesis.provider_registry import model_profile_id
from tesis.tui_forms import SettingsDrawer


EVIDENCE = Path("results/validation/evaluator-settings")


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


@pytest.mark.parametrize("size", [(120, 40), (80, 24), (60, 18)])
def test_evaluator_selection_is_staged_saved_and_keyboard_reachable(evaluator_config, size):
    original = evaluator_config.read_bytes()

    async def scenario():
        app = SettingsApp()
        async with app.run_test(size=size) as pilot:
            drawer = app.screen
            drawer.query_one("#settings-categories", OptionList).highlighted = 4
            await pilot.pause()
            picker = drawer.query_one("#settings-evaluator-provider", Select)
            assert picker.value == model_profile_id("gateway", "first")
            picker.value = model_profile_id("responses", "second")
            drawer.query_one("#settings-evaluator-tokens", Input).value = "2048"
            drawer.query_one("#settings-evaluator-timeout", Input).value = "45"
            await pilot.pause()
            details = str(drawer.query_one("#settings-evaluator-details", Static).content)
            assert "OpenAI Responses" in details and "https://responses.invalid/v1" in details
            assert "offline-evaluator-secret" not in details
            apply = drawer.query_one("#settings-evaluator-apply", Button)
            apply.focus()
            apply.scroll_visible(animate=False)
            await pilot.pause()
            assert apply.region.overlaps(app.screen.region)
            EVIDENCE.mkdir(parents=True, exist_ok=True)
            (EVIDENCE / f"settings-{size[0]}x{size[1]}.svg").write_text(app.export_screenshot())
            await pilot.press("enter")
            await pilot.pause()
            staged = parse_yaml_config(drawer.query_one("#yaml-editor", TextArea).text)
            assert staged["provider"] == model_profile_id("gateway", "first")
            assert staged["scoring_evaluator"] == {
                "provider": model_profile_id("responses", "second"),
                "max_attempts": 2, "max_tokens": 2048, "timeout": 45}
            assert evaluator_config.read_bytes() == original
            save = drawer.query_one("#settings-save", Button)
            save.focus()
            save.scroll_visible(animate=False)
            await pilot.pause()
            await pilot.press("enter")
            await wait_saved(pilot, drawer)
            config = load_and_resolve_config(config_path=str(evaluator_config), cli_args={})
            assert config.scoring_evaluator["provider"] == model_profile_id("responses", "second")
            assert config.scoring_evaluator["adapter"] == "openai"
            assert config.scoring_evaluator["model"] == "second"
            assert config.scoring_evaluator["use_responses_api"] is True
            assert config.scoring_evaluator["base_url"] == "https://responses.invalid/v1"
            assert "offline-evaluator-secret" not in evaluator_config.read_text()
            await pilot.press("escape")
            assert not isinstance(app.screen, SettingsDrawer)
    asyncio.run(scenario())


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
            assert drawer.query_one("#settings-evaluator-provider", Select).value is Select.NULL
            drawer.apply_evaluator()
            assert "Choose a saved provider" in str(drawer.query_one("#settings-evaluator-status", Static).content)
            await pilot.press("escape")
            assert evaluator_config.read_bytes() == original
    asyncio.run(scenario())


def test_empty_evaluator_choices_do_not_guess_a_model(tmp_path, monkeypatch):
    path = save_yaml_config(tmp_path / "config.yaml", {"target_url": "http://localhost/dvwa", "provider": "gemini"})
    monkeypatch.setattr(tui_state, "CONFIG_PATH", path)

    async def scenario():
        app = SettingsApp()
        async with app.run_test(size=(60, 18)) as pilot:
            drawer = app.screen
            assert drawer.query_one("#settings-evaluator-provider", Select).disabled
            drawer.query_one("#settings-scoring-mode", Select).value = "ai"
            drawer.apply_evaluator()
            assert "Choose a saved provider" in str(drawer.query_one("#settings-evaluator-status", Static).content)
            assert "scoring_evaluator" not in load_yaml_config(path)
    asyncio.run(scenario())


@pytest.mark.parametrize("size", [(80, 24), (60, 18)])
def test_codex_manual_model_can_be_used_by_evaluator_independently_and_rail_stays_selected(tmp_path, monkeypatch, size):
    from tesis.tui_reasoning import ReasoningControl

    path = save_yaml_config(tmp_path / "config.yaml", {
        "target_url": "http://localhost/dvwa", "provider": "codex",
        "models": {"codex": {"provider": "openai_codex_auth", "model_name": "saved-model",
                              "extra": {"account": "research"}}},
        "reasoning_catalog": {"manual-model": ["low", "high"], "evaluator-model": ["low", "high"]},
    })
    monkeypatch.setattr(tui_state, "CONFIG_PATH", path)

    async def scenario():
        app = SettingsApp()
        async with app.run_test(size=size) as pilot:
            drawer = app.screen
            rail = drawer.query_one("#settings-categories", OptionList)
            rail.highlighted = 2
            await pilot.pause()
            assert drawer.query_one("#settings-chatgpt-model", Select).value == "saved-model"
            drawer.query_one("#settings-chatgpt-manual", Input).value = "manual-model"
            await pilot.pause()
            control = drawer.query_one("#settings-chatgpt-reasoning", ReasoningControl)
            control.query_one(Select).value = "high"
            await pilot.pause()
            drawer.apply_chatgpt_model()
            draft = parse_yaml_config(drawer.query_one("#yaml-editor", TextArea).text)
            assert draft["models"]["codex"]["model_name"] == "manual-model"
            assert draft["models"]["codex"]["reasoning_effort"] == "high"
            rail.highlighted = 4
            await pilot.pause(0.3)
            drawer.query_one("#settings-evaluator-provider", Select).value = "codex"
            drawer.query_one("#settings-evaluator-model", Input).value = "evaluator-model"
            await pilot.pause()
            effort = drawer.query_one("#settings-evaluator-reasoning", ReasoningControl)
            effort.query_one(Select).value = "low"
            drawer.query_one("#settings-scoring-mode", Select).value = "ai"
            timeout = drawer.query_one("#settings-evaluator-timeout", Input)
            timeout.focus()
            timeout.scroll_visible(animate=False)
            await pilot.pause()
            assert app.focused is timeout
            assert rail.highlighted == 4 and not rail.has_focus
            assert rail.get_visual_style("option-list--option-highlighted").rich_style.bold
            drawer.apply_evaluator()
            draft = parse_yaml_config(drawer.query_one("#yaml-editor", TextArea).text)
            evaluator_id = draft["scoring_evaluator"]["provider"]
            assert evaluator_id != "codex"
            assert draft["models"][evaluator_id]["model_name"] == "evaluator-model"
            assert draft["scoring_evaluator"]["reasoning_effort"] == "low"
            assert draft["models"]["codex"]["model_name"] == "manual-model"
            assert draft["provider"] == "codex"
            EVIDENCE.mkdir(parents=True, exist_ok=True)
            (EVIDENCE / f"codex-reasoning-{size[0]}x{size[1]}.svg").write_text(app.export_screenshot())
            drawer.save_settings()
            await wait_saved(pilot, drawer)
            resolved = load_and_resolve_config(config_path=str(path), cli_args={})
            assert resolved.models["codex"].model_name == "manual-model"
            assert resolved.scoring_evaluator["model"] == "evaluator-model"
            assert resolved.scoring_evaluator["account"] == "research"
    asyncio.run(scenario())
