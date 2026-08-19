"""Keyboard and screen smoke tests for the Textual application."""

from __future__ import annotations

import asyncio

from tesis import tui
from tesis.model_config import EngagementConfig, ModelConfig
from tesis.runtime_events import RunEvent


def test_main_menu_keyboard_navigation_opens_single_setup():
    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, tui.MainMenuScreen)
            assert app.screen.query_one("#main-menu").option_count == 7
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, tui.RunSetupScreen)
            assert not app.screen.matrix
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, tui.MainMenuScreen)

    asyncio.run(scenario())


def test_matrix_screen_calculates_total_and_uses_compact_layout():
    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(90, 44)) as pilot:
            await pilot.pause()
            await pilot.press("down", "enter")
            await pilot.pause()
            assert isinstance(app.screen, tui.RunSetupScreen)
            assert app.screen.matrix
            assert "18 runs" in str(app.screen.query_one("#run-total").render())
            assert app.screen.has_class("compact")

    asyncio.run(scenario())


def test_run_setup_round_trips_llm_runtime_controls(monkeypatch):
    config = EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="openai_compatible",
        level="low",
        models={
            "openai_compatible": ModelConfig(
                "openai_compatible", "", "baseline-model"
            ),
        },
    )
    config.llm_runtime = {
        "max_concurrency": 2,
        "cache_scope": "run",
        "roles": {
            "orchestrator": {"model_profile": "orchestrator-profile", "model_name": "orch-model"},
            "payload_generator": {"model_profile": "payload-profile", "model_name": "payload-model"},
        },
    }
    monkeypatch.setattr(tui, "load_and_resolve_config", lambda **_kwargs: config)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 44)) as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            setup = app.screen
            assert isinstance(setup, tui.RunSetupScreen)
            assert setup.query_one("#llm-max-concurrency").value == "2"
            assert setup.query_one("#llm-cache-scope").value == "run"
            assert "orchestrator-profile/orch-model" in str(
                setup.query_one("#setup-summary").render()
            )

            setup.query_one("#llm-max-concurrency").value = "1"
            setup.query_one("#llm-cache-scope").value = "none"
            setup.query_one("#orchestrator-model-profile").value = "new-orch-profile"
            setup.query_one("#orchestrator-model").value = "new-orch-model"
            resolved = setup.resolved_config()
            assert resolved.llm_runtime["max_concurrency"] == 1
            assert resolved.llm_runtime["cache_scope"] == "none"
            assert resolved.llm_runtime["roles"]["orchestrator"]["model_profile"] == "new-orch-profile"
            assert resolved.llm_runtime["roles"]["orchestrator"]["model_name"] == "new-orch-model"

    asyncio.run(scenario())


def test_settings_saves_llm_runtime_controls(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        "models:\n  gemini:\n    model_name: baseline-model\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(tui, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 44)) as pilot:
            await pilot.pause()
            await pilot.press("down", "down", "enter")
            await pilot.pause()
            settings = app.screen
            assert isinstance(settings, tui.SettingsScreen)
            settings.query_one("#settings-llm-max-concurrency").value = "2"
            settings.query_one("#settings-llm-cache-scope").value = "run"
            settings.query_one("#settings-orchestrator-model-profile").value = "orch-profile"
            settings.query_one("#settings-orchestrator-model").value = "orch-model"
            settings.query_one("#settings-payload-model-profile").value = "payload-profile"
            settings.query_one("#settings-payload-model").value = "payload-model"
            settings.query_one("#settings-save").press()
            await pilot.pause()
            saved = config_path.read_text(encoding="utf-8")
            assert "max_concurrency: 2" in saved
            assert "cache_scope: run" in saved
            assert "model_profile: orch-profile" in saved
            assert "model_name: payload-model" in saved

    asyncio.run(scenario())


def test_settings_loads_round_trip_yaml_editor(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "# keep me\ntarget_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\nfuture_key: yes\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(tui, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause()
            await pilot.press("down", "down", "enter")
            await pilot.pause()
            assert isinstance(app.screen, tui.SettingsScreen)
            raw = app.screen.query_one("#yaml-editor").text
            assert "# keep me" in raw
            assert "future_key" in raw

    asyncio.run(scenario())


def test_settings_rejects_invalid_yaml_without_overwriting(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    original = "# keep\ntarget_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
    config_path.write_text(original, encoding="utf-8")
    monkeypatch.setattr(tui, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause()
            await pilot.press("down", "down", "enter")
            await pilot.pause()
            app.screen.query_one("#yaml-editor").text = "key: [unterminated"
            app.screen.query_one("#settings-save").press()
            await pilot.pause()
            assert config_path.read_text(encoding="utf-8") == original
            assert "Not saved" in str(app.screen.query_one("#settings-status").render())

    asyncio.run(scenario())


def test_settings_masks_literal_secret_in_raw_editor(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        "models:\n  gemini:\n    model_name: test-model\n    api_key: literal-secret-value\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(tui, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause()
            await pilot.press("down", "down", "enter")
            await pilot.pause()
            raw = app.screen.query_one("#yaml-editor").text
            assert "literal-secret-value" not in raw
            assert "__TESIS_PRESERVE_SECRET_" in raw
            assert app.screen.query_one("#settings-api-key").value == ""

    asyncio.run(scenario())


def test_dashboard_stream_and_tab_trace_toggle(monkeypatch):
    monkeypatch.setattr(tui.RuntimeDashboardScreen, "run_experiment", lambda self: None)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            setup = app.screen
            setup.query_one("#start-run").press()
            await pilot.pause()
            await pilot.pause()
            assert isinstance(app.screen, tui.RuntimeDashboardScreen)
            app.screen.post_message(tui.DashboardEvent(
                RunEvent(event_type="llm.token", message="hello", data={"streaming": True})
            ))
            await pilot.pause()
            assert app.screen.query_one("#trace-log").has_class("hidden")
            await pilot.press("tab")
            await pilot.pause()
            assert not app.screen.query_one("#trace-log").has_class("hidden")
            assert app.screen.query_one("#stream-log").has_class("hidden")

    asyncio.run(scenario())
