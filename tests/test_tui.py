"""Keyboard and screen smoke tests for the Textual application."""

from __future__ import annotations

import asyncio

from tesis import tui
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
