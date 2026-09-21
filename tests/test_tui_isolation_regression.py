"""Shell-default isolation regression (P2): default launch is the shell.

Covers handoff P2 checks: separate default shell vs legacy opt-out startup,
palette contents, cancel, narrow-terminal history, theme switch, clean exit.
"""

from __future__ import annotations

import asyncio

from textual.app import App

from tesis import tui
from tesis.tui_shell import (
    COMMANDS,
    SHELL_MONO_THEME_NAME,
    RunConsoleScreen,
    TesisShellProvider,
    suggest_commands,
)


def test_legacy_instance_excludes_shell_provider_while_shell_keeps_it() -> None:
    assert any(p is TesisShellProvider for p in tui.TesisApp.COMMANDS)
    legacy = tui.TesisApp(new_shell=False)
    shell = tui.TesisApp(new_shell=True)
    assert not any(p is TesisShellProvider for p in legacy.COMMANDS)
    assert any(p is TesisShellProvider for p in shell.COMMANDS)
    assert legacy.COMMANDS == set(App.COMMANDS)
    # Class set untouched: future shell instances still resolve the provider.
    assert any(p is TesisShellProvider for p in tui.TesisApp.COMMANDS)


def test_shell_is_default_flag_and_env(monkeypatch) -> None:
    monkeypatch.delenv("TESIS_NEW_SHELL", raising=False)
    assert tui.TesisApp()._new_shell is True
    assert tui.TesisApp(new_shell=True)._new_shell is True
    assert tui.TesisApp(new_shell=False)._new_shell is False


def test_shell_enabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("TESIS_NEW_SHELL", "1")
    app = tui.TesisApp()
    assert app._new_shell is True
    assert any(p is TesisShellProvider for p in app.COMMANDS)


def test_legacy_opt_out_via_env(monkeypatch) -> None:
    monkeypatch.setenv("TESIS_NEW_SHELL", "0")
    app = tui.TesisApp()
    assert app._new_shell is False
    assert not any(p is TesisShellProvider for p in app.COMMANDS)


def test_mono_theme_registered_without_changing_default() -> None:
    for app in (tui.TesisApp(), tui.TesisApp(new_shell=True)):
        assert SHELL_MONO_THEME_NAME in app.available_themes
        assert app.current_theme.name == "textual-dark"


def test_legacy_starts_on_main_menu_shell_on_console() -> None:
    async def scenario() -> None:
        legacy = tui.TesisApp(new_shell=False)
        async with legacy.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            assert isinstance(legacy.screen, tui.MainMenuScreen)
        shell = tui.TesisApp(new_shell=True)
        async with shell.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            assert isinstance(shell.screen, RunConsoleScreen)

    asyncio.run(scenario())


def test_legacy_palette_gathers_only_builtin_providers() -> None:
    async def scenario() -> None:
        app = tui.TesisApp(new_shell=False)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await pilot.press("ctrl+p")
            await pilot.pause()
            await pilot.pause()
            from textual.command import CommandPalette

            assert isinstance(app.screen, CommandPalette)
            providers = getattr(app.screen, "_providers", None) or []
            assert not any(isinstance(p, TesisShellProvider) for p in providers)
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, tui.MainMenuScreen)

    asyncio.run(scenario())


def test_shell_palette_lists_registry_and_cancels_cleanly() -> None:
    async def scenario() -> None:
        app = tui.TesisApp(new_shell=True)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            await pilot.press("ctrl+p")
            await pilot.pause()
            await pilot.pause()
            from textual.command import CommandPalette

            assert isinstance(app.screen, CommandPalette)
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, RunConsoleScreen)
            # Idle cancel is honest; no controller attached.
            assert "idle" in screen.request_shell_cancel().lower()

    asyncio.run(scenario())


def test_shell_narrow_history_theme_switch_and_clean_exit() -> None:
    async def scenario() -> None:
        app = tui.TesisApp(new_shell=True)
        async with app.run_test(size=(70, 24)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            assert screen.has_class("narrow")
            composer = screen.query_one("#console-composer")
            composer.value = "/run"
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("escape")  # /run delegates to setup screen
            await pilot.pause()
            composer.value = "/plan"
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("escape")  # /plan opens the preview overlay
            await pilot.pause()
            assert screen.composer_history == ["/run", "/plan"]
            await pilot.press("up")
            await pilot.pause()
            assert composer.value == "/plan"
            # Theme switch round-trip keeps the console readable.
            app.theme = SHELL_MONO_THEME_NAME
            await pilot.pause()
            svg = app.export_screenshot()
            assert "TESIS" in svg
            app.theme = "textual-dark"
            await pilot.pause()
        assert not app.is_running
        assert list(app.screen_stack) == []

    asyncio.run(scenario())
    assert len(COMMANDS) > 0
    assert "/run" in suggest_commands("/")
