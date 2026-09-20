"""Behavior coverage for the opt-in run-console shell (Phase 0 + shell Phase 1).

Legacy UI in ``tesis.tui`` is covered by ``tests/test_tui.py``; these tests
own only the new shell: registry/intent/view-model units plus headless
``run_test``/``Pilot`` coverage of the console screen at wide, standard,
80x24, and <80 sizes.
"""

from __future__ import annotations

import asyncio

from tesis import tui
from tesis.model_config import EngagementConfig
from tesis.runtime_events import RunEvent
from tesis.tui_shell import (
    COMMANDS,
    ActivityEntry,
    ActivityTranscriptModel,
    ContextHeaderModel,
    CoordinateFilter,
    CoordinateOverlayScreen,
    CoordinateRow,
    FailureInspectorScreen,
    OperatorIntent,
    PlanPreviewScreen,
    RunConsoleScreen,
    ShellHelpScreen,
    StatusLineModel,
    build_plan_preview,
    dispatch_intent,
    expand_coordinates,
    filter_coordinates,
    find_command,
    format_failure_lines,
    help_lines,
    parse_composer_text,
    present_event,
    suggest_commands,
    summarize_coordinates,
)

REQUIRED_VOCABULARY = (
    "run", "matrix", "plan", "cancel", "coordinates", "failure", "details",
    "doctor", "results", "resume", "retry", "model", "settings", "export",
    "info", "help", "quit",
)


def test_command_registry_covers_required_shell_vocabulary() -> None:
    names = [c.name for c in COMMANDS]
    assert names == list(REQUIRED_VOCABULARY)
    assert all(c.title and c.summary for c in COMMANDS)


def test_resume_retry_disabled_with_explanation() -> None:
    for name in ("resume", "retry"):
        spec = find_command(name)
        assert spec is not None
        assert not spec.enabled
        assert spec.disabled_reason


def test_parse_composer_text_routes_slash_commands_to_typed_intents() -> None:
    assert parse_composer_text("/run") == OperatorIntent(name="run")
    assert parse_composer_text("  /matrix  ") == OperatorIntent(name="matrix")
    assert parse_composer_text("/doctor") == OperatorIntent(name="doctor")
    assert parse_composer_text("/plan") == OperatorIntent(name="plan")
    assert parse_composer_text("/resume") == OperatorIntent(name="resume")
    assert parse_composer_text("hello") is None
    assert parse_composer_text("/") is None
    assert parse_composer_text("/nope") is None


def test_slash_completion_derives_from_registry() -> None:
    assert suggest_commands("/") == [f"/{c.name}" for c in COMMANDS]
    assert "/run" in suggest_commands("/r")
    assert "/results" in suggest_commands("/r")
    assert "/resume" in suggest_commands("/r")
    assert "/retry" in suggest_commands("/r")
    assert suggest_commands("run") == []
    assert find_command("/settings") is not None


def test_help_derives_from_registry() -> None:
    body = "\n".join(help_lines())
    for spec in COMMANDS:
        assert f"/{spec.name}" in body
        assert spec.summary in body


def test_transcript_model_is_bounded() -> None:
    model = ActivityTranscriptModel(max_entries=3)
    for i in range(5):
        model.append(ActivityEntry(f"e{i}", f"summary {i}", status="completed"))
    assert len(model) == 3
    assert model.rows() == ["✓ summary 2", "✓ summary 3", "✓ summary 4"]


def test_header_and_status_models_render_without_runner_state() -> None:
    assert "TESIS" in ContextHeaderModel().render()
    assert "IDLE" in ContextHeaderModel().render()
    assert StatusLineModel().render()


def test_presenter_suppresses_tokens_and_state() -> None:
    assert present_event(RunEvent(event_type="llm.token", message="tok")) == []
    assert present_event(RunEvent(event_type="graph.state", message="snap")) == []


def test_presenter_maps_status_and_redacts_secrets() -> None:
    entries = present_event(RunEvent(
        event_type="llm.failed",
        message="Model call failed",
        data={"provider": "openai", "api_key": "sk-live-secret",
              "failure_class": "http_rejected"},
    ))
    assert len(entries) == 1
    entry = entries[0]
    assert entry.status == "failed"
    assert entry.failure_class == "http_rejected"
    assert entry.default_expanded
    assert "sk-live-secret" not in " ".join(entry.detail_rows)


def test_presenter_never_exposes_prompt_bodies() -> None:
    entries = present_event(RunEvent(
        event_type="llm.completed",
        message="done",
        data={"prompt_hash": "abc", "response": "full body leaks here"},
    ))
    assert entries
    assert "full body leaks here" not in " ".join(entries[0].detail_rows)


def test_presenter_is_deterministic_for_same_input() -> None:
    event = RunEvent(event_type="graph.node.completed", node="recon",
                     message="recon completed")
    first = present_event(event)[0]
    second = present_event(event)[0]
    assert (first.status, first.summary, first.detail_rows) == (
        second.status, second.summary, second.detail_rows)


def test_expand_coordinates_single_and_matrix() -> None:
    single = EngagementConfig(target_url="http://x/", provider="openai", level="low")
    assert len(expand_coordinates(single)) == 1
    matrix = EngagementConfig(
        target_url="http://x/", provider="openai", level="low", matrix=True,
        providers=["openai"], levels=["low"], surfaces=["sqli"],
        payload_modes=["hybrid"], repeats=2,
    )
    rows = expand_coordinates(matrix)
    assert len(rows) == 2
    assert rows[0].coordinate_id != rows[1].coordinate_id


def test_coordinate_filters_and_honest_aggregates() -> None:
    rows = [
        CoordinateRow("a", provider="openai", status="completed"),
        CoordinateRow("b", provider="gemini", status="failed"),
    ]
    shown = filter_coordinates(rows, CoordinateFilter(provider="openai"))
    assert [r.coordinate_id for r in shown] == ["a"]
    summary = summarize_coordinates(rows)
    assert summary["total"] == 2
    assert summary["tokens"] == "N/A"
    assert summary["cost"] == "N/A"


def test_failure_lines_lead_with_remediation_and_redact() -> None:
    lines = format_failure_lines({
        "failure_class": "http_rejected",
        "provider": "openai",
        "endpoint": "https://user:pass@example.com/v1/?k=v",
        "api_key": "sk-live-secret",
        "remediation": "Check the credential.",
    })
    assert lines[0].startswith("remediation:")
    assert "pass@" not in " ".join(lines)
    assert "sk-live-secret" not in " ".join(lines)


def test_plan_preview_resolves_matrix_values() -> None:
    cfg = EngagementConfig(
        target_url="http://x/", provider="openai", level="low", matrix=True,
        providers=["openai"], levels=["low"], surfaces=["sqli"],
        payload_modes=["hybrid"], repeats=1,
    )
    body = "\n".join(build_plan_preview(cfg))
    assert "1 coordinates" in body
    assert "openai" in body
    assert "Config fingerprint:" in body


def _shell_app(**kwargs):
    return tui.TesisApp(new_shell=True, **kwargs)


def test_new_shell_is_opt_in_and_legacy_stays_default() -> None:
    assert tui.TesisApp()._new_shell is False

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, tui.MainMenuScreen)

    asyncio.run(scenario())


def test_console_mounts_with_empty_transcript_and_focused_composer() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            assert len(screen.transcript_model) == 0
            assert "No activity" in str(screen.query_one("#console-empty").render())
            assert screen.query_one("#console-composer").has_focus
            assert "TESIS" in str(screen.query_one("#console-header").render())

    asyncio.run(scenario())


def test_console_slash_command_dispatches_to_existing_screens() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            assert dispatch_intent(screen, OperatorIntent(name="run")) == (
                "Opened single-run setup"
            )
            await pilot.pause()
            assert isinstance(app.screen, tui.RunSetupScreen)
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_console_matrix_doctor_results_settings_help_routes() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            assert "matrix" in dispatch_intent(screen, OperatorIntent(name="matrix"))
            await pilot.pause()
            assert isinstance(app.screen, tui.RunSetupScreen)
            assert app.screen.matrix
            await pilot.press("escape")
            await pilot.pause()
            assert "validation" in dispatch_intent(
                screen, OperatorIntent(name="doctor")
            ).lower()
            await pilot.pause()
            assert isinstance(app.screen, tui.ValidationScreen)
            await pilot.press("escape")
            await pilot.pause()
            dispatch_intent(screen, OperatorIntent(name="results"))
            await pilot.pause()
            assert isinstance(app.screen, tui.RecentResultsScreen)
            await pilot.press("escape")
            await pilot.pause()
            dispatch_intent(screen, OperatorIntent(name="settings"))
            await pilot.pause()
            assert isinstance(app.screen, tui.SettingsScreen)
            await pilot.press("escape")
            await pilot.pause()
            dispatch_intent(screen, OperatorIntent(name="help"))
            await pilot.pause()
            assert isinstance(app.screen, ShellHelpScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, RunConsoleScreen)

    asyncio.run(scenario())


def test_console_new_delegates_open_overlays() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            dispatch_intent(screen, OperatorIntent(name="plan"))
            await pilot.pause()
            assert isinstance(app.screen, PlanPreviewScreen)
            await pilot.press("escape")
            await pilot.pause()
            dispatch_intent(screen, OperatorIntent(name="failure"))
            await pilot.pause()
            assert isinstance(app.screen, FailureInspectorScreen)
            await pilot.press("escape")
            await pilot.pause()
            dispatch_intent(screen, OperatorIntent(name="model"))
            await pilot.pause()
            assert isinstance(app.screen, tui.SettingsScreen)
            await pilot.press("escape")
            await pilot.pause()
            dispatch_intent(screen, OperatorIntent(name="coordinates"))
            await pilot.pause()
            assert isinstance(app.screen, CoordinateOverlayScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert dispatch_intent(screen, OperatorIntent(name="resume")).startswith("Resume is disabled")
            assert dispatch_intent(screen, OperatorIntent(name="retry")).startswith("Retry is disabled")
            assert "idle" in dispatch_intent(screen, OperatorIntent(name="cancel")).lower()
            assert "expanded" in dispatch_intent(screen, OperatorIntent(name="details")).lower()
            assert "collapsed" in dispatch_intent(screen, OperatorIntent(name="details")).lower()

    asyncio.run(scenario())


def test_console_ingests_presented_events_into_transcript() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            screen.push_transcript_event(RunEvent(event_type="llm.token", message="tok"))
            assert len(screen.transcript_model) == 0
            screen.push_transcript_event(RunEvent(
                event_type="llm.completed", node="orchestrator",
                message="selected sqli_union",
                data={"provider": "openai", "api_key": "sk-secret"},
            ))
            assert len(screen.transcript_model) == 1
            entry = screen.transcript_model._entries[0]
            assert entry.status == "completed"
            assert "sk-secret" not in entry.summary

    asyncio.run(scenario())


def test_console_composer_submit_routes_and_unknown_command_hints_help() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            composer = screen.query_one("#console-composer")
            composer.value = "/nope"
            await pilot.press("enter")
            await pilot.pause()
            assert "/help" in str(screen.query_one("#console-status").render())
            composer.value = "/results"
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, tui.RecentResultsScreen)
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_console_help_opens_on_question_mark_with_empty_composer() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            # Printable keys go to the focused composer, so blur it first;
            # the binding then fires with an empty composer.
            screen.set_focus(None)
            await pilot.pause()
            await pilot.press("?")
            await pilot.pause()
            assert isinstance(app.screen, ShellHelpScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, RunConsoleScreen)

    asyncio.run(scenario())


def test_console_command_palette_opens_and_lists_registry_commands() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, RunConsoleScreen)
            await pilot.press("ctrl+p")
            await pilot.pause()
            await pilot.pause()
            from textual.command import CommandPalette

            assert isinstance(app.screen, CommandPalette)
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, RunConsoleScreen)

    asyncio.run(scenario())


def test_console_keyboard_shortcuts_for_details_coords_failure() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            await pilot.press("ctrl+o")
            await pilot.pause()
            assert screen.details_expanded
            await pilot.press("ctrl+t")
            await pilot.pause()
            assert isinstance(app.screen, CoordinateOverlayScreen)
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("ctrl+f")
            await pilot.pause()
            assert isinstance(app.screen, FailureInspectorScreen)
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_console_layout_modes_are_exclusive() -> None:
    for width, mode in [(160, "wide"), (100, "standard"), (80, "standard"), (70, "narrow")]:
        async def scenario() -> None:
            app = _shell_app()
            async with app.run_test(size=(width, 30)) as pilot:
                await pilot.pause()
                screen = app.screen
                assert isinstance(screen, RunConsoleScreen)
                assert screen.has_class(mode)
                others = {"wide", "standard", "narrow"} - {mode}
                assert not any(screen.has_class(other) for other in others)
                composer = screen.query_one("#console-composer")
                assert composer.display
                assert screen.query_one("#console-status").display
                composer.value = "/help"
                await pilot.press("enter")
                await pilot.pause()
                assert isinstance(app.screen, ShellHelpScreen)
                await pilot.press("escape")
                await pilot.pause()

        asyncio.run(scenario())


def test_console_quit_intent_exits() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            dispatch_intent(screen, OperatorIntent(name="quit"))
            await pilot.pause()
            assert not app.is_running

    asyncio.run(scenario())

def test_console_info_dispatches_to_framework_screen() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            assert dispatch_intent(screen, OperatorIntent(name="info")) == (
                "Opened framework information"
            )
            await pilot.pause()
            assert isinstance(app.screen, tui.FrameworkInfoScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, RunConsoleScreen)

    asyncio.run(scenario())


def test_palette_provider_lists_shared_registry() -> None:
    import asyncio as _asyncio

    from textual.command import DiscoveryHit

    from tesis.tui_shell import TesisShellProvider

    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            provider = TesisShellProvider(screen)
            count = 0
            async for hit in provider.discover():
                assert isinstance(hit, DiscoveryHit)
                count += 1
            # discover() must yield one hit per registry entry, same intents
            # as slash commands (count + spot-check via search).
            count = 0
            async for _ in provider.discover():
                count += 1
            assert count == len(COMMANDS)
            found: list[str] = []
            async for hit in provider.search("info"):
                found.append(hit.match_display or "")
            assert any("framework information" in str(d).lower() for d in found)

    _asyncio.run(scenario())


def test_cancel_forwards_to_stacked_legacy_controller() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            # Idle first: honest message, no controller attached.
            assert "idle" in screen.request_shell_cancel().lower()
            app.push_screen(tui.SettingsScreen())
            await pilot.pause()
            legacy = app.screen
            # Swap the pushed screen's cancel with the fake controller hook
            # by stacking a stub object exposing request_cancel.
            calls: list[str] = []
            legacy.request_cancel = lambda: calls.append("cancel")  # type: ignore[attr-defined]
            app.push_screen(screen)
            await pilot.pause()
            # screen is re-pushed; find it and request cancel.
            top = app.screen
            assert top is screen or isinstance(top, RunConsoleScreen)
            msg = top.request_shell_cancel()
            assert "cancellation requested" in msg.lower()
            assert calls == ["cancel"]
            # dispatch_intent /cancel routes through the same forwarder.
            calls.clear()
            out = dispatch_intent(top, OperatorIntent(name="cancel"))
            assert "cancellation requested" in out.lower()
            assert calls == ["cancel"]
    asyncio.run(scenario())


def test_dispatch_cancel_falls_back_to_legacy_request_cancel() -> None:
    from types import SimpleNamespace

    seen: list[str] = []
    legacy = SimpleNamespace(request_cancel=lambda: seen.append("cancel"))
    out = dispatch_intent(legacy, OperatorIntent(name="cancel"))  # type: ignore[arg-type]
    assert "cancellation requested" in out.lower()
    assert seen == ["cancel"]


def test_mono_theme_is_readable_hex_contrast() -> None:
    from tesis.tui_shell import SHELL_MONO_THEME, SHELL_MONO_THEME_NAME

    assert SHELL_MONO_THEME_NAME == "tesis-mono"
    for attr in ("primary", "foreground", "accent"):
        assert getattr(SHELL_MONO_THEME, attr).upper() == "#FFFFFF"
    for attr in ("background", "surface"):
        assert getattr(SHELL_MONO_THEME, attr).upper() == "#000000"
    assert "ansi" not in str(SHELL_MONO_THEME.background).lower()
    assert "ansi" not in str(SHELL_MONO_THEME.foreground).lower()


def test_shell_renders_under_mono_theme() -> None:
    from tesis.tui_shell import SHELL_MONO_THEME

    async def scenario() -> None:
        app = _shell_app()
        app.register_theme(SHELL_MONO_THEME)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.theme = SHELL_MONO_THEME.name
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            assert "TESIS" in screen.header_model.render()
            svg = app.export_screenshot()
            assert "TESIS" in svg
            assert "#FFFFFF" in svg or "#ffffff" in svg.lower()

    asyncio.run(scenario())

def test_mono_theme_registered_without_changing_default() -> None:
    from tesis.tui_shell import SHELL_MONO_THEME_NAME

    app = tui.TesisApp()
    assert SHELL_MONO_THEME_NAME in app.available_themes
    assert app.current_theme.name == "textual-dark"
    assert app.get_theme(SHELL_MONO_THEME_NAME) is not None


def test_composer_history_previous_next_restores_draft() -> None:
    async def scenario() -> None:
        app = _shell_app()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, RunConsoleScreen)
            composer = screen.query_one("#console-composer")
            assert screen.composer_history == []
            composer.value = "/run"
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("escape")  # /run delegates to the setup screen
            await pilot.pause()
            composer.value = "/plan"
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("escape")  # /plan opens the preview overlay
            await pilot.pause()
            assert screen.composer_history == ["/run", "/plan"]
            # Up walks back: newest first.
            await pilot.press("up")
            await pilot.pause()
            assert composer.value == "/plan"
            await pilot.press("up")
            await pilot.pause()
            assert composer.value == "/run"
            # Newest draft remembered when leaving it.
            composer.value = "/run-edited"
            await pilot.press("down")
            await pilot.pause()
            assert composer.value == "/plan"
            await pilot.press("down")
            await pilot.pause()
            assert composer.value == ""
            # Down at the end restores the in-progress draft.
            composer.value = "/draft"
            await pilot.press("up")
            await pilot.pause()
            assert composer.value == "/plan"
            await pilot.press("down")
            await pilot.pause()
            assert composer.value == "/draft"
            # Slash completion still offers registry entries on a fresh draft.
            composer.value = "/"
            await pilot.pause()
            assert "/run" in suggest_commands(composer.value)

    asyncio.run(scenario())
