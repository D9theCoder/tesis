"""Mission-control behavioral contracts.

Handoff: docs/active/HANDOFF_TUI_MISSION_CONTROL_REDESIGN_2026-09-21.md.
Only observable behavior is asserted. Visual/PTY verification (themes,
mouse, screenshots, exhaustive drawer interaction) is intentionally out
of scope here.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from dataclasses import fields
from pathlib import Path

from tesis import tui, tui_commands, tui_drawers, tui_forms, tui_mission, tui_security, tui_state
from tesis.artifact_repository import ArtifactRepository
from tesis.model_config import EngagementConfig, ModelConfig
from tesis.runtime_events import RunEvent


# ---------------------------------------------------------------- public contract

def test_public_tui_exports_resolve():
    expected = (
        "AboutDrawer",
        "COMMANDS",
        "CONFIG_PATH",
        "CommandLauncher",
        "CommandSpec",
        "CoordinateDrawer",
        "CoordinateRow",
        "DETAIL_LOG_MAX_LINES",
        "DETAIL_RENDER_MAX_CHARS",
        "DoctorDrawer",
        "EvidenceDrawer",
        "FailureDrawer",
        "FailureSummary",
        "HelpDrawer",
        "LaunchDrawer",
        "MissionControlScreen",
        "PlanDrawer",
        "ResultsDrawer",
        "RunStatus",
        "SettingsDrawer",
        "StageRow",
        "StageStatus",
        "SHELL_MONO_THEME",
        "SHELL_MONO_THEME_NAME",
        "TesisApp",
        "TraceDrawer",
        "TuiRunState",
        "apply_run_event",
        "run_tui",
    )
    assert tuple(tui.__all__) == expected
    for name in expected:
        assert getattr(tui, name) is not None, f"tesis.tui.{name} missing"
    for name in (
        "CONFIG_PATH",
        "CoordinateRow",
        "FailureSummary",
        "RunStatus",
        "StageRow",
        "StageStatus",
        "TuiRunState",
        "apply_run_event",
    ):
        assert getattr(tui, name) is getattr(tui_state, name), f"{name} must be re-exported by identity"
    assert tui.REPOSITORY_ROOT is tui_state.REPOSITORY_ROOT
    for name in ("COMMANDS", "CommandSpec", "CommandLauncher"):
        assert getattr(tui, name) is getattr(tui_commands, name), f"{name} must be re-exported by identity"
    assert tui.MissionControlScreen is tui_mission.MissionControlScreen
    for name in ("LaunchDrawer", "SettingsDrawer"):
        assert getattr(tui, name) is getattr(tui_forms, name), f"{name} must be re-exported by identity"
    for name in (
        "AboutDrawer",
        "CoordinateDrawer",
        "DETAIL_LOG_MAX_LINES",
        "DETAIL_RENDER_MAX_CHARS",
        "DoctorDrawer",
        "EvidenceDrawer",
        "FailureDrawer",
        "HelpDrawer",
        "PlanDrawer",
        "ResultsDrawer",
        "TraceDrawer",
    ):
        assert getattr(tui, name) is getattr(tui_drawers, name), f"{name} must be re-exported by identity"


# ---------------------------------------------------------------- helpers

def _require(name: str):
    value = getattr(tui, name, None)
    assert value is not None, f"core: tesis.tui.{name} missing (handoff contract)"
    return value


def _config(tmp_path: Path | None = None) -> EngagementConfig:
    kwargs: dict = {
        "target_url": "http://localhost/dvwa",
        "provider": "gemini",
        "level": "low",
        "models": {"gemini": ModelConfig("gemini", "", "test-model")},
    }
    if tmp_path is not None:
        kwargs["output_dir"] = str(tmp_path / "results")
    return EngagementConfig(**kwargs)


def _fresh_state():
    TuiRunState = _require("TuiRunState")
    try:
        return TuiRunState()
    except TypeError as exc:
        import pytest

        pytest.fail(f"core: TuiRunState() must be constructible with defaults: {exc}")


def _apply(state, event: RunEvent):
    apply_run_event = _require("apply_run_event")
    dirty = apply_run_event(state, event)
    assert isinstance(dirty, frozenset), "core: apply_run_event must return frozenset[str]"
    assert dirty <= {"header", "pipeline", "coordinates", "evidence", "notices"}, (
        f"core: unexpected dirty regions {sorted(dirty)}"
    )
    return dirty


def _svg_text(app) -> str:
    try:
        return app.export_screenshot()
    except Exception:
        return ""


async def _drain(screen) -> None:
    drain = getattr(screen, "_drain_runtime_events", None)
    if callable(drain):
        drain()
        await asyncio.sleep(0)


async def _wait_for_thread(pilot, thread, timeout: float = 5.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while thread.is_alive() and loop.time() < deadline:
        await pilot.pause(0.01)
    assert not thread.is_alive(), f"{thread.name} did not stop within {timeout:g} seconds"


def _pane_text(screen, selector: str) -> str:
    from textual.widgets import Static

    try:
        return str(screen.query_one(selector, Static).render())
    except Exception:
        return ""


def _options(launcher) -> list:
    from textual.widgets import OptionList

    try:
        return list(launcher.query_one("#launcher-list", OptionList).options)
    except Exception:
        return getattr(launcher, "_filtered", [])


# ---------------------------------------------------------------- root

def test_root_is_always_mission_control():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, MissionControlScreen), (
                f"core: root must be MissionControlScreen, got {type(app.screen).__name__}"
            )

    asyncio.run(scenario())


def test_no_new_shell_option_or_env_dual_path():
    assert "new_shell" not in inspect.signature(tui.TesisApp.__init__).parameters, (
        "core: remove the new_shell constructor option"
    )
    assert not hasattr(tui, "TESIS_NEW_SHELL"), "core: remove TESIS_NEW_SHELL"
    for legacy in (
        "MainMenuScreen", "RunSetupScreen", "RuntimeDashboardScreen",
        "SettingsScreen", "RecentResultsScreen", "ResultDetailScreen",
        "ValidationScreen", "FrameworkInfoScreen",
    ):
        assert not hasattr(tui, legacy), f"core: remove legacy {legacy}"


def test_no_permanent_command_input_at_idle():
    from textual.widgets import Input

    _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            assert len(app.screen.query(Input)) == 0, "idle must not mount a permanent Input"

    asyncio.run(scenario())


def test_app_uses_single_stylesheet():
    assert getattr(tui.TesisApp, "CSS_PATH", None) == "tui.tcss", (
        "core: TesisApp.CSS_PATH must be 'tui.tcss'"
    )


def test_idle_readiness_summarises_target_condition_provider_and_actions():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            body = _pane_text(screen, "#notice-text").lower()
            for action in ("r run", "m matrix", "p plan", "d doctor"):
                assert action in body, f"idle readiness must list {action!r}"
            for field in ("target", "condition", "provider", "coordinates", "config", "containment"):
                assert field in body, f"idle readiness must report {field!r}"

    asyncio.run(scenario())


def test_context_bar_redacts_target_credentials_and_query_tokens(monkeypatch):
    MissionControlScreen = _require("MissionControlScreen")
    secret = "sk-live-target-secret"
    leaked = "hunter2-target-password"
    config = _config()
    config.target_url = (
        f"http://admin:{leaked}@localhost/dvwa"
        f"?api_key={secret}&debug=1#token={secret}"
    )
    monkeypatch.setattr(tui_mission, "load_and_resolve_config", lambda **_kw: config)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            bar = _pane_text(screen, "#context-bar")
            screenshot = _svg_text(app)
            for credential in (secret, leaked):
                assert credential not in bar, f"context bar leaked {credential!r}"
                assert credential not in screenshot, f"screenshot leaked {credential!r}"
            # Redaction keeps the URL readable: host survives, secrets do not.
            assert "localhost/dvwa" in bar
            assert "[REDACTED]" in bar, "redaction must be visible, not silent truncation"
            assert "api_key=" in bar

    asyncio.run(scenario())


def test_chrome_shows_context_status_and_navigation_footer():
    MissionControlScreen = _require("MissionControlScreen")
    COMMANDS = _require("COMMANDS")
    NAVIGATION_KEYS = tui_commands.NAVIGATION_KEYS

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            assert "TESIS" in _pane_text(screen, "#context-bar")
            assert "READY" in _pane_text(screen, "#status-label")
            footer = _pane_text(screen, "#context-footer")
            # Every footer segment must trace to the one navigation list or the
            # one command registry, so nothing unbindable is ever advertised.
            nav_keys = {key for key, _ in NAVIGATION_KEYS}
            specs = {spec.name: spec for spec in COMMANDS}
            for segment in (part.strip() for part in footer.split("·")):
                assert segment, f"empty footer segment in {footer!r}"
                key, _, name = segment.rpartition(" ")
                assert key in nav_keys or (
                    name in specs and key and key == specs[name].keys
                ), f"footer segment {segment!r} is not a navigation key or registry hint"

    asyncio.run(scenario())


def test_paused_notice_badge_grows_past_the_cap_and_coalescing_counts_repeats():
    MissionControlScreen = _require("MissionControlScreen")
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    for _ in range(3):
        _apply(state, RunEvent("graph.node.completed", node="recon", message="same"))
    assert state.notices[-1].endswith("(x3)"), f"repeats must coalesce twice: {state.notices[-1]!r}"
    assert "same" in state.notices[-1], "the coalesced notice must keep its text"

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            for i in range(tui_state.NOTICE_MAX_ENTRIES + 60):
                screen._post_event(RunEvent("graph.node.completed", node="recon", message=f"evt-{i}"))
            await _drain(screen)
            await pilot.pause()
            capped = len(screen.state.notices)
            assert capped == tui_state.NOTICE_MAX_ENTRIES, f"notices must stay bounded, got {capped}"

            body = screen.query_one("#notice-body")
            body.scroll_to(y=0, animate=False)
            await pilot.pause()
            assert not screen._notice_following, "scrolling away pauses auto-follow"
            for i in range(3):
                screen._post_event(RunEvent("graph.node.completed", node="recon", message=f"late-{i}"))
            await _drain(screen)
            await pilot.pause()
            assert len(screen.state.notices) == capped, "the capped list length must not change"
            assert "3 new" in _pane_text(screen, "#notice-new-badge"), (
                "paused notices must still be counted once the list is capped: "
                f"{_pane_text(screen, '#notice-new-badge')!r}"
            )

    asyncio.run(scenario())


def test_notice_pane_pauses_auto_follow_and_resumes_at_bottom():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            body = screen.query_one("#notice-body")
            for i in range(60):
                screen._post_event(RunEvent("graph.node.completed", node="recon", message=f"evt-{i}"))
            await _drain(screen)
            await pilot.pause()
            focused_before = getattr(app.focused, "id", None)
            assert screen._notice_following
            assert body.is_vertical_scroll_end, "a following pane sits at the bottom"

            # Scrolling away from the bottom pauses auto-follow.
            body.scroll_to(y=5, animate=False)
            await pilot.pause()
            assert not screen._notice_following, "scrolling away must pause auto-follow"
            paused_at = body.scroll_offset.y
            badge = _pane_text(screen, "#notice-new-badge")
            assert "new" not in badge, f"nothing new yet: {badge!r}"

            # Incoming events keep the position and count themselves in the badge.
            for i in range(60, 65):
                screen._post_event(RunEvent("graph.node.completed", node="recon", message=f"evt-{i}"))
            await _drain(screen)
            await pilot.pause()
            assert body.scroll_offset.y == paused_at, (
                f"a paused pane must hold position: {paused_at} -> {body.scroll_offset.y}"
            )
            assert "5 new" in _pane_text(screen, "#notice-new-badge"), "paused events must be counted"
            assert "evt-64" in _pane_text(screen, "#notice-text")
            assert getattr(app.focused, "id", None) == focused_before, "events must not steal focus"

            # Returning to the bottom clears the badge and follows again.
            body.scroll_end(animate=False)
            await pilot.pause()
            assert screen._notice_following, "reaching the bottom resumes auto-follow"
            assert "new" not in _pane_text(screen, "#notice-new-badge")
            screen._post_event(RunEvent("graph.node.completed", node="recon", message="evt-latest"))
            await _drain(screen)
            await pilot.pause()
            assert body.scroll_offset.y == body.max_scroll_y, "a resumed pane follows the tail"
            assert "evt-latest" in _pane_text(screen, "#notice-text")

    asyncio.run(scenario())


def test_run_elapsed_never_regresses_on_out_of_order_events():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", timestamp=1000.0, message="go"))
    _apply(state, RunEvent("graph.node.completed", timestamp=1012.5, node="scorer", message="scored"))
    assert state.elapsed == "12.5s"
    _apply(state, RunEvent("graph.state", timestamp=1003.0, message="replayed older event"))
    assert state.elapsed == "12.5s", f"an out-of-order event must not rewind the clock: {state.elapsed!r}"
    _apply(state, RunEvent("graph.node.started", timestamp=1090.0, node="recon", message="later"))
    assert state.elapsed == "1m30.0s", state.elapsed


def test_late_coordinate_start_does_not_revert_terminal_status():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.started", timestamp=100.0, data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    _apply(state, RunEvent("matrix.run.finished", timestamp=112.5, data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    row = state.coordinates[0]
    assert row.status == "succeeded" and row.elapsed == "12.5s"
    _apply(state, RunEvent("matrix.run.started", timestamp=120.0, data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    assert row.status == "succeeded", f"a late start must not revert a finished coordinate: {row.status}"
    assert row.elapsed == "12.5s", f"a late start must not restart the coordinate clock: {row.elapsed}"


def test_run_state_tracks_elapsed_from_event_timestamps():
    state = _fresh_state()
    assert state.elapsed == "—", "no run start means no elapsed value"
    _apply(state, RunEvent("run.started", timestamp=1000.0, message="go"))
    assert state.elapsed == "0.0s"
    _apply(state, RunEvent("graph.node.completed", timestamp=1012.5, node="recon", message="scanning"))
    assert state.elapsed == "12.5s", f"elapsed must advance with events, got {state.elapsed!r}"
    _apply(state, RunEvent("run.finished", timestamp=1075.0, message="done"))
    assert state.elapsed == "1m15.0s", f"terminal event records the final elapsed, got {state.elapsed!r}"
    _apply(state, RunEvent("graph.node.completed", timestamp=1200.0, node="recon", message="late"))
    assert state.elapsed == "1m15.0s", "a finished run must not keep accruing elapsed time"


def test_context_bar_shows_target_condition_and_provider_model(monkeypatch):
    MissionControlScreen = _require("MissionControlScreen")
    config = _config()
    config.target_url = "http://admin:hunter2@172.19.48.1/dvwa/?id=7"
    config.experiment_condition = "akg_guided_hybrid"
    config.provider = "openai_compatible"
    config.models = {"openai_compatible": ModelConfig("openai_compatible", "", "test-model")}
    monkeypatch.setattr(tui_mission, "load_and_resolve_config", lambda **kwargs: config)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            bar = _pane_text(screen, "#context-bar")
            assert "akg_guided_hybrid" in bar, f"condition must be in the context bar: {bar!r}"
            assert "openai_compatible/test-model" in bar, f"provider/model must be shown: {bar!r}"
            for absent in ("hunter2", "id=7"):
                assert absent not in bar, f"context bar must not leak {absent!r}: {bar!r}"

    asyncio.run(scenario())


def test_status_strip_reports_containment_method_elapsed_and_artifacts(monkeypatch):
    MissionControlScreen = _require("MissionControlScreen")
    config = _config()
    config.output_dir = "results/runs"
    monkeypatch.setattr(tui_mission, "load_and_resolve_config", lambda **kwargs: config)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            idle = _pane_text(screen, "#status-label")
            assert "READY" in idle and "contained" in idle and "results/runs" in idle, idle
            assert "—" in idle, f"unknown method/elapsed must stay unavailable: {idle!r}"

            screen._post_event(RunEvent("run.started", timestamp=1000.0, message="go"))
            screen._post_event(RunEvent("graph.state", timestamp=1012.5, message="snap", data={
                "selected_method": "sqli_union", "candidate_count": 3}))
            await _drain(screen)
            await pilot.pause()
            running = _pane_text(screen, "#status-label")
            for expected in ("RUNNING", "contained", "sqli_union", "12.5s", "results/runs"):
                assert expected in running, f"status strip missing {expected!r}: {running!r}"

            screen._post_event(RunEvent("containment.violated", timestamp=1013.0, message="blocked"))
            await _drain(screen)
            await pilot.pause()
            degraded = _pane_text(screen, "#status-label")
            assert "containment 1" in degraded, f"a violation must be counted: {degraded!r}"
            assert "DEGRADED" in degraded, degraded

    asyncio.run(scenario())


def test_evidence_pane_shows_latest_failure_summary(monkeypatch):
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            before = _pane_text(screen, "#evidence-body")
            assert "remediation" not in before, "no failure means no failure lines"
            screen._post_event(RunEvent("run.started", message="go"))
            screen._post_event(RunEvent("run.failed", message="boom sk-live-evidence-secret",
                                       data={"failure_class": "http_rejected", "provider": "gemini",
                                             "request_id": "req-42",
                                             "remediation": "Check the provider credential."}))
            await _drain(screen)
            await pilot.pause()
            body = _pane_text(screen, "#evidence-body")
            for expected in ("http_rejected", "gemini", "req-42", "Check the provider credential."):
                assert expected in body, f"evidence pane missing {expected!r}: {body!r}"
            assert "sk-live-evidence-secret" not in body, f"failure text must stay redacted: {body!r}"

    asyncio.run(scenario())


def test_narrow_pipeline_uses_concise_stage_labels():
    MissionControlScreen = _require("MissionControlScreen")

    async def wide() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            text = _pane_text(app.screen, "#pipeline-pane")
            assert "payload candidate builder" in text and "chaining router" in text, text
            assert "candidates" not in text, f"wide layout keeps full labels: {text!r}"

    async def narrow() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(60, 18)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            text = _pane_text(screen, "#pipeline-pane")
            assert "candidates" in text and "validation" in text and "chain router" in text, text
            assert "payload candidate builder" not in text, f"narrow layout must abbreviate: {text!r}"
            assert "recon" in text and "scorer" in text, text

    asyncio.run(wide())
    asyncio.run(narrow())


def test_footer_thresholds_at_80_and_120_columns():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        # Idle at 80 columns still fits the full idle set.
        app = tui.TesisApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            idle = _pane_text(app.screen, "#context-footer")
            for hint in ("r run", "m matrix", "p plan", "d doctor", "/ command", "? help", "q quit"):
                assert hint in idle, f"idle footer at 80 columns must keep {hint!r}: {idle!r}"

            # Active at 80 columns is compact: no full navigation keys, but the
            # command/cancel/help hints the operator needs stay visible.
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen._post_event(RunEvent("run.started", timestamp=1000.0, message="go"))
            await _drain(screen)
            await pilot.pause()
            active_80 = _pane_text(screen, "#context-footer")
            for hint in ("/ command", "ctrl+c cancel", "? help"):
                assert hint in active_80, f"active 80-column footer missing {hint!r}: {active_80!r}"
            for dropped in ("1 pipeline", "Tab/Shift+Tab"):
                assert dropped not in active_80, (
                    f"full active navigation starts at 120 columns: {active_80!r}"
                )
            assert len(active_80) <= 78, f"the 80-column footer must not clip: {active_80!r}"

        # Active at 120 columns gets the full navigation set.
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen._post_event(RunEvent("run.started", timestamp=1000.0, message="go"))
            await _drain(screen)
            await pilot.pause()
            active_120 = _pane_text(screen, "#context-footer")
            for hint in ("1 pipeline", "2 coordinates", "3 evidence", "Tab/Shift+Tab focus",
                         "Enter inspect", "/ command", "ctrl+c cancel", "? help"):
                assert hint in active_120, f"active 120-column footer missing {hint!r}: {active_120!r}"
            assert len(active_120) <= 118, f"the 120-column footer must not clip: {active_120!r}"

    asyncio.run(scenario())


def test_compact_readiness_keeps_every_fact_visible_at_60_columns(monkeypatch):
    MissionControlScreen = _require("MissionControlScreen")
    config = _config()
    config.experiment_condition = "akg_guided_hybrid"
    config.target_method = "sqli_union"
    config.provider = "openai_compatible"
    config.models = {"openai_compatible": ModelConfig(
        "openai_compatible", "", "a-deliberately-long-coordinate-model-name")}
    monkeypatch.setattr(tui_mission, "load_and_resolve_config", lambda **_kw: config)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(60, 18)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            text = _pane_text(screen, "#triage-line")
            for expected in ("target", "akg_guided_hybrid", "method sqli_union", "provider",
                             "coordinates 1", "config valid", "containment enforced",
                             "r run", "m matrix", "p plan", "d doctor"):
                assert expected in text, f"missing {expected!r} at 60 columns: {text!r}"
            lines = [line for line in text.splitlines() if line.strip()]
            assert len(lines) == 4, f"compact readiness must stay inside four rows: {text!r}"
            for line in lines:
                assert len(line) <= 60, f"row must fit the 60-column terminal, got {len(line)}: {line!r}"

    asyncio.run(scenario())


def test_footer_is_contextual_for_idle_and_active_runs():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            idle = _pane_text(screen, "#context-footer")
            for hint in ("r run", "m matrix", "p plan", "d doctor", "/ command", "? help", "q quit"):
                assert hint in idle, f"idle footer must advertise {hint!r}: {idle!r}"
            assert "ctrl+c cancel" not in idle.lower(), f"idle has nothing to cancel: {idle!r}"

            screen._post_event(RunEvent("run.started", timestamp=1000.0, message="go"))
            await _drain(screen)
            await pilot.pause()
            active = _pane_text(screen, "#context-footer")
            for hint in ("1 pipeline", "2 coordinates", "3 evidence", "Enter inspect",
                         "/ command", "ctrl+c cancel", "? help"):
                assert hint in active, f"active footer must advertise {hint!r}: {active!r}"
            assert "r run" not in active, f"an active run cannot be started again: {active!r}"

        app = tui.TesisApp()
        async with app.run_test(size=(60, 18)) as pilot:
            await pilot.pause()
            screen = app.screen
            compact = _pane_text(screen, "#context-footer")
            for hint in ("r run", "m matrix", "/ command", "? help", "q quit"):
                assert hint in compact, f"compact footer must keep {hint!r}: {compact!r}"
            for dropped in ("p plan", "d doctor", "Tab/Shift+Tab", "1 pipeline"):
                assert dropped not in compact, f"compact footer must drop {dropped!r}: {compact!r}"
            screen._post_event(RunEvent("run.started", timestamp=1000.0, message="go"))
            await _drain(screen)
            await pilot.pause()
            compact_active = _pane_text(screen, "#context-footer")
            for hint in ("Enter inspect", "/ command", "ctrl+c cancel", "? help"):
                assert hint in compact_active, f"compact active footer missing {hint!r}: {compact_active!r}"
            for dropped in ("1 pipeline", "Tab/Shift+Tab", "r run"):
                assert dropped not in compact_active, f"compact active footer must drop {dropped!r}: {compact_active!r}"

    asyncio.run(scenario())


def test_help_lists_navigation_keys_and_registry_commands():
    COMMANDS = _require("COMMANDS")
    NAVIGATION_KEYS = tui_commands.NAVIGATION_KEYS

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await pilot.press("?")
            await pilot.pause()
            assert isinstance(app.screen, tui.HelpDrawer)
            body = str(app.screen.query_one("#help-body").render())
            for key, label in NAVIGATION_KEYS:
                assert f"{key} {label}" in body, f"help must list navigation {key} {label}"
            for required in ("1 pipeline", "2 coordinates", "3 evidence",
                             "Tab/Shift+Tab", "Enter"):
                assert required in body, f"help must explicitly include {required!r}"
            for spec in COMMANDS:
                assert f"/{spec.name}" in body, f"help must list /{spec.name}"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


# ---------------------------------------------------------------- operator state

EXACT_STAGES = (
    "recon", "orchestrator", "payload_candidate_builder",
    "payload_validator", "method_agent", "chaining_router", "scorer",
)


def test_initial_status_is_ready_with_exact_seven_stages():
    state = _fresh_state()
    assert state.status == "ready"
    assert state.run_mode == "single"
    assert state.execution_id is None
    assert state.selected_coordinate is None
    assert state.dropped_events == 0
    assert state.unseen_evidence == 0
    ids = [row.stage_id for row in state.stages]
    assert tuple(ids) == EXACT_STAGES, f"stages must be exactly {EXACT_STAGES}; got {tuple(ids)}"
    assert all(row.status == "queued" for row in state.stages)


def test_run_started_records_execution_id_and_mode():
    state = _fresh_state()
    dirty = _apply(state, RunEvent("run.started", execution_id="exec-1", message="go"))
    assert state.status == "running"
    assert state.execution_id == "exec-1"
    assert state.run_mode == "single"
    assert "header" in dirty and "pipeline" in dirty


def test_matrix_started_enters_running():
    state = _fresh_state()
    _apply(state, RunEvent("matrix.started", message="go"))
    assert state.status == "running"


def test_run_started_resets_prior_run():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.started", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    _apply(state, RunEvent("run.started", execution_id="exec-2", message="again"))
    assert state.coordinates == {}
    assert state.exec_index == {}
    assert state.confirmed_vulns == []
    assert state.execution_id == "exec-2"
    assert all(row.status == "queued" for row in state.stages)


def test_terminal_success_only_when_no_coordinate_failed():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.started",
                           data={"coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    _apply(state, RunEvent("matrix.run.finished",
                           data={"coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    _apply(state, RunEvent("run.finished", message="done"))
    assert state.status == "succeeded"


def test_terminal_failure_beats_success():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    for index in (0, 1):
        _apply(state, RunEvent("matrix.run.started", data={
            "coordinate_index": index, "coordinate_execution_id": f"exec-{index}"}))
    _apply(state, RunEvent("matrix.run.finished", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    _apply(state, RunEvent("matrix.run.finished", data={
        "coordinate_index": 1, "coordinate_execution_id": "exec-1",
        "failure_class": "http_rejected"}))
    _apply(state, RunEvent("run.finished", message="done"))
    assert state.status == "failed", "one failed coordinate must fail the terminal status"


def test_coordinate_failure_degrades_continuing_matrix():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.started",
                           data={"coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    _apply(state, RunEvent("matrix.run.finished",
                           data={"coordinate_index": 0, "coordinate_execution_id": "exec-0",
                                 "failure_class": "http_rejected"}))
    assert state.status == "degraded"


def test_parent_terminal_failure_is_failed():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("run.failed", message="boom"))
    assert state.status == "failed"


def test_finished_summary_message_is_redacted():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("run.finished", message="done sk-live-summary-secret"))
    assert state.status == "succeeded"
    assert "sk-live-summary-secret" not in json.dumps(state.notices, default=str)


def test_cancellation_is_labelled_cancelled():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("run.cancelled", message="user cancel"))
    assert state.status == "cancelled"


def test_cancel_is_sticky_against_late_finish():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("run.cancelled", message="user cancel"))
    _apply(state, RunEvent("run.finished", message="late"))
    assert state.status == "cancelled", "cancelled is terminal; late finish must not overwrite it"


def test_skipped_coordinate_keeps_skipped_label():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.started", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    _apply(state, RunEvent("matrix.run.finished", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0", "status": "skipped"}))
    row = state.coordinates[0]
    assert row.status == "skipped", f"skipped coordinate must not read as {row.status}"


def test_cancelled_coordinate_keeps_cancelled_label():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.started", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    _apply(state, RunEvent("matrix.run.finished", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0", "status": "cancelled"}))
    row = state.coordinates[0]
    assert row.status == "cancelled", f"cancelled coordinate must not read as {row.status}"


def test_containment_violation_degrades_running_matrix():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("containment.violated", message="cross-scope request blocked"))
    assert state.status == "degraded"
    assert state.containment_count >= 1


def test_llm_failed_for_known_coordinate_degrades():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.started", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    dirty = _apply(state, RunEvent("llm.failed", execution_id="exec-0",
                                   message="provider down",
                                   data={"failure_class": "http_rejected"}))
    assert state.status == "degraded"
    assert state.coordinates[0].status == "failed"
    assert "coordinates" in dirty and "evidence" in dirty and "notices" in dirty


def test_selected_coordinate_gates_state_evidence():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    state.selected_coordinate = 0
    _apply(state, RunEvent("matrix.run.finished", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0",
        "confirmed_vulns": ["sqli"], "achieved_outcomes": ["auth"]}))
    _apply(state, RunEvent("matrix.run.finished", data={
        "coordinate_index": 1, "coordinate_execution_id": "exec-1",
        "confirmed_vulns": ["idor"], "achieved_outcomes": ["admin"]}))
    assert list(state.confirmed_vulns) == ["sqli"]
    assert list(state.achieved_outcomes) == ["auth"]
    assert list(state.coordinates[1].confirmed_vulns) == ["idor"]


def test_out_of_order_coordinate_completion_hits_correct_rows():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    for index in (0, 1):
        _apply(state, RunEvent("matrix.run.started", data={
            "coordinate_index": index, "coordinate_execution_id": f"exec-{index}"}))
    _apply(state, RunEvent("matrix.run.finished", data={
        "coordinate_index": 1, "coordinate_execution_id": "exec-1",
        "selected_method": "sqli_union", "run_id": "run-1"}))
    _apply(state, RunEvent("matrix.run.finished", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0",
        "selected_method": "sqli_error", "run_id": "run-0"}))
    assert state.coordinates[1].selected_method == "sqli_union"
    assert state.coordinates[1].run_id == "run-1"
    assert state.coordinates[0].selected_method == "sqli_error"
    assert state.coordinates[0].run_id == "run-0"


def test_child_events_map_via_coordinate_execution_id():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.started", data={
        "coordinate_index": 2, "coordinate_execution_id": "exec-child-2"}))
    dirty = _apply(state, RunEvent("graph.node.failed", node="recon",
                                   execution_id="exec-child-2", message="recon failed"))
    assert "coordinates" in dirty
    assert state.coordinates[2].status == "failed"
    assert state.status == "degraded"
    _apply(state, RunEvent("matrix.run.started", data={
        "coordinate_index": 3, "coordinate_execution_id": "exec-child-3"}))
    assert state.coordinates[3].status == "running"


def test_unknown_child_execution_id_leaves_coordinates_alone():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.started", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    dirty = _apply(state, RunEvent("graph.node.completed", node="recon",
                                   execution_id="exec-unknown", message="done"))
    assert "coordinates" not in dirty
    assert state.coordinates[0].status == "running"


def test_graph_state_updates_summary_without_raw_text_dump():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    secret = "sk-live-graph-secret-abc123"
    dirty = _apply(state, RunEvent("graph.state", message="snapshot", data={
        "selected_method": "sqli_union",
        "candidate_count": 4, "validation_count": 2,
        "confirmed_vulns": ["sqli"],
        "verifier_decision": "exploited",
        "raw_state": {"prompt": secret, "chain_of_thought": "think step by step"},
    }))
    assert "evidence" in dirty
    assert state.selected_method == "sqli_union"
    assert state.candidate_count == 4
    assert state.validation_count == 2
    assert list(state.confirmed_vulns) == ["sqli"]
    assert state.verifier_decision == "exploited"
    blob = json.dumps({f.name: getattr(state, f.name) for f in fields(state)}, default=str)
    assert secret not in blob
    assert "think step by step" not in blob


def test_render_time_redaction_drops_chain_of_thought():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen._post_event(RunEvent("graph.state", message="snap", data={
                "selected_method": "sqli_union",
                "chain_of_thought": "think step by step sk-live-cot",
                "prompt": "sk-live-prompt"}))
            await _drain(screen)
            await pilot.pause()
            svg = _svg_text(app)
            assert "think step by step" not in svg
            assert "sk-live-cot" not in svg
            assert "sk-live-prompt" not in svg

    asyncio.run(scenario())


def test_token_events_return_empty_dirty_and_no_notices():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    before = len(state.notices)
    for _ in range(50):
        dirty = _apply(state, RunEvent("llm.token", message="tok"))
        assert dirty == frozenset()
    assert len(state.notices) == before


def test_notices_are_bounded_and_coalesced():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    before = len(state.notices)
    for _ in range(5):
        _apply(state, RunEvent("graph.node.started", node="recon", message="same"))
    # Identical repeats coalesce: at most one new notice, never five rows.
    assert len(state.notices) - before <= 1, f"duplicates not coalesced: {state.notices[-6:]!r}"
    assert "recon" in state.notices[-1] and "same" in state.notices[-1]
    for i in range(600):
        _apply(state, RunEvent("graph.node.started", node="recon", message=f"evt-{i}"))
    assert len(state.notices) <= 500, f"notices unbounded: {len(state.notices)}"
    assert any("evt-599" in str(n) for n in state.notices[-5:])


def test_redaction_in_notices_and_trace():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    secret = "sk-live-notice-secret-xyz"
    _apply(state, RunEvent("llm.failed", message="Model call failed",
                           data={"api_key": secret, "failure_class": "http_rejected"}))
    blob = json.dumps([str(n) for n in state.notices] + [str(state.failure)], default=str)
    assert secret not in blob
    assert state.failure is not None
    assert state.failure.failure_class == "http_rejected"


def test_endpoint_query_values_are_redacted_in_failure_drawer():
    FailureDrawer = _require("FailureDrawer")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            failure = {
                "failure_class": "http_rejected", "provider": "openai",
                "endpoint": "https://user:pass@example.com/v1/?api_key=sk-live-q&token=abc",
                "api_key": "sk-live-secret",
                "remediation": "Check the credential.",
                "request_id": "req-123",
            }
            await app.push_screen(FailureDrawer(failure))
            await pilot.pause()
            svg = _svg_text(app)
            assert "sk-live-secret" not in svg
            assert "sk-live-q" not in svg
            assert "pass@" not in svg
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_node_events_return_pipeline_and_notices_regions():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    dirty = _apply(state, RunEvent("graph.node.started", node="recon", message="scanning"))
    assert {"pipeline", "notices"} <= dirty
    assert state.stages[0].status == "running"


def test_graph_state_returns_evidence_region_only():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    dirty = _apply(state, RunEvent("graph.state", message="snap", data={"candidate_count": 2}))
    assert dirty == frozenset({"evidence"})


def test_matrix_coordinate_started_returns_header_and_coordinates():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    dirty = _apply(state, RunEvent("matrix.run.started", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    assert dirty == frozenset({"header", "coordinates"})


def test_matrix_coordinate_records_mode_and_derives_elapsed():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.started", timestamp=100.0, data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0",
        "provider": "gemini", "surface": "sqli", "security_level": "low",
        "payload_mode": "hybrid"}))
    row = state.coordinates[0]
    assert row.mode == "hybrid"
    assert row.elapsed == "—", "a running coordinate has no elapsed value yet"
    _apply(state, RunEvent("matrix.run.finished", timestamp=112.5, data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    assert row.elapsed == "12.5s", f"elapsed must derive from the coordinate clock, got {row.elapsed!r}"


def test_coordinate_mode_and_elapsed_unavailable_render_as_dash():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.finished", timestamp=40.0, data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    row = state.coordinates[0]
    assert row.mode == "—", "an absent payload mode must stay unavailable, never fabricated"
    assert row.elapsed == "—", "a finish without a recorded start must stay unavailable"
    _apply(state, RunEvent("matrix.run.started", timestamp=100.0, data={
        "coordinate_index": 1, "coordinate_execution_id": "exec-1"}))
    _apply(state, RunEvent("matrix.run.finished", timestamp=90.0, data={
        "coordinate_index": 1, "coordinate_execution_id": "exec-1"}))
    assert state.coordinates[1].elapsed == "—", "a backwards clock must not report negative elapsed"


def test_coordinate_elapsed_consumes_runner_reported_duration():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.finished", timestamp=40.0, data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0", "duration_ms": 4500}))
    assert state.coordinates[0].elapsed == "4.5s"
    _apply(state, RunEvent("matrix.run.started", timestamp=50.0, data={
        "coordinate_index": 1, "coordinate_execution_id": "exec-1"}))
    _apply(state, RunEvent("matrix.run.finished", timestamp=50.25, data={
        "coordinate_index": 1, "coordinate_execution_id": "exec-1", "elapsed": "250ms"}))
    assert state.coordinates[1].elapsed == "250ms", "a runner-reported label is kept verbatim"


def test_matrix_coordinate_finished_returns_header_coordinates_evidence():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("matrix.run.started", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    dirty = _apply(state, RunEvent("matrix.run.finished", data={
        "coordinate_index": 0, "coordinate_execution_id": "exec-0"}))
    assert dirty == frozenset({"header", "coordinates", "evidence"})


def test_run_failed_returns_header_evidence_notices():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    dirty = _apply(state, RunEvent("run.failed", message="boom"))
    assert dirty == frozenset({"header", "evidence", "notices"})


def test_run_cancelled_returns_header_and_notices():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    dirty = _apply(state, RunEvent("run.cancelled", message="stop"))
    assert dirty == frozenset({"header", "notices"})


def test_containment_returns_header_evidence_notices():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    dirty = _apply(state, RunEvent("containment.violated", message="blocked"))
    assert dirty == frozenset({"header", "evidence", "notices"})


# ---------------------------------------------------------------- commands + launcher

EXPECTED_COMMANDS = {
    "run", "matrix", "plan", "cancel", "coordinates", "evidence",
    "failure", "trace", "doctor", "results", "settings", "export",
    "about", "help", "quit",
}


# Exact registry keymap. A key is listed only when the screen binds it, so the
# footer and the `?` help can never advertise a keystroke that does nothing.
EXPECTED_COMMAND_KEYS = {
    "run": "r", "matrix": "m", "plan": "p", "cancel": "ctrl+c",
    "coordinates": "2", "evidence": "3", "failure": "",
    "trace": "", "doctor": "d", "results": "", "settings": "",
    "export": "", "about": "", "help": "?", "quit": "q",
}


def test_command_registry_is_exact_and_described():
    COMMANDS = _require("COMMANDS")
    names = [c.name for c in COMMANDS]
    assert set(names) == EXPECTED_COMMANDS, f"registry must be {sorted(EXPECTED_COMMANDS)}; got {sorted(set(names))}"
    assert len(names) == len(set(names)), "duplicate command names"
    for spec in COMMANDS:
        assert spec.title and spec.summary, f"/{spec.name} needs title + summary"
    assert {spec.name: spec.keys for spec in COMMANDS} == EXPECTED_COMMAND_KEYS, (
        "registry keys must match the global bindings exactly"
    )
    for removed in ("resume", "retry", "model", "info", "details", "validate"):
        assert removed not in names, f"removed command /{removed} must stay gone"


def test_registry_keys_are_dispatchable_and_pane_keys_agree():
    MissionControlScreen = _require("MissionControlScreen")
    COMMANDS = _require("COMMANDS")
    bound = set()
    for binding in MissionControlScreen.BINDINGS:
        bound.add(binding.key)
        if binding.key_display:
            bound.add(binding.key_display.lower())
    for spec in COMMANDS:
        if spec.keys:
            assert spec.keys.lower() in bound, (
                f"/{spec.name} advertises {spec.keys!r}, which the screen does not bind"
            )
    # 1/2/3 mean the same three panes in the registry and in the bindings.
    actions = {str(binding.key): str(binding.action) for binding in MissionControlScreen.BINDINGS}
    assert actions["1"].endswith("pipeline")
    assert actions["2"].endswith("coordinates") and actions["3"].endswith("evidence")
    keys = {spec.name: spec.keys for spec in COMMANDS}
    assert keys["coordinates"] == "2" and keys["evidence"] == "3"


def test_command_spec_carries_launcher_keys_and_gating():
    CommandSpec = _require("CommandSpec")
    fields = set(getattr(CommandSpec, "__dataclass_fields__", {}))
    assert {"name", "title", "summary", "keys", "enabled_when"} <= fields, (
        f"core: CommandSpec fields must include name/title/summary/keys/enabled_when; got {sorted(fields)}"
    )


def test_launcher_lists_registry_with_per_command_gating_while_active():
    from threading import Event

    MissionControlScreen = _require("MissionControlScreen")
    started = Event()
    release = Event()

    def blocked_single(**kwargs):
        started.set()
        release.wait(timeout=5)
        return {"status": "cancelled"}

    async def scenario() -> None:
        from unittest.mock import patch

        with patch.object(tui_mission, "run_single_engagement", blocked_single):
            app = tui.TesisApp()
            async with app.run_test(size=(120, 36)) as pilot:
                await pilot.pause()
                screen = app.screen
                assert isinstance(screen, MissionControlScreen)
                screen.start_run(_config(), mode="single")
                for _ in range(500):
                    if started.is_set():
                        break
                    await asyncio.sleep(0.01)
                assert started.is_set()
                await app.push_screen(tui.CommandLauncher())
                await pilot.pause()
                launcher = app.screen
                assert isinstance(launcher, tui.CommandLauncher)
                options = _options(launcher)
                assert len(options) == len(tui.COMMANDS), (
                    "launcher must list one option per registry command"
                )
                idle_marked = [
                    str(getattr(o, "prompt", getattr(o, "label", o)))
                    for o in options
                    if "run" in str(getattr(o, "id", "")).lower()
                    or "setting" in str(getattr(o, "id", "")).lower()
                ]
                assert any("disabled" in text.lower() or "active" in text.lower()
                           for text in idle_marked), (
                    "idle-only commands must carry a disabled marker + reason while active"
                )
                launcher._dispatch("run")
                await pilot.pause()
                assert not any(isinstance(s, tui.LaunchDrawer) for s in app.screen_stack), (
                    "run must not open the guided launcher while a run is active"
                )
                launcher2 = tui.CommandLauncher()
                await app.push_screen(launcher2)
                await pilot.pause()
                launcher2._dispatch("cancel")
                await pilot.pause()
                assert screen.cancel_token.is_cancelled
                await pilot.press("ctrl+c")
                await pilot.pause()
                assert not app.is_running
        release.set()

    try:
        asyncio.run(asyncio.wait_for(scenario(), timeout=15))
    finally:
        release.set()


def test_launcher_displays_all_idle_commands_when_idle():
    _require("CommandLauncher")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(tui.CommandLauncher())
            await pilot.pause()
            launcher = app.screen
            assert isinstance(launcher, tui.CommandLauncher)
            options = _options(launcher)
            ids = {str(getattr(o, "id", "")) for o in options}
            assert {s.name for s in tui.COMMANDS} <= ids
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_launch_drawer_has_four_steps_and_frozen_review_count(monkeypatch):
    LaunchDrawer = _require("LaunchDrawer")
    monkeypatch.setattr(tui_forms, "load_and_resolve_config", lambda **_kw: _config())

    async def scenario() -> None:
        from textual.widgets import Button, Input, Select

        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            for mode in ("single", "matrix"):
                await app.push_screen(LaunchDrawer(mode=mode))
                await pilot.pause()
                drawer = app.screen
                assert isinstance(drawer, LaunchDrawer)

                # All four steps are named; Scope is the active step.
                svg = _svg_text(app)
                for step in ("Scope", "Coordinates", "Runtime", "Review"):
                    assert step in svg, f"{mode} launcher missing step {step}"
                assert drawer.query_one("#launch-step-scope").display

                # Scope carries real inputs: target, condition, target method.
                assert isinstance(drawer.query_one("#launch-field-target-url", Input), Input)
                assert isinstance(drawer.query_one("#launch-field-experiment-condition"), Select)
                assert isinstance(drawer.query_one("#launch-field-target-method"), Select)

                drawer.query_one("#launch-next", Button).press()
                await pilot.pause()
                assert drawer.query_one("#launch-step-coordinates").display
                for field in ("provider", "model-profile", "level", "surface", "payload-mode"):
                    assert drawer.query_one(f"#launch-field-{field}") is not None, field
                if mode == "matrix":
                    assert drawer.query_one("#launch-field-repeats", Input) is not None

                drawer.query_one("#launch-next", Button).press()
                await pilot.pause()
                assert drawer.query_one("#launch-step-runtime").display
                assert drawer.query_one("#launch-advanced") is not None
                assert drawer.query_one("#launch-field-candidate-budget", Input) is not None
                assert not drawer.query_one("#launch-start").display, (
                    "Start must not be offered before Review"
                )

                drawer.query_one("#launch-next", Button).press()
                await pilot.pause()
                assert drawer.query_one("#launch-step-review").display
                review = str(drawer.query_one("#launch-review").render()).lower()
                assert "fingerprint" in review, f"{mode} review must show fingerprint"
                assert "coordinates=" in review, f"{mode} review must show coordinate count"
                assert drawer.query_one("#launch-start").display, (
                    "Review is the only step that offers Start"
                )
                await pilot.press("escape")
                await pilot.pause()

    asyncio.run(scenario())


def test_launch_start_freezes_request_until_terminal(monkeypatch):
    from threading import Event

    LaunchDrawer = _require("LaunchDrawer")
    started = Event()
    release = Event()

    def blocked_single(**kwargs):
        started.set()
        release.wait(timeout=5)
        return {"status": "cancelled"}

    monkeypatch.setattr(tui_mission, "run_single_engagement", blocked_single)
    monkeypatch.setattr(tui_forms, "load_and_resolve_config", lambda **_kw: _config())

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(LaunchDrawer(mode="single"))
            await pilot.pause()
            try:
                app.screen._goto_step(len(app.screen.STEPS) - 1)
                await pilot.pause()
                app.screen.query_one("#launch-start").press()
                for _ in range(500):
                    if started.is_set():
                        break
                    await asyncio.sleep(0.01)
                assert started.is_set()
                mission = next(s for s in app.screen_stack if isinstance(s, tui.MissionControlScreen))
                first_thread = mission._runtime_thread
                assert mission.run_active
                mission.start_run(_config(), mode="single")
                await pilot.pause()
                assert mission._runtime_thread is first_thread
            finally:
                release.set()
                await pilot.press("ctrl+c")
                await pilot.pause()
                await pilot.press("ctrl+c")
                await pilot.pause()

    try:
        asyncio.run(asyncio.wait_for(scenario(), timeout=15))
    finally:
        release.set()


async def _launcher_roundtrip(opener: str):
    _require("MissionControlScreen")
    app = tui.TesisApp()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        screen = app.screen
        await pilot.press(opener)
        await pilot.pause()
        assert isinstance(app.screen, tui.CommandLauncher), f"{opener!r} must summon the launcher"
        await pilot.press("escape")
        await pilot.pause()
        assert type(app.screen) is type(screen)
        # Esc must leave focus on the default screen surface, not a dead widget.
        assert app.screen.focused is not None or app.focused is not None


def test_launcher_summoned_by_slash_restores_focus():
    asyncio.run(_launcher_roundtrip("/"))


def test_launcher_summoned_by_colon_restores_focus():
    asyncio.run(_launcher_roundtrip(":"))


def test_launcher_summoned_by_ctrl_p_restores_focus():
    asyncio.run(_launcher_roundtrip("ctrl+p"))


def test_launcher_typed_dispatch_opens_trace_drawer():
    _require("CommandLauncher")

    async def scenario() -> None:
        from textual.widgets import Input

        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(tui.CommandLauncher())
            await pilot.pause()
            launcher = app.screen
            assert isinstance(launcher, tui.CommandLauncher)
            launcher.query_one("#launcher-input", Input).value = "trace"
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, tui.TraceDrawer), "typed 'trace' must open TraceDrawer"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_launcher_unknown_text_keeps_launcher_open():
    _require("CommandLauncher")

    async def scenario() -> None:
        from textual.widgets import Input

        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(tui.CommandLauncher())
            await pilot.pause()
            launcher = app.screen
            launcher.query_one("#launcher-input", Input).value = "no-such-command-xyz"
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, tui.CommandLauncher), (
                "unknown text must not dispatch or close the launcher"
            )
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_global_keys_open_drawers_and_quit_idle_only():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen.action_launch_single()
            await pilot.pause()
            assert isinstance(app.screen, tui.LaunchDrawer)
            await pilot.press("escape")
            await pilot.pause()
            screen.action_launch_matrix()
            await pilot.pause()
            assert isinstance(app.screen, tui.LaunchDrawer)
            assert app.screen.mode == "matrix"
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("?")
            await pilot.pause()
            assert isinstance(app.screen, tui.HelpDrawer)
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()
            assert not app.is_running

    asyncio.run(scenario())


def test_pane_keys_tab_and_enter():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)

            # Wide: 1/2/3 move focus between the three visible panes and never
            # replace them with a drawer.
            for key, pane_id in (("1", "pipeline-pane"), ("2", "coordinate-pane"),
                                 ("3", "evidence-body")):
                await pilot.press(key)
                await pilot.pause()
                assert type(app.screen) is MissionControlScreen, (
                    f"{key!r} must focus the visible pane, not open a drawer"
                )
                assert getattr(app.focused, "id", None) == pane_id, (
                    f"{key!r} must focus #{pane_id}; got {getattr(app.focused, 'id', None)!r}"
                )
                focused = app.screen.query_one(f"#{pane_id}")
                for other_id in ("pipeline-pane", "coordinate-pane", "evidence-body"):
                    if other_id == pane_id:
                        continue
                    other = app.screen.query_one(f"#{other_id}")
                    assert (focused.styles.text_style != other.styles.text_style
                            or focused.styles.background != other.styles.background), (
                        f"#{pane_id} must be visually distinct while focused"
                    )

            # Tab/Shift+Tab walk the focusable panes in DOM order and wrap.
            # The notice pane is a scrollable surface, so it is a tab stop of
            # its own; it only exists in the wide layout, where the other
            # hidden panes are skipped.
            await pilot.press("1")
            await pilot.pause()
            for key, pane_id in (("tab", "coordinate-pane"), ("tab", "notice-body"),
                                 ("tab", "evidence-body"),
                                 ("tab", "pipeline-pane"), ("shift+tab", "evidence-body")):
                await pilot.press(key)
                await pilot.pause()
                assert getattr(app.focused, "id", None) == pane_id, (
                    f"{key!r} must move focus to #{pane_id}"
                )

    asyncio.run(scenario())


def test_pane_keys_open_drawers_when_panes_are_hidden():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario(size, expect_drawer: bool) -> None:
        app = tui.TesisApp()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, MissionControlScreen)
            await pilot.press("2")
            await pilot.pause()
            if expect_drawer:
                assert isinstance(app.screen, tui.CoordinateDrawer), (
                    f"{size} hides the coordinates pane, so 2 must open the drawer"
                )
                await pilot.press("escape")
                await pilot.pause()
            else:
                assert type(app.screen) is MissionControlScreen
            await pilot.press("3")
            await pilot.pause()
            if expect_drawer:
                assert isinstance(app.screen, tui.EvidenceDrawer), (
                    f"{size} hides the evidence pane, so 3 must open the drawer"
                )
                await pilot.press("escape")
                await pilot.pause()
            else:
                assert type(app.screen) is MissionControlScreen

    asyncio.run(scenario((80, 24), expect_drawer=True))
    asyncio.run(scenario((60, 18), expect_drawer=True))


def test_live_evidence_keeps_default_surface_focus():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            for i in range(5):
                screen._post_event(RunEvent("graph.state", message=f"snap-{i}", data={
                    "selected_method": "sqli_union", "confirmed_vulns": ["sqli"]}))
            await _drain(screen)
            await pilot.pause()
            # Incoming evidence must not move focus onto a drawer or launcher.
            assert type(app.screen) is type(screen)
            assert app.screen.focused is not None or app.focused is not None

    asyncio.run(scenario())


def test_evidence_unseen_counter_increments_on_graph_state():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    assert state.unseen_evidence == 0
    _apply(state, RunEvent("graph.state", message="snap", data={"confirmed_vulns": ["sqli"]}))
    assert state.unseen_evidence >= 1


def test_evidence_badge_selector_surfaces_unseen_count():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen._post_event(RunEvent("graph.state", message="snap", data={"confirmed_vulns": ["sqli"]}))
            await _drain(screen)
            await pilot.pause()
            try:
                badge = screen.query_one("#evidence-badge")
                text = str(badge.render())
            except Exception:
                raise AssertionError("core: evidence pane needs a dedicated #evidence-badge selector")
            assert str(screen.state.unseen_evidence) in text

    asyncio.run(scenario())


# ---------------------------------------------------------------- responsive

def _displays(screen) -> dict[str, bool]:
    out = {}
    for selector in ("#pipeline-pane", "#coordinate-pane", "#evidence-pane",
                     "#notice-pane", "#triage-line", "#size-notice"):
        try:
            out[selector] = bool(screen.query_one(selector).display)
        except Exception:
            out[selector] = False
    return out


def test_idle_readiness_stays_visible_at_standard_and_narrow():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario(size) -> None:
        app = tui.TesisApp()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            triage = screen.query_one("#triage-line")
            assert triage.display, f"{size} must keep the triage line visible"
            idle = str(triage.render()).lower()
            for field in ("target", "condition", "coordinates", "config valid", "containment"):
                assert field in idle, f"{size} idle triage must report {field!r}"
            for action in ("r run", "m matrix", "p plan", "d doctor"):
                assert action in idle, f"{size} idle triage must offer {action!r}"
            assert triage.size.height >= 2, "idle readiness must use its compact block"
            # A running run keeps the triage line to a single summary row.
            screen._post_event(RunEvent("run.started", message="go"))
            await _drain(screen)
            await pilot.pause()
            assert triage.size.height == 1, "running triage must stay one line"
            assert "running" in str(triage.render()).lower()

    asyncio.run(scenario((80, 24)))
    asyncio.run(scenario((60, 18)))


def test_overlays_dismiss_below_the_floor_but_help_stays():
    _require("MissionControlScreen")

    async def opens_below_floor(drawer_factory) -> str:
        app = tui.TesisApp()
        async with app.run_test(size=(59, 17)) as pilot:
            await pilot.pause()
            await app.push_screen(drawer_factory())
            await pilot.pause()
            active = type(app.screen).__name__
            if isinstance(app.screen, tui_commands.BaseDrawer):
                await pilot.press("escape")
                await pilot.pause()
            return active

    # Every captured overlay except Help must refuse to stay below 60x18.
    for factory in (tui.LaunchDrawer, tui.CommandLauncher, tui.CoordinateDrawer,
                    tui.EvidenceDrawer, tui.ResultsDrawer, tui.DoctorDrawer,
                    tui.SettingsDrawer, tui.PlanDrawer, tui.FailureDrawer,
                    tui.TraceDrawer, tui.AboutDrawer):
        active = asyncio.run(opens_below_floor(factory))
        assert active == "MissionControlScreen", f"{factory.__name__} must dismiss below the floor"

    # Help is the documented exception: it is one of the two actions left.
    assert asyncio.run(opens_below_floor(tui.HelpDrawer)) == "HelpDrawer"


def test_open_overlay_dismisses_when_resized_below_the_floor():
    _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await app.push_screen(tui.CoordinateDrawer())
            await pilot.pause()
            assert isinstance(app.screen, tui.CoordinateDrawer)
            await pilot.resize_terminal(59, 17)
            await pilot.pause()
            await pilot.pause()
            assert not isinstance(app.screen, tui.CoordinateDrawer), (
                "a drawer must dismiss when the terminal drops below the floor"
            )
            assert app.screen.has_class("too-small")
            assert "Terminal too small" in _svg_text(app)

    asyncio.run(scenario())


def test_coordinate_pane_declares_the_canonical_columns():
    from textual.widgets import DataTable

    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            table = app.screen.query_one("#coordinate-pane", DataTable)
            assert [str(column.label) for column in table.ordered_columns] == [
                "#", "status", "provider", "surface", "level", "mode",
                "method", "findings", "elapsed",
            ], "the coordinate pane must expose the canonical triage columns"

    asyncio.run(scenario())


def test_responsive_wide_medium_narrow_and_too_small():
    MissionControlScreen = _require("MissionControlScreen")

    async def wide() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            flags = _displays(screen)
            assert flags["#pipeline-pane"] and flags["#coordinate-pane"] and flags["#evidence-pane"]
            assert "TESIS" in _svg_text(app)
            assert screen.has_class("wide"), "core: wide layout must set the wide class"

    async def medium() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            screen = app.screen
            flags = _displays(screen)
            assert flags["#pipeline-pane"]
            assert not flags["#coordinate-pane"] and not flags["#evidence-pane"]
            assert flags["#triage-line"]
            assert screen.has_class("standard"), "core: medium layout must set the standard class"

    async def narrow() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(60, 18)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert _displays(screen)["#triage-line"]
            assert screen.has_class("narrow"), "core: narrow layout must set the narrow class"

    async def too_small() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(59, 17)) as pilot:
            await pilot.pause()
            screen = app.screen
            svg = _svg_text(app)
            assert "Terminal too small" in svg
            assert "60" in svg and "18" in svg
            assert "59" in svg and "17" in svg
            # Below the floor only quit/help stay reachable.
            footer = _pane_text(screen, "#context-footer").lower()
            assert "help" in footer and "quit" in footer
            for hidden in ("run", "matrix", "plan", "doctor", "coordinates", "evidence"):
                assert hidden not in footer, f"too-small footer must not offer {hidden!r}"
            assert not _displays(screen)["#pipeline-pane"]
            for key in ("r", "m", "p", "d", "/", "1", "2", "3"):
                await pilot.press(key)
                await pilot.pause()
                assert type(app.screen) is MissionControlScreen, (
                    f"{key!r} must do nothing below the 60x18 floor"
                )
            await pilot.press("?")
            await pilot.pause()
            assert isinstance(app.screen, tui.HelpDrawer), "help must stay reachable"
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()
            assert not app.is_running, "quit must stay reachable"

    asyncio.run(wide())
    asyncio.run(medium())
    asyncio.run(narrow())
    asyncio.run(too_small())


def test_drawers_take_the_screen_only_below_eighty_columns():
    _require("MissionControlScreen")

    async def scenario(size, expect_full: bool) -> None:
        app = tui.TesisApp()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await app.push_screen(tui.CoordinateDrawer())
            await pilot.pause()
            drawer = app.screen
            assert isinstance(drawer, tui.CoordinateDrawer)
            panel = drawer.query_one(".drawer")
            if expect_full:
                assert drawer.has_class("drawer-full")
                assert panel.region.x == 0 and panel.region.width == size[0], (
                    f"below 80 columns the drawer must own the screen; got {panel.region}"
                )
                assert not panel.styles.border_left[0] or panel.styles.border_left[0] == "none", (
                    "a full-screen drawer carries no dock border"
                )
            else:
                assert not drawer.has_class("drawer-full")
                assert panel.region.width == 76, (
                    f"a drawer must be a 76-cell panel; got {panel.region.width}"
                )
                assert panel.region.x == size[0] - 76, (
                    f"the drawer must dock right; got x={panel.region.x}"
                )
                assert panel.styles.border_left[0] == "solid", "the docked panel needs one left border"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario((140, 40), expect_full=False))
    asyncio.run(scenario((120, 36), expect_full=False))
    asyncio.run(scenario((80, 24), expect_full=False))
    asyncio.run(scenario((60, 18), expect_full=True))


def test_docked_drawer_leaves_the_mission_surface_visible():
    _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            mission = app.screen
            summary = _pane_text(mission, "#notice-text")
            assert summary, "mission surface must render before the drawer opens"
            await app.push_screen(tui.CoordinateDrawer())
            await pilot.pause()
            svg = _svg_text(app)
            assert "READY" in svg, "the mission status must stay visible beside the drawer"
            assert "pipeline" in svg.lower(), "the mission panes must stay visible beside the drawer"
            assert "Coordinates (Esc" in svg, "the drawer must render its own content"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_method_agent_row_shows_selected_method_on_screen():
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen._post_event(RunEvent("graph.state", message="snap", data={
                "selected_method": "sqli_union"}))
            await _drain(screen)
            await pilot.pause()
            assert "sqli_union" in _pane_text(screen, "#pipeline-pane"), (
                "method-agent row must substitute the selected method"
            )

    asyncio.run(scenario())


# ---------------------------------------------------------------- config / secrets (preserved)

def test_yaml_round_trip_preserves_comments_order_and_env_placeholders(tmp_path):
    from tesis.config_loader import dump_yaml_config, load_yaml_config, parse_yaml_config

    raw = (
        "# keep me\n"
        "target_url: http://localhost/dvwa\n"
        "provider: gemini\n"
        "level: low\n"
        "models:\n"
        "  gemini:\n"
        "    model_name: test-model\n"
        "    api_key: ${GEMINI_KEY}\n"
        "future_key: yes\n"
    )
    parsed = parse_yaml_config(raw)
    assert parsed["models"]["gemini"]["api_key"] == "${GEMINI_KEY}"
    assert list(parsed)[:3] == ["target_url", "provider", "level"]
    out = dump_yaml_config(parsed)
    assert "${GEMINI_KEY}" in out
    path = tmp_path / "config.yaml"
    path.write_text(raw, encoding="utf-8")
    assert load_yaml_config(path)["future_key"] == "yes"


def test_masked_secrets_restore_and_blank_stays_blank():
    masked, preserved = tui_security._mask_yaml_secrets({
        "models": {"gemini": {"api_key": "literal-secret-value", "model_name": "m"}},
    })
    assert "literal-secret-value" not in json.dumps(masked)
    assert preserved, "literal secret must produce a restorable placeholder"
    restored = tui_security._restore_yaml_secrets(masked, preserved)
    assert restored["models"]["gemini"]["api_key"] == "literal-secret-value"

    masked_blank, preserved_blank = tui_security._mask_yaml_secrets(
        {"models": {"gemini": {"api_key": ""}}})
    assert preserved_blank == {}
    assert masked_blank["models"]["gemini"]["api_key"] == ""


def test_settings_two_save_literal_secret_warning(tmp_path, monkeypatch):
    SettingsDrawer = _require("SettingsDrawer")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        "models:\n  gemini:\n    model_name: test-model\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(tui_state, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(SettingsDrawer())
            await pilot.pause()
            screen = app.screen
            screen.query_one("#yaml-editor").text = (
                "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
                "models:\n  gemini:\n    model_name: test-model\n    api_key: literal-secret-value\n"
            )
            save = screen.query_one("#settings-save")
            save.press()
            await pilot.pause()
            status = str(screen.query_one("#settings-status").render())
            assert "Save again" in status or "ENV_VAR" in status
            assert "literal-secret-value" not in status
            assert "literal-secret-value" not in config_path.read_text(encoding="utf-8")
            save.press()
            await pilot.pause()
            status = str(screen.query_one("#settings-status").render())
            assert "Saved" in status
            assert "literal-secret-value" not in status
            assert "literal-secret-value" in config_path.read_text(encoding="utf-8")
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_settings_rejects_bad_yaml_and_bad_concurrency(tmp_path, monkeypatch):
    SettingsDrawer = _require("SettingsDrawer")
    config_path = tmp_path / "config.yaml"
    original = "# keep\ntarget_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
    config_path.write_text(original, encoding="utf-8")
    monkeypatch.setattr(tui_state, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(SettingsDrawer())
            await pilot.pause()
            screen = app.screen
            screen.query_one("#yaml-editor").text = "key: [unterminated"
            screen.query_one("#settings-save").press()
            await pilot.pause()
            assert config_path.read_text(encoding="utf-8") == original
            assert "Not saved" in str(screen.query_one("#settings-status").render())
            screen.query_one("#yaml-editor").text = original + "llm_max_concurrency: 99\n"
            screen.query_one("#settings-save").press()
            await pilot.pause()
            assert config_path.read_text(encoding="utf-8") == original
            assert "Not saved" in str(screen.query_one("#settings-status").render())
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_config_error_text_redacts_secrets():
    text = tui_security._safe_config_error_text(RuntimeError("boom sk-live-abc123"))
    assert "sk-live-abc123" not in text


# ---------------------------------------------------------------- cancellation + run lifecycle

def test_ctrl_c_cancels_and_second_ctrl_c_exits(tmp_path, monkeypatch):
    from threading import Event

    MissionControlScreen = _require("MissionControlScreen")
    started = Event()
    release = Event()

    def blocked_single(**kwargs):
        started.set()
        release.wait(timeout=5)
        return {"status": "cancelled"}

    monkeypatch.setattr(tui_mission, "run_single_engagement", blocked_single)
    thread_ref: dict = {}

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            result = screen.start_run(_config(tmp_path), mode="single")
            if inspect.isawaitable(result):
                await result
            for _ in range(500):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            assert started.is_set()
            thread = getattr(screen, "_runtime_thread", None)
            assert thread is not None
            thread_ref["thread"] = thread
            assert thread.daemon
            await pilot.press("ctrl+c")
            await pilot.pause()
            assert screen.cancel_token.is_cancelled
            await pilot.press("ctrl+c")
            await pilot.pause()
            assert not app.is_running

    try:
        asyncio.run(asyncio.wait_for(scenario(), timeout=15))
    finally:
        release.set()
        if "thread" in thread_ref:
            thread_ref["thread"].join(timeout=2)


def test_q_quits_only_while_idle():
    _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()
            assert not app.is_running

    asyncio.run(scenario())


def test_q_refused_while_run_active(tmp_path, monkeypatch):
    from threading import Event

    MissionControlScreen = _require("MissionControlScreen")
    started = Event()
    release = Event()

    def blocked_single(**kwargs):
        started.set()
        release.wait(timeout=5)
        return {"status": "cancelled"}

    monkeypatch.setattr(tui_mission, "run_single_engagement", blocked_single)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen.start_run(_config(tmp_path), mode="single")
            for _ in range(500):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            assert started.is_set()
            await pilot.press("q")
            await pilot.pause()
            assert app.is_running, "q must not quit while a run is active"
            await pilot.press("ctrl+c")
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            assert not app.is_running

    try:
        asyncio.run(asyncio.wait_for(scenario(), timeout=15))
    finally:
        release.set()


def test_natural_run_completion_reaches_terminal_status(tmp_path, monkeypatch):
    MissionControlScreen = _require("MissionControlScreen")

    def silent_single(**kwargs):
        return {"status": "success"}

    monkeypatch.setattr(tui_mission, "run_single_engagement", silent_single)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen.start_run(_config(tmp_path), mode="single")
            thread = screen._runtime_thread
            assert thread is not None
            await _wait_for_thread(pilot, thread)
            await _drain(screen)
            await pilot.pause()
            assert not screen.run_active
            assert screen.state.status == "succeeded", (
                f"natural completion must reach succeeded, got {screen.state.status}"
            )

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))


def test_single_runner_receives_serialized_model_config(tmp_path, monkeypatch):
    MissionControlScreen = _require("MissionControlScreen")
    captured: dict[str, object] = {}

    def boundary_single(**kwargs):
        model_config = kwargs["model_config"]
        captured["model_config"] = dict(model_config)
        return {"status": "success"}

    config = _config(tmp_path)
    config.provider = "openai"
    config.models = {
        "openai": ModelConfig(
            "openai",
            "test-key",
            "test-model",
            extra={"nested": {"enabled": True}},
        )
    }
    monkeypatch.setattr(tui_mission, "run_single_engagement", boundary_single)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen.start_run(config, mode="single")
            thread = screen._runtime_thread
            assert thread is not None
            await _wait_for_thread(pilot, thread)
            await _drain(screen)
            await pilot.pause()
            assert screen.state.status == "succeeded"

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))
    model_config = captured["model_config"]
    assert isinstance(model_config, dict)
    assert model_config["provider"] == "openai"
    assert model_config["api_key"] == "test-key"
    assert model_config["extra"] == {"nested": {"enabled": True}}


def test_sink_emitted_terminal_event_drives_succeeded(tmp_path, monkeypatch):
    MissionControlScreen = _require("MissionControlScreen")

    def emitting_single(**kwargs):
        sink = kwargs.get("event_sink")
        if sink is not None:
            sink.emit(RunEvent("graph.node.completed", node="scorer", message="scored"))
            sink.emit(RunEvent("run.finished", message="done"))
        return {"status": "success"}

    monkeypatch.setattr(tui_mission, "run_single_engagement", emitting_single)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen.start_run(_config(tmp_path), mode="single")
            thread = screen._runtime_thread
            assert thread is not None
            await _wait_for_thread(pilot, thread)
            await _drain(screen)
            await pilot.pause()
            assert screen.state.status == "succeeded"
            assert "scorer" in _pane_text(screen, "#pipeline-pane").lower()

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))


def test_run_journal_records_terminal_status(tmp_path, monkeypatch):
    MissionControlScreen = _require("MissionControlScreen")

    def instant_single(**kwargs):
        return {"status": "success"}

    monkeypatch.setattr(tui_mission, "run_single_engagement", instant_single)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen.start_run(_config(tmp_path), mode="single")
            thread = screen._runtime_thread
            await _wait_for_thread(pilot, thread)
            await _drain(screen)
            await pilot.pause()
            journal = screen._journal_path
            assert journal is not None and journal.is_file()
            text = journal.read_text(encoding="utf-8")
            assert "succeeded" in text or "success" in text

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))


def test_run_mode_matrix_propagates_to_state(tmp_path, monkeypatch):
    MissionControlScreen = _require("MissionControlScreen")

    def instant_matrix(**kwargs):
        sink = kwargs.get("event_sink")
        if sink is not None:
            sink.emit(RunEvent("matrix.finished", message="done"))
        return {"status": "success"}

    monkeypatch.setattr(tui_mission, "run_provider_matrix", instant_matrix)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen.start_run(_config(tmp_path), mode="matrix")
            assert screen.state.run_mode == "matrix"
            thread = screen._runtime_thread
            await _wait_for_thread(pilot, thread)
            await _drain(screen)
            await pilot.pause()
            assert screen.state.run_mode == "matrix"

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))


# ---------------------------------------------------------------- artifacts / doctor / guards

def test_artifact_scan_without_raw_keeps_metadata_only(tmp_path):
    path = tmp_path / "run.json"
    path.write_text(json.dumps({
        "run_id": "run-1", "status": "success", "provider": "gemini",
        "surface": "sqli", "security_level": "low", "payload_mode": "hybrid",
        "config": {"target_url": "http://localhost/dvwa"},
        "execution_log": [{"event": "secret-detail"}],
    }), encoding="utf-8")
    items = ArtifactRepository(tmp_path).scan(retain_raw=False)
    assert len(items) == 1
    assert items[0].run_id == "run-1"
    assert items[0].config["target_url"] == "http://localhost/dvwa"
    assert dict(items[0].raw) == {}


def _write_artifact(directory: Path, run_id: str, **fields) -> Path:
    payload = {
        "run_id": run_id, "status": "success",
        "config": {"target_url": "http://localhost/dvwa", "provider": "gemini"},
        "selected_method": "sqli_union",
        "scores": {"composite": 3, "exploitation": 3},
        "confirmed_vulns": ["sqli"],
        "verifier_decision": "exploited",
    }
    payload.update(fields)
    path = directory / f"{run_id}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_results_drawer_lists_scanned_rows_promptly(tmp_path, monkeypatch):
    ResultsDrawer = _require("ResultsDrawer")
    artifact_dir = tmp_path / "results"
    artifact_dir.mkdir()
    for i in range(5):
        _write_artifact(artifact_dir, f"run-{i}")
    monkeypatch.setattr(tui_state, "CONFIG_PATH", tmp_path / "config.yaml")
    (tmp_path / "config.yaml").write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        f"output_dir: {artifact_dir}\n",
        encoding="utf-8",
    )

    async def scenario() -> None:
        from textual.widgets import DataTable

        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(ResultsDrawer())
            await pilot.pause()
            drawer = app.screen
            assert isinstance(drawer, ResultsDrawer)
            for _ in range(200):
                try:
                    if drawer.query_one("#results-table", DataTable).row_count >= 5:
                        break
                except Exception:
                    pass
                await asyncio.sleep(0.02)
            assert drawer.query_one("#results-table", DataTable).row_count >= 5
            summary = str(drawer.query_one("#results-summary").render())
            assert "5 artifacts" in summary
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))


def test_results_detail_is_triage_only_truncated_and_redacted(tmp_path, monkeypatch):
    ResultsDrawer = _require("ResultsDrawer")
    artifact_dir = tmp_path / "results"
    artifact_dir.mkdir()
    _write_artifact(artifact_dir, "run-1",
                    large_raw_field="x" * 600_000,
                    prompt="sk-live-prompt-secret",
                    chain_of_thought="think step by step")
    _write_artifact(artifact_dir, "run-nonscore", scores={})
    monkeypatch.setattr(tui_drawers, "DETAIL_LOG_MAX_LINES", 64)
    monkeypatch.setattr(tui_drawers, "DETAIL_RENDER_MAX_CHARS", 256)
    monkeypatch.setattr(tui_state, "CONFIG_PATH", tmp_path / "config.yaml")
    (tmp_path / "config.yaml").write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        f"output_dir: {artifact_dir}\n",
        encoding="utf-8",
    )

    async def scenario() -> None:
        from textual.widgets import DataTable

        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(ResultsDrawer())
            await pilot.pause()
            drawer = app.screen
            assert isinstance(drawer, ResultsDrawer)
            for _ in range(200):
                try:
                    if drawer.query_one("#results-table", DataTable).row_count >= 2:
                        break
                except Exception:
                    pass
                await asyncio.sleep(0.02)
            drawer._show_detail("run-1")
            await pilot.pause()
            detail = str(drawer.query_one("#results-detail").render())
            assert "run-1" in detail
            assert "sqli_union" in detail
            assert "sk-live-prompt-secret" not in detail
            assert "think step by step" not in detail
            assert "x" * 100 not in detail, "large raw payload must be truncated"
            assert "truncat" in detail.lower()
            drawer._show_detail("run-nonscore")
            await pilot.pause()
            missing = str(drawer.query_one("#results-detail").render())
            assert "—" in missing, "missing scores must render as —, never fabricated zeros"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))


def test_results_drawer_offers_filters_and_export(tmp_path, monkeypatch):
    ResultsDrawer = _require("ResultsDrawer")
    artifact_dir = tmp_path / "results"
    artifact_dir.mkdir()
    _write_artifact(artifact_dir, "run-1", provider="gemini")
    monkeypatch.setattr(tui_state, "CONFIG_PATH", tmp_path / "config.yaml")
    (tmp_path / "config.yaml").write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        f"output_dir: {artifact_dir}\n",
        encoding="utf-8",
    )

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(ResultsDrawer())
            await pilot.pause()
            svg = _svg_text(app).lower()
            assert "filter" in svg, "results drawer must expose status/provider/surface/level/mode filters"
            assert "export" in svg, "results drawer must expose an export action"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))


def test_stale_results_scan_never_overwrites_newer_render(tmp_path, monkeypatch):
    ResultsDrawer = _require("ResultsDrawer")
    artifact_dir = tmp_path / "results"
    artifact_dir.mkdir()
    _write_artifact(artifact_dir, "run-new")
    monkeypatch.setattr(tui_state, "CONFIG_PATH", tmp_path / "config.yaml")
    (tmp_path / "config.yaml").write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        f"output_dir: {artifact_dir}\n",
        encoding="utf-8",
    )

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(ResultsDrawer())
            await pilot.pause()
            drawer = app.screen
            assert isinstance(drawer, ResultsDrawer)
            current = drawer._scan_generation
            before = list(drawer._items)
            drawer._render_scan(current - 1, [], None)
            await pilot.pause()
            assert list(drawer._items) == before, "stale generation must not overwrite newer items"
            drawer.prepare_shutdown()
            drawer._render_scan(current + 1, [], None)
            await pilot.pause()
            assert list(drawer._items) == before, "closing drawer must ignore late renders"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))


def test_unmount_drops_pending_events_without_crash(tmp_path, monkeypatch):
    MissionControlScreen = _require("MissionControlScreen")

    def blocked_single(**kwargs):
        import time as _time

        _time.sleep(0.2)
        return {"status": "success"}

    monkeypatch.setattr(tui_mission, "run_single_engagement", blocked_single)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen.start_run(_config(tmp_path), mode="single")
            await pilot.pause()
            thread = screen._runtime_thread
            screen.prepare_shutdown()
            screen._post_event(RunEvent("graph.node.completed", node="scorer", message="late"))
            await _drain(screen)
            await pilot.pause()
            if thread is not None:
                await _wait_for_thread(pilot, thread)
            await pilot.press("ctrl+c")
            await pilot.pause()
            assert not app.is_running

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))


def test_doctor_offline_renders_structured_checks_with_counts(monkeypatch):
    DoctorDrawer = _require("DoctorDrawer")
    import tesis.doctor as doctor_mod

    def fake_doctor(_config, *, live=False):
        assert live is False
        return {
            "status": "failed",
            "summary": {"passed": 1, "failed": 1, "skipped": 1, "total": 3},
            "checks": [
                {"id": "akg", "category": "graph", "status": "passed",
                 "summary": "AKG topology is valid", "details": "9 methods covered"},
                {"id": "provider", "category": "llm", "status": "failed",
                 "summary": "Provider configuration is incomplete",
                 "remediation": "Set the provider API key"},
                {"id": "reach", "category": "target", "status": "skipped",
                 "summary": "Reachability skipped offline"},
            ],
        }

    monkeypatch.setattr(doctor_mod, "run_doctor", fake_doctor)
    monkeypatch.setattr(tui_drawers, "load_and_resolve_config", lambda **_kw: _config())

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(DoctorDrawer())
            await pilot.pause()
            thread = app.screen._doctor_thread
            if thread is not None:
                await _wait_for_thread(pilot, thread)
            await pilot.pause()
            svg = _svg_text(app)
            assert "AKG topology is valid" in svg
            assert "Set the provider API key" in svg
            assert "1 passed" in svg and "1 failed" in svg and "1 skipped" in svg
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_doctor_live_requires_explicit_confirmation(monkeypatch):
    DoctorDrawer = _require("DoctorDrawer")
    calls: list[bool] = []
    import tesis.doctor as doctor_mod

    def fake_doctor(_config, *, live=False):
        calls.append(live)
        return {"status": "passed", "summary": {"passed": 1, "failed": 0, "skipped": 0, "total": 1},
                "checks": [{"id": "live", "category": "target", "status": "passed", "summary": "ok"}]}

    monkeypatch.setattr(doctor_mod, "run_doctor", fake_doctor)
    monkeypatch.setattr(tui_drawers, "load_and_resolve_config", lambda **_kw: _config())

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(DoctorDrawer())
            await pilot.pause()
            drawer = app.screen
            assert isinstance(drawer, DoctorDrawer)
            live_calls_before = len([c for c in calls if c])
            drawer.run_live_pressed()
            await pilot.pause()
            svg = _svg_text(app)
            assert "confirm" in svg.lower(), "first live press must warn and require confirmation"
            assert len([c for c in calls if c]) == live_calls_before
            drawer.run_live_pressed()
            thread = drawer._doctor_thread
            if thread is not None:
                await _wait_for_thread(pilot, thread)
            await pilot.pause()
            assert any(calls), "second live press must run live checks"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))


def test_failure_drawer_leads_with_remediation_and_request_id():
    FailureDrawer = _require("FailureDrawer")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            failure = {
                "failure_class": "http_rejected", "provider": "openai",
                "endpoint": "https://example.com/v1/?k=v",
                "api_key": "sk-live-secret",
                "remediation": "Check the credential.",
                "request_id": "req-abc-123",
            }
            await app.push_screen(FailureDrawer(failure))
            await pilot.pause()
            body = _pane_text(app.screen, "#failure-body")
            assert body.startswith("Remediation:"), f"remediation must lead; got {body[:80]!r}"
            assert "req-abc-123" in body
            svg = _svg_text(app)
            assert "sk-live-secret" not in svg
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_plan_preview_resolves_values_and_fingerprint():
    PlanDrawer = _require("PlanDrawer")
    cfg = EngagementConfig(
        target_url="http://x/", provider="openai", level="low", matrix=True,
        providers=["openai"], levels=["low"], surfaces=["sqli"],
        payload_modes=["hybrid"], repeats=1,
    )

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(PlanDrawer(cfg))
            await pilot.pause()
            svg = _svg_text(app)
            assert "http://x/" in svg
            assert "openai" in svg
            assert "fingerprint" in svg.lower()
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_trace_paused_badge_selector_and_position_hold():
    TraceDrawer = _require("TraceDrawer")
    MissionControlScreen = _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            for i in range(10):
                screen._post_event(RunEvent("graph.node.completed", node="recon", message=f"evt-{i}"))
            await _drain(screen)
            await pilot.pause()
            await app.push_screen(TraceDrawer())
            await pilot.pause()
            first = _pane_text(app.screen, "#trace-body")
            assert "evt-9" in first
            for i in range(10, 15):
                screen._post_event(RunEvent("graph.node.completed", node="recon", message=f"evt-{i}"))
            await _drain(screen)
            await pilot.pause()
            try:
                badge = app.screen.query_one("#trace-new-badge")
                badge_text = str(badge.render())
            except Exception:
                raise AssertionError("core: trace needs a dedicated #trace-new-badge selector")
            assert "5" in badge_text or "new" in badge_text.lower()
            assert "evt-9" in _pane_text(app.screen, "#trace-body")

    asyncio.run(scenario())


# ---------------------------------------------------------------- drawer workflow

def test_launch_inputs_resolve_into_the_review(monkeypatch):
    LaunchDrawer = _require("LaunchDrawer")
    captured: list[dict] = []

    def resolver(*, config_path, cli_args):
        captured.append(dict(cli_args))
        cfg = _config()
        if cli_args.get("target"):
            cfg.target_url = cli_args["target"]
        if cli_args.get("provider"):
            cfg.provider = cli_args["provider"]
        return cfg

    monkeypatch.setattr(tui_forms, "load_and_resolve_config", resolver)

    async def scenario() -> None:
        from textual.widgets import Input, Select

        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(LaunchDrawer(mode="matrix"))
            await pilot.pause()
            drawer = app.screen
            drawer.query_one("#launch-field-target-url", Input).value = "http://edited/dvwa"
            drawer.query_one("#launch-field-provider", Select).value = "openai"
            await pilot.pause()
            drawer._goto_step(3)
            await pilot.pause()
            review = str(drawer.query_one("#launch-review").render())
            assert "http://edited/dvwa" in review
            assert "openai" in review
            assert captured[-1].get("target") == "http://edited/dvwa"
            assert captured[-1].get("provider") == "openai"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_settings_drawer_exposes_named_collapsible_sections(tmp_path, monkeypatch):
    SettingsDrawer = _require("SettingsDrawer")
    from textual.widgets import Collapsible

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        "models:\n  gemini:\n    model_name: test-model\n    api_key: sk-live-section-secret\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(tui_state, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(SettingsDrawer())
            await pilot.pause()
            drawer = app.screen
            titles = [str(section.title) for section in drawer.query(Collapsible)]
            for expected in ("Target & defaults", "Model profile", "LLM runtime",
                             "Policy & output", "Advanced YAML"):
                assert expected in titles, f"missing settings section {expected}"
            for selector in ("#settings-target-body", "#settings-model-body",
                             "#settings-llm-body", "#settings-policy-body"):
                text = str(drawer.query_one(selector).render())
                assert text.strip(), f"{selector} must summarize the resolved config"
                assert "sk-live-section-secret" not in text
            assert "sk-live-section-secret" not in _svg_text(app)
            assert drawer.query_one("#yaml-editor") is not None
            assert drawer.query_one("#settings-save").display
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_coordinate_drawer_filters_and_enter_inspects():
    CoordinateDrawer = _require("CoordinateDrawer")

    async def scenario() -> None:
        from textual.widgets import DataTable, Select

        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            state = app.screen.state
            tui.apply_run_event(state, RunEvent("run.started", message="go"))
            tui.apply_run_event(state, RunEvent("matrix.run.started", message="", data={
                "coordinate_index": 0, "coordinate_execution_id": "e0", "provider": "gemini",
                "surface": "sqli", "security_level": "low", "payload_mode": "hybrid"}))
            tui.apply_run_event(state, RunEvent("matrix.run.started", message="", data={
                "coordinate_index": 1, "coordinate_execution_id": "e1", "provider": "openai",
                "surface": "brute_force", "security_level": "high", "payload_mode": "static_only"}))
            tui.apply_run_event(state, RunEvent("matrix.run.finished", message="", data={
                "coordinate_index": 1, "coordinate_execution_id": "e1", "duration_ms": 1500,
                "selected_method": "bf_dictionary",
                "confirmed_vulns": ["brute_force_confirmed"]}))
            await app.push_screen(CoordinateDrawer())
            await pilot.pause()
            drawer = app.screen
            table = drawer.query_one("#coordinates-table", DataTable)
            assert [str(column.label) for column in table.ordered_columns][-1] == "Elapsed"
            assert table.row_count == 2
            drawer.query_one("#filter-provider", Select).value = "openai"
            await pilot.pause()
            assert table.row_count == 1, "provider filter must narrow the coordinate table"
            table.focus()
            table.move_cursor(row=0)
            await pilot.press("enter")
            await pilot.pause()
            detail = str(drawer.query_one("#coordinates-detail").render())
            assert "openai" in detail and "1.5s" in detail
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_evidence_and_failure_drawers_expand_selected_records():
    EvidenceDrawer = _require("EvidenceDrawer")
    FailureDrawer = _require("FailureDrawer")

    async def scenario() -> None:
        from textual.widgets import DataTable

        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            state = app.screen.state
            tui.apply_run_event(state, RunEvent("run.started", message="go"))
            tui.apply_run_event(state, RunEvent("graph.state", message="snap", data={
                "selected_method": "sqli_union", "confirmed_vulns": ["sqli"],
                "achieved_outcomes": ["credentials_extracted"],
                "verifier_decision": "exploited"}))
            await app.push_screen(EvidenceDrawer())
            await pilot.pause()
            evidence = app.screen
            records = evidence.query_one("#evidence-records", DataTable)
            assert records.row_count >= 3
            records.move_cursor(row=1)
            await pilot.press("enter")
            await pilot.pause()
            assert "sqli" in str(evidence.query_one("#evidence-detail").render())
            await pilot.press("escape")
            await pilot.pause()

            failure = {"failure_class": "http_rejected", "provider": "openai",
                       "endpoint": "https://example.com/v1/?k=v", "api_key": "sk-live-secret",
                       "remediation": "Check the credential.", "request_id": "req-abc-123"}
            await app.push_screen(FailureDrawer(failure))
            await pilot.pause()
            faults = app.screen
            rows = faults.query_one("#failure-records", DataTable)
            assert rows.row_count >= 3
            rows.move_cursor(row=0)
            await pilot.press("enter")
            await pilot.pause()
            detail = str(faults.query_one("#failure-detail").render())
            assert "req-abc-123" in detail
            assert "sk-live-secret" not in detail
            assert "sk-live-secret" not in _svg_text(app)
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_results_drawer_stacks_filters_at_eighty_columns(tmp_path, monkeypatch):
    ResultsDrawer = _require("ResultsDrawer")
    artifact_dir = tmp_path / "results"
    artifact_dir.mkdir()
    _write_artifact(artifact_dir, "run-1")
    monkeypatch.setattr(tui_state, "CONFIG_PATH", tmp_path / "config.yaml")
    (tmp_path / "config.yaml").write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        f"output_dir: {artifact_dir}\n",
        encoding="utf-8",
    )

    async def scenario() -> None:
        from textual.widgets import DataTable, Select

        # A drawer is a 76-cell panel whatever the terminal width, so the
        # filters stack in it at every size at or above the floor.
        for width, height in ((80, 24), (120, 36)):
            app = tui.TesisApp()
            async with app.run_test(size=(width, height)) as pilot:
                await pilot.pause()
                await app.push_screen(ResultsDrawer())
                await pilot.pause()
                drawer = app.screen
                assert drawer.query_one(".drawer").region.width == 76
                row = drawer.query_one("#results-filters")
                assert row.has_class("stacked"), (
                    f"{width}x{height} must stack the filters for the 76-cell panel"
                )
                selects = list(row.query(Select))
                assert len(selects) == 5, "all five filters stay available"
                widths = [select.size.width for select in selects]
                assert row.size.height >= 5, "stacked filters must occupy one row each"
                assert min(widths) >= 40, f"{width}-column filters must not clip: {widths}"
                table = drawer.query_one("#results-table", DataTable)
                columns = [column.get_render_width(table) for column in table.ordered_columns]
                assert sum(columns) <= table.size.width, (
                    f"{width}x{height} result columns must fit the panel: "
                    f"{sum(columns)} > {table.size.width}"
                )
                await pilot.press("escape")
                await pilot.pause()

    asyncio.run(asyncio.wait_for(scenario(), timeout=30))


def test_doctor_offline_checks_do_not_block_the_event_loop(monkeypatch):
    DoctorDrawer = _require("DoctorDrawer")
    from threading import Event

    import tesis.doctor as doctor_mod

    started = Event()
    release = Event()

    def slow_doctor(_config, *, live=False):
        started.set()
        release.wait(timeout=5)
        return {"status": "passed",
                "summary": {"passed": 1, "failed": 0, "skipped": 0, "total": 1},
                "checks": [{"id": "cfg", "category": "config", "status": "passed",
                            "summary": "ok"}]}

    monkeypatch.setattr(doctor_mod, "run_doctor", slow_doctor)
    monkeypatch.setattr(tui_drawers, "load_and_resolve_config", lambda **_kw: _config())

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(DoctorDrawer())
            # Opening Doctor must not block the loop even while checks are running.
            await asyncio.wait_for(pilot.pause(), timeout=3)
            assert started.wait(2), "offline checks must run on a worker thread"
            await asyncio.wait_for(pilot.press("escape"), timeout=3)
            await pilot.pause()
            release.set()

    try:
        asyncio.run(asyncio.wait_for(scenario(), timeout=15))
    finally:
        release.set()


def test_help_and_plan_drawers_render_aligned_registry_content(monkeypatch):
    HelpDrawer = _require("HelpDrawer")
    PlanDrawer = _require("PlanDrawer")
    monkeypatch.setattr(tui_drawers, "load_and_resolve_config", lambda **_kw: _config())

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(HelpDrawer())
            await pilot.pause()
            body = _pane_text(app.screen, "#help-body")
            for spec in tui.COMMANDS:
                assert f"/{spec.name}" in body
            await pilot.press("escape")
            await pilot.pause()
            await app.push_screen(PlanDrawer(config=_config()))
            await pilot.pause()
            plan = _pane_text(app.screen, "#plan-body")
            assert "fingerprint" in plan and "coordinates" in plan
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_failure_drawer_shows_production_failure_summary():
    FailureDrawer = _require("FailureDrawer")
    CommandLauncher = _require("CommandLauncher")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            tui.apply_run_event(screen.state, RunEvent("run.failed", message="boom sk-live-prod", data={
                "failure_class": "http_rejected", "provider": "openai",
                "remediation": "Check the credential.", "request_id": "req-prod-1"}))
            assert isinstance(screen.state.failure, tui.FailureSummary), (
                "production state carries the slotted FailureSummary dataclass"
            )
            launcher = CommandLauncher()
            await app.push_screen(launcher)
            await pilot.pause()
            launcher._dispatch("failure")
            await pilot.pause()
            drawer = app.screen
            assert isinstance(drawer, FailureDrawer)
            body = _pane_text(drawer, "#failure-body")
            assert body.startswith("Remediation:")
            assert "Check the credential." in body
            assert "http_rejected" in body
            assert "req-prod-1" in body
            assert "openai" in body
            assert "unknown" not in body, "dataclass fields must not be dropped to defaults"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_target_query_credentials_are_hidden_in_drawer_displays(tmp_path, monkeypatch):
    LaunchDrawer = _require("LaunchDrawer")
    PlanDrawer = _require("PlanDrawer")
    SettingsDrawer = _require("SettingsDrawer")
    secret_url = "http://172.19.48.1/dvwa/?api_key=QUERYSECRET123&token=TOK456"

    def resolver(**_kw):
        cfg = _config()
        cfg.target_url = secret_url
        return cfg

    monkeypatch.setattr(tui_forms, "load_and_resolve_config", resolver)
    monkeypatch.setattr(tui_drawers, "load_and_resolve_config", resolver)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(LaunchDrawer(mode="single"))
            await pilot.pause()
            drawer = app.screen
            drawer._goto_step(len(drawer.STEPS) - 1)
            await pilot.pause()
            review = str(drawer.query_one("#launch-review").render())
            assert "QUERYSECRET123" not in review
            assert "[REDACTED]" in review, "the redaction placeholder must stay visible in the drawer"
            assert "QUERYSECRET123" not in _svg_text(app)
            await pilot.press("escape")
            await pilot.pause()

            cfg = _config()
            cfg.target_url = secret_url
            await app.push_screen(PlanDrawer(config=cfg))
            await pilot.pause()
            plan = _pane_text(app.screen, "#plan-body")
            assert "QUERYSECRET123" not in plan
            assert "[REDACTED]" in plan
            assert "QUERYSECRET123" not in _svg_text(app)
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())

    # Settings: the YAML view masks URL credentials while save round-trips them.
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "# keep me\n"
        f"target_url: {secret_url}\n"
        "provider: gemini\nlevel: low\n"
        "models:\n  gemini:\n    model_name: test-model\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(tui_state, "CONFIG_PATH", config_path)

    async def settings_scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(SettingsDrawer())
            await pilot.pause()
            drawer = app.screen
            assert "QUERYSECRET123" not in str(drawer.query_one("#settings-target-body").render())
            assert "QUERYSECRET123" not in drawer.query_one("#yaml-editor").text
            assert "QUERYSECRET123" not in _svg_text(app)
            drawer.query_one("#settings-save").press()
            await pilot.pause()
            saved = config_path.read_text(encoding="utf-8")
            assert "QUERYSECRET123" in saved, "an untouched save must round-trip the original URL"
            assert "keep me" in saved, "comments must survive the masked round-trip"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(asyncio.wait_for(settings_scenario(), timeout=15))


def test_url_query_and_fragment_values_are_all_redacted_and_round_trip(tmp_path, monkeypatch):
    LaunchDrawer = _require("LaunchDrawer")
    SettingsDrawer = _require("SettingsDrawer")
    url = ("http://admin:hunter2@172.19.48.1/dvwa/"
           "?id=7&view=full&api_key=QUERYSECRET123&token=TOK456#session=FRAGSECRET")
    # Innocuous values must be masked too: the canonical contract redacts every
    # query/fragment value, not only credential-shaped keys.
    forbidden = ("id=7", "view=full", "QUERYSECRET123", "TOK456", "FRAGSECRET", "hunter2")

    def resolver(**_kw):
        cfg = _config()
        cfg.target_url = url
        return cfg

    monkeypatch.setattr(tui_forms, "load_and_resolve_config", resolver)
    monkeypatch.setattr(tui_drawers, "load_and_resolve_config", resolver)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(LaunchDrawer(mode="single"))
            await pilot.pause()
            drawer = app.screen
            drawer._goto_step(len(drawer.STEPS) - 1)
            await pilot.pause()
            review = str(drawer.query_one("#launch-review").render())
            svg = _svg_text(app)
            for needle in forbidden:
                assert needle not in review, f"launch review leaked {needle!r}"
                assert needle not in svg, f"screenshot leaked {needle!r}"
            # Keys and their order survive; every value is masked.
            assert "id=[REDACTED]&view=[REDACTED]&api_key=[REDACTED]&token=[REDACTED]" in review
            assert "session=[REDACTED]" in review
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "# keep me\n"
        f"target_url: {url}\n"
        "provider: gemini\nlevel: low\n"
        "models:\n  gemini:\n    model_name: test-model\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(tui_state, "CONFIG_PATH", config_path)

    async def settings_scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(SettingsDrawer())
            await pilot.pause()
            drawer = app.screen
            editor = drawer.query_one("#yaml-editor").text
            target_body = str(drawer.query_one("#settings-target-body").render())
            svg = _svg_text(app)
            for needle in forbidden:
                assert needle not in editor, f"yaml editor leaked {needle!r}"
                assert needle not in target_body, f"target summary leaked {needle!r}"
                assert needle not in svg, f"screenshot leaked {needle!r}"
            drawer.query_one("#settings-save").press()
            await pilot.pause()
            saved = config_path.read_text(encoding="utf-8")
            assert url in saved, "an untouched save must restore the exact original URL"
            assert "keep me" in saved, "comments must survive the masked round-trip"
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(asyncio.wait_for(settings_scenario(), timeout=15))


def test_launch_target_input_masks_configured_endpoint_and_omits_untouched_override(monkeypatch):
    LaunchDrawer = _require("LaunchDrawer")
    from textual.widgets import Input

    configured = "http://admin:hunter2@172.19.48.1/dvwa/?id=7&view=full&api_key=CFGSECRET"
    calls: list[dict] = []

    def resolver(*, config_path, cli_args):
        calls.append(dict(cli_args))
        cfg = _config()
        cfg.target_url = cli_args.get("target", configured)
        return cfg

    monkeypatch.setattr(tui_forms, "load_and_resolve_config", resolver)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(LaunchDrawer(mode="single"))
            await pilot.pause()
            drawer = app.screen
            field = drawer.query_one("#launch-field-target-url", Input)
            assert field.value == (
                "http://admin:[REDACTED]@172.19.48.1/dvwa/"
                "?id=[REDACTED]&view=[REDACTED]&api_key=[REDACTED]"
            ), "the configured endpoint must be seeded masked"
            for needle in ("CFGSECRET", "hunter2", "id=7", "view=full"):
                assert needle not in field.value
                assert needle not in _svg_text(app)
            assert "target" not in drawer._cli_args(), (
                "an untouched masked seed must not override the configured endpoint"
            )
            assert calls[-1].get("target") is None
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_launch_target_edit_keeps_visible_masked_and_overrides_with_raw(monkeypatch):
    LaunchDrawer = _require("LaunchDrawer")
    from textual.widgets import Input

    typed = "http://localhost/dvwa/?id=99&api_key=EDITSECRET&token=TOK"
    calls: list[dict] = []
    frozen: list[Any] = []

    def resolver(*, config_path, cli_args):
        calls.append(dict(cli_args))
        cfg = _config()
        cfg.target_url = cli_args.get("target", "http://localhost/dvwa")
        return cfg

    monkeypatch.setattr(tui_forms, "load_and_resolve_config", resolver)
    monkeypatch.setattr(tui.MissionControlScreen, "start_run",
                        lambda self, config, mode="single": frozen.append(config))

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(LaunchDrawer(mode="single"))
            await pilot.pause()
            drawer = app.screen
            field = drawer.query_one("#launch-field-target-url", Input)
            field.value = typed
            await pilot.pause()
            assert field.value == (
                "http://localhost/dvwa/?id=[REDACTED]&api_key=[REDACTED]&token=[REDACTED]"
            ), "the visible widget must be re-masked immediately"
            for needle in ("id=99", "EDITSECRET", "TOK"):
                assert needle not in field.value
                assert needle not in _svg_text(app)
            assert drawer._target_raw == typed, "the raw endpoint stays privately captured"
            assert calls[-1]["target"] == typed
            review = str(drawer.query_one("#launch-review").render())
            assert "EDITSECRET" not in review and "[REDACTED]" in review

            # Start must hand the resolved raw endpoint to the run.
            drawer._goto_step(len(drawer.STEPS) - 1)
            await pilot.pause()
            drawer.query_one("#launch-start").press()
            await pilot.pause()
            assert frozen and frozen[-1].target_url == typed

            # Reverting to the masked seed drops the override again.
            await app.push_screen(LaunchDrawer(mode="single"))
            await pilot.pause()
            reverted = app.screen
            reverted_field = reverted.query_one("#launch-field-target-url", Input)
            reverted_field.value = "http://localhost/dvwa/?id=SECOND&api_key=SEC2"
            await pilot.pause()
            assert reverted._target_raw is not None
            reverted_field.value = reverted._target_seed
            await pilot.pause()
            assert reverted._target_raw is None
            assert "target" not in reverted._cli_args()
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_launch_guardrail_controls_use_canonical_names_and_resolved_values(monkeypatch):
    LaunchDrawer = _require("LaunchDrawer")

    def resolver(**_kw):
        cfg = _config()
        cfg.evasion_enabled = True
        cfg.evasion_mode = "proactive"
        cfg.evasion_max_retries = 2
        cfg.evasion_cooldown_threshold = 4
        return cfg

    monkeypatch.setattr(tui_forms, "load_and_resolve_config", resolver)

    async def scenario() -> None:
        from textual.widgets import Checkbox, Input, Select

        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(LaunchDrawer(mode="single"))
            await pilot.pause()
            drawer = app.screen
            enabled = drawer.query_one("#launch-field-guardrail-retry-enabled", Checkbox)
            handling = drawer.query_one("#launch-field-guardrail-handling", Select)
            retries = drawer.query_one("#launch-field-guardrail-retry-max", Input)
            cooldown = drawer.query_one("#launch-field-guardrail-retry-cooldown-threshold", Input)
            assert enabled.value is True, "guardrail state must come from the resolved config"
            assert handling.value == "proactive"
            assert retries.value == "2"
            assert cooldown.value == "4"
            assert not list(drawer.query("#launch-field-evasion-enabled")), (
                "new TUI ids must use the canonical guardrail vocabulary"
            )
            submitted = drawer._cli_args()
            assert submitted["guardrail_retry_enabled"] is True
            assert submitted["guardrail_handling"] == "proactive"
            assert submitted["guardrail_retry_max"] == 2
            assert submitted["guardrail_retry_cooldown_threshold"] == 4
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


def test_launch_off_registry_select_value_degrades_to_blank(monkeypatch):
    LaunchDrawer = _require("LaunchDrawer")

    def resolver(**_kw):
        cfg = _config()
        cfg.experiment_condition = "legacy_condition"
        cfg.surface = "legacy_surface"
        return cfg

    monkeypatch.setattr(tui_forms, "load_and_resolve_config", resolver)

    async def scenario() -> None:
        from textual.widgets import Select

        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await app.push_screen(LaunchDrawer(mode="single"))
            await pilot.pause()
            drawer = app.screen
            condition = drawer.query_one("#launch-field-experiment-condition", Select)
            surface = drawer.query_one("#launch-field-surface", Select)
            assert condition.value is Select.NULL, "off-registry values must degrade to blank"
            assert surface.value is Select.NULL
            submitted = drawer._cli_args()
            assert "experiment_condition" not in submitted
            assert "surface" not in submitted
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(scenario())


# ---------------------------------------------------------------- themes / redaction

def test_mono_theme_registered_without_changing_default(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    mono_name = tui.SHELL_MONO_THEME_NAME
    assert mono_name == "tesis-mono"
    app = tui.TesisApp()
    assert mono_name in app.available_themes
    assert app.current_theme.name == "textual-dark"


def test_no_color_selects_mono_theme(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    mono_app = tui.TesisApp()
    assert mono_app.current_theme.name == "tesis-mono"


def test_no_secret_in_screenshot_from_live_state():
    MissionControlScreen = _require("MissionControlScreen")
    secret = "sk-live-screenshot-secret"

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, MissionControlScreen)
            screen._post_event(RunEvent("llm.failed", message="bad",
                                       data={"api_key": secret, "failure_class": "auth"}))
            await _drain(screen)
            await pilot.pause()
            svg = _svg_text(app)
            assert secret not in svg
            assert "TESIS" in svg

    asyncio.run(scenario())
