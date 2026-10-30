"""Mission-control behavioral contracts.

Handoff: docs/active/HANDOFF_TUI_MISSION_CONTROL_REDESIGN_2026-09-21.md.
Only observable behavior is asserted. Visual/PTY verification (themes,
mouse, screenshots, exhaustive drawer interaction) is intentionally out
of scope here.
"""

from __future__ import annotations

import asyncio
from pathlib import Path


from tesis import tui, tui_mission
from tesis.model_config import EngagementConfig, ModelConfig
from tesis.runtime_events import RunEvent


# ---------------------------------------------------------------- helpers


def _require(name: str):
    value = getattr(tui, name, None)
    assert value is not None, f"core: tesis.tui.{name} missing (handoff contract)"
    return value


def _config(tmp_path: Path | None = None) -> EngagementConfig:
    kwargs: dict = {
        "target_url": "http://localhost/dvwa",
        "provider": "openai_compatible",
        "level": "low",
        "models": {"openai_compatible": ModelConfig(
            "openai_compatible", "", "test-model", base_url="http://localhost:9999/v1",
        )},
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
        # Flush the batched render deterministically before reading widgets.
        timer = getattr(screen, "_render_timer", None)
        if timer is not None:
            timer.stop()
        screen._flush_render()
        await asyncio.sleep(0)


def _pane_text(screen, selector: str) -> str:
    from textual.widgets import Static, OptionList

    try:
        widget = screen.query_one(selector)
        if isinstance(widget, OptionList):
            return "\n".join(str(widget.get_option_at_index(i).prompt) for i in range(widget.option_count))
        if isinstance(widget, Static):
            return str(widget.render())
        return "\n".join(str(child.render()) for child in widget.query(Static))
    except Exception:
        return ""


# ---------------------------------------------------------------- root


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
            assert "api_key=" in _pane_text(screen, "#notice-text")

    asyncio.run(scenario())


# ---------------------------------------------------------------- operator state


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


def test_cancel_is_sticky_against_late_finish():
    state = _fresh_state()
    _apply(state, RunEvent("run.started", message="go"))
    _apply(state, RunEvent("run.cancelled", message="user cancel"))
    _apply(state, RunEvent("run.finished", message="late"))
    assert state.status == "cancelled", "cancelled is terminal; late finish must not overwrite it"


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


# ---------------------------------------------------------------- commands + launcher


# Exact registry keymap. A key is listed only when the screen binds it, so the
# footer and the `?` help can never advertise a keystroke that does nothing.


# ---------------------------------------------------------------- responsive


# ---------------------------------------------------------------- config / secrets (preserved)


# ---------------------------------------------------------------- cancellation + run lifecycle


# ---------------------------------------------------------------- artifacts / doctor / guards


# ---------------------------------------------------------------- drawer workflow


# ---------------------------------------------------------------- themes / redaction


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
