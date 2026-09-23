"""Performance smoke checks for the mission-control TUI.

Throughput and shutdown behavior only. Operator-state correctness
(bounded notices, token suppression, terminal-status survival) lives in
tests/test_tui.py; this file asserts no duplicate state contracts.
Thresholds are generous smoke bounds, not benchmarks.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from threading import Event
from time import monotonic

from evaluation.runner import _RuntimeCallbackHandler
from tesis import tui, tui_mission, tui_state
from tesis.model_config import EngagementConfig, ModelConfig
from tesis.runtime_events import RunEvent


def _require(name: str):
    value = getattr(tui, name, None)
    assert value is not None, f"core: tesis.tui.{name} missing (handoff contract)"
    return value


def test_event_throughput_smoke():
    state = tui.TuiRunState()
    tui.apply_run_event(state, RunEvent("run.started", message="go"))
    started = monotonic()
    for i in range(2_000):
        tui.apply_run_event(state, RunEvent("graph.node.started", node="recon", message=f"evt-{i}"))
    elapsed = monotonic() - started
    assert elapsed < 10.0, f"2000 events took {elapsed:.2f}s"


def test_runtime_callback_batches_thousands_of_tokens_without_loss() -> None:
    emitted: list[tuple[str, dict[str, object]]] = []
    handler = _RuntimeCallbackHandler(
        lambda event_type, **payload: emitted.append((event_type, payload)),
        provider="test-provider",
    )
    tokens = ["0123456789"[index % 10] for index in range(8_192)]
    call_id = "rapid-call"

    for token in tokens:
        handler.on_llm_new_token(token, run_id=call_id)
    handler.on_llm_end("", run_id=call_id)

    token_events = [payload for event_type, payload in emitted if event_type == "llm.token"]
    assert len(token_events) < len(tokens) // 10
    assert "".join(str(payload["message"]) for payload in token_events) == "".join(tokens)
    assert all(payload["data"]["call_id"] == call_id for payload in token_events)


def test_results_drawer_lists_many_artifacts_promptly(tmp_path: Path) -> None:
    ResultsDrawer = _require("ResultsDrawer")
    for i in range(60):
        (tmp_path / f"run-{i}.json").write_text(
            '{"run_id": "run-%d", "status": "success", '
            '"config": {"target_url": "http://localhost/dvwa"}}' % i,
            encoding="utf-8",
        )
    (tmp_path / "config.yaml").write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        f"output_dir: {tmp_path}\n",
        encoding="utf-8",
    )

    async def scenario() -> None:
        from unittest.mock import patch

        from textual.widgets import DataTable

        with patch.object(tui_state, "CONFIG_PATH", tmp_path / "config.yaml"):
            app = tui.TesisApp()
            started = monotonic()
            async with app.run_test(size=(120, 36)) as pilot:
                await pilot.pause()
                await app.push_screen(ResultsDrawer())
                await pilot.pause()
                drawer = app.screen
                assert isinstance(drawer, ResultsDrawer)
                for _ in range(300):
                    try:
                        if drawer.query_one("#results-table", DataTable).row_count >= 60:
                            break
                    except Exception:
                        pass
                    await asyncio.sleep(0.02)
                assert drawer.query_one("#results-table", DataTable).row_count >= 60
                assert monotonic() - started < 10.0
                assert drawer._scan_thread is None or drawer._scan_thread.daemon
                await pilot.press("escape")
                await pilot.pause()

    asyncio.run(asyncio.wait_for(scenario(), timeout=20))


def test_idle_quit_exits_promptly() -> None:
    _require("MissionControlScreen")

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            started = monotonic()
            await pilot.press("q")
            await pilot.pause()
            elapsed = monotonic() - started
            assert not app.is_running
            assert elapsed < 2.0

    asyncio.run(scenario())


def test_blocked_runtime_shutdown_is_prompt_and_worker_is_daemon(tmp_path: Path) -> None:
    from unittest.mock import patch

    MissionControlScreen = _require("MissionControlScreen")
    operation_started = Event()
    release_operation = Event()
    runtime_thread = None

    def blocked_engagement(**_kwargs):
        operation_started.set()
        release_operation.wait(timeout=5)
        return {"status": "cancelled"}

    async def scenario() -> None:
        nonlocal runtime_thread
        with patch.object(tui_mission, "run_single_engagement", blocked_engagement):
            config = EngagementConfig(
                target_url="http://localhost/dvwa", provider="gemini", level="low",
                output_dir=str(tmp_path / "results"),
                models={"gemini": ModelConfig("gemini", "", "test-model")},
            )
            app = tui.TesisApp()
            started = monotonic()
            async with app.run_test(size=(120, 36)) as pilot:
                await pilot.pause()
                screen = app.screen
                assert isinstance(screen, MissionControlScreen)
                screen.start_run(config, mode="single")
                for _ in range(500):
                    if operation_started.is_set():
                        break
                    await asyncio.sleep(0.01)
                assert operation_started.is_set()
                runtime_thread = screen._runtime_thread
                assert runtime_thread is not None
                assert runtime_thread.daemon

                await pilot.press("ctrl+c")
                await pilot.pause()
                assert screen.cancel_token.is_cancelled
                await pilot.press("ctrl+c")
                await pilot.pause()
                assert not app.is_running
            assert monotonic() - started < 10.0

    try:
        asyncio.run(asyncio.wait_for(scenario(), timeout=20))
    finally:
        release_operation.set()
        if runtime_thread is not None:
            runtime_thread.join(timeout=2.0)
