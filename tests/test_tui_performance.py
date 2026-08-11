"""Small performance-regression checks for the live TUI dashboard."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from threading import Event
from time import monotonic
from types import SimpleNamespace

from evaluation.runner import _RuntimeCallbackHandler
from tesis import tui
from tesis.artifact_repository import ArtifactMetadata, ArtifactRepository
from tesis.model_config import EngagementConfig, ModelConfig
from tesis.runtime_events import RunEvent


def _dashboard() -> tui.RuntimeDashboardScreen:
    config = EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="gemini",
        level="low",
        models={"gemini": ModelConfig("gemini", "", "test-model")},
    )
    return tui.RuntimeDashboardScreen(
        config,
        matrix=False,
        condition="linear_hybrid",
        target_method=None,
    )


def test_high_volume_token_events_are_coalesced_into_small_ui_batches(monkeypatch) -> None:
    screen = _dashboard()
    received: list[RunEvent] = []
    monkeypatch.setattr(screen, "_consume_runtime_event", received.append)
    monkeypatch.setattr(screen, "set_timer", lambda *_args, **_kwargs: None)

    event_count = 2_048
    screen._pending_events.extend(
        RunEvent("llm.token", message="x", data={"call_id": "same-call"})
        for _ in range(event_count)
    )
    screen._event_flush_scheduled = True

    while screen._pending_events:
        screen._flush_event_batch()

    assert len(received) == (event_count + tui.UI_EVENT_BATCH_SIZE - 1) // tui.UI_EVENT_BATCH_SIZE
    assert all(event.event_type == "llm.token" for event in received)
    assert sum(event.data["ui_chunk_count"] for event in received) == event_count
    assert all(event.data["ui_chunk_count"] <= tui.UI_EVENT_BATCH_SIZE for event in received)


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


def test_dashboard_ingress_is_bounded_and_preserves_terminal_events(monkeypatch) -> None:
    screen = _dashboard()
    scheduler = SimpleNamespace(call_from_thread=lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tui.RuntimeDashboardScreen, "app", scheduler, raising=False)

    maximum_seen = 0
    for index in range(tui.UI_PENDING_EVENT_MAX):
        screen._post_event(RunEvent("graph.node.started", node=f"node-{index}"))
        maximum_seen = max(maximum_seen, len(screen._pending_events))

    terminal = RunEvent("run.finished", message="finished")
    screen._post_event(terminal)
    maximum_seen = max(maximum_seen, len(screen._pending_events))

    for index in range(tui.UI_PENDING_EVENT_MAX * 2):
        screen._post_event(RunEvent("graph.node.started", node=f"flood-{index}"))
        maximum_seen = max(maximum_seen, len(screen._pending_events))

    assert maximum_seen <= tui.UI_PENDING_EVENT_MAX
    assert len(screen._pending_events) == tui.UI_PENDING_EVENT_MAX
    assert any(event is terminal for event in screen._pending_events)


def test_artifact_scan_without_raw_payload_keeps_metadata_only(tmp_path) -> None:
    artifact_path = tmp_path / "run.json"
    artifact_path.write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "status": "success",
                "provider": "gemini",
                "surface": "sqli",
                "security_level": "low",
                "payload_mode": "hybrid",
                "config": {"target_url": "http://localhost/dvwa"},
                "execution_log": [{"event": "secret-detail"}],
            }
        ),
        encoding="utf-8",
    )

    items = ArtifactRepository(tmp_path).scan(retain_raw=False)

    assert len(items) == 1
    assert items[0].run_id == "run-1"
    assert items[0].config["target_url"] == "http://localhost/dvwa"
    assert items[0].raw == {}


def test_result_detail_renders_active_tab_lazily_and_truncates_raw(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(tui.ResultDetailScreen, "_load_artifact", lambda self: None)
    monkeypatch.setattr(tui, "DETAIL_LOG_MAX_LINES", 64)
    monkeypatch.setattr(tui, "DETAIL_RENDER_MAX_CHARS", 256)
    metadata = ArtifactMetadata(
        path=Path(tmp_path) / "run.json",
        execution_id="exec-1",
        status="success",
    )
    artifact = {
        "status": "success",
        "config": {"target_url": "http://localhost/dvwa"},
        "timing": {"duration_ms": 10},
        "large_raw_field": "x" * 32_768,
    }

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause()
            screen = tui.ResultDetailScreen(metadata)
            app.push_screen(screen)
            await pilot.pause()

            screen._artifact_loaded(artifact, None)
            await pilot.pause()
            tabs = screen.query_one("#result-tabs", tui.TabbedContent)
            assert tabs.active == "result-tab-overview"
            assert screen.rendered_tabs == {"overview"}
            assert len(screen.query_one("#detail-overview", tui.RichLog).lines) > 0
            assert not screen.query_one("#detail-scores", tui.RichLog).lines
            assert not screen.query_one("#detail-raw", tui.RichLog).lines

            tabs.active = "result-tab-raw"
            await pilot.pause()
            raw = screen.query_one("#detail-raw", tui.RichLog)
            assert "raw" in screen.rendered_tabs
            assert any("live view truncated" in str(line) for line in raw.lines)
            assert len(raw.lines) <= tui.DETAIL_LOG_MAX_LINES

    asyncio.run(scenario())


def test_trace_buffer_retains_recent_entries_with_bounded_memory() -> None:
    screen = _dashboard()

    for index in range(tui.TRACE_BUFFER_MAX_ENTRIES * 2):
        screen._append_trace(f"short-entry-{index}")

    assert len(screen._trace_entries) <= tui.TRACE_BUFFER_MAX_ENTRIES
    assert screen._trace_chars <= tui.TRACE_BUFFER_MAX_CHARS
    assert screen._trace_dropped > 0
    assert screen._trace_entries[-1] == "short-entry-1999"

    for index in range(600):
        screen._append_trace(f"large-entry-{index}-" + ("x" * 2_048))

    assert len(screen._trace_entries) <= tui.TRACE_BUFFER_MAX_ENTRIES
    assert screen._trace_chars <= tui.TRACE_BUFFER_MAX_CHARS
    assert screen._trace_entries[-1].startswith("large-entry-599-")


def test_dashboard_rich_logs_have_hard_line_limits(monkeypatch) -> None:
    monkeypatch.setattr(tui.RuntimeDashboardScreen, "run_experiment", lambda self: None)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause()
            screen = _dashboard()
            app.push_screen(screen)
            await pilot.pause()

            stream = screen.query_one("#stream-log", tui.RichLog)
            trace = screen.query_one("#trace-log", tui.RichLog)
            trace.remove_class("hidden")
            await pilot.pause()

            for index in range(tui.STREAM_LOG_MAX_LINES + 25):
                stream.write(f"stream-{index}")
            for index in range(tui.TRACE_LOG_MAX_LINES + 25):
                trace.write(f"trace-{index}")
            await pilot.pause()

            assert stream.max_lines == tui.STREAM_LOG_MAX_LINES
            assert trace.max_lines == tui.TRACE_LOG_MAX_LINES
            assert len(stream.lines) <= tui.STREAM_LOG_MAX_LINES
            assert len(trace.lines) <= tui.TRACE_LOG_MAX_LINES

    asyncio.run(scenario())


def test_main_menu_q_exits_promptly() -> None:
    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            started = monotonic()
            await pilot.press("q")
            await pilot.pause()
            elapsed = monotonic() - started
            assert not app.is_running
            assert elapsed < 1.0

    asyncio.run(scenario())


def test_blocked_runtime_shutdown_is_prompt_and_worker_is_daemon(monkeypatch) -> None:
    operation_started = Event()
    release_operation = Event()
    runtime_thread = None

    def blocked_engagement(**_kwargs):
        operation_started.set()
        release_operation.wait()
        return {"status": "cancelled"}

    monkeypatch.setattr(tui, "run_single_engagement", blocked_engagement)

    async def scenario() -> None:
        nonlocal runtime_thread
        app = tui.TesisApp()
        started = monotonic()
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause()
            screen = _dashboard()
            app.push_screen(screen)
            for _ in range(100):
                if operation_started.is_set():
                    break
                await asyncio.sleep(0.01)
            assert operation_started.is_set()
            runtime_thread = screen._runtime_thread
            assert runtime_thread is not None
            assert runtime_thread.daemon

            screen._post_event(RunEvent("graph.node.started", node="queued"))
            screen._append_trace("queued trace")
            await pilot.pause()

            await pilot.press("ctrl+c")
            await pilot.pause()
            assert screen.cancel_token.is_cancelled
            await pilot.press("ctrl+c")
            await pilot.pause()
            assert not app.is_running
            assert not screen._pending_events
            assert not screen._trace_entries
        assert monotonic() - started < 1.5

    try:
        asyncio.run(asyncio.wait_for(scenario(), timeout=2.0))
    finally:
        release_operation.set()
        if runtime_thread is not None:
            runtime_thread.join(timeout=1.0)
