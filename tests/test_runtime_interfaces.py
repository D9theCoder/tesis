"""Focused contract tests for runtime events and artifact discovery."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor

import pytest

from tesis.artifact_repository import config_fingerprint
from tesis.runtime_events import (
    CancellationRequested,
    CancellationToken,
    CollectingRuntimeEventSink,
    RunEvent,
)


def test_event_sink_preserves_order_and_collects_concurrent_events() -> None:
    """Events stay in emission order and concurrent producers lose nothing."""

    sink = CollectingRuntimeEventSink()
    for event_type in ("run.started", "graph.node.started", "run.completed"):
        sink.emit(RunEvent(event_type, data={"sequence": len(sink)}))

    assert [event.event_type for event in sink.snapshot()] == [
        "run.started",
        "graph.node.started",
        "run.completed",
    ]
    assert [event.data["sequence"] for event in sink.events] == [0, 1, 2]

    def emit_worker(worker: int) -> None:
        for index in range(25):
            sink.emit(RunEvent("llm.token", data={"worker": worker, "index": index}))

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(emit_worker, range(8)))

    concurrent_events = sink.snapshot()[3:]
    assert len(concurrent_events) == 8 * 25
    assert {(event.data["worker"], event.data["index"]) for event in concurrent_events} == {
        (worker, index) for worker in range(8) for index in range(25)
    }


def test_cancellation_token_is_cooperative_and_one_shot() -> None:
    token = CancellationToken()

    assert not token.is_cancelled
    assert token.cancel("user requested stop")
    assert not token.cancel("a later reason is ignored")
    assert token.cancelled
    assert token.reason == "user requested stop"
    assert token.wait(0)

    with pytest.raises(CancellationRequested, match="stop") as raised:
        token.check()
    assert raised.value.reason == "user requested stop"


def test_config_fingerprint_excludes_secrets_and_execution_identity() -> None:
    config = {
        "provider": "openai",
        "model": "gpt-5",
        "surface": "sqli",
        "payload_mode": "hybrid",
        "candidate_budget": 4,
        "target_url": "http://dvwa.test/login.php?api_key=query-secret&mode=low",
        "api_key": "secret-a",
        "execution_id": "exec-a",
        "run_id": "logical-a",
        "repeat_index": 0,
        "output_path": "/tmp/first.json",
        "timing": {"started_at": "2026-01-01T00:00:00Z", "duration_ms": 10},
    }
    repeated = copy.deepcopy(config)
    repeated.update(
        {
            "api_key": "secret-b",
            "execution_id": "exec-b",
            "run_id": "logical-b",
            "repeat_index": 3,
            "output_path": "/tmp/second.json",
            "timing": {"started_at": "2027-01-01T00:00:00Z", "duration_ms": 99},
        }
    )

    first = config_fingerprint(config)
    second = config_fingerprint(repeated)

    assert first.startswith("sha256:")
    assert first == second
    assert "secret-a" not in first
    assert "secret-b" not in second

    changed_setup = copy.deepcopy(config)
    changed_setup["candidate_budget"] = 5
    assert config_fingerprint(changed_setup) != first
