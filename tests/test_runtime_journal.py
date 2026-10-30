"""Tests for the redacted JSONL journal, multiplexing, and cursor reads."""

from __future__ import annotations

import json
from pathlib import Path


from tesis.runtime_events import RunEvent
from tesis.runtime_journal import (
    JSONLJournalSink,
)


def _event(event_type: str, **data: object) -> RunEvent:
    return RunEvent(event_type, data=data)


def test_sink_writes_one_redacted_jsonl_line_per_event(tmp_path: Path) -> None:
    path = tmp_path / "runtime.events.jsonl"
    with JSONLJournalSink(path) as sink:
        sink.emit(_event("run.started", sequence=0))
        sink.emit(_event("graph.node.started", sequence=1))

    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 2
    assert [json.loads(line)["event_type"] for line in lines] == [
        "run.started",
        "graph.node.started",
    ]
    assert [json.loads(line)["data"]["sequence"] for line in lines] == [0, 1]
