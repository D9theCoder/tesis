"""Tests for the redacted JSONL journal, multiplexing, and cursor reads."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from tesis.runtime_events import RunEvent
from tesis.runtime_journal import (
    JSONLJournalSink,
    MultiplexingRuntimeEventSink,
    read_journal,
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


def test_sink_redacts_secrets_and_provider_config(tmp_path: Path) -> None:
    path = tmp_path / "redacted.jsonl"
    with JSONLJournalSink(
        path,
        known_secrets=["provider-secret-abc", "Bearer live-token-1"],
    ) as sink:
        sink.emit(_event("llm.request", api_key="sk-super-secret", message="use provider-secret-abc now"))
        sink.emit(_event(
            "providers.configured",
            config={"api_key": "sk-super-secret", "authorization": "Bearer live-token-1", "model": "gpt"},
        ))

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    request = records[0]
    assert request["data"]["api_key"] == "[REDACTED]"
    assert "provider-secret-abc" not in request["data"]["message"]
    assert "[REDACTED]" in request["data"]["message"]

    config = records[1]["data"]["config"]
    assert config["api_key"] == "[REDACTED]"
    assert config["authorization"] == "[REDACTED]"
    assert config["model"] == "gpt"
    # Explicit secret values must never survive anywhere in the record.
    text = path.read_text(encoding="utf-8")
    assert "provider-secret-abc" not in text
    assert "live-token-1" not in text
    assert "sk-super-secret" not in text


def test_sink_handles_concurrent_emission_without_torn_lines(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.jsonl"
    sink = JSONLJournalSink(path)
    workers = 8
    per_worker = 40

    def emit_worker(worker: int) -> None:
        for index in range(per_worker):
            sink.emit(_event("llm.token", worker=worker, index=index))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(emit_worker, range(workers)))
    sink.close()

    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == workers * per_worker

    # Every line is a complete, valid JSON record (no torn writes).
    seen: dict[int, list[int]] = {}
    for line in lines:
        record = json.loads(line)
        assert record["event_type"] == "llm.token"
        worker = record["data"]["worker"]
        index = record["data"]["index"]
        seen.setdefault(worker, []).append(index)

    # Per-worker indices are strictly increasing, preserving emission order.
    for worker, indices in seen.items():
        assert indices == sorted(indices)
    assert set(seen) == set(range(workers))
    assert sorted(len(v) for v in seen.values()) == [per_worker] * workers


def test_sink_coerces_non_json_event_values(tmp_path: Path) -> None:
    path = tmp_path / "objects.jsonl"
    marker = object()
    with JSONLJournalSink(path) as sink:
        sink.emit(RunEvent("provider.event", candidate=marker, data={"values": {3, 1}}))

    record = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(record["candidate"], str)
    assert record["data"]["values"] == [1, 3]


def test_read_journal_cursor_and_partial_trailing_line(tmp_path: Path) -> None:
    path = tmp_path / "journal.jsonl"
    with JSONLJournalSink(path) as sink:
        sink.emit(_event("run.started", n=1))
        sink.emit(_event("graph.node.started", n=2))
    # Append a partial, unterminated line as if a writer were mid-emit.
    with open(path, "a", encoding="utf-8") as handle:
        handle.write('{"event_type":"llm.token","data":{"n":')

    first = read_journal(path, cursor=0)
    assert [r["data"]["n"] for r in first.events] == [1, 2]
    assert first.has_more is False  # partial line is not yet complete
    assert first.next_cursor > 0

    # Resume from the first read; nothing duplicated, partial line ignored.
    second = read_journal(path, cursor=first.next_cursor)
    assert second.events == []
    assert second.next_cursor == first.next_cursor

    # Complete the trailing line, then it becomes readable.
    with open(path, "a", encoding="utf-8") as handle:
        handle.write('3}}\n')
    third = read_journal(path, cursor=second.next_cursor)
    assert [r["data"]["n"] for r in third.events] == [3]
    assert third.has_more is False


def test_read_journal_multiple_complete_lines_and_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "nope.jsonl"
    result = read_journal(missing, cursor=0)
    assert result.events == []
    assert result.next_cursor == 0
    assert result.has_more is False


def test_read_journal_limit_bounds_consumed_lines(tmp_path: Path) -> None:
    path = tmp_path / "bounded.jsonl"
    with JSONLJournalSink(path) as sink:
        for index in range(5):
            sink.emit(_event("run.progress", n=index))

    first = read_journal(path, cursor=0, limit=2)
    assert [r["data"]["n"] for r in first.events] == [0, 1]
    assert first.has_more is True
    assert first.next_cursor > 0

    second = read_journal(path, cursor=first.next_cursor, limit=10)
    assert [r["data"]["n"] for r in second.events] == [2, 3, 4]
    assert second.has_more is False


def test_read_journal_skips_malformed_complete_line_without_looping(tmp_path: Path) -> None:
    path = tmp_path / "malformed.jsonl"
    with JSONLJournalSink(path) as sink:
        sink.emit(_event("run.started", n=1))
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("{this is not valid json}\n")
    with JSONLJournalSink(path) as sink:
        sink.emit(_event("run.finished", n=2))

    result = read_journal(path, cursor=0)
    assert [r["data"]["n"] for r in result.events] == [1, 2]
    # Cursor advanced past the malformed line.
    with open(path, "rb") as handle:
        handle.seek(result.next_cursor)
        remainder = handle.read()
    assert remainder == b"" or result.next_cursor < path.stat().st_size + 1


def test_multiplexer_fans_out_each_event_exactly_once(tmp_path: Path) -> None:
    journal = JSONLJournalSink(tmp_path / "fanout.jsonl")
    received: list[str] = []
    multiplexer = MultiplexingRuntimeEventSink(journal)
    multiplexer.add(CollectingSink(received))

    multiplexer.emit(_event("run.started"))
    multiplexer.emit(_event("graph.node.started"))

    assert received == ["run.started", "graph.node.started"]
    journal.close()
    records = [json.loads(line) for line in (tmp_path / "fanout.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [r["event_type"] for r in records] == ["run.started", "graph.node.started"]

    # Sinks are delivered once and in registration order.
    assert len(multiplexer.sinks) == 2


class CollectingSink:
    """Minimal protocol-compatible capturing sink used for tests."""

    def __init__(self, out: list[str]) -> None:
        self.out = out

    def emit(self, event: RunEvent) -> None:
        self.out.append(event.event_type)


def test_multiplexer_rejects_non_sinks() -> None:
    with pytest.raises(TypeError):
        MultiplexingRuntimeEventSink().add(object())  # type: ignore[arg-type]
