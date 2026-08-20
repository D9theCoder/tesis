"""UI-independent redacted JSONL runtime journal and multiplexing sink.

This module provides an append-only, thread-safe journal sink that records one
redacted :class:`~tesis.runtime_events.RunEvent` per JSONL line, a small
multiplexing sink so existing UI callbacks and the journal receive the same
event exactly once, and cursor-based readers that tolerate a partially written
trailing line.

It intentionally does not depend on Textual or any presentation framework, and
it leaves the existing enriched ``.events.jsonl`` behavior untouched.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Iterable, Mapping

from tesis.runtime_events import (
    REDACTED,
    RunEvent,
    RuntimeEventSink,
    redact_secrets,
)


def _json_safe(value: Any) -> Any:
    """Convert a redacted event value into strict JSON-compatible data."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_json_safe(item) for item in value), key=repr)
    return str(value)


class JSONLJournalSink:
    """Thread-safe, redacted, append-only JSONL event sink.

    Each :meth:`emit` call serializes one redacted ``RunEvent.as_dict()`` to a
    single line and flushes immediately so an external reader can tail the file.
    A reader opening the file while a line is being written sees an incomplete
    trailing line, which the cursor-based readers in this module ignore.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        known_secrets: Iterable[Any] | Mapping[Any, Any] | Any | None = None,
        extra_secrets: Iterable[Any] | Mapping[Any, Any] | Any | None = None,
        append: bool = True,
        encoding: str = "utf-8",
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._encoding = encoding
        self._known_secrets = known_secrets
        self._extra_secrets = extra_secrets
        mode = "a" if append else "w"
        self._handle = open(self.path, mode, encoding=encoding, newline="")

    def emit(self, event: RunEvent) -> None:
        """Serialize one redacted event as a single flushed JSONL line."""

        payload = redact_secrets(
            event.as_dict(),
            known_secrets=self._known_secrets,
            extra_secrets=self._extra_secrets,
        )
        payload = _json_safe(payload)
        line = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
        ) + "\n"
        with self._lock:
            self._handle.write(line)
            self._handle.flush()

    def flush(self) -> None:
        """Flush buffered output to disk."""

        with self._lock:
            self._handle.flush()

    def close(self) -> None:
        """Flush and close the underlying file handle."""

        with self._lock:
            try:
                self._handle.flush()
            finally:
                self._handle.close()

    # Context-manager support
    def __enter__(self) -> "JSONLJournalSink":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class MultiplexingRuntimeEventSink:
    """Fan-out sink that delivers every event exactly once to each child sink.

    Sinks receive events in registration order.  A child's failure is
    propagated to the emitting thread and stops delivery to later sinks,
    matching the behavior of ``CollectingRuntimeEventSink``.
    """

    def __init__(self, *sinks: RuntimeEventSink) -> None:
        self._sinks: list[RuntimeEventSink] = []
        self._lock = RLock()
        for sink in sinks:
            self.add(sink)

    def add(self, sink: RuntimeEventSink) -> "MultiplexingRuntimeEventSink":
        """Register a child sink to receive future events."""

        if not hasattr(sink, "emit"):
            raise TypeError("sink must implement emit(event)")
        with self._lock:
            self._sinks.append(sink)
        return self

    def remove(self, sink: RuntimeEventSink) -> None:
        """Unregister a child sink."""

        with self._lock:
            self._sinks.remove(sink)

    def emit(self, event: RunEvent) -> None:
        """Deliver ``event`` exactly once to each registered sink."""

        with self._lock:
            for sink in self._sinks:
                sink.emit(event)

    @property
    def sinks(self) -> tuple[RuntimeEventSink, ...]:
        """Stable tuple of registered child sinks."""

        with self._lock:
            return tuple(self._sinks)

    @property
    def multiplexed_sinks(self) -> tuple[RuntimeEventSink, ...]:
        """Alias for :attr:`sinks` used by UI wiring."""

        return self.sinks


@dataclass(frozen=True, slots=True)
class JournalRead:
    """Result of a cursor-based journal read.

    ``events`` contains the complete, redacted records read starting at
    ``cursor``.  ``next_cursor`` is the byte offset immediately after the last
    complete line consumed, so the next poll resumes without duplicates or
    lost records.  ``has_more`` indicates whether more complete data exists in
    the file.  An incomplete trailing line is never returned.
    """

    cursor: int
    events: list[dict[str, Any]]
    next_cursor: int
    has_more: bool = False


def read_journal(
    path: str | Path,
    cursor: int = 0,
    *,
    limit: int | None = None,
) -> JournalRead:
    """Read complete redacted JSONL records after a byte ``cursor``.

    Records must each occupy one line terminated by ``\\n``.  A trailing line
    without a newline (e.g. a writer mid-emit) is ignored and left for the next
    cursor read.  Malformed complete lines are skipped but still advance the
    cursor so the reader cannot loop on a corrupt record.  ``limit`` bounds the
    number of complete lines consumed in one call.
    """

    path = Path(path)
    if cursor < 0:
        cursor = 0
    try:
        size = path.stat().st_size
    except OSError:
        return JournalRead(cursor=cursor, events=[], next_cursor=cursor, has_more=False)
    if cursor > size:
        cursor = size

    if size == cursor:
        return JournalRead(cursor=cursor, events=[], next_cursor=cursor, has_more=False)

    with open(path, "rb") as handle:
        handle.seek(cursor)
        raw = handle.read()

    if not raw:
        return JournalRead(cursor=cursor, events=[], next_cursor=cursor, has_more=False)

    # Only consume the region up to and including the last complete newline.
    last_newline = raw.rfind(b"\n")
    if last_newline == -1:
        # No complete line is available yet; keep the cursor where it is.
        return JournalRead(cursor=cursor, events=[], next_cursor=cursor, has_more=False)

    consumed = raw[: last_newline + 1]
    if limit is not None and limit > 0:
        segments = consumed.split(b"\n")
        chosen = segments[:limit]
        if not chosen:
            return JournalRead(cursor=cursor, events=[], next_cursor=cursor, has_more=(cursor < size))
        consumed = b"\n".join(chosen) + b"\n"

    next_cursor = cursor + len(consumed)
    text = consumed.decode("utf-8", errors="replace")
    events: list[dict[str, Any]] = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            events.append(json.loads(stripped))
        except json.JSONDecodeError:
            # Skip a malformed complete line without stalling the cursor.
            continue

    # More complete data exists only if a subsequent complete line is present.
    # A trailing partial line (writer mid-emit) does not count as "has more".
    remainder = raw[len(consumed):]
    has_more = b"\n" in remainder and next_cursor < size
    return JournalRead(cursor=cursor, events=events, next_cursor=next_cursor, has_more=has_more)


__all__ = [
    "REDACTED",
    "JSONLJournalSink",
    "MultiplexingRuntimeEventSink",
    "JournalRead",
    "read_journal",
]
