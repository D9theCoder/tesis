"""UI-independent runtime events, cancellation, redaction, and stream helpers.

This module is deliberately independent of Textual (or any other presentation
framework).  Runtime code can emit :class:`RunEvent` objects to a callback or
collector, while a UI decides how those events are rendered.  The helpers in
this module also provide one safe place for secret masking and provider-specific
stream normalization.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from threading import Event, Lock, RLock
from time import time
from types import MappingProxyType
from typing import Any, Final, Protocol, TypeAlias, runtime_checkable


REDACTED: Final[str] = "[REDACTED]"
"""Replacement used for values that must not be exposed."""

REDACTION_MARKER: Final[str] = REDACTED


def _timestamp() -> float:
    """Return a wall-clock timestamp suitable for event records."""

    return time()


@dataclass(frozen=True, slots=True, init=False)
class RunEvent:
    """An immutable, UI-independent description of runtime activity.

    The canonical constructor names are ``event_type``, ``run_id``,
    ``execution_id``, ``node``, ``method``, ``candidate``, ``message``, and
    ``data``.  ``event_name``/``name``/``type`` and ``payload`` are accepted as
    compatibility aliases because event producers often use those spellings.
    The event owns a read-only copy of its top-level data mapping; nested
    values are intentionally not copied so callers can retain their provider
    objects when needed.
    """

    event_type: str
    name: str
    timestamp: float
    execution_id: str | None
    run_id: str | None
    node: str | None
    method: str | None
    candidate: Any
    message: str | None
    data: Mapping[str, Any]

    def __init__(
        self,
        event_type: str | None = None,
        name: str | Mapping[str, Any] | None = None,
        timestamp: float | None = None,
        execution_id: str | None = None,
        run_id: str | None = None,
        node: str | None = None,
        method: str | None = None,
        candidate: Any = None,
        message: str | None = None,
        data: Mapping[str, Any] | None = None,
        *,
        event_name: str | None = None,
        type: str | None = None,
        kind: str | None = None,
        payload: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Create an event, accepting common event/payload aliases."""

        # A mapping as the second positional argument is a useful shorthand
        # for ``RunEvent("event.name", data={...})`` and is unambiguous.
        if isinstance(name, Mapping):
            if data is not None or payload is not None or metadata is not None or details is not None:
                raise TypeError("event data was supplied more than once")
            data = name
            name = None

        resolved_type = event_type or event_name or type or kind
        if resolved_type is None and isinstance(name, str):
            # ``RunEvent(name="run.started")`` is a reasonable shorthand.
            resolved_type = name
        if resolved_type is None:
            raise TypeError("RunEvent requires event_type (or event_name/type/kind)")

        resolved_name = name if isinstance(name, str) else event_name
        if resolved_name is None:
            resolved_name = str(resolved_type)

        data_sources = [source for source in (data, payload, metadata, details) if source is not None]
        if len(data_sources) > 1:
            raise TypeError("event data was supplied more than once")
        event_data = data_sources[0] if data_sources else {}
        if not isinstance(event_data, Mapping):
            raise TypeError("event data/payload must be a mapping")

        object.__setattr__(self, "event_type", str(resolved_type))
        object.__setattr__(self, "name", str(resolved_name))
        object.__setattr__(self, "timestamp", _coerce_timestamp(timestamp))
        object.__setattr__(self, "execution_id", execution_id)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "node", node)
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "candidate", candidate)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "data", MappingProxyType(dict(event_data)))

    @property
    def event_name(self) -> str:
        """Alias for :attr:`name`."""

        return self.name

    @property
    def type(self) -> str:
        """Alias for :attr:`event_type`."""

        return self.event_type

    @property
    def kind(self) -> str:
        """Alias for :attr:`event_type` used by some event consumers."""

        return self.event_type

    @property
    def payload(self) -> Mapping[str, Any]:
        """Alias for the read-only :attr:`data` mapping."""

        return self.data

    @property
    def created_at(self) -> float:
        """Alias for :attr:`timestamp`."""

        return self.timestamp

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly shallow event representation."""

        return {
            "event_type": self.event_type,
            "name": self.name,
            "timestamp": self.timestamp,
            "execution_id": self.execution_id,
            "run_id": self.run_id,
            "node": self.node,
            "method": self.method,
            "candidate": self.candidate,
            "message": self.message,
            "data": dict(self.data),
        }

    to_dict = as_dict


def _coerce_timestamp(value: Any) -> float:
    if value is None:
        return _timestamp()
    if hasattr(value, "timestamp") and callable(value.timestamp):
        return float(value.timestamp())
    return float(value)


@runtime_checkable
class RuntimeEventSink(Protocol):
    """Protocol implemented by objects that receive :class:`RunEvent` values."""

    def emit(self, event: RunEvent) -> None:
        """Consume one runtime event."""


EventCallback: TypeAlias = Callable[[RunEvent], None]


class CollectingRuntimeEventSink:
    """Thread-safe event collector with an optional forwarding callback.

    Events are retained before the callback is called.  Callback failures are
    deliberately propagated to the emitting thread, while the event remains
    available in the collector for diagnostics.
    """

    def __init__(self, callback: EventCallback | None = None) -> None:
        if callback is not None and not callable(callback):
            raise TypeError("callback must be callable")
        self._events: list[RunEvent] = []
        self._lock = RLock()
        self._callback = callback

    def emit(self, event: RunEvent) -> None:
        """Store ``event`` and invoke the optional callback in emission order."""

        with self._lock:
            self._events.append(event)
            if self._callback is not None:
                self._callback(event)

    @property
    def events(self) -> tuple[RunEvent, ...]:
        """Return a stable snapshot of collected events."""

        return self.snapshot()

    def snapshot(self) -> tuple[RunEvent, ...]:
        """Return collected events in emission order."""

        with self._lock:
            return tuple(self._events)

    def clear(self) -> None:
        """Remove all retained events."""

        with self._lock:
            self._events.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    def __iter__(self) -> Iterator[RunEvent]:
        return iter(self.snapshot())


class CallbackRuntimeEventSink:
    """Thread-safe adapter that serializes calls to one event callback."""

    def __init__(self, callback: EventCallback) -> None:
        if not callable(callback):
            raise TypeError("callback must be callable")
        self._callback = callback
        self._lock = RLock()

    def emit(self, event: RunEvent) -> None:
        """Forward ``event`` to the callback."""

        with self._lock:
            self._callback(event)


# Concise aliases are useful to small adapters and retain compatibility with
# earlier callers that chose the shorter names.
CollectingEventSink = CollectingRuntimeEventSink
CallbackEventSink = CallbackRuntimeEventSink
ThreadSafeEventSink = CollectingRuntimeEventSink
ThreadSafeCollectingEventSink = CollectingRuntimeEventSink
ThreadSafeCallbackEventSink = CallbackRuntimeEventSink
ThreadSafeCallbackSink = CallbackRuntimeEventSink
EventCollector = CollectingRuntimeEventSink


class RuntimeCancellationError(RuntimeError):
    """Base exception for cooperative runtime cancellation."""


class CancellationRequested(RuntimeCancellationError):
    """Raised when a :class:`CancellationToken` has been cancelled."""

    def __init__(self, message: str = "Runtime execution was cancelled", *, reason: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason or message


class CancellationToken:
    """A small, one-way, thread-safe cooperative cancellation token."""

    def __init__(self) -> None:
        self._event = Event()
        self._lock = Lock()
        self._reason: str | None = None

    def cancel(self, reason: str | None = None) -> bool:
        """Request cancellation and return ``True`` only for the first request."""

        with self._lock:
            if self._event.is_set():
                return False
            self._reason = reason
            self._event.set()
            return True

    @property
    def is_cancelled(self) -> bool:
        """Whether cancellation has been requested."""

        return self._event.is_set()

    @property
    def cancelled(self) -> bool:
        """Alias for :attr:`is_cancelled`."""

        return self.is_cancelled

    @property
    def reason(self) -> str | None:
        """The first cancellation reason, if one was supplied."""

        with self._lock:
            return self._reason

    def is_set(self) -> bool:
        """Return whether the underlying cancellation event is set."""

        return self.is_cancelled

    def check(self, message: str | None = None) -> None:
        """Raise :class:`CancellationRequested` when cancellation is active."""

        if self.is_cancelled:
            reason = self.reason
            raise CancellationRequested(message or reason or "Runtime execution was cancelled", reason=reason)

    def raise_if_cancelled(self) -> None:
        """Alias for :meth:`check`."""

        self.check()

    def throw_if_cancelled(self) -> None:
        """Alias for :meth:`check` used by worker loops."""

        self.check()

    def raise_if_cancellation_requested(self) -> None:
        """Explicitly named alias for :meth:`check`."""

        self.check()

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for cancellation, returning ``True`` when it is requested."""

        return self._event.wait(timeout)


# Compatibility names used by different runner layers.
CancellationError = RuntimeCancellationError
CancellationException = CancellationRequested
CancelledError = CancellationRequested
RunCancelledError = CancellationRequested


_SECRET_KEY_NAMES: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access_token",
        "api_key",
        "api_secret",
        "api_token",
        "apikey",
        "auth",
        "authorization",
        "bearer",
        "client_secret",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "csrf_token",
        "id_token",
        "jwt",
        "oauth_token",
        "password",
        "passwd",
        "private_key",
        "refresh_token",
        "secret",
        "secret_key",
        "session_cookie",
        "session_token",
        "set_cookie",
        "signing_key",
        "token",
        "user_token",
        "webhook_secret",
        "x_api_key",
        "x_auth_token",
    }
)


def _normalise_key(key: Any) -> str:
    text = str(key).strip()
    # Make camelCase and PascalCase keys comparable to snake_case names.
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    return text.strip("_").casefold()


def _is_secret_key(key: Any) -> bool:
    normalised = _normalise_key(key)
    if normalised in _SECRET_KEY_NAMES:
        return True
    # Cover conventional variants such as ``authorization_header``,
    # ``my_secret_value``, ``auth_token``, and ``session-id-token`` without
    # masking harmless keys such as ``token_count``.
    return (
        normalised.startswith(("auth_", "bearer_", "secret_", "private_key_"))
        or normalised.endswith(("_secret", "_token", "_password", "_cookie", "_key"))
    )


def _iter_secret_values(known_secrets: Iterable[Any] | Mapping[Any, Any] | Any | None) -> Iterable[Any]:
    if known_secrets is None:
        return ()
    if isinstance(known_secrets, Mapping):
        return known_secrets.values()
    if isinstance(known_secrets, (str, bytes, bytearray)):
        return (known_secrets,)
    try:
        return iter(known_secrets)
    except TypeError:
        return (known_secrets,)


def _secret_values(*collections: Iterable[Any] | Mapping[Any, Any] | Any | None) -> tuple[str, ...]:
    values: set[str] = set()
    for collection in collections:
        for value in _iter_secret_values(collection):
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            elif not isinstance(value, str):
                continue
            if value:
                values.add(value)
    return tuple(sorted(values, key=len, reverse=True))


def _redact_string(value: str, secrets: Sequence[str], replacement: str) -> str:
    result = value
    for secret in secrets:
        result = result.replace(secret, replacement)
    return result


def _redact_bytes(value: bytes, secrets: Sequence[str], replacement: str) -> bytes:
    result = value
    replacement_bytes = replacement.encode("utf-8")
    for secret in secrets:
        result = result.replace(secret.encode("utf-8"), replacement_bytes)
    return result


def redact_secrets(
    value: Any,
    known_secrets: Iterable[Any] | Mapping[Any, Any] | Any | None = None,
    *,
    secrets: Iterable[Any] | Mapping[Any, Any] | Any | None = None,
    extra_secrets: Iterable[Any] | Mapping[Any, Any] | Any | None = None,
    replacement: str = REDACTED,
) -> Any:
    """Recursively mask sensitive values without mutating the input.

    Mapping values whose keys look like credentials are replaced wholesale.
    Explicit ``known_secrets`` (plus the ``secrets`` and ``extra_secrets``
    aliases) are replaced wherever they occur in nested strings or bytes.
    Lists, tuples, sets, and nested mappings are traversed.  Cycles are
    replaced with the redaction marker rather than causing an infinite loop.
    """

    if not isinstance(replacement, str):
        raise TypeError("replacement must be a string")
    explicit_secrets = _secret_values(known_secrets, secrets, extra_secrets)
    active: set[int] = set()

    def visit(item: Any) -> Any:
        if isinstance(item, str):
            return _redact_string(item, explicit_secrets, replacement)
        if isinstance(item, bytes):
            return _redact_bytes(item, explicit_secrets, replacement)
        if isinstance(item, bytearray):
            return bytearray(_redact_bytes(bytes(item), explicit_secrets, replacement))
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in active:
                return replacement
            active.add(identity)
            try:
                return {
                    key: replacement if _is_secret_key(key) else visit(item_value)
                    for key, item_value in item.items()
                }
            finally:
                active.remove(identity)
        if isinstance(item, list):
            identity = id(item)
            if identity in active:
                return replacement
            active.add(identity)
            try:
                return [visit(item_value) for item_value in item]
            finally:
                active.remove(identity)
        if isinstance(item, tuple):
            identity = id(item)
            if identity in active:
                return replacement
            active.add(identity)
            try:
                return tuple(visit(item_value) for item_value in item)
            finally:
                active.remove(identity)
        if isinstance(item, set):
            identity = id(item)
            if identity in active:
                return replacement
            active.add(identity)
            try:
                return {visit(item_value) for item_value in item}
            finally:
                active.remove(identity)
        if isinstance(item, frozenset):
            identity = id(item)
            if identity in active:
                return replacement
            active.add(identity)
            try:
                return frozenset(visit(item_value) for item_value in item)
            finally:
                active.remove(identity)
        return item

    return visit(value)


def _normalise_provider_key(key: Any) -> str:
    return _normalise_key(key)


def _mapping_entry(mapping: Mapping[Any, Any], wanted: str) -> tuple[bool, Any]:
    wanted_normalised = _normalise_provider_key(wanted)
    for key, value in mapping.items():
        if _normalise_provider_key(key) == wanted_normalised:
            return True, value
    return False, None


_CHUNK_KEYS: Final[tuple[str, ...]] = (
    "output_text",
    "generated_text",
    "completion",
    "text",
    "token",
    "content",
    "delta",
    "choices",
    "candidates",
    "parts",
    "content_block",
    "content_blocks",
    "message",
    "output",
    "item",
    "generations",
    "generation",
    "response",
    "data",
)
_TEXT_BLOCK_TYPES: Final[frozenset[str]] = frozenset(
    {
        "text",
        "text_delta",
        "output_text",
        "input_text",
        "text_block",
        "text_block_delta",
        "content_block_delta",
        "content_block_start",
        "message_delta",
    }
)
_NON_TEXT_BLOCK_TYPES: Final[frozenset[str]] = frozenset(
    {
        "audio",
        "image",
        "image_url",
        "input_audio",
        "tool_use",
        "tool_result",
        "server_tool_use",
        "web_search_tool_result",
        "function",
        "function_call",
        "json",
    }
)


def _normalise_chunk_value(chunk: Any, active: set[int]) -> str:
    if chunk is None:
        return ""
    if isinstance(chunk, str):
        return chunk
    if isinstance(chunk, bytes):
        return chunk.decode("utf-8", errors="replace")
    if isinstance(chunk, bytearray):
        return bytes(chunk).decode("utf-8", errors="replace")

    if isinstance(chunk, Mapping):
        identity = id(chunk)
        if identity in active:
            return ""
        active.add(identity)
        try:
            found, block_type = _mapping_entry(chunk, "type")
            if found and isinstance(block_type, str):
                normalised_type = _normalise_provider_key(block_type)
                if normalised_type in _NON_TEXT_BLOCK_TYPES:
                    return ""

            # Provider envelopes have deliberately ordered keys.  We return
            # the first non-empty text-bearing field to avoid duplicating the
            # same response when an SDK exposes both ``output_text`` and
            # ``output``.
            for key in _CHUNK_KEYS:
                found, value = _mapping_entry(chunk, key)
                if not found:
                    continue
                text = _normalise_chunk_value(value, active)
                if text:
                    return text
            return ""
        finally:
            active.remove(identity)

    if isinstance(chunk, Sequence) and not isinstance(chunk, (str, bytes, bytearray)):
        identity = id(chunk)
        if identity in active:
            return ""
        active.add(identity)
        try:
            return "".join(_normalise_chunk_value(item, active) for item in chunk)
        finally:
            active.remove(identity)

    # LangChain chunks, Gemini response objects, OpenAI SDK objects, and
    # Anthropic events expose the same provider fields as attributes.
    identity = id(chunk)
    if identity in active:
        return ""
    active.add(identity)
    try:
        try:
            block_type = getattr(chunk, "type")
        except (AttributeError, TypeError, ValueError):
            block_type = None
        if isinstance(block_type, str) and _normalise_provider_key(block_type) in _NON_TEXT_BLOCK_TYPES:
            return ""

        for key in _CHUNK_KEYS:
            try:
                value = getattr(chunk, key)
            except (AttributeError, TypeError, ValueError):
                continue
            if callable(value):
                continue
            text = _normalise_chunk_value(value, active)
            if text:
                return text

        # A few pydantic/provider objects only expose their fields through a
        # dump method.  This fallback remains conservative: arbitrary object
        # attributes are never stringified into the stream.
        for dump_name in ("model_dump", "dict"):
            try:
                dump = getattr(chunk, dump_name)
                value = dump() if callable(dump) else None
            except (AttributeError, TypeError, ValueError):
                continue
            text = _normalise_chunk_value(value, active)
            if text:
                return text
        return ""
    finally:
        active.remove(identity)


def normalize_stream_chunk(chunk: Any) -> str:
    """Extract visible text from strings, SDK chunks, and provider envelopes.

    Supported shapes include LangChain ``AIMessageChunk``/content blocks,
    Gemini ``candidates[].content.parts[].text``, OpenAI and compatible
    ``choices[].delta.content``/``message.content`` responses, OpenAI
    Responses ``output[].content[].text`` values, and Claude/Anthropic
    ``delta.text``/``content[].text`` events.  Non-text chunks return ``""``.
    """

    return _normalise_chunk_value(chunk, set())


def normalize_token_chunk(chunk: Any) -> str:
    """Compatibility name for :func:`normalize_stream_chunk`."""

    return normalize_stream_chunk(chunk)


def normalize_stream_chunks(chunks: Iterable[Any]) -> str:
    """Concatenate visible text from an iterable of stream chunks."""

    if isinstance(chunks, (str, bytes, bytearray, Mapping)):
        return normalize_stream_chunk(chunks)
    try:
        return "".join(normalize_stream_chunk(chunk) for chunk in chunks)
    except TypeError:
        return normalize_stream_chunk(chunks)


def normalize_token_chunks(chunks: Iterable[Any]) -> str:
    """Compatibility name for :func:`normalize_stream_chunks`."""

    return normalize_stream_chunks(chunks)


normalise_token_chunk = normalize_token_chunk
normalise_stream_chunk = normalize_stream_chunk
normalise_stream_chunks = normalize_stream_chunks
extract_text_from_chunk = normalize_stream_chunk
extract_chunk_text = normalize_stream_chunk
get_chunk_text = normalize_stream_chunk
chunk_to_text = normalize_stream_chunk


__all__ = [
    "REDACTED",
    "REDACTION_MARKER",
    "RunEvent",
    "RuntimeEventSink",
    "EventCallback",
    "CollectingRuntimeEventSink",
    "CollectingEventSink",
    "CallbackRuntimeEventSink",
    "CallbackEventSink",
    "ThreadSafeEventSink",
    "ThreadSafeCollectingEventSink",
    "ThreadSafeCallbackEventSink",
    "ThreadSafeCallbackSink",
    "EventCollector",
    "RuntimeCancellationError",
    "CancellationRequested",
    "CancellationError",
    "CancellationException",
    "CancelledError",
    "RunCancelledError",
    "CancellationToken",
    "redact_secrets",
    "normalize_stream_chunk",
    "normalise_stream_chunk",
    "normalize_token_chunk",
    "normalise_token_chunk",
    "normalize_stream_chunks",
    "normalise_stream_chunks",
    "normalize_token_chunks",
    "extract_text_from_chunk",
    "extract_chunk_text",
    "get_chunk_text",
    "chunk_to_text",
]
