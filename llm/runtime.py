"""Bounded, reusable LLM runtime with coordinate-local cache and telemetry."""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import BoundedSemaphore, Condition, Lock
from time import perf_counter
from typing import Any, Callable, Iterator, Mapping

from langchain_core.messages import HumanMessage, SystemMessage

from llm.diagnostics import enrich_provider_exception, provider_error_details
from llm.provider import get_llm


ORCHESTRATOR_SCHEMA_VERSION = "orchestrator.v2"
PAYLOAD_SCHEMA_VERSION = "payload-variants.v2"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _secret_key(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in ("key", "secret", "token", "password"))


def _tool_call_arguments(raw: Any) -> Mapping[str, Any] | None:
    """Return decoded first native tool-call arguments when LangChain omits parsed."""
    calls = getattr(raw, "tool_calls", None)
    if not isinstance(calls, list) or not calls:
        return None
    first = calls[0]
    if not isinstance(first, Mapping):
        return None
    arguments = first.get("args")
    if isinstance(arguments, Mapping):
        return arguments
    if isinstance(arguments, str):
        try:
            decoded = json.loads(arguments)
        except json.JSONDecodeError:
            return None
        return decoded if isinstance(decoded, Mapping) else None
    return None


def _finish_reason(response: Any) -> str:
    metadata = getattr(response, "response_metadata", {})
    if not isinstance(metadata, Mapping):
        return ""
    return str(metadata.get("finish_reason") or "").strip().lower()


def _incomplete_reason(response: Any) -> str | None:
    """Return an explicit provider completion-limit reason, if reported."""
    finish_reason = _finish_reason(response)
    if finish_reason in {"length", "max_tokens", "max_output_tokens", "content_filter"}:
        return finish_reason

    metadata = getattr(response, "response_metadata", {})
    additional = getattr(response, "additional_kwargs", {})
    sources = [
        source
        for source in (metadata, additional, response if isinstance(response, Mapping) else None)
        if isinstance(source, Mapping)
    ]
    for source in sources:
        status = str(source.get("status") or "").strip().lower()
        details = source.get("incomplete_details")
        reason = details.get("reason") if isinstance(details, Mapping) else None
        if status == "incomplete":
            return str(reason or "provider_reported_incomplete").strip().lower()

    status = str(getattr(response, "status", "") or "").strip().lower()
    details = getattr(response, "incomplete_details", None)
    reason = details.get("reason") if isinstance(details, Mapping) else getattr(details, "reason", None)
    if status == "incomplete":
        return str(reason or "provider_reported_incomplete").strip().lower()
    return None


def _response_text(content: Any) -> str:
    """Normalize chat and Responses API content blocks to plain text."""
    if not isinstance(content, list):
        return str(content)
    text_blocks: list[str] = []
    for item in content:
        if isinstance(item, str):
            text_blocks.append(item)
            continue
        if not isinstance(item, Mapping):
            continue
        block_type = str(item.get("type") or "").strip().lower()
        if block_type and block_type not in {"text", "output_text"}:
            continue
        text = item.get("text")
        if isinstance(text, str):
            text_blocks.append(text)
        elif isinstance(text, Mapping) and isinstance(text.get("value"), str):
            text_blocks.append(text["value"])
    return "\n".join(text_blocks)


def _reasoning_token_evidence(usage: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return explicit provider-reported reasoning tokens, when available."""
    candidates = (
        ("reasoning_tokens",),
        ("reasoning",),
        ("output_token_details", "reasoning"),
        ("output_token_details", "reasoning_tokens"),
        ("completion_tokens_details", "reasoning_tokens"),
    )
    for path in candidates:
        value: Any = usage
        for key in path:
            if not isinstance(value, Mapping) or key not in value:
                break
            value = value[key]
        else:
            if isinstance(value, bool):
                continue
            try:
                tokens = int(value)
            except (TypeError, ValueError):
                continue
            if tokens >= 0:
                return {
                    "tokens": tokens,
                    "source": "provider_usage." + ".".join(path),
                }
    return None


def model_fingerprint(config: Mapping[str, Any]) -> str:
    """Return a non-reversible fingerprint without exposing model credentials."""
    safe: dict[str, Any] = {}
    for key, value in config.items():
        if _secret_key(str(key)):
            digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]
            safe[str(key)] = f"secret:{digest}"
        elif isinstance(value, Mapping):
            safe[str(key)] = model_fingerprint(value)
        else:
            safe[str(key)] = value
    return "sha256:" + hashlib.sha256(_canonical(safe).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RoleSettings:
    """Resolved overrides for one runtime role."""

    model_profile: str | None = None
    model_name: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    reasoning_effort: str | None = None
    structured_output: str = "auto"


@dataclass(slots=True)
class LLMCallResult:
    """Validated model result plus non-sensitive performance metadata."""

    text: str
    parsed: dict[str, Any]
    performance: dict[str, Any]


class LLMOutputError(ValueError):
    """A completed provider response that failed JSON/schema validation."""

    def __init__(self, message: str, *, text: str = "", performance: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.text = text
        self.performance = dict(performance or {})


@dataclass(slots=True)
class CoordinateCallContext:
    """Cache and telemetry isolated to one experiment matrix coordinate."""

    runtime: "LLMRuntime"
    coordinate_id: str
    default_provider: str
    default_model_config: dict[str, Any]
    model_profiles: dict[str, dict[str, Any]]
    role_settings: dict[str, RoleSettings]
    cache_enabled: bool
    activity_callback: Callable[[str, dict[str, Any]], None] | None = None
    cache: dict[str, tuple[str, dict[str, Any]]] = field(default_factory=dict)
    records: list[dict[str, Any]] = field(default_factory=list)
    _lock: Lock = field(default_factory=Lock, repr=False)
    _call_sequence: int = field(default=0, init=False, repr=False)

    def role_config(self, role: str, *, max_tokens: int | None) -> tuple[str, dict[str, Any], RoleSettings]:
        settings = self.role_settings.get(role, RoleSettings())
        profile = settings.model_profile or self.default_provider
        base = dict(self.model_profiles.get(profile) or self.default_model_config)
        provider = str(base.pop("provider", profile or self.default_provider)).strip().lower()
        extra = base.pop("extra", {})
        if isinstance(extra, Mapping):
            base.update(extra)
        if settings.model_name:
            base["model_name"] = settings.model_name
        if settings.temperature is not None:
            base["temperature"] = settings.temperature
        if settings.reasoning_effort is not None:
            base["reasoning_effort"] = settings.reasoning_effort
        resolved_tokens = settings.max_tokens if settings.max_tokens is not None else max_tokens
        if resolved_tokens is not None:
            base["max_tokens"] = int(resolved_tokens)
        return provider, base, settings

    def append_record(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.records.append(record)

    def next_call_id(self, role: str) -> str:
        """Return a coordinate-local identifier for one logical model call."""
        with self._lock:
            self._call_sequence += 1
            return f"{self.coordinate_id}:{role}:{self._call_sequence}"

    def emit_activity(
        self,
        event_type: str,
        *,
        call_id: str,
        record: Mapping[str, Any],
    ) -> None:
        """Forward safe runtime lifecycle data without replayable prompt text."""
        callback = self.activity_callback
        if callback is None:
            return
        data = {
            "source": "llm_runtime",
            "provider": record.get("provider"),
            "model": record.get("model"),
            "role": record.get("role"),
            "coordinate_id": record.get("coordinate_id"),
            "call_id": call_id,
            "prompt_hash": record.get("prompt_hash"),
            "model_fingerprint": record.get("model_fingerprint"),
            "cache_hit": bool(record.get("cache_hit")),
            "queue_wait_ms": int(record.get("queue_wait_ms", 0) or 0),
            "call_duration_ms": int(record.get("call_duration_ms", 0) or 0),
            "structured_output_mode": record.get("structured_output_mode"),
            "parse_status": record.get("parse_status"),
            "reasoning_effort_requested": record.get("reasoning_effort_requested"),
        }
        if event_type == "llm.completed":
            data["provider_usage"] = dict(record.get("provider_usage") or {})
            if record.get("reasoning_token_evidence") is not None:
                data["reasoning_token_evidence"] = dict(record["reasoning_token_evidence"])
        elif event_type == "llm.failed":
            data["error_type"] = record.get("error_type")
            if record.get("provider_usage"):
                data["provider_usage"] = dict(record["provider_usage"])
            if record.get("reasoning_token_evidence") is not None:
                data["reasoning_token_evidence"] = dict(record["reasoning_token_evidence"])
            for key in (
                "status_code",
                "request_id",
                "cause_type",
                "error_message",
                "incomplete_reason",
                "remediation",
            ):
                if record.get(key) is not None:
                    data[key] = record[key]
        try:
            callback(event_type, data)
        except Exception:
            # Telemetry must not turn a completed provider response into a
            # runtime failure.  The performance record remains authoritative.
            return

    def performance_summary(self) -> dict[str, Any]:
        with self._lock:
            rows = [dict(row) for row in self.records]
        calls = len(rows)
        hits = sum(bool(row.get("cache_hit")) for row in rows)
        invalid = sum(
            str(row.get("parse_status")) in {"invalid", "incomplete"}
            for row in rows
        )
        by_role: dict[str, dict[str, Any]] = {}
        for row in rows:
            role = str(row.get("role", "unknown"))
            payload = by_role.setdefault(role, {"calls": 0, "cache_hits": 0, "duration_ms": 0})
            payload["calls"] += 1
            payload["cache_hits"] += int(bool(row.get("cache_hit")))
            payload["duration_ms"] += int(row.get("call_duration_ms", 0) or 0)
        return {
            "calls": calls,
            "cache_hits": hits,
            "cache_hit_rate": round(hits / calls, 4) if calls else 0.0,
            "invalid_outputs": invalid,
            "invalid_output_rate": round(invalid / calls, 4) if calls else 0.0,
            "peak_llm_concurrency": self.runtime.peak_llm_concurrency,
            "peak_dvwa_node_concurrency": self.runtime.peak_http_concurrency,
            "by_role": by_role,
        }


_CURRENT_CONTEXT: ContextVar[CoordinateCallContext | None] = ContextVar(
    "tesis_llm_coordinate_context", default=None
)


def current_call_context() -> CoordinateCallContext | None:
    return _CURRENT_CONTEXT.get()


class _ClientPool:
    def __init__(self, maximum: int, factory: Callable[[], Any]) -> None:
        self.maximum = maximum
        self.factory = factory
        self.idle: list[Any] = []
        self.clients: list[Any] = []
        self.condition = Condition()

    @contextmanager
    def lease(self) -> Iterator[Any]:
        with self.condition:
            while not self.idle and len(self.clients) >= self.maximum:
                self.condition.wait()
            if self.idle:
                client = self.idle.pop()
            else:
                client = self.factory()
                self.clients.append(client)
        try:
            yield client
        finally:
            with self.condition:
                self.idle.append(client)
                self.condition.notify()


class LLMRuntime:
    """Matrix-scoped client pool and synchronization service."""

    def __init__(self, *, max_concurrency: int = 1) -> None:
        if not 1 <= int(max_concurrency) <= 4:
            raise ValueError("llm max concurrency must be between 1 and 4")
        self.max_concurrency = int(max_concurrency)
        self._llm_slots = BoundedSemaphore(self.max_concurrency)
        self._http_slots = BoundedSemaphore(1)
        self._pool_lock = Lock()
        self._pools: dict[tuple[str, str], _ClientPool] = {}
        self._capabilities: dict[tuple[str, str], bool] = {}
        self._counter_lock = Lock()
        self._active_llm = 0
        self._active_http = 0
        self.peak_llm_concurrency = 0
        self.peak_http_concurrency = 0

    @contextmanager
    def coordinate(
        self,
        *,
        coordinate_id: str,
        default_provider: str,
        default_model_config: Mapping[str, Any] | None = None,
        model_profiles: Mapping[str, Mapping[str, Any]] | None = None,
        role_settings: Mapping[str, RoleSettings | Mapping[str, Any]] | None = None,
        cache_enabled: bool = False,
        activity_callback: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> Iterator[CoordinateCallContext]:
        resolved_roles = {
            role: value if isinstance(value, RoleSettings) else RoleSettings(**dict(value))
            for role, value in (role_settings or {}).items()
        }
        context = CoordinateCallContext(
            runtime=self,
            coordinate_id=coordinate_id,
            default_provider=default_provider,
            default_model_config=dict(default_model_config or {}),
            model_profiles={key: dict(value) for key, value in (model_profiles or {}).items()},
            role_settings=resolved_roles,
            cache_enabled=bool(cache_enabled),
            activity_callback=activity_callback,
        )
        token = _CURRENT_CONTEXT.set(context)
        try:
            yield context
        finally:
            _CURRENT_CONTEXT.reset(token)

    @contextmanager
    def http_lease(self) -> Iterator[None]:
        self._http_slots.acquire()
        with self._counter_lock:
            self._active_http += 1
            self.peak_http_concurrency = max(self.peak_http_concurrency, self._active_http)
        try:
            yield
        finally:
            with self._counter_lock:
                self._active_http -= 1
            self._http_slots.release()

    def _pool(self, role: str, provider: str, config: Mapping[str, Any]) -> tuple[_ClientPool, str]:
        fingerprint = model_fingerprint({"provider": provider, **dict(config)})
        key = (role, fingerprint)
        with self._pool_lock:
            pool = self._pools.get(key)
            if pool is None:
                pool = _ClientPool(
                    self.max_concurrency,
                    lambda: get_llm(provider, **dict(config)),
                )
                self._pools[key] = pool
        return pool, fingerprint

    @staticmethod
    def _usage(response: Any) -> dict[str, Any]:
        usage = getattr(response, "usage_metadata", None)
        if isinstance(usage, Mapping):
            return dict(usage)
        metadata = getattr(response, "response_metadata", None)
        if isinstance(metadata, Mapping):
            token_usage = metadata.get("token_usage") or metadata.get("usage")
            if isinstance(token_usage, Mapping):
                return dict(token_usage)
        return {}

    @staticmethod
    def _structured_output_unsupported(exc: BaseException) -> bool:
        status_code = getattr(exc, "status_code", None)
        if status_code is None:
            status_code = getattr(getattr(exc, "response", None), "status_code", None)
        try:
            normalized_status = int(status_code) if status_code is not None else None
        except (TypeError, ValueError):
            normalized_status = None
        if normalized_status is not None and normalized_status not in {400, 404, 422}:
            return False
        text = str(exc).lower()
        if any(marker in text for marker in (
            "api key", "authentication", "unauthorized", "forbidden", "rate limit",
            "timeout", "connection", "dns", "name resolution",
        )):
            return False
        return any(marker in text for marker in (
            "response_format", "json_schema", "structured output", "structured_output",
            "tool_choice", "function_calling",
        )) and any(marker in text for marker in (
            "unsupported", "not support", "unknown", "invalid", "not available"
        ))

    def preflight_structured_output(
        self,
        *,
        context: CoordinateCallContext,
        role: str,
        schema: Mapping[str, Any],
        max_tokens: int,
    ) -> bool:
        """Validate local client support without making a provider request."""
        provider, config, settings = context.role_config(role, max_tokens=max_tokens)
        pool, fingerprint = self._pool(role, provider, config)
        key = (role, fingerprint)
        if settings.structured_output not in {"auto", "native"}:
            self._capabilities[key] = False
            return False
        with pool.lease() as client:
            factory = getattr(client, "with_structured_output", None)
            if not callable(factory):
                self._capabilities[key] = False
                return False
            try:
                method = "function_calling" if provider == "openai_compatible" else "json_schema"
                factory(
                    dict(schema),
                    method=method,
                    # OpenAI-compatible gateways often spend substantially
                    # more reasoning tokens when strict tool schemas are
                    # enabled.  The runtime validator remains authoritative.
                    strict=False if method == "function_calling" else True,
                    include_raw=True,
                )
            except (AttributeError, NotImplementedError, TypeError, ValueError):
                if settings.structured_output == "native":
                    raise
                self._capabilities[key] = False
                return False
        self._capabilities[key] = True
        return True

    def invoke(
        self,
        *,
        context: CoordinateCallContext,
        role: str,
        system_message: str,
        user_message: str,
        schema: dict[str, Any],
        schema_version: str,
        validator: Callable[[dict[str, Any]], dict[str, Any]],
        max_tokens: int,
    ) -> LLMCallResult:
        provider, config, settings = context.role_config(role, max_tokens=max_tokens)
        pool, fingerprint = self._pool(role, provider, config)
        model = str(config.get("model_name") or config.get("model") or "unknown")
        reasoning_effort = config.get("reasoning_effort")
        call_id = context.next_call_id(role)
        prompt_hash = "sha256:" + hashlib.sha256(
            _canonical({"system": system_message, "user": user_message}).encode("utf-8")
        ).hexdigest()
        cache_key = "sha256:" + hashlib.sha256(_canonical({
            "role": role,
            "model": fingerprint,
            "schema_version": schema_version,
            "system": system_message,
            "user": user_message,
            "max_tokens": max_tokens,
            "temperature": config.get("temperature", 0),
            "structured_output": settings.structured_output,
            "reasoning_effort": reasoning_effort,
        }).encode("utf-8")).hexdigest()
        base_record = {
            "prompt_hash": prompt_hash,
            "role": role,
            "provider": provider,
            "model": model,
            "call_id": call_id,
            "coordinate_id": context.coordinate_id,
            "model_fingerprint": fingerprint,
            "cache_hit": False,
            "queue_wait_ms": 0,
            "call_duration_ms": 0,
            "structured_output_mode": "json_prompt",
            "parse_status": "pending",
            "provider_usage": {},
            "reasoning_effort_requested": reasoning_effort,
            "reasoning_token_evidence": None,
        }
        if context.cache_enabled and cache_key in context.cache:
            text, parsed = context.cache[cache_key]
            record = {**base_record, "cache_hit": True, "parse_status": "ok"}
            context.emit_activity("llm.started", call_id=call_id, record=record)
            context.append_record(record)
            context.emit_activity("llm.completed", call_id=call_id, record=record)
            return LLMCallResult(text=text, parsed=dict(parsed), performance=record)

        queued_at = perf_counter()
        self._llm_slots.acquire()
        acquired_at = perf_counter()
        with self._counter_lock:
            self._active_llm += 1
            self.peak_llm_concurrency = max(self.peak_llm_concurrency, self._active_llm)
        context.emit_activity(
            "llm.started",
            call_id=call_id,
            record={
                **base_record,
                "queue_wait_ms": int((acquired_at - queued_at) * 1000),
                "structured_output_mode": "pending",
            },
        )
        response: Any = None
        text = ""
        mode = "json_prompt"
        output_incomplete = False
        incomplete_reason: str | None = None
        structured_output_fallback: dict[str, Any] | None = None
        try:
            capability_key = (role, fingerprint)
            native_allowed = settings.structured_output in {"auto", "native"}
            native_supported = self._capabilities.get(capability_key)
            if native_supported is None:
                native_supported = (
                    self.preflight_structured_output(
                        context=context,
                        role=role,
                        schema=schema,
                        max_tokens=max_tokens,
                    )
                    if native_allowed
                    else False
                )
                self._capabilities[capability_key] = native_supported
            with pool.lease() as client:
                started_at = perf_counter()
                if native_supported:
                    structured_method = (
                        "function_calling" if provider == "openai_compatible" else "json_schema"
                    )
                    mode = f"native_{structured_method}"
                    try:
                        structured = client.with_structured_output(
                            schema,
                            method=structured_method,
                            strict=False if structured_method == "function_calling" else True,
                            include_raw=True,
                        )
                    except (AttributeError, NotImplementedError, TypeError, ValueError):
                        if settings.structured_output != "auto":
                            raise
                        self._capabilities[capability_key] = False
                        native_supported = False
                        mode = "json_prompt_fallback"
                    if native_supported:
                        try:
                            response = structured.invoke([
                                SystemMessage(content=system_message),
                                HumanMessage(content=user_message),
                            ])
                        except Exception as exc:
                            if (
                                settings.structured_output == "auto"
                                and self._structured_output_unsupported(exc)
                            ):
                                structured_output_fallback = provider_error_details(
                                    exc,
                                    provider=provider,
                                    model=model,
                                    role=role,
                                    coordinate_id=context.coordinate_id,
                                )
                                self._capabilities[capability_key] = False
                                native_supported = False
                                mode = "json_prompt_fallback"
                            else:
                                raise
                    if not native_supported:
                        response = client.invoke([
                            SystemMessage(content=system_message),
                            HumanMessage(content=user_message),
                        ])
                        incomplete_reason = _incomplete_reason(response)
                        output_incomplete = incomplete_reason is not None
                        content = getattr(response, "content", response)
                        text = _response_text(content)
                        if output_incomplete:
                            raise ValueError("provider reported incomplete output")
                        parsed_raw = json.loads(text)
                        if not isinstance(parsed_raw, dict):
                            raise ValueError("structured output must be a JSON object")
                        parsed = validator(parsed_raw)
                        usage_source = response
                    else:
                        raw = response.get("raw") if isinstance(response, Mapping) else None
                        parsed_raw = response.get("parsed") if isinstance(response, Mapping) else response
                        if raw is not None:
                            raw_content = getattr(raw, "content", "")
                            text = _response_text(raw_content) if raw_content is not None else ""
                            incomplete_reason = _incomplete_reason(raw)
                            output_incomplete = incomplete_reason is not None
                            if not isinstance(parsed_raw, Mapping):
                                parsed_raw = _tool_call_arguments(raw)
                            if not text and not isinstance(parsed_raw, Mapping):
                                refusal = getattr(raw, "additional_kwargs", {}).get("refusal")
                                if refusal:
                                    text = str(refusal)
                        if output_incomplete:
                            raise ValueError("native structured output was truncated")
                        if not isinstance(parsed_raw, Mapping):
                            message = (
                                "native structured output was truncated"
                                if output_incomplete
                                else "native structured output did not return an object"
                            )
                            raise ValueError(message)
                        text = text or _canonical(dict(parsed_raw))
                        parsed = validator(dict(parsed_raw))
                        usage_source = raw
                else:
                    response = client.invoke([
                        SystemMessage(content=system_message),
                        HumanMessage(content=user_message),
                    ])
                    incomplete_reason = _incomplete_reason(response)
                    output_incomplete = incomplete_reason is not None
                    content = getattr(response, "content", response)
                    text = _response_text(content)
                    if output_incomplete:
                        raise ValueError("provider reported incomplete output")
                    parsed_raw = json.loads(text)
                    if not isinstance(parsed_raw, dict):
                        raise ValueError("structured output must be a JSON object")
                    parsed = validator(parsed_raw)
                    usage_source = response
                duration_ms = int((perf_counter() - started_at) * 1000)
        except Exception as exc:
            incomplete = output_incomplete or type(exc).__name__ == "LengthFinishReasonError"
            failure_usage_source = (
                response.get("raw") if isinstance(response, Mapping) else response
            )
            failure_usage = self._usage(failure_usage_source)
            diagnostic = None
            if not text and not incomplete:
                diagnostic = provider_error_details(
                    exc,
                    provider=provider,
                    model=model,
                    role=role,
                    coordinate_id=context.coordinate_id,
                )
            record = {
                **base_record,
                "queue_wait_ms": int((acquired_at - queued_at) * 1000),
                "call_duration_ms": int((perf_counter() - acquired_at) * 1000),
                "structured_output_mode": mode,
                "parse_status": (
                    "incomplete" if incomplete else "invalid" if text else "provider_error"
                ),
                "error_type": type(exc).__name__,
                "provider_usage": failure_usage,
                "reasoning_token_evidence": _reasoning_token_evidence(failure_usage),
            }
            if incomplete:
                reason = incomplete_reason or "provider_output_limit"
                record["incomplete_reason"] = reason
                record["remediation"] = (
                    "Increase max_tokens/max_output_tokens for this role or reduce the "
                    "requested structured response size, then retry the coordinate."
                )
            if structured_output_fallback is not None:
                record["structured_output_fallback"] = structured_output_fallback
            if diagnostic is not None:
                record.update({
                    "status_code": diagnostic.get("status_code"),
                    "request_id": diagnostic.get("request_id"),
                    "cause_type": diagnostic.get("cause_type"),
                    "error_message": diagnostic["message"],
                    "remediation": diagnostic["remediation"],
                })
            context.append_record(record)
            context.emit_activity("llm.failed", call_id=call_id, record=record)
            if text or incomplete:
                message = str(exc)
                if incomplete:
                    message = (
                        f"LLM response was incomplete ({record['incomplete_reason']}). "
                        f"{record['remediation']} Cause: {type(exc).__name__}: {exc}"
                    )
                raise LLMOutputError(message, text=text, performance=record) from exc
            if diagnostic is not None:
                enrich_provider_exception(exc, diagnostic)
            raise
        finally:
            with self._counter_lock:
                self._active_llm -= 1
            self._llm_slots.release()

        provider_usage = self._usage(usage_source)
        record = {
            **base_record,
            "queue_wait_ms": int((acquired_at - queued_at) * 1000),
            "call_duration_ms": duration_ms,
            "structured_output_mode": mode,
            "parse_status": "ok",
            "provider_usage": provider_usage,
            "reasoning_token_evidence": _reasoning_token_evidence(provider_usage),
        }
        if structured_output_fallback is not None:
            record["structured_output_fallback"] = structured_output_fallback
        context.append_record(record)
        if context.cache_enabled:
            context.cache[cache_key] = (text, dict(parsed))
        context.emit_activity("llm.completed", call_id=call_id, record=record)
        return LLMCallResult(text=text, parsed=parsed, performance=record)

    def close(self) -> None:
        """Best-effort cleanup for clients that expose a synchronous close hook."""
        with self._pool_lock:
            pools = list(self._pools.values())
            self._pools.clear()
        for pool in pools:
            for client in pool.clients:
                close = getattr(client, "close", None)
                if callable(close):
                    close()


@contextmanager
def serialized_dvwa_node() -> Iterator[None]:
    """Serialize recon and method-node HTTP activity for an active coordinate."""
    context = current_call_context()
    if context is None:
        yield
        return
    with context.runtime.http_lease():
        yield


__all__ = [
    "CoordinateCallContext",
    "LLMCallResult",
    "LLMOutputError",
    "LLMRuntime",
    "ORCHESTRATOR_SCHEMA_VERSION",
    "PAYLOAD_SCHEMA_VERSION",
    "RoleSettings",
    "current_call_context",
    "model_fingerprint",
    "serialized_dvwa_node",
]
