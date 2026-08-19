"""Tests for bounded role-based LLM execution and coordinate isolation."""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from llm.runtime import LLMOutputError, LLMRuntime, RoleSettings


SCHEMA = {
    "type": "object",
    "properties": {"value": {"type": "string"}},
    "required": ["value"],
}


class _Response:
    def __init__(self, content: str, *, finish_reason: str | None = None) -> None:
        self.content = content
        self.usage_metadata = {"input_tokens": 3, "output_tokens": 2}
        self.response_metadata = (
            {"finish_reason": finish_reason} if finish_reason is not None else {}
        )


class _FakeClient:
    def __init__(self, *, contents: list[str], gate=None, counters=None) -> None:
        self.contents = contents
        self.gate = gate
        self.counters = counters
        self.calls = 0

    def invoke(self, messages):
        del messages
        self.calls += 1
        if self.counters is not None:
            with self.counters["lock"]:
                self.counters["active"] += 1
                self.counters["peak"] = max(self.counters["peak"], self.counters["active"])
            if self.gate is not None:
                self.gate.wait(timeout=2)
            with self.counters["lock"]:
                self.counters["active"] -= 1
        value = self.contents[min(self.calls - 1, len(self.contents) - 1)]
        return _Response(value)


def _validator(payload):
    if not isinstance(payload.get("value"), str):
        raise ValueError("value is required")
    return {"value": payload["value"]}


def _invoke(runtime, context, *, schema_version="v1"):
    return runtime.invoke(
        context=context,
        role="orchestrator",
        system_message="stable system",
        user_message="compact capsule",
        schema=SCHEMA,
        schema_version=schema_version,
        validator=_validator,
        max_tokens=32,
    )


def test_cache_reuses_only_valid_output_within_one_coordinate(monkeypatch):
    client = _FakeClient(contents=[json.dumps({"value": "ok"})])
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: client)
    runtime = LLMRuntime(max_concurrency=1)

    with runtime.coordinate(
        coordinate_id="one",
        default_provider="openai",
        role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
        cache_enabled=True,
    ) as context:
        first = _invoke(runtime, context)
        second = _invoke(runtime, context)

    assert first.parsed == second.parsed == {"value": "ok"}
    assert client.calls == 1
    assert context.records[0]["cache_hit"] is False
    assert context.records[1]["cache_hit"] is True


def test_activity_callback_is_hash_only_and_includes_cache_lifecycle(monkeypatch):
    client = _FakeClient(contents=['{"value":"ok"}'])
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: client)
    activity: list[tuple[str, dict]] = []
    runtime = LLMRuntime(max_concurrency=1)

    with runtime.coordinate(
        coordinate_id="one",
        default_provider="openai",
        role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
        cache_enabled=True,
        activity_callback=lambda event_type, data: activity.append((event_type, data)),
    ) as context:
        _invoke(runtime, context)
        _invoke(runtime, context)

    assert [event_type for event_type, _data in activity] == [
        "llm.started",
        "llm.completed",
        "llm.started",
        "llm.completed",
    ]
    assert activity[0][1]["cache_hit"] is False
    assert activity[2][1]["cache_hit"] is True
    for _event_type, data in activity:
        assert data["prompt_hash"].startswith("sha256:")
        assert "system" not in data
        assert "user" not in data
        assert "prompt" not in data
        assert "response" not in data


def test_invalid_output_is_not_cached_and_schema_version_invalidates(monkeypatch):
    client = _FakeClient(contents=["not-json", '{"value":"ok"}', '{"value":"new"}'])
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: client)
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="one",
        default_provider="openai",
        role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
        cache_enabled=True,
    ) as context:
        with pytest.raises(LLMOutputError):
            _invoke(runtime, context)
        assert _invoke(runtime, context).parsed == {"value": "ok"}
        assert _invoke(runtime, context, schema_version="v2").parsed == {"value": "new"}
    assert client.calls == 3


def test_length_limited_structured_response_is_invalid_and_not_cached(monkeypatch):
    class LengthFinishReasonError(Exception):
        pass

    class Client(_FakeClient):
        def invoke(self, messages):
            del messages
            self.calls += 1
            if self.calls == 1:
                raise LengthFinishReasonError("completion length limit reached")
            return _Response('{"value":"ok"}')

    client = Client(contents=[])
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: client)
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="one",
        default_provider="openai",
        role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
        cache_enabled=True,
    ) as context:
        with pytest.raises(LLMOutputError) as caught:
            _invoke(runtime, context)
        assert caught.value.performance["parse_status"] == "incomplete"
        assert _invoke(runtime, context).parsed == {"value": "ok"}

    assert client.calls == 2
    assert context.performance_summary()["invalid_output_rate"] == 0.5


def test_json_prompt_finish_reason_marks_truncated_json_incomplete(monkeypatch):
    class Client(_FakeClient):
        def invoke(self, messages):
            del messages
            self.calls += 1
            if self.calls == 1:
                return _Response('{"value":"', finish_reason="length")
            return _Response('{"value":"ok"}')

    client = Client(contents=[])
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: client)
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="one",
        default_provider="openai",
        role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
        cache_enabled=True,
    ) as context:
        with pytest.raises(LLMOutputError) as caught:
            _invoke(runtime, context)
        assert caught.value.performance["parse_status"] == "incomplete"
        assert _invoke(runtime, context).parsed == {"value": "ok"}

    assert client.calls == 2


def test_cache_and_telemetry_do_not_cross_coordinates(monkeypatch):
    client = _FakeClient(contents=['{"value":"ok"}'])
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: client)
    runtime = LLMRuntime(max_concurrency=1)
    for coordinate_id in ("one", "two"):
        with runtime.coordinate(
            coordinate_id=coordinate_id,
            default_provider="openai",
            role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
            cache_enabled=True,
        ) as context:
            _invoke(runtime, context)
            assert len(context.records) == 1
            assert context.records[0]["cache_hit"] is False
    assert client.calls == 2


def test_model_calls_overlap_but_never_exceed_bound(monkeypatch):
    gate = threading.Barrier(2)
    counters = {"active": 0, "peak": 0, "lock": threading.Lock()}
    clients: list[_FakeClient] = []

    def factory(*_args, **_kwargs):
        client = _FakeClient(contents=['{"value":"ok"}'], gate=gate, counters=counters)
        clients.append(client)
        return client

    monkeypatch.setattr("llm.runtime.get_llm", factory)
    runtime = LLMRuntime(max_concurrency=2)

    def worker(index: int):
        with runtime.coordinate(
            coordinate_id=str(index),
            default_provider="openai",
            role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
        ) as context:
            return _invoke(runtime, context).parsed

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert list(executor.map(worker, range(2))) == [{"value": "ok"}, {"value": "ok"}]

    assert counters["peak"] == runtime.peak_llm_concurrency == 2
    assert len(clients) == 2


def test_http_gate_is_serial_across_coordinate_contexts():
    runtime = LLMRuntime(max_concurrency=2)
    counters = {"active": 0, "peak": 0}
    lock = threading.Lock()

    def worker(index: int):
        with runtime.coordinate(coordinate_id=str(index), default_provider="openai"):
            with runtime.http_lease():
                with lock:
                    counters["active"] += 1
                    counters["peak"] = max(counters["peak"], counters["active"])
                time.sleep(0.03)
                with lock:
                    counters["active"] -= 1

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(worker, range(2)))

    assert counters["peak"] == runtime.peak_http_concurrency == 1


def test_clients_are_reused_for_same_role_and_isolated_for_different_config(monkeypatch):
    clients: list[_FakeClient] = []

    def factory(*_args, **_kwargs):
        client = _FakeClient(contents=['{"value":"ok"}'])
        clients.append(client)
        return client

    monkeypatch.setattr("llm.runtime.get_llm", factory)
    runtime = LLMRuntime(max_concurrency=1)
    for coordinate_id in ("one", "two"):
        with runtime.coordinate(
            coordinate_id=coordinate_id,
            default_provider="openai",
            default_model_config={"model_name": "same"},
            role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
        ) as context:
            _invoke(runtime, context)
    with runtime.coordinate(
        coordinate_id="three",
        default_provider="openai",
        default_model_config={"model_name": "different"},
        role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
    ) as context:
        _invoke(runtime, context)

    assert len(clients) == 2
    assert clients[0].calls == 2
    assert clients[1].calls == 1


def test_auto_structured_output_falls_back_once_when_endpoint_rejects_schema(monkeypatch):
    class UnsupportedRunnable:
        def invoke(self, messages):
            del messages
            raise ValueError("response_format json_schema is unsupported")

    class Client(_FakeClient):
        def with_structured_output(self, *args, **kwargs):
            del args, kwargs
            return UnsupportedRunnable()

    client = Client(contents=['{"value":"fallback"}'])
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: client)
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="one",
        default_provider="openai",
        role_settings={"orchestrator": RoleSettings(structured_output="auto")},
    ) as context:
        result = _invoke(runtime, context)

    assert result.parsed == {"value": "fallback"}
    assert result.performance["structured_output_mode"] == "json_prompt_fallback"
    assert client.calls == 1


def test_openai_compatible_native_output_uses_required_function_calling(monkeypatch):
    captured = {}

    class StructuredRunnable:
        def invoke(self, messages):
            del messages
            return {"raw": _Response(""), "parsed": {"value": "ok"}}

    class Client(_FakeClient):
        def with_structured_output(self, schema, **kwargs):
            captured.update(kwargs)
            captured["schema"] = schema
            return StructuredRunnable()

    client = Client(contents=[])
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: client)
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="one",
        default_provider="openai_compatible",
        role_settings={"orchestrator": RoleSettings(structured_output="auto")},
    ) as context:
        result = _invoke(runtime, context)

    assert result.parsed == {"value": "ok"}
    assert result.performance["structured_output_mode"] == "native_function_calling"
    assert captured["method"] == "function_calling"
    assert captured["strict"] is False


def test_native_tool_arguments_are_used_when_langchain_parsed_is_empty(monkeypatch):
    class Raw:
        content = ""
        tool_calls = [{"args": {"value": "from-tool"}}]
        response_metadata = {"finish_reason": "tool_calls"}
        additional_kwargs = {}
        usage_metadata = {}

    class StructuredRunnable:
        def invoke(self, messages):
            del messages
            return {"raw": Raw(), "parsed": None}

    class Client(_FakeClient):
        def with_structured_output(self, *args, **kwargs):
            del args, kwargs
            return StructuredRunnable()

    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: Client(contents=[]))
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="one",
        default_provider="openai_compatible",
        role_settings={"orchestrator": RoleSettings(structured_output="auto")},
    ) as context:
        assert _invoke(runtime, context).parsed == {"value": "from-tool"}


def test_native_length_response_is_recorded_as_incomplete(monkeypatch):
    class Raw:
        content = ""
        tool_calls = []
        response_metadata = {"finish_reason": "length"}
        additional_kwargs = {"refusal": None}
        usage_metadata = {}

    class StructuredRunnable:
        def invoke(self, messages):
            del messages
            return {"raw": Raw(), "parsed": None}

    class Client(_FakeClient):
        def with_structured_output(self, *args, **kwargs):
            del args, kwargs
            return StructuredRunnable()

    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: Client(contents=[]))
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="one",
        default_provider="openai_compatible",
        role_settings={"orchestrator": RoleSettings(structured_output="auto")},
    ) as context:
        with pytest.raises(LLMOutputError) as caught:
            _invoke(runtime, context)

    assert caught.value.performance["parse_status"] == "incomplete"
