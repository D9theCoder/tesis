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
