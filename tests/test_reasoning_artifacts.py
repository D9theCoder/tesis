"""Provider reasoning survives SDK conversion and artifact writing, offline."""

import asyncio
import json
from contextlib import contextmanager

import httpx
import pytest
from langchain_core.messages import AIMessage

from evaluation.reporter import write_json_report
from llm.provider import get_llm
from llm.reasoning_evidence import reasoning_evidence
from llm.runtime import LLMOutputError, LLMRuntime


SCHEMA = {"title": "TraceProbe", "type": "object", "properties": {"answer": {"type": "integer"}},
          "required": ["answer"], "additionalProperties": False}
SECRET = "private-profile-credential"
TRACE = "Provider trace with " + SECRET


def _response(*, streaming, native=False, text='{"answer":346}', finish="stop", trace=TRACE):
    usage = {"prompt_tokens": 12, "completion_tokens": 20, "total_tokens": 32,
             "completion_tokens_details": {"reasoning_tokens": 14}}
    tool = {"id": "call_probe", "type": "function", "function": {"name": "TraceProbe", "arguments": text}}
    if not streaming:
        message = {"role": "assistant", "content": None if native else text}
        if trace is not None:
            message["reasoning_content"] = trace
        if native:
            message["tool_calls"] = [tool]
        return httpx.Response(200, json={"id": "chatcmpl_probe", "object": "chat.completion", "created": 1,
            "model": "gateway-model", "usage": usage,
            "choices": [{"index": 0, "message": message, "finish_reason": finish}]})
    deltas = [{"role": "assistant", "content": ""}]
    if trace is not None:
        split = len(trace) // 2
        deltas.extend({"reasoning_content": part} for part in (trace[:split], trace[split:]))
    if native:
        deltas.append({"tool_calls": [{"index": 0, **tool}]})
    else:
        deltas.append({"content": text})
    chunks = [{"id": "chatcmpl_probe", "object": "chat.completion.chunk", "created": 1, "model": "gateway-model",
               "choices": [{"index": 0, "delta": delta, "finish_reason": None}]} for delta in deltas]
    chunks.append({"id": "chatcmpl_probe", "object": "chat.completion.chunk", "created": 1,
        "model": "gateway-model", "usage": usage, "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]})
    body = "".join("data: " + json.dumps(chunk) + "\n\n" for chunk in chunks) + "data: [DONE]\n\n"
    return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body)


@contextmanager
def _coordinate(monkeypatch, *, streaming, native=False, text='{"answer":346}', finish="stop", trace=TRACE, cache=False):
    calls = []

    def handle(request):
        calls.append(json.loads(request.content))
        return _response(streaming=streaming, native=native, text=text, finish=finish, trace=trace)

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        def factory(provider, **kwargs):
            return get_llm(provider, **kwargs, http_client=client)
        monkeypatch.setattr("llm.runtime.get_llm", factory)
        runtime = LLMRuntime()
        try:
            with runtime.coordinate(coordinate_id="trace-unit", default_provider="gateway", model_profiles={"gateway": {
                "provider": "openai_compatible", "model_name": "gateway-model", "api_key": SECRET,
                "base_url": "https://gateway.invalid/v1", "reasoning_effort": "low", "streaming": streaming,
                "use_responses_api": False}}, role_settings={"orchestrator": {
                    "model_profile": "gateway", "structured_output": "native" if native else "json_prompt"}},
                cache_enabled=cache) as context:
                yield runtime, context, calls
        finally:
            runtime.close()


def _invoke(runtime, context):
    return runtime.invoke(context=context, role="orchestrator", system_message="Return JSON",
        user_message="Return answer 346", schema=SCHEMA, schema_version="trace-test.v1",
        validator=lambda value: value, max_tokens=512)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("native", [False, True])
def test_returned_trace_is_separate_redacted_and_written_in_artifact(monkeypatch, tmp_path, streaming, native):
    with _coordinate(monkeypatch, streaming=streaming, native=native) as (runtime, context, calls):
        result = _invoke(runtime, context)
        assert result.parsed == {"answer": 346}
        assert result.performance["reasoning_trace"] == "Provider trace with [REDACTED]"
        assert result.performance["reasoning_trace_source"] == "additional_kwargs.reasoning_content"
        assert result.performance["reasoning_summary"] is None
        assert result.performance["reasoning_token_evidence"]["tokens"] == 14
        assert result.performance["attempt_records"][0]["reasoning_trace"] == result.performance["reasoning_trace"]
        path = write_json_report(tmp_path / "run.json", {"llm_performance": context.records})
        artifact = json.loads(path.read_text())
        assert artifact["llm_performance"][0]["reasoning_trace"] == result.performance["reasoning_trace"]
        assert SECRET not in path.read_text()
        assert len(calls) == 1


@pytest.mark.parametrize(("text", "finish", "parse_status"), [("invalid JSON", "stop", "invalid"), ("", "length", "incomplete")])
def test_rejected_or_truncated_answer_keeps_returned_trace(monkeypatch, text, finish, parse_status):
    with _coordinate(monkeypatch, streaming=True, text=text, finish=finish) as (runtime, context, _):
        with pytest.raises(LLMOutputError):
            _invoke(runtime, context)
        record = context.records[0]
        assert record["parse_status"] == parse_status
        assert record["reasoning_trace"] == "Provider trace with [REDACTED]"
        assert record["attempt_records"][0]["reasoning_trace"] == record["reasoning_trace"]


def test_cache_hit_has_no_new_reasoning_and_preserves_original_call_evidence(monkeypatch):
    with _coordinate(monkeypatch, streaming=False, cache=True) as (runtime, context, calls):
        first = _invoke(runtime, context)
        cached = _invoke(runtime, context)
        assert first.performance["reasoning_trace"]
        assert cached.performance["cache_hit"] and cached.performance["reasoning_trace"] is None
        assert cached.performance["reasoning_summary"] is None
        assert context.records[0]["reasoning_trace"] == first.performance["reasoning_trace"]
        assert len(calls) == 1


def test_absent_trace_stays_null_without_inference_from_answer_or_token_count(monkeypatch):
    with _coordinate(monkeypatch, streaming=False, trace=None) as (runtime, context, _):
        record = _invoke(runtime, context).performance
        assert record["reasoning_token_evidence"]["tokens"] == 14
        assert record["reasoning_trace"] is record["reasoning_summary"] is None
        assert record["reasoning_trace_source"] is record["reasoning_summary_source"] is None


@pytest.mark.parametrize("streaming", [False, True])
def test_async_calls_preserve_trace_without_changing_answer(streaming):
    async def scenario():
        def with_response(request):
            return _response(streaming=streaming, trace="Async provider trace")
        async with httpx.AsyncClient(transport=httpx.MockTransport(with_response)) as client:
            model = get_llm("openai_compatible", model_name="gateway-model", base_url="https://gateway.invalid/v1",
                api_key="offline", use_responses_api=False, streaming=streaming, http_async_client=client)
            task = asyncio.create_task(model.ainvoke("Return JSON"))
            try:
                for _ in range(500):
                    if task.done():
                        break
                    await asyncio.sleep(0.01)
                assert task.done(), "The isolated async SDK call did not finish"
                message = task.result()
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
            assert message.content == '{"answer":346}'
            assert reasoning_evidence(message)["reasoning_trace"] == "Async provider trace"
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(scenario())
        loop.run_until_complete(loop.shutdown_asyncgens())
    finally:
        loop.close()


def test_summaries_and_encrypted_reasoning_are_never_mislabeled_as_trace():
    message = AIMessage(content=[{"type": "reasoning", "summary": [{"type": "summary_text", "text": "Provider summary"}],
                                "encrypted_content": "opaque-data"}, {"type": "text", "text": "Final answer"}])
    evidence = reasoning_evidence(message)
    assert evidence["reasoning_trace"] is None
    assert evidence["reasoning_summary"] == "Provider summary"
    assert evidence["reasoning_summary_source"] == "content"
    assert "opaque-data" not in json.dumps(evidence)


def test_detail_blocks_preserve_trace_and_summary_separately():
    message = AIMessage(content="Final answer", additional_kwargs={"reasoning_details": [
        {"type": "reasoning.text", "text": "Provider reasoning"},
        {"type": "reasoning.summary", "summary": "Provider summary"},
        {"type": "reasoning.encrypted", "data": "opaque"}]})
    evidence = reasoning_evidence(message)
    assert evidence["reasoning_trace"] == "Provider reasoning"
    assert evidence["reasoning_summary"] == "Provider summary"


def test_repeated_streamed_calls_do_not_accumulate_previous_reasoning():
    calls = []

    def handle(request):
        calls.append(request)
        return _response(streaming=True, trace=f"Trace for call {len(calls)}")

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        model = get_llm("openai_compatible", model_name="gateway-model", api_key="offline",
                       base_url="https://gateway.invalid/v1", streaming=True, use_responses_api=False,
                       http_client=client)
        first = model.invoke("First call")
        second = model.invoke("Second call")
    assert reasoning_evidence(first)["reasoning_trace"] == "Trace for call 1"
    assert reasoning_evidence(second)["reasoning_trace"] == "Trace for call 2"
