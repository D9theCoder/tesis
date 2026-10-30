"""Provider reasoning survives SDK conversion and artifact writing, offline."""

import json
from contextlib import contextmanager

import httpx

from llm.provider import get_llm
from llm.runtime import LLMRuntime


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


def test_absent_trace_stays_null_without_inference_from_answer_or_token_count(monkeypatch):
    with _coordinate(monkeypatch, streaming=False, trace=None) as (runtime, context, _):
        record = _invoke(runtime, context).performance
        assert record["reasoning_token_evidence"]["tokens"] == 14
        assert record["reasoning_trace"] is record["reasoning_summary"] is None
        assert record["reasoning_trace_source"] is record["reasoning_summary_source"] is None
