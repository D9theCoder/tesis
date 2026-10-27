"""LangChain adapter for SIWC's documented public Responses HTTP/SSE route."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import RunnableLambda
from pydantic import Field, PrivateAttr

from llm.siwc import PROVIDER, RESOURCE
from llm.siwc.oauth import SIWCRequestError, SIWCSession, response_error
from llm.siwc.storage import SIWCError


class ChatGPTSubscriptionModel(BaseChatModel):
    """Consume the stream to a terminal event before returning an AIMessage.

    Credentials are fetched per dispatch, never retained in serializable model
    fields. No inference retry or automatic API-key billing fallback occurs.
    """

    model_name: str
    account: str = "default"
    request_timeout: float = Field(default=60, gt=0)
    reasoning_effort: str | None = None
    streaming: bool = True
    _session: SIWCSession = PrivateAttr(default_factory=SIWCSession)

    @property
    def _llm_type(self) -> str:
        return PROVIDER

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {"model_name": self.model_name, "account": self.account,
                "reasoning_effort": self.reasoning_effort}

    def with_structured_output(self, schema: dict[str, Any], *, include_raw: bool = False,
                               method: str = "json_schema", strict: bool = True, **kwargs: Any):
        if method != "json_schema" or not isinstance(schema, dict) or kwargs:
            raise ValueError("SIWC structured output requires a JSON schema.")
        json_schema = schema.get("schema", schema)
        if "parameters" in schema:
            json_schema = schema["parameters"]
        formatted = {"format": {"type": "json_schema", "name": schema.get("name", "tesis_response"),
                                 "schema": json_schema, "strict": strict}}

        def parse(raw: AIMessage) -> Any:
            parsed = None
            error = None
            try:
                parsed = json.loads(raw.content)
            except (ValueError, TypeError) as exc:
                if not include_raw:
                    raise
                error = exc
            if include_raw:
                return {"raw": raw, "parsed": parsed, "parsing_error": error}
            return parsed

        return self.bind(text=formatted) | RunnableLambda(parse)

    def _generate(self, messages: list[BaseMessage], stop: list[str] | None = None,
                  run_manager: CallbackManagerForLLMRun | None = None, **kwargs: Any) -> ChatResult:
        if not self.model_name.strip():
            raise SIWCError("Choose a model from auth models or the TUI ChatGPT model selector.")
        if stop or set(kwargs) - {"text"}:
            raise SIWCError("This SIWC adapter accepts only its documented text response format.")
        inputs = []
        for message in messages:
            role = {"system": "developer", "human": "user", "ai": "assistant"}.get(message.type)
            if role is None or not isinstance(message.content, str):
                raise SIWCError("TESIS SIWC inference expects text system/user/assistant messages.")
            inputs.append({"role": role, "content": message.content})
        body: dict[str, Any] = {"model": self.model_name, "input": inputs, "store": False, "stream": True}
        body["reasoning"] = {"summary": "auto"}
        if self.reasoning_effort:
            body["reasoning"]["effort"] = self.reasoning_effort
        if "text" in kwargs:
            body["text"] = kwargs["text"]
        token = self._session.access_token(self.account)
        deadline = time.monotonic() + self.request_timeout
        final: dict[str, Any] | None = None
        terminal: str | None = None
        request_id = None
        try:
            with self._session.http() as client:
                with client.stream("POST", f"{RESOURCE}/responses", json=body,
                        timeout=self.request_timeout, headers={"Authorization": f"Bearer {token}",
                        "Accept": "text/event-stream"}) as response:
                    request_id = response.headers.get("x-request-id") or response.headers.get("openai-request-id")
                    if response.status_code != 200:
                        response.read()
                        raise response_error(response, "ChatGPT inference")
                    for event in response_events(response, deadline=deadline):
                        kind = event.get("type")
                        if kind == "response.output_text.delta":
                            if run_manager:
                                run_manager.on_llm_new_token(event["delta"])
                        elif kind in {"response.completed", "response.incomplete"}:
                            final = event["response"]
                            terminal = kind
                            break
        except httpx.TimeoutException:
            raise SIWCRequestError("ChatGPT inference", code="timeout", request_id=request_id) from None
        except httpx.HTTPError:
            raise SIWCRequestError("ChatGPT inference", code="connection_error", request_id=request_id) from None
        assert final is not None  # response_events requires a validated terminal response.
        status = "incomplete" if terminal == "response.incomplete" else "completed"
        output = final["output"]
        final_text = "".join(part.get("text", "") for item in output if item.get("type") == "message"
            for part in item.get("content", []) if part.get("type") == "output_text")
        refusal = "".join(part.get("refusal", "") for item in output if item.get("type") == "message"
            for part in item.get("content", []) if part.get("type") == "refusal")
        usage = final.get("usage")
        incomplete_details = final.get("incomplete_details")
        limited = isinstance(incomplete_details, dict) and incomplete_details.get("reason") == "max_output_tokens"
        metadata = {"model_name": self.model_name, "status": status, "request_id": request_id,
                    "finish_reason": ("length" if limited else "incomplete") if status == "incomplete" else "stop",
                    "incomplete_details": final.get("incomplete_details"), "usage": usage,
                    "response_id": final.get("id"),
                    "max_output_tokens_applied": False, "temperature_applied": False}
        additional = {"refusal": refusal} if refusal else {}
        summaries = [{"type": "reasoning", "summary": item["summary"]} for item in output
                     if item.get("type") == "reasoning" and any(part.get("type") == "summary_text" and part["text"]
                                                                for part in item.get("summary", []))]
        if summaries:
            additional["reasoning"] = summaries
        elif final["reasoning_summary"]:
            additional["reasoning_summary"] = final["reasoning_summary"]
        message = AIMessage(content="" if refusal else final_text, response_metadata=metadata,
            additional_kwargs=additional)
        return ChatResult(generations=[ChatGeneration(message=message)])


def _validate_output_item(item: Any, *, code: str, request_id: str | None) -> dict[str, Any]:
    """Validate the output fields consumed by both chat and experiment callers."""
    if not isinstance(item, dict):
        raise SIWCRequestError("ChatGPT inference", code=code, request_id=request_id)
    item_type = item.get("type")
    if not isinstance(item_type, str):
        raise SIWCRequestError("ChatGPT inference", code=code, request_id=request_id)
    parts_key = {"message": "content", "reasoning": "summary"}.get(item_type)
    if parts_key:
        parts = item.get(parts_key, [])
        if not isinstance(parts, list) or any(not isinstance(part, dict) for part in parts):
            raise SIWCRequestError("ChatGPT inference", code=code, request_id=request_id)
        for part in parts:
            kind = part.get("type")
            field = "text" if kind in ("output_text", "summary_text") else "refusal" if kind == "refusal" else None
            if field and not isinstance(part.get(field), str):
                raise SIWCRequestError("ChatGPT inference", code=code, request_id=request_id)
    return item


def response_events(response: httpx.Response, *, deadline: float):
    """Validate SSE content and assemble completed items under a terminal event.

    Some SIWC responses omit Content-Type and leave terminal output empty.
    Completed output items can supply that output, but tentative deltas cannot
    turn an interrupted stream into a successful response.
    """
    request_id = response.headers.get("x-request-id") or response.headers.get("openai-request-id")
    completed_items: dict[int, dict[str, Any]] = {}
    summary_parts: dict[tuple[int, int], str] = {}
    for event in _events(response, deadline=deadline):
        kind = event.get("type")
        if not isinstance(kind, str):
            raise SIWCRequestError("ChatGPT inference", code="invalid_stream", request_id=request_id)
        if kind in {"response.output_text.delta", "response.reasoning_summary_text.delta", "response.refusal.delta"}:
            if not isinstance(event.get("delta"), str):
                raise SIWCRequestError("ChatGPT inference", code="invalid_stream", request_id=request_id)
        if kind in {"response.reasoning_summary_text.delta", "response.reasoning_summary_text.done", "response.reasoning_summary_part.done"}:
            output_index, summary_index = event.get("output_index"), event.get("summary_index")
            if type(output_index) is not int or output_index < 0 or type(summary_index) is not int or summary_index < 0:
                raise SIWCRequestError("ChatGPT inference", code="invalid_stream", request_id=request_id)
            key = output_index, summary_index
            if kind == "response.reasoning_summary_text.delta":
                summary_parts[key] = summary_parts.get(key, "") + event["delta"]
            else:
                part = event.get("part")
                text = part.get("text") if isinstance(part, dict) and part.get("type") == "summary_text" else None
                if kind == "response.reasoning_summary_text.done":
                    text = event.get("text")
                if not isinstance(text, str):
                    raise SIWCRequestError("ChatGPT inference", code="invalid_stream", request_id=request_id)
                summary_parts[key] = text
        elif kind == "response.output_item.done":
            index = event.get("output_index")
            if type(index) is not int or index < 0:
                raise SIWCRequestError("ChatGPT inference", code="invalid_stream", request_id=request_id)
            completed_items[index] = _validate_output_item(event.get("item"), code="invalid_stream", request_id=request_id)
        elif kind in {"response.completed", "response.incomplete"}:
            final = event.get("response")
            status = "completed" if kind == "response.completed" else "incomplete"
            if not isinstance(final, dict) or final.get("status") != status or not isinstance(final.get("output"), list):
                raise SIWCRequestError("ChatGPT inference", code="invalid_terminal_event", request_id=request_id)
            if final["output"]:
                output = [_validate_output_item(item, code="invalid_terminal_event", request_id=request_id) for item in final["output"]]
            else:
                output = [completed_items[index] for index in sorted(completed_items)]
            # A terminal answer can omit reasoning items that were streamed.
            # Prefer final summaries, then completed items, then summary events.
            for items in (output, [completed_items[index] for index in sorted(completed_items)]):
                summaries = [part["text"] for item in items if item.get("type") == "reasoning"
                             for part in item.get("summary", []) if part.get("type") == "summary_text" and part["text"]]
                if summaries:
                    break
            if not summaries:
                summaries = [summary_parts[key] for key in sorted(summary_parts) if summary_parts[key]]
            yield {**event, "response": {**final, "output": output, "reasoning_summary": "\n".join(summaries)}}
            return
        elif kind in {"response.failed", "error"}:
            final = event.get("response")
            error = (final.get("error") if isinstance(final, dict) else None) or event.get("error") or event
            if not isinstance(error, dict):
                error = {"code": "stream_error"}
            raise SIWCRequestError("ChatGPT inference", code=error.get("code"),
                param=error.get("param"), body=error, request_id=request_id)
        yield event
    raise SIWCRequestError("ChatGPT inference", code="interrupted_stream", request_id=request_id)


def _events(response: httpx.Response, *, deadline: float):
    """Parse SSE data blocks, including comments and multi-line JSON events."""
    data: list[str] = []
    for line in response.iter_lines():
        if time.monotonic() > deadline:
            raise SIWCRequestError("ChatGPT inference", code="timeout")
        if line == "":
            if data:
                payload = "\n".join(data)
                data.clear()
                if payload == "[DONE]":
                    return
                try:
                    event = json.loads(payload)
                    if not isinstance(event, dict):
                        raise ValueError
                except ValueError:
                    raise SIWCRequestError("ChatGPT inference", code="invalid_stream") from None
                yield event
        elif line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
    # Missing delimiters or terminal events are interrupted, never successful.


def build_model(**kwargs: Any) -> ChatGPTSubscriptionModel:
    """Normalize only harness controls, rejecting arbitrary request overrides."""
    if kwargs.pop("api_key", None):
        raise ValueError("openai_codex_auth uses saved SIWC credentials; remove api_key.")
    base_url = kwargs.pop("base_url", None)
    if base_url and str(base_url).rstrip("/") != RESOURCE:
        raise ValueError("openai_codex_auth requires the public https://api.openai.com/v1 endpoint.")
    model = kwargs.pop("model_name", kwargs.pop("model", ""))
    timeout = kwargs.pop("request_timeout", kwargs.pop("timeout", 60))
    retries = kwargs.pop("max_retries", 0)
    if retries not in (None, 0):
        raise ValueError("openai_codex_auth does not perform hidden inference retries; use max_retries: 0.")
    # These shared harness controls are unsupported by the SIWC preview. They
    # remain in experiment configuration but must never enter the HTTP body.
    for name in ("temperature", "max_tokens", "max_output_tokens", "system_prompt", "streaming"):
        kwargs.pop(name, None)
    account = kwargs.pop("account", "default")
    effort = kwargs.pop("reasoning_effort", None)
    if kwargs:
        raise ValueError("Unsupported openai_codex_auth configuration fields: " + ", ".join(sorted(kwargs)))
    return ChatGPTSubscriptionModel(model_name=model, account=account,
                                  request_timeout=timeout, reasoning_effort=effort, cache=False)
