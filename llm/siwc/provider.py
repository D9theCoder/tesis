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
        if self.reasoning_effort:
            body["reasoning"] = {"effort": self.reasoning_effort}
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
                    if "text/event-stream" not in response.headers.get("content-type", ""):
                        raise SIWCRequestError("ChatGPT inference", code="invalid_stream", request_id=request_id)
                    for event in _events(response, deadline=deadline):
                        if time.monotonic() > deadline:
                            raise SIWCRequestError("ChatGPT inference", code="timeout", request_id=request_id)
                        kind = event.get("type")
                        if kind == "response.output_text.delta":
                            delta = event.get("delta")
                            if not isinstance(delta, str):
                                raise SIWCRequestError("ChatGPT inference", code="invalid_stream", request_id=request_id)
                            if run_manager:
                                run_manager.on_llm_new_token(delta)
                        elif kind in {"response.completed", "response.incomplete"}:
                            final = event.get("response")
                            terminal = kind
                            break
                        elif kind in {"response.failed", "error"}:
                            error = (event.get("response") or {}).get("error") or event.get("error") or event
                            if not isinstance(error, dict):
                                error = {"code": "stream_error"}
                            raise SIWCRequestError("ChatGPT inference", code=error.get("code"),
                                param=error.get("param"), body=error, request_id=request_id)
        except httpx.TimeoutException:
            raise SIWCRequestError("ChatGPT inference", code="timeout", request_id=request_id) from None
        except httpx.HTTPError:
            raise SIWCRequestError("ChatGPT inference", code="connection_error", request_id=request_id) from None
        if terminal is None or not isinstance(final, dict):
            raise SIWCRequestError("ChatGPT inference", code="interrupted_stream", request_id=request_id)
        status = "incomplete" if terminal == "response.incomplete" else "completed"
        if final.get("status") != status:
            raise SIWCRequestError("ChatGPT inference", code="invalid_terminal_event", request_id=request_id)
        # The terminal response is authoritative; deltas may include tentative text.
        output = final.get("output")
        if not isinstance(output, list) or any(not isinstance(item, dict) for item in output):
            raise SIWCRequestError("ChatGPT inference", code="invalid_terminal_event", request_id=request_id)
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
        message = AIMessage(content="" if refusal else final_text, response_metadata=metadata,
            additional_kwargs={"refusal": refusal} if refusal else {})
        return ChatResult(generations=[ChatGeneration(message=message)])


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
                                  request_timeout=timeout, reasoning_effort=effort)
