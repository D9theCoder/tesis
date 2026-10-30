"""Focused tests for safe LLM and AKG failure diagnostics."""

from __future__ import annotations

import pytest

from llm.diagnostics import (
    redact_diagnostic_text,
)
from llm.runtime import LLMRuntime, RoleSettings


_SCHEMA = {
    "type": "object",
    "properties": {"value": {"type": "string"}},
    "required": ["value"],
}


def _invoke(runtime: LLMRuntime, context):
    return runtime.invoke(
        context=context,
        role="orchestrator",
        system_message="system",
        user_message="user",
        schema=_SCHEMA,
        schema_version="diagnostics.v1",
        validator=lambda value: value,
        max_tokens=32,
    )


def test_redaction_is_bounded_and_removes_named_credentials():
    result = redact_diagnostic_text("password=hunter2 " + "x" * 1_000, limit=80)
    assert "hunter2" not in result
    assert len(result) == 80


def test_auth_failure_that_mentions_structured_output_is_not_masked_by_fallback(monkeypatch):
    class Response:
        status_code = 401
        headers = {}

    class AuthenticationError(RuntimeError):
        response = Response()

    class Structured:
        def invoke(self, messages):
            del messages
            raise AuthenticationError(
                "response_format json_schema unsupported because API key is unauthorized"
            )

    class Client:
        direct_calls = 0

        def with_structured_output(self, *args, **kwargs):
            del args, kwargs
            return Structured()

        def invoke(self, messages):
            del messages
            self.direct_calls += 1
            raise AssertionError("json-prompt fallback must not mask authentication failures")

    client = Client()
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: client)
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="auth-coordinate",
        default_provider="openai",
        default_model_config={"model_name": "gpt-test"},
        role_settings={"orchestrator": RoleSettings(structured_output="auto")},
    ) as context:
        with pytest.raises(AuthenticationError):
            _invoke(runtime, context)

    assert client.direct_calls == 0
    assert context.records[0]["parse_status"] == "provider_error"
