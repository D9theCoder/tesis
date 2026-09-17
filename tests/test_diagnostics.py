"""Focused tests for safe LLM and AKG failure diagnostics."""

from __future__ import annotations

import pytest

from core.knowledge_graph import AKGValidationError
from llm.diagnostics import (
    format_provider_error,
    provider_error_details,
    redact_diagnostic_text,
)
from llm.runtime import LLMOutputError, LLMRuntime, RoleSettings


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


def test_provider_diagnostic_extracts_http_context_and_redacts_secrets():
    class Response:
        status_code = 429
        headers = {"x-request-id": "req-safe-123"}

    class ProviderError(RuntimeError):
        response = Response()

    try:
        raise OSError("socket closed")
    except OSError as cause:
        try:
            raise ProviderError(
                "Bearer top-secret https://user:pass@example.test/v1?api_key=also-secret "
                "request body: {'prompt': 'private'}"
            ) from cause
        except ProviderError as exc:
            details = provider_error_details(
                exc,
                provider="openai_compatible",
                model="example-model",
                role="orchestrator",
                coordinate_id="coord-1",
            )

    rendered = format_provider_error(details)
    assert details["status_code"] == 429
    assert details["request_id"] == "req-safe-123"
    assert details["cause_type"] == "OSError"
    assert details["remediation"]
    assert "coord-1" in rendered
    assert "top-secret" not in rendered
    assert "user:pass" not in rendered
    assert "also-secret" not in rendered
    assert "private" not in rendered


def test_provider_diagnostic_walks_to_chained_http_metadata():
    class Response:
        status_code = 503
        headers = {"x-request-id": "req-from-cause"}

    class CauseError(RuntimeError):
        response = Response()

    try:
        try:
            raise CauseError("upstream failed")
        except CauseError as cause:
            raise RuntimeError("outer wrapper has no HTTP metadata") from cause
    except RuntimeError as exc:
        details = provider_error_details(
            exc,
            provider="openai",
            model="gpt-test",
            role="orchestrator",
            coordinate_id="chain-coordinate",
        )

    assert details["status_code"] == 503
    assert details["request_id"] == "req-from-cause"
    assert details["cause_type"] == "CauseError"


@pytest.mark.parametrize(
    ("separator", "key"),
    [
        ("?", "token"),
        ("?", "access_token"),
        ("?", "auth"),
        ("?", "session"),
        ("?", "sid"),
        ("?", "code"),
        ("?", "sig"),
        ("?", "signature"),
        ("?", "api_key"),
        ("#", "access_token"),
    ],
)
def test_provider_diagnostic_redacts_every_url_value(separator, key):
    secret = f"private-{key.replace('_', '-')}-value"
    details = provider_error_details(
        RuntimeError(f"request failed at https://example.test/callback{separator}{key}={secret}"),
        provider="openai",
        model="gpt-test",
        role="orchestrator",
        coordinate_id="redaction-coordinate",
    )

    rendered = format_provider_error(details)
    assert secret not in rendered
    assert f"{key}=[REDACTED]" in rendered


def _render_url_diagnostic(url):
    details = provider_error_details(
        RuntimeError(f"request failed at {url}"),
        provider="openai",
        model="gpt-test",
        role="orchestrator",
        coordinate_id="redaction-coordinate",
    )
    return format_provider_error(details)


def test_provider_diagnostic_redacts_single_bare_query_segment():
    rendered = _render_url_diagnostic("https://p.test/v1/chat?opaqueToken123")

    assert "opaqueToken123" not in rendered
    assert "https://p.test/v1/chat?[REDACTED]" in rendered


def test_provider_diagnostic_redacts_bare_query_segment_after_named_pair():
    rendered = _render_url_diagnostic("https://p.test/x?a=1&abc456")

    assert "abc456" not in rendered
    assert "https://p.test/x?a=[REDACTED]&[REDACTED]" in rendered


def test_provider_diagnostic_redacts_bare_fragment_segment():
    rendered = _render_url_diagnostic("https://p.test/x#sess9f2b")

    assert "sess9f2b" not in rendered
    assert "https://p.test/x#[REDACTED]" in rendered


def test_redaction_is_bounded_and_removes_named_credentials():
    result = redact_diagnostic_text("password=hunter2 " + "x" * 1_000, limit=80)
    assert "hunter2" not in result
    assert len(result) == 80


def test_runtime_records_reasoning_request_and_provider_token_evidence(monkeypatch):
    captured_config = {}

    class Response:
        content = '{"value":"ok"}'
        usage_metadata = {
            "input_tokens": 3,
            "output_tokens": 9,
            "output_token_details": {"reasoning": 7},
        }
        response_metadata = {}

    class Client:
        def invoke(self, messages):
            del messages
            return Response()

    def factory(_provider, **config):
        captured_config.update(config)
        return Client()

    monkeypatch.setattr("llm.runtime.get_llm", factory)
    events = []
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="reasoning-coordinate",
        default_provider="openai",
        default_model_config={"model_name": "gpt-test", "reasoning_effort": "low"},
        role_settings={
            "orchestrator": RoleSettings(
                reasoning_effort="xhigh",
                structured_output="json_prompt",
            )
        },
        activity_callback=lambda event, data: events.append((event, data)),
    ) as context:
        result = _invoke(runtime, context)

    assert captured_config["reasoning_effort"] == "xhigh"
    assert result.performance["reasoning_effort_requested"] == "xhigh"
    assert result.performance["reasoning_token_evidence"] == {
        "tokens": 7,
        "source": "provider_usage.output_token_details.reasoning",
    }
    completed = next(data for event, data in events if event == "llm.completed")
    assert completed["model"] == "gpt-test"
    assert completed["coordinate_id"] == "reasoning-coordinate"
    assert completed["reasoning_effort_requested"] == "xhigh"
    assert completed["reasoning_token_evidence"]["tokens"] == 7


def test_runtime_preserves_provider_exception_type_with_actionable_safe_text(monkeypatch):
    class Response:
        status_code = 401
        headers = {"x-request-id": "req-auth-1"}

    class AuthenticationError(RuntimeError):
        response = Response()

    class Client:
        def invoke(self, messages):
            del messages
            raise AuthenticationError("invalid api_key=super-secret")

    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: Client())
    events = []
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="provider-coordinate",
        default_provider="openai",
        default_model_config={"model_name": "gpt-test"},
        role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
        activity_callback=lambda event, data: events.append((event, data)),
    ) as context:
        with pytest.raises(AuthenticationError) as caught:
            _invoke(runtime, context)

    message = str(caught.value)
    assert "provider=openai" in message
    assert "model=gpt-test" in message
    assert "coordinate_id=provider-coordinate" in message
    assert "Remediation:" in message
    assert "super-secret" not in message
    failed = next(data for event, data in events if event == "llm.failed")
    assert failed["status_code"] == 401
    assert failed["request_id"] == "req-auth-1"
    assert failed["error_type"] == "AuthenticationError"
    assert failed["remediation"]
    assert context.records[0]["parse_status"] == "provider_error"


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


@pytest.mark.parametrize("status_location", ["response_metadata", "response_attribute"])
def test_responses_incomplete_status_rejects_valid_looking_json(monkeypatch, status_location):
    class Response:
        content = [{"type": "output_text", "text": '{"value":"partial"}'}]
        usage_metadata = {}

        def __init__(self):
            self.response_metadata = {}
            if status_location == "response_metadata":
                self.response_metadata = {
                    "status": "incomplete",
                    "incomplete_details": {"reason": "max_output_tokens"},
                }
            else:
                self.status = "incomplete"
                self.incomplete_details = {"reason": "max_output_tokens"}

    class Client:
        def invoke(self, messages):
            del messages
            return Response()

    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: Client())
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="incomplete-coordinate",
        default_provider="openai",
        default_model_config={"model_name": "gpt-test", "use_responses_api": True},
        role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
    ) as context:
        with pytest.raises(LLMOutputError) as caught:
            _invoke(runtime, context)

    assert caught.value.performance["parse_status"] == "incomplete"
    assert caught.value.performance["incomplete_reason"] == "max_output_tokens"
    assert context.records[0]["parse_status"] == "incomplete"


def test_responses_list_content_skips_non_text_blocks_before_json(monkeypatch):
    class Response:
        content = [
            {"type": "reasoning", "text": "internal reasoning is not response text"},
            {"type": "tool_call", "name": "ignored"},
            {"type": "output_text", "text": '{"value":"from-output-text"}'},
        ]
        usage_metadata = {}
        response_metadata = {"status": "completed"}

    class Client:
        def invoke(self, messages):
            del messages
            return Response()

    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: Client())
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="list-content-coordinate",
        default_provider="openai",
        default_model_config={"model_name": "gpt-test", "use_responses_api": True},
        role_settings={"orchestrator": RoleSettings(structured_output="json_prompt")},
    ) as context:
        result = _invoke(runtime, context)

    assert result.parsed == {"value": "from-output-text"}
    assert result.text == '{"value":"from-output-text"}'
    assert "internal reasoning" not in result.text


def test_native_responses_incomplete_status_rejects_parsed_mapping(monkeypatch):
    class Raw:
        content = [{"type": "output_text", "text": '{"value":"partial"}'}]
        tool_calls = []
        response_metadata = {
            "status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
        }
        additional_kwargs = {}
        usage_metadata = {}

    class Structured:
        def invoke(self, messages):
            del messages
            return {"raw": Raw(), "parsed": {"value": "partial"}}

    class Client:
        def with_structured_output(self, *args, **kwargs):
            del args, kwargs
            return Structured()

    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: Client())
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(
        coordinate_id="native-incomplete-coordinate",
        default_provider="openai",
        default_model_config={"model_name": "gpt-test", "use_responses_api": True},
        role_settings={"orchestrator": RoleSettings(structured_output="native")},
    ) as context:
        with pytest.raises(LLMOutputError) as caught:
            _invoke(runtime, context)

    assert caught.value.performance["parse_status"] == "incomplete"
    assert caught.value.performance["incomplete_reason"] == "max_output_tokens"


def test_akg_validation_error_carries_invariant_and_repair_hint():
    error = AKGValidationError(
        "Chain edge source->target missing target_agent",
        invariant="chain_metadata",
        repair="set target_agent to an in-scope method",
    )
    assert isinstance(error, ValueError)
    assert error.invariant == "chain_metadata"
    assert error.repair == "set target_agent to an in-scope method"
    assert "AKG validation failed" in str(error)
    assert "Repair:" in str(error)
