"""Focused offline OAuth, storage, refresh, catalog, and Responses contracts."""

from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
import json
import os
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode

from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt
import pytest
from langchain_core.messages import HumanMessage, SystemMessage

from llm.provider import get_llm, get_llm_from_model_config
from llm.siwc import ISSUER, RESOURCE, SCOPES
from llm.siwc.oauth import SIWCRequestError, SIWCSession
from llm.siwc.storage import CredentialStore, SIWCError
from tesis.model_config import ModelConfig


@pytest.fixture(scope="module")
def signing_key():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    public.update(kid="test-key", alg="RS256", use="sig")
    return private, public


@pytest.fixture
def oauth(tmp_path, monkeypatch, signing_key):
    monkeypatch.setenv("TESIS_SIWC_HOME", str(tmp_path / "siwc"))
    state = SimpleNamespace(calls=[], tokens=None, refresh=None, inference=None, status=200, content_type="text/event-stream",
        model_data={"models": [
            {"slug": "future-model-b", "display_name": "Future B", "visibility": "list"},
            {"slug": "hidden", "display_name": "Hidden", "visibility": "hidden"},
            {"slug": "future-model-a", "display_name": "Future A", "visibility": "list"},
        ]})
    metadata = {"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/api/accounts/authorize",
        "token_endpoint": f"{ISSUER}/api/accounts/oauth/token", "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "revocation_endpoint": f"{ISSUER}/oauth/revoke"}

    def handler(request):
        state.calls.append(request)
        path = request.url.path
        if path.endswith("openid-configuration"):
            return httpx.Response(200, json=metadata)
        if path.endswith("jwks.json"):
            return httpx.Response(200, json={"keys": [signing_key[1]]})
        if path.endswith("/token"):
            form = parse_qs(request.content.decode())
            result = state.refresh if form["grant_type"] == ["refresh_token"] else state.tokens
            if isinstance(result, httpx.Response):
                return result
            return httpx.Response(200, json=result)
        if path.endswith("/revoke"):
            return httpx.Response(state.status)
        if path.endswith("/models"):
            return httpx.Response(state.status, json=state.model_data)
        if path.endswith("/responses"):
            if state.status != 200:
                return httpx.Response(state.status, json=state.inference, headers={"x-request-id": "req-test"})
            data = "".join("data: " + json.dumps(event) + "\n\n" for event in state.inference)
            headers = {"x-request-id": "req-test"}
            if state.content_type is not None:
                headers["content-type"] = state.content_type
            return httpx.Response(200, content=data.encode(), headers=headers)
        raise AssertionError(f"Unexpected network route: {request.method} {request.url.path}")

    state.transport = httpx.MockTransport(handler)
    state.session = SIWCSession(transport=state.transport)
    state.metadata = metadata
    state.key = signing_key[0]

    def sign(attempt, **overrides):
        claims = {"iss": ISSUER, "aud": attempt.client_id if attempt.client_id != "dynamic_agent_client" else "oaiapp_test",
            "sub": "subject-1", "email": "same@example.test", "nonce": attempt.nonce,
            "iat": int(time.time()), "exp": int(time.time()) + 3600}
        claims.update(overrides)
        return jwt.encode(claims, state.key, algorithm="RS256", headers={"kid": "test-key"})

    state.sign = sign

    def begin(account="default"):
        return state.session.begin(account, "http://127.0.0.1:1455/auth/callback")

    state.begin = begin

    def complete(attempt, **overrides):
        state.tokens = {"access_token": "access-initial", "refresh_token": "refresh-initial",
            "id_token": sign(attempt), "expires_in": 3600, "token_type": "Bearer", "scope": " ".join(SCOPES)}
        state.tokens.update(overrides)
        query = {"code": "authorization-code", "state": attempt.state}
        if attempt.client_id == "dynamic_agent_client":
            query["client_id"] = "oaiapp_test"
        return state.session.complete(attempt, "/auth/callback?" + urlencode(query))

    state.complete = complete

    def connect(account="default", **overrides):
        attempt, _ = begin(account)
        return complete(attempt, **overrides)

    state.connect = connect
    state.refresh = {"access_token": "access-renewed", "refresh_token": "refresh-renewed",
        "expires_in": 3600, "token_type": "Bearer"}
    return state


def _document(oauth):
    with oauth.session.store.locked():
        return oauth.session.store.read()


def _expire(oauth):
    with oauth.session.store.locked():
        document = oauth.session.store.read()
        document["profiles"]["default"]["expires_at"] = time.time() + 10
        oauth.session.store.write(document)


def _token_calls(oauth):
    return [call for call in oauth.calls if call.url.path.endswith("/token")]


def test_dynamic_registration_pkce_and_host_survive_restart(oauth):
    first, url = oauth.begin()
    params = parse_qs(url.split("?", 1)[1])
    expected = base64.urlsafe_b64encode(hashlib.sha256(first.verifier.encode()).digest()).rstrip(b"=").decode()
    assert params["code_challenge"] == [expected]
    assert params["scope"] == [" ".join(SCOPES)]
    assert params["resource"] == [RESOURCE]
    assert params["client_id"] == ["dynamic_agent_client"]
    assert params["agent_name_hint"] == ["TESIS"]
    restarted = SIWCSession(transport=oauth.transport)
    second, _ = restarted.begin("default", first.redirect_uri)
    assert second.host_id == first.host_id
    assert second.state != first.state and second.nonce != first.nonce and second.verifier != first.verifier
    assert first.verifier not in repr(first)


def test_code_exchange_verifies_identity_and_stores_private_credentials(oauth):
    result = oauth.connect()
    profile = _document(oauth)["profiles"]["default"]
    form = parse_qs(_token_calls(oauth)[0].content.decode())
    assert form["client_id"] == ["oaiapp_test"]
    assert form["redirect_uri"] == ["http://127.0.0.1:1455/auth/callback"]
    assert form["resource"] == [RESOURCE]
    assert "client_secret" not in form
    assert profile["subject"] == "subject-1"
    assert profile["expires_at"] > time.time() + 3500
    assert result["default"]["plan_usage"] is True
    assert "access-initial" not in json.dumps(result)
    if os.name == "posix":
        assert oauth.session.store.path.stat().st_mode & 0o777 == 0o600
        assert oauth.session.store.directory.stat().st_mode & 0o777 == 0o700


def test_returning_signin_reuses_registration_and_validates_new_identity(oauth):
    oauth.connect()
    first = _document(oauth)
    attempt, url = oauth.begin()
    params = parse_qs(url.split("?", 1)[1])
    assert params["client_id"] == ["oaiapp_test"]
    assert "agent_name_hint" not in params
    assert params["id_token_hint"] == [first["profiles"]["default"]["id_token"]]
    oauth.complete(attempt, access_token="access-second")
    assert _document(oauth)["host_id"] == first["host_id"]
    assert _document(oauth)["profiles"]["default"]["access_token"] == "access-second"


@pytest.mark.parametrize("query", [
    {"state": "wrong", "code": "bad", "client_id": "oaiapp_test"},
    {"error": "access_denied"},
    {"code": "bad"},
    {"code": "bad", "client_id": "dynamic_agent_client"},
    {"client_id": "oaiapp_test"},
])
def test_bad_callbacks_never_exchange_credentials(oauth, query):
    attempt, _ = oauth.begin()
    query.setdefault("state", attempt.state)
    with pytest.raises(SIWCError):
        oauth.session.complete(attempt, "/auth/callback?" + urlencode(query))
    assert not _token_calls(oauth)
    assert not _document(oauth)["profiles"]


def test_duplicate_callback_and_replay_are_rejected(oauth):
    attempt, _ = oauth.begin()
    with pytest.raises(SIWCError, match="Ambiguous"):
        oauth.session.complete(attempt, f"/auth/callback?state={attempt.state}&state={attempt.state}")
    with pytest.raises(SIWCError, match="already used"):
        oauth.complete(attempt)
    assert not _token_calls(oauth)


def test_expired_attempt_and_wrong_callback_origin_are_rejected(oauth):
    attempt, _ = oauth.begin()
    attempt.expires_at = time.time() - 1
    with pytest.raises(SIWCError, match="expired"):
        oauth.complete(attempt)
    attempt, _ = oauth.begin()
    with pytest.raises(SIWCError, match="does not match"):
        oauth.session.complete(attempt, "https://external.example/auth/callback")


@pytest.mark.parametrize("override", [
    {"nonce": "wrong"}, {"iss": "https://untrusted.example"}, {"aud": "another-client"},
    {"exp": 1}, {"iat": 9999999999}, {"sub": ""}, {"azp": "wrong-client"},
])
def test_invalid_id_claims_never_store_tokens(oauth, override):
    attempt, _ = oauth.begin()
    with pytest.raises(SIWCError, match="verification failed"):
        oauth.complete(attempt, id_token=oauth.sign(attempt, **override))
    assert not _document(oauth)["profiles"]


def test_unverified_signature_and_symmetric_algorithm_are_rejected(oauth):
    attempt, _ = oauth.begin()
    forged = jwt.encode({"sub": "attacker"}, "attacker-secret-longer-than-thirty-two-bytes", algorithm="HS256", headers={"kid": "test-key"})
    with pytest.raises(SIWCError, match="verification failed"):
        oauth.complete(attempt, id_token=forged)
    attempt, _ = oauth.begin()
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = {"sub": "subject-1", "iss": ISSUER, "aud": "oaiapp_test", "exp": int(time.time()) + 3600,
              "iat": int(time.time()), "nonce": attempt.nonce}
    forged = jwt.encode(claims, other, algorithm="RS256", headers={"kid": "test-key"})
    with pytest.raises(SIWCError, match="verification failed"):
        oauth.complete(attempt, id_token=forged)


def test_returning_account_mismatch_preserves_previous_session(oauth):
    oauth.connect()
    before = _document(oauth)
    attempt, _ = oauth.begin()
    with pytest.raises(SIWCError, match="differs"):
        oauth.complete(attempt, id_token=oauth.sign(attempt, sub="another-subject"))
    assert _document(oauth) == before


def test_changed_client_callback_is_rejected(oauth):
    oauth.connect()
    attempt, _ = oauth.begin()
    with pytest.raises(SIWCError, match="different client"):
        oauth.session.complete(attempt, "/auth/callback?" + urlencode({"state": attempt.state, "code": "code", "client_id": "oaiapp_other"}))
    assert len(_token_calls(oauth)) == 1


def test_identity_only_connection_is_saved_but_cannot_infer(oauth):
    result = oauth.connect(scope="openid profile email", refresh_token=None)
    assert result["default"]["signed_in"] and not result["default"]["plan_usage"]
    with pytest.raises(SIWCError, match="plan usage is disabled"):
        oauth.session.list_models()
    assert not any(call.url.path.endswith("/models") for call in oauth.calls)


def test_identity_only_token_response_does_not_require_an_inference_token(oauth):
    result = oauth.connect(scope="openid profile email", access_token=None, expires_in=None, refresh_token=None)
    assert result["default"]["signed_in"] and not result["default"]["plan_usage"]
    with pytest.raises(SIWCError, match="plan usage is disabled"):
        oauth.session.access_token()


def test_same_email_registrations_stay_separate(oauth):
    oauth.connect("personal")
    attempt, _ = oauth.begin("workspace")
    oauth.complete(attempt, id_token=oauth.sign(attempt, sub="workspace-subject"))
    profiles = _document(oauth)["profiles"]
    assert profiles["personal"]["email"] == profiles["workspace"]["email"]
    assert profiles["personal"]["subject"] != profiles["workspace"]["subject"]


def test_discovery_rejects_external_endpoints_before_token_requests(oauth):
    oauth.metadata["token_endpoint"] = "https://external.example/token"
    with pytest.raises(SIWCError, match="unsafe"):
        oauth.begin()
    assert not _token_calls(oauth)


def test_near_expiry_refresh_rotates_tokens_atomically_across_restart(oauth):
    oauth.connect()
    _expire(oauth)
    assert oauth.session.access_token() == "access-renewed"
    form = parse_qs(_token_calls(oauth)[-1].content.decode())
    assert form == {"grant_type": ["refresh_token"], "client_id": ["oaiapp_test"],
                    "refresh_token": ["refresh-initial"], "resource": [RESOURCE]}
    restarted = SIWCSession(transport=oauth.transport)
    assert restarted.access_token() == "access-renewed"
    assert len(_token_calls(oauth)) == 2
    assert _document(oauth)["profiles"]["default"]["refresh_token"] == "refresh-renewed"


def test_parallel_refreshes_use_only_one_rotating_token(oauth):
    oauth.connect()
    _expire(oauth)
    def access(_index):
        return SIWCSession(transport=oauth.transport).access_token()
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(access, range(4))) == ["access-renewed"] * 4
    assert len(_token_calls(oauth)) == 2


@pytest.mark.parametrize("code", ["invalid_grant", "invalid_refresh_token", "token_expired",
    "refresh_token_expired", "refresh_token_invalidated", "refresh_token_reused"])
def test_terminal_refresh_failures_clear_tokens_and_keep_registration(oauth, code):
    oauth.connect()
    _expire(oauth)
    oauth.refresh = httpx.Response(400, json={"error": code})
    with pytest.raises(SIWCError, match="expired or was revoked"):
        oauth.session.access_token()
    profile = _document(oauth)["profiles"]["default"]
    assert profile["client_id"] == "oaiapp_test" and profile["subject"] == "subject-1"
    assert not {"access_token", "refresh_token", "id_token"} & profile.keys()


def test_temporary_refresh_failure_preserves_credentials(oauth):
    oauth.connect()
    _expire(oauth)
    before = _document(oauth)
    oauth.refresh = httpx.Response(503, json={"detail": "Temporarily unavailable"}, headers={"x-request-id": "req-refresh"})
    with pytest.raises(SIWCRequestError) as error:
        oauth.session.access_token()
    assert error.value.status_code == 503 and error.value.request_id == "req-refresh"
    assert error.value.body == {"detail": "Temporarily unavailable"}
    assert _document(oauth) == before


def test_refresh_network_error_preserves_credentials(oauth):
    oauth.connect()
    _expire(oauth)
    before = _document(oauth)
    def fail(request):
        raise httpx.ConnectError("Network unavailable", request=request)
    oauth.session.transport = httpx.MockTransport(fail)
    with pytest.raises(SIWCRequestError) as error:
        oauth.session.access_token()
    assert error.value.code == "connection_error"
    assert _document(oauth) == before


def test_refresh_rejects_a_different_verified_subject(oauth):
    oauth.connect()
    _expire(oauth)
    attempt, _ = oauth.begin()
    oauth.refresh["id_token"] = oauth.sign(attempt, sub="another-subject")
    with pytest.raises(SIWCError, match="identity changed"):
        oauth.session.access_token()
    assert not oauth.session.status("default")["default"]["signed_in"]


def test_refresh_checks_new_grants_before_returning_access(oauth):
    oauth.connect()
    _expire(oauth)
    oauth.refresh["scope"] = "openid profile email offline_access"
    with pytest.raises(SIWCError, match="permission was removed"):
        oauth.session.access_token()
    assert not oauth.session.status("default")["default"]["plan_usage"]


def test_earliest_refresh_time_uses_unexpired_token(oauth):
    oauth.connect(earliest_refresh_at=time.time() + 120)
    _expire(oauth)
    assert oauth.session.access_token() == "access-initial"
    assert len(_token_calls(oauth)) == 1


@pytest.mark.parametrize("status,confirmed", [(200, True), (503, False)])
def test_logout_revokes_clears_tokens_and_retains_host(oauth, monkeypatch, status, confirmed):
    oauth.connect()
    before = _document(oauth)
    oauth.status = status
    monkeypatch.setattr("llm.siwc.oauth.time.sleep", lambda _seconds: None)
    assert oauth.session.logout() is confirmed
    document = _document(oauth)
    assert document["host_id"] == before["host_id"]
    assert document["profiles"]["default"]["client_id"] == "oaiapp_test"
    assert not oauth.session.status("default")["default"]["signed_in"]
    attempt, url = oauth.begin()
    assert attempt.client_id == "oaiapp_test" and "id_token_hint" not in url
    with pytest.raises(SIWCError, match="signed out"):
        oauth.session.access_token()


def test_model_discovery_uses_account_token_and_server_order(oauth):
    oauth.connect()
    assert oauth.session.list_models() == [
        {"slug": "future-model-b", "display_name": "Future B"},
        {"slug": "future-model-a", "display_name": "Future A"}]
    request = oauth.calls[-1]
    assert str(request.url) == f"{RESOURCE}/models"
    assert request.headers["authorization"] == "Bearer access-initial"


def test_public_model_catalog_keeps_reasoning_metadata(oauth, monkeypatch):
    oauth.connect()
    monkeypatch.setattr(oauth.session, "request_json", lambda *_args, **_kwargs: {"data": [
        {"id": "future-model", "supported_reasoning_efforts": [
            {"reasoning_effort": "low"}, {"reasoning_effort": "max"}]},
        {"id": "hidden", "visibility": "hidden"},
    ]})
    assert oauth.session.list_models() == [{"slug": "future-model", "display_name": "future-model",
                                           "reasoning_efforts": ["low", "max"]}]


def _model(oauth):
    model = get_llm("openai_codex_auth", model_name="future-model-b", api_key="", temperature=0,
                    max_tokens=512, streaming=True, reasoning_effort="low")
    model._session = oauth.session
    return model


def _completed(text='{"answer":"ok"}'):
    return [{"type": "response.output_text.delta", "delta": text},
        {"type": "response.completed", "response": {"id": "resp-test", "status": "completed",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}],
            "usage": {"input_tokens": 20, "output_tokens": 8, "output_tokens_details": {"reasoning_tokens": 3}}}}]


def test_inference_serializes_only_siwc_supported_fields_and_keeps_usage(oauth):
    oauth.connect()
    oauth.inference = _completed()
    result = _model(oauth).invoke([SystemMessage(content="Return JSON"), HumanMessage(content="Hi")])
    body = json.loads(oauth.calls[-1].content)
    assert body == {"model": "future-model-b", "input": [{"role": "developer", "content": "Return JSON"},
        {"role": "user", "content": "Hi"}], "store": False, "stream": True, "reasoning": {"effort": "low", "summary": "auto"}}
    assert oauth.calls[-1].headers["authorization"] == "Bearer access-initial"
    assert result.content == '{"answer":"ok"}'
    assert result.response_metadata["usage"]["output_tokens_details"]["reasoning_tokens"] == 3
    assert result.response_metadata["request_id"] == "req-test"
    assert "access-initial" not in json.dumps(result.model_dump())
    assert not result.additional_kwargs.get("reasoning_summary")
    assert not result.additional_kwargs.get("reasoning")


def test_siwc_preserves_returned_summary_separately_from_encrypted_reasoning(oauth):
    from llm.reasoning_evidence import reasoning_evidence
    oauth.connect()
    oauth.inference = _completed()
    oauth.inference.insert(0, {"type": "response.reasoning_summary_text.delta", "output_index": 0,
        "summary_index": 0, "delta": "earlier summary"})
    oauth.inference[-1]["response"]["output"].insert(0, {"type": "reasoning", "encrypted_content": "opaque",
        "summary": [{"type": "summary_text", "text": "Provider summary"}]})
    message = _model(oauth).invoke("Return JSON")
    assert message.content == '{"answer":"ok"}'
    fields = reasoning_evidence(message)
    assert fields["reasoning_trace"] is None
    assert fields["reasoning_summary"] == "Provider summary"
    assert "opaque" not in json.dumps(message.model_dump())


@pytest.mark.parametrize("kind", ["response.reasoning_summary_text.delta", "response.reasoning_summary_text.done",
                                  "response.reasoning_summary_part.done", "response.output_item.done"])
@pytest.mark.parametrize("empty_terminal_summary", [False, True])
def test_summary_events_survive_terminal_answer_without_reasoning(oauth, kind, empty_terminal_summary):
    from llm.reasoning_evidence import reasoning_evidence
    oauth.connect()
    event = {"type": kind, "output_index": 0, "summary_index": 0}
    if kind.endswith(".delta"):
        event["delta"] = "Provider summary"
    elif kind == "response.reasoning_summary_text.done":
        event["text"] = "Provider summary"
    elif kind == "response.reasoning_summary_part.done":
        event["part"] = {"type": "summary_text", "text": "Provider summary"}
    else:
        event["item"] = {"type": "reasoning", "summary": [{"type": "summary_text", "text": "Provider summary"}],
                         "encrypted_content": "private"}
    oauth.inference = [event, *_completed()]
    if empty_terminal_summary:
        oauth.inference[-1]["response"]["output"].insert(0, {"type": "reasoning",
            "summary": [{"type": "summary_text", "text": ""}]})
    message = _model(oauth).invoke("Return JSON")
    assert message.content == '{"answer":"ok"}'
    evidence = reasoning_evidence(message)
    assert evidence["reasoning_summary"] == "Provider summary"
    assert evidence["reasoning_summary_source"] == "additional_kwargs.reasoning_summary"
    assert evidence["reasoning_trace"] is evidence["reasoning_trace_source"] is None
    assert "private" not in json.dumps(message.model_dump())


def test_summary_parts_are_ordered_and_completed_events_replace_deltas(oauth):
    from llm.reasoning_evidence import reasoning_evidence
    oauth.connect()
    oauth.inference = [
        {"type": "response.reasoning_summary_text.done", "output_index": 2, "summary_index": 0, "text": "last"},
        {"type": "response.reasoning_summary_text.delta", "output_index": 0, "summary_index": 0, "delta": "tentative"},
        {"type": "response.reasoning_summary_text.done", "output_index": 0, "summary_index": 0, "text": "first"},
        {"type": "response.reasoning_summary_part.done", "output_index": 0, "summary_index": 0,
         "part": {"type": "summary_text", "text": "first"}},
        {"type": "response.reasoning_summary_text.delta", "output_index": 0, "summary_index": 1, "delta": "sec"},
        {"type": "response.reasoning_summary_text.delta", "output_index": 0, "summary_index": 1, "delta": "ond"},
        *_completed(),
    ]
    assert reasoning_evidence(_model(oauth).invoke("Hi"))["reasoning_summary"] == "first\nsecond\nlast"


def test_completed_summary_without_terminal_is_still_interrupted(oauth):
    oauth.connect()
    oauth.inference = [{"type": "response.reasoning_summary_text.done", "output_index": 0, "summary_index": 0, "text": "summary"}]
    with pytest.raises(SIWCRequestError) as error:
        _model(oauth).invoke("Hi")
    assert error.value.code == "interrupted_stream"


def test_cached_model_resolves_refreshed_credentials_on_each_inference(oauth):
    oauth.connect()
    oauth.inference = _completed()
    model = _model(oauth)
    model.invoke("First")
    _expire(oauth)
    model.invoke("Second")
    requests = [call for call in oauth.calls if call.url.path.endswith("/responses")]
    assert [request.headers["authorization"] for request in requests] == ["Bearer access-initial", "Bearer access-renewed"]
    assert "access-renewed" not in repr(model)


@pytest.mark.parametrize("compact_stream", [False, True])
def test_native_runtime_validation_keeps_siwc_usage_and_request_constraints(oauth, monkeypatch, compact_stream):
    from llm.runtime import LLMRuntime
    oauth.connect()
    oauth.inference = _completed()
    if compact_stream:
        oauth.content_type = None
        output = oauth.inference[-1]["response"]["output"]
        oauth.inference.insert(1, {"type": "response.output_item.done", "output_index": 0, "item": output[0]})
        oauth.inference[-1]["response"]["output"] = []
    oauth.inference.insert(0, {"type": "response.reasoning_summary_text.done", "output_index": 0,
        "summary_index": 0, "text": "Runtime summary"})
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: _model(oauth))
    runtime = LLMRuntime()
    schema = {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"], "additionalProperties": False}
    with runtime.coordinate(coordinate_id="unit-native-siwc", default_provider="openai_codex_auth",
                            default_model_config={"model_name": "future-model-b", "account": "default"}) as context:
        result = runtime.invoke(context=context, role="orchestrator", system_message="Return JSON",
            user_message="Hello", schema=schema, schema_version="test.v1", validator=lambda value: value, max_tokens=512)
        assert result.parsed == {"answer": "ok"}
        assert result.performance["structured_output_mode"] == "native_json_schema"
        assert result.performance["reasoning_token_evidence"]["tokens"] == 3
        assert result.performance["reasoning_summary"] == "Runtime summary"
        assert result.performance["reasoning_trace"] is None
        assert result.performance["provider_request_constraints"]["unsupported_fields"] == ["max_output_tokens", "temperature"]
        assert result.performance["endpoint"] == RESOURCE
        assert context.performance_summary()["provider_requests"] == 1
    runtime.close()


def test_runtime_failure_retains_sanitized_error_body_and_parameter(oauth, monkeypatch):
    from llm.runtime import LLMRuntime
    oauth.connect()
    oauth.status = 403
    oauth.inference = {"error": {"code": "subscription_sharing_user_not_eligible", "param": "model"},
                       "refresh_token": "must-stay-private"}
    monkeypatch.setattr("llm.runtime.get_llm", lambda *_args, **_kwargs: _model(oauth))
    runtime = LLMRuntime()
    with runtime.coordinate(coordinate_id="unit-siwc-error", default_provider="openai_codex_auth",
                            default_model_config={"model_name": "future-model-b"}) as context:
        with pytest.raises(SIWCRequestError):
            runtime.invoke(context=context, role="orchestrator", system_message="Return JSON",
                user_message="Hello", schema={"type": "object"}, schema_version="test.v1",
                validator=lambda value: value, max_tokens=512)
        record = context.records[-1]
        assert record["provider_response"]["param"] == "model"
        assert record["provider_response"]["body"]["refresh_token"] == "[REDACTED]"
        assert "must-stay-private" not in json.dumps(record)
        assert record["status_code"] == 403
    runtime.close()


def test_stream_refusal_remains_available_to_runtime(oauth):
    oauth.connect()
    oauth.inference = [{"type": "response.completed", "response": {"status": "completed", "output": [
        {"type": "message", "content": [{"type": "refusal", "refusal": "I cannot help with that request."}]}]}}]
    result = _model(oauth).invoke("Hi")
    assert result.additional_kwargs["refusal"] == "I cannot help with that request."


def test_model_catalog_is_account_specific_and_empty_is_valid(oauth):
    oauth.connect("research")
    oauth.model_data = {"models": []}
    assert oauth.session.list_models("research") == []
    with pytest.raises(SIWCError, match="signed out"):
        oauth.session.list_models("default")


def test_subscription_provider_is_opt_in_for_implicit_matrices():
    from llm.provider import SUPPORTED_PROVIDERS, provider_capabilities
    defaults = [name for name in SUPPORTED_PROVIDERS if not provider_capabilities(name).requires_explicit_selection]
    assert defaults == ["gemini", "openai", "claude", "openai_compatible"]


def test_structured_output_returns_raw_for_harness_validation(oauth):
    oauth.connect()
    oauth.inference = _completed()
    schema = {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"], "additionalProperties": False}
    model = _model(oauth).with_structured_output(schema, include_raw=True)
    result = model.invoke([HumanMessage(content="Hi")])
    assert result["parsed"] == {"answer": "ok"} and result["parsing_error"] is None
    assert result["raw"].response_metadata["status"] == "completed"
    assert json.loads(oauth.calls[-1].content)["text"]["format"]["schema"] == schema


def test_missing_terminal_stream_never_succeeds(oauth):
    oauth.connect()
    oauth.inference = [{"type": "response.output_text.delta", "delta": "partial"}]
    with pytest.raises(SIWCRequestError) as error:
        _model(oauth).invoke("Hi")
    assert error.value.code == "interrupted_stream"


@pytest.mark.parametrize("content_type", [None, "text/plain", "text/event-stream; charset=utf-8"])
def test_completed_items_supply_empty_terminal_output_in_index_order(oauth, content_type):
    from llm.reasoning_evidence import reasoning_evidence
    oauth.connect()
    oauth.content_type = content_type
    oauth.inference = [
        {"type": "response.output_text.delta", "delta": "tentative text"},
        {"type": "response.output_item.done", "output_index": 2,
         "item": {"type": "message", "content": [{"type": "output_text", "text": "second"}]}},
        {"type": "response.output_item.done", "output_index": 0,
         "item": {"type": "reasoning", "encrypted_content": "private",
                  "summary": [{"type": "summary_text", "text": "summary"}]}},
        {"type": "response.output_item.done", "output_index": 1,
         "item": {"type": "message", "content": [{"type": "output_text", "text": "first "}]}},
        {"type": "response.completed", "response": {"status": "completed", "output": [],
            "usage": {"output_tokens": 42}}},
    ]
    message = _model(oauth).invoke("Hi")
    assert message.content == "first second"
    assert reasoning_evidence(message)["reasoning_summary"] == "summary"
    assert reasoning_evidence(message)["reasoning_trace"] is None
    assert message.response_metadata["usage"] == {"output_tokens": 42}
    assert "private" not in json.dumps(message.model_dump())


def test_terminal_output_overrides_completed_items_and_deltas(oauth):
    oauth.connect()
    oauth.inference = _completed("terminal answer")
    oauth.inference.insert(1, {"type": "response.output_item.done", "output_index": 0,
        "item": {"type": "message", "content": [{"type": "output_text", "text": "earlier answer"}]}})
    assert _model(oauth).invoke("Hi").content == "terminal answer"


def test_completed_item_without_terminal_still_fails(oauth):
    oauth.connect()
    oauth.content_type = None
    oauth.inference = [{"type": "response.output_item.done", "output_index": 0,
        "item": {"type": "message", "content": [{"type": "output_text", "text": "finished item"}]}}]
    with pytest.raises(SIWCRequestError) as error:
        _model(oauth).invoke("Hi")
    assert error.value.code == "interrupted_stream"


@pytest.mark.parametrize("event,code", [
    ({"type": "response.output_text.delta", "delta": 3}, "invalid_stream"),
    ({"type": "response.reasoning_summary_text.done", "output_index": 0, "summary_index": 0, "text": None}, "invalid_stream"),
    ({"type": "response.reasoning_summary_part.done", "output_index": 0, "summary_index": 0,
      "part": {"type": "summary_text", "text": 3}}, "invalid_stream"),
    ({"type": "response.output_item.done", "output_index": -1, "item": {}}, "invalid_stream"),
    ({"type": "response.output_item.done", "output_index": 0, "item": {"type": "message", "content": None}}, "invalid_stream"),
    ({"type": "response.completed", "response": {"status": "incomplete", "output": []}}, "invalid_terminal_event"),
    ({"type": "response.completed", "response": {"status": "completed"}}, "invalid_terminal_event"),
    ({"type": "response.completed", "response": {"status": "completed", "output": [
        {"type": "message", "content": [{"type": "output_text", "text": 3}]}]}}, "invalid_terminal_event"),
])
def test_malformed_response_events_fail_with_safe_diagnostics(oauth, event, code):
    oauth.connect()
    oauth.inference = [event]
    with pytest.raises(SIWCRequestError) as error:
        _model(oauth).invoke("Hi")
    assert error.value.code == code
    assert error.value.request_id == "req-test"


def test_incomplete_stream_preserves_incomplete_status(oauth):
    oauth.connect()
    oauth.inference = [{"type": "response.incomplete", "response": {
        "status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}, "output": []}}]
    result = _model(oauth).invoke("Hi")
    assert result.response_metadata["status"] == "incomplete"
    assert result.response_metadata["finish_reason"] == "length"


def test_streamed_usage_limit_is_an_error_without_billing_fallback(oauth):
    oauth.connect()
    oauth.inference = [{"type": "response.output_text.delta", "delta": "partial"},
        {"type": "response.failed", "response": {"error": {"code": "subscription_sharing_usage_limit_exceeded"}}}]
    with pytest.raises(SIWCRequestError, match="ChatGPT Settings") as error:
        _model(oauth).invoke("Hi")
    assert error.value.code == "subscription_sharing_usage_limit_exceeded"
    assert len([call for call in oauth.calls if call.url.path.endswith("/responses")]) == 1


@pytest.mark.parametrize("status,body,code", [(401, {"detail": "Identity rejected"}, "unknown_error"),
    (403, {"error": {"code": "subscription_sharing_user_not_eligible", "param": "model"}}, "subscription_sharing_user_not_eligible"),
    (429, {"error": {"code": "subscription_sharing_usage_limit_exceeded"}}, "subscription_sharing_usage_limit_exceeded"),
    (503, {"detail": "Route unavailable"}, "unknown_error")])
def test_inference_admission_failures_preserve_safe_diagnostics(oauth, status, body, code):
    oauth.connect()
    oauth.status = status
    oauth.inference = body
    with pytest.raises(SIWCRequestError) as error:
        _model(oauth).invoke("Hi")
    assert error.value.status_code == status and error.value.code == code
    assert error.value.body == body and error.value.request_id == "req-test"
    assert oauth.session.status("default")["default"]["signed_in"]


def test_api_keys_and_external_endpoints_cannot_override_siwc(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-used")
    monkeypatch.setenv("OPENAI_COMPATIBLE_API_KEY", "must-not-be-used-either")
    with pytest.raises(ValueError, match="remove api_key"):
        get_llm("openai_codex_auth", model_name="chosen", api_key="api-key")
    with pytest.raises(ValueError, match="public"):
        get_llm("openai_codex_auth", model_name="chosen", base_url="https://external.example/v1")
    model = get_llm_from_model_config(ModelConfig(provider="openai_codex_auth", api_key="", model_name="chosen"))
    assert "must-not-be-used" not in repr(model)


def test_credential_symlinks_and_public_modes_are_rejected(oauth, tmp_path):
    oauth.connect()
    path = oauth.session.store.path
    original = path.read_bytes()
    path.unlink()
    target = tmp_path / "outside.json"
    target.write_bytes(original)
    path.symlink_to(target)
    with pytest.raises(SIWCError):
        oauth.session.status()
    path.unlink()
    path.write_bytes(original)
    path.chmod(0o644)
    if os.name == "posix":
        with pytest.raises(SIWCError, match="owner-only"):
            oauth.session.status()


def test_pending_registration_survives_failed_code_exchange(oauth):
    attempt, _ = oauth.begin()
    oauth.tokens = httpx.Response(400, json={"error": "invalid_grant"})
    with pytest.raises(SIWCRequestError):
        oauth.session.complete(attempt, "/auth/callback?" + urlencode({"state": attempt.state, "code": "code", "client_id": "oaiapp_test"}))
    restarted, url = oauth.begin()
    assert restarted.client_id == "oaiapp_test"
    assert "agent_name_hint" not in url


def test_auth_cli_dispatch_status_and_no_identity_hint_leak(oauth, monkeypatch, capsys):
    import tesis.auth as auth
    import tesis.cli as cli
    oauth.connect()
    monkeypatch.setattr(auth, "SIWCSession", lambda: oauth.session)
    assert cli.main(["auth", "status"]) == 0
    output = capsys.readouterr().out
    assert "same@example.test" in output and "access-initial" not in output and "refresh-initial" not in output
    safe = auth._without_identity_hint("https://auth.openai.com/api/accounts/authorize?id_token_hint=secret&state=random")
    assert "secret" not in safe and "state=random" in safe
