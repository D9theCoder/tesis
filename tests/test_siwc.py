"""Focused offline OAuth, storage, refresh, catalog, and Responses contracts."""

import json
import os
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode

from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt
import pytest

from llm.siwc import ISSUER, RESOURCE, SCOPES
from llm.siwc.oauth import SIWCSession
from llm.siwc.storage import SIWCError


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
