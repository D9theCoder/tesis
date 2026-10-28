"""SIWC public-client OAuth, discovery, OIDC verification, and token lifecycle.

Contract: https://developers.openai.com/siwc/token-sharing-open-source/sign-in
No Codex credentials, private endpoints, client secrets, or API keys are used.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import math
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt

from llm.diagnostics import redact_diagnostic_text
from llm.reasoning import advertised_efforts
from llm.siwc import INFERENCE_SCOPES, ISSUER, RESOURCE, SCOPES
from llm.siwc.storage import CredentialStore, SIWCError, clear_tokens

_TERMINAL_REFRESH_ERRORS = frozenset({
    "invalid_grant", "invalid_refresh_token", "token_expired", "refresh_token_expired",
    "refresh_token_invalidated", "refresh_token_reused",
})
_ASYMMETRIC_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"})


class SIWCRequestError(SIWCError):
    """Retain safe provider diagnostics without retaining request credentials."""

    def __init__(self, operation: str, *, status_code: int | None = None,
                 code: str | None = None, request_id: str | None = None,
                 body: Any = None, param: str | None = None):
        self.status_code = status_code
        self.code = redact_diagnostic_text(code or "unknown_error", limit=160)
        self.request_id = redact_diagnostic_text(request_id or "", limit=160) or None
        self.body = _safe_body(body)
        self.param = redact_diagnostic_text(param or "", limit=160) or None
        self.safe_provider_error = {"code": self.code, "param": self.param, "body": self.body}
        remediation = {
            "subscription_sharing_user_not_eligible": "This account/workspace is not eligible; check ChatGPT plan and policy.",
            "subscription_sharing_usage_limit_exceeded": "Pause requests and review ChatGPT Settings > Usage.",
            "subscription_sharing_unsupported_capability": "Select an available model and supported request settings.",
            "invalid_client": "Check the saved client registration.",
        }.get(self.code, "Check the selected SIWC account and grant; retry temporary failures later.")
        super().__init__(f"{operation} failed (status={status_code}, code={self.code}, "
                         f"request_id={self.request_id or 'unavailable'}). {remediation}")


def _safe_body(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): ("[REDACTED]" if any(word in str(key).lower() for word in
                ("token", "secret", "authorization", "verifier", "password")) else _safe_body(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_body(item) for item in value[:30]]
    return redact_diagnostic_text(value, limit=1000) if isinstance(value, str) else value


def response_error(response: httpx.Response, operation: str) -> SIWCRequestError:
    try:
        body = response.json()
    except ValueError:
        body = {"detail": "Non-JSON error response"}
    error = body.get("error") if isinstance(body, dict) else None
    code = error.get("code") or error.get("type") if isinstance(error, dict) else error
    exc = SIWCRequestError(operation, status_code=response.status_code, code=code,
        param=error.get("param") if isinstance(error, dict) else None,
        request_id=response.headers.get("x-request-id") or response.headers.get("openai-request-id"),
        body=body)
    exc.retry_headers = {key: response.headers[key] for key in ("retry-after", "retry-after-ms")
                         if key in response.headers}
    return exc


@dataclass(repr=False)
class AuthorizationAttempt:
    account: str
    client_id: str
    host_id: str
    redirect_uri: str
    state: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    nonce: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    verifier: str = field(default_factory=lambda: secrets.token_urlsafe(64))
    expires_at: float = field(default_factory=lambda: time.time() + 300)
    selected: dict[str, Any] = field(default_factory=dict)
    consumed: bool = False


class SIWCSession:
    """Network operations are explicit; construction and status are offline."""

    def __init__(self, store: CredentialStore | None = None, *,
                 transport: httpx.BaseTransport | None = None, timeout: float = 30):
        self.store = store or CredentialStore()
        self.transport = transport
        self.timeout = timeout
        self._metadata: dict[str, Any] | None = None
        self._jwks: dict[str, Any] = {}
        self._jwks_at = 0.0

    def http(self) -> httpx.Client:
        # Refuse redirects before any bearer/token form can cross an origin.
        return httpx.Client(timeout=self.timeout, follow_redirects=False, transport=self.transport)

    def request_json(self, method: str, url: str, *, operation: str, **kwargs: Any) -> dict[str, Any]:
        try:
            with self.http() as client:
                response = client.request(method, url, **kwargs)
        except httpx.HTTPError:
            raise SIWCRequestError(operation, code="connection_error") from None
        if not 200 <= response.status_code < 300:
            raise response_error(response, operation)
        try:
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError
            return data
        except ValueError:
            raise SIWCRequestError(operation, code="invalid_json") from None

    def metadata(self) -> dict[str, Any]:
        if self._metadata is None:
            data = self.request_json("GET", f"{ISSUER}/.well-known/openid-configuration", operation="OIDC discovery")
            if data.get("issuer") != ISSUER:
                raise SIWCError("OpenAI discovery returned an unexpected issuer.")
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "revocation_endpoint"):
                endpoint = urlsplit(str(data.get(key, "")))
                if (endpoint.scheme != "https" or endpoint.netloc != "auth.openai.com"
                        or endpoint.query or endpoint.fragment or not endpoint.path):
                    raise SIWCError("OpenAI discovery returned an unsafe or missing endpoint.")
            self._metadata = data
        return self._metadata

    def begin(self, account: str, redirect_uri: str, *, consent: bool = False) -> tuple[AuthorizationAttempt, str]:
        parsed = urlsplit(redirect_uri)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                or parsed.path != "/auth/callback" or parsed.query or parsed.fragment
                or parsed.username or parsed.password or not parsed.port):
            raise SIWCError("SIWC requires http://127.0.0.1:PORT/auth/callback.")
        if not account.strip():
            raise SIWCError("Choose a nonempty local account label.")
        with self.store.locked():
            document = self.store.read()
            selected = dict(document["profiles"].get(account, {}))
            self.store.write(document)  # Persist the host ID before first sign-in.
        pending_client = document.get("pending_registrations", {}).get(account)
        attempt = AuthorizationAttempt(account, selected.get("client_id") or pending_client or "dynamic_agent_client",
            document["host_id"], redirect_uri, selected=selected)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(attempt.verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        params = {
            "client_id": attempt.client_id, "ext_agent_host_id": attempt.host_id,
            "response_type": "code", "redirect_uri": redirect_uri,
            "scope": " ".join(SCOPES), "resource": RESOURCE, "state": attempt.state,
            "nonce": attempt.nonce, "code_challenge_method": "S256", "code_challenge": challenge,
        }
        if attempt.client_id == "dynamic_agent_client":
            params["agent_name_hint"] = "TESIS"
        else:
            if selected.get("id_token"):
                params["id_token_hint"] = selected["id_token"]
            if selected.get("email"):
                params["login_hint"] = selected["email"]
        if consent:
            params["prompt"] = "consent"
        return attempt, self.metadata()["authorization_endpoint"] + "?" + urlencode(params)

    def _identity(self, token: str, client_id: str, nonce: str | None) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            if algorithm not in _ASYMMETRIC_ALGORITHMS or not header.get("kid"):
                raise ValueError
            if time.monotonic() - self._jwks_at > 300 or not self._jwks:
                self._load_jwks()
            keys = [key for key in self._jwks.get("keys", []) if key.get("kid") == header["kid"]]
            if not keys:
                self._load_jwks()  # Key rotation, never follow a JWT-supplied URL.
                keys = [key for key in self._jwks.get("keys", []) if key.get("kid") == header["kid"]]
            if len(keys) != 1 or keys[0].get("use", "sig") != "sig":
                raise ValueError
            if keys[0].get("alg", algorithm) != algorithm:
                raise ValueError
            key = jwt.PyJWK.from_dict(keys[0], algorithm=algorithm)
            claims = jwt.decode(token, key.key, algorithms=[algorithm], issuer=ISSUER,
                audience=client_id, leeway=5, options={"require": ["iss", "aud", "sub", "exp", "iat"]})
            if not isinstance(claims["sub"], str) or not claims["sub"]:
                raise ValueError
            if nonce is not None and not secrets.compare_digest(str(claims.get("nonce", "")).encode(), nonce.encode()):
                raise ValueError
            audience = claims["aud"]
            if (claims.get("azp", client_id) != client_id
                    or isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != client_id):
                raise ValueError
            return claims
        except (jwt.PyJWTError, ValueError, KeyError, TypeError):
            raise SIWCError("OpenAI ID-token verification failed; sign in again.") from None

    def _load_jwks(self) -> None:
        self._jwks = self.request_json("GET", self.metadata()["jwks_uri"], operation="OpenAI signing keys")
        if not isinstance(self._jwks.get("keys"), list) or any(not isinstance(key, dict) for key in self._jwks["keys"]):
            raise SIWCError("OpenAI returned invalid signing keys.")
        self._jwks_at = time.monotonic()

    def complete(self, attempt: AuthorizationAttempt, callback: str) -> dict[str, Any]:
        if attempt.consumed or time.time() >= attempt.expires_at:
            raise SIWCError("This sign-in attempt expired or was already used; start a fresh sign-in.")
        attempt.consumed = True  # One-time consumption, including failed callbacks.
        parsed = urlsplit(callback)
        if (parsed.scheme or parsed.netloc) and (
            parsed.scheme + "://" + parsed.netloc + parsed.path != attempt.redirect_uri
        ):
            raise SIWCError("The OAuth callback does not match this sign-in attempt.")
        if parsed.path != "/auth/callback" or parsed.fragment:
            raise SIWCError("Invalid OAuth callback path.")
        query = parse_qs(parsed.query, keep_blank_values=True)
        if any(len(values) != 1 for values in query.values()):
            raise SIWCError("Ambiguous OAuth callback parameters.")
        state = query.get("state", [""])[0]
        if not secrets.compare_digest(state.encode(), attempt.state.encode()):
            raise SIWCError("OAuth state mismatch; no credentials were changed.")
        if "error" in query:
            raise SIWCError("ChatGPT authorization was declined or failed; no credentials were changed.")
        client_id = query.get("client_id", [attempt.client_id])[0]
        if attempt.client_id == "dynamic_agent_client":
            if not client_id or client_id == "dynamic_agent_client" or any(char.isspace() for char in client_id):
                raise SIWCError("Dynamic registration did not return an issued client ID.")
        elif client_id != attempt.client_id:
            raise SIWCError("OAuth returned a different client registration; no credentials were changed.")
        code = query.get("code", [""])[0]
        if not code:
            raise SIWCError("OAuth callback has no authorization code.")
        # Retain the issued ID in this attempt if code exchange must be restarted.
        attempt.client_id = client_id
        if not attempt.selected:
            with self.store.locked():
                document = self.store.read()
                document.setdefault("pending_registrations", {})[attempt.account] = client_id
                self.store.write(document)
        data = self.request_json("POST", self.metadata()["token_endpoint"], operation="OAuth code exchange", data={
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "code_verifier": attempt.verifier, "redirect_uri": attempt.redirect_uri, "resource": RESOURCE,
        })
        claims = self._identity(str(data.get("id_token", "")), client_id, attempt.nonce)
        if attempt.selected and claims["sub"] != attempt.selected.get("subject"):
            raise SIWCError("The verified account differs from the selected account; credentials were not replaced.")
        profile = {"client_id": client_id, "issuer": ISSUER, "subject": claims["sub"],
                   "email": claims.get("email"), "ext_agent_host_id": attempt.host_id}
        profile.update(self._tokens(data))
        with self.store.locked():
            document = self.store.read()
            if document["profiles"].get(attempt.account, {}) != attempt.selected:
                raise SIWCError("This account changed during sign-in; repeat sign-in to avoid replacing another session.")
            document["profiles"][attempt.account] = profile
            document.get("pending_registrations", {}).pop(attempt.account, None)
            self.store.write(document)
        return self.status(attempt.account)

    @staticmethod
    def _tokens(data: dict[str, Any], previous: dict[str, Any] | None = None) -> dict[str, Any]:
        old = previous or {}
        try:
            scope = data.get("scope", " ".join(old.get("scopes", [])))
            if not isinstance(scope, str):
                raise ValueError
            if not previous and not data.get("access_token") and not INFERENCE_SCOPES.issubset(scope.split()):
                return {"id_token": data["id_token"], "scopes": scope.split(), "saved_at": time.time()}
            lifetime = float(data["expires_in"])
            if not math.isfinite(lifetime) or lifetime <= 0:
                raise ValueError
            access = data["access_token"]
            if not isinstance(access, str) or not access or str(data["token_type"]).lower() != "bearer":
                raise ValueError
            refresh = data.get("refresh_token")
            if "offline_access" in scope.split() and (not isinstance(refresh, str) or not refresh):
                raise ValueError
            if data.get("id_token") is not None and not isinstance(data["id_token"], str):
                raise ValueError
            now = time.time()
            result = {"access_token": access, "refresh_token": refresh,
                "id_token": data.get("id_token", old.get("id_token")), "token_type": "Bearer",
                "expires_in": lifetime, "expires_at": now + lifetime, "saved_at": now,
                "scopes": scope.split()}
            if data.get("earliest_refresh_at") is not None:
                earliest = float(data["earliest_refresh_at"])
                if not math.isfinite(earliest):
                    raise ValueError
                result["earliest_refresh_at"] = earliest
            return result
        except (KeyError, ValueError, TypeError):
            raise SIWCError("OpenAI returned an incomplete or invalid token response.") from None

    def access_token(self, account: str = "default") -> str:
        with self.store.locked():
            document = self.store.read()
            profile = document["profiles"].get(account)
            if not profile or not (profile.get("access_token") or profile.get("id_token")):
                raise SIWCError("SIWC is signed out; run: python -m tesis auth login --account ACCOUNT")
            if not INFERENCE_SCOPES.issubset(profile.get("scopes", [])):
                raise SIWCError("ChatGPT plan usage is disabled; run auth login --enable-plan-usage, or select another provider.")
            if not profile.get("access_token"):
                raise SIWCError("SIWC has no inference credential; sign in again.")
            now = time.time()
            expires_at = float(profile.get("expires_at", 0))
            if now < expires_at - 60:
                return profile["access_token"]
            if now < float(profile.get("earliest_refresh_at", 0)):
                if now < expires_at:
                    return profile["access_token"]
                raise SIWCError("The access token expired before its allowed refresh time; retry later or sign in again.")
            if not profile.get("refresh_token"):
                clear_tokens(profile)
                self.store.write(document)
                raise SIWCError("SIWC cannot refresh this session; sign in again using the saved registration.")
            try:
                data = self.request_json("POST", self.metadata()["token_endpoint"], operation="OAuth token refresh", data={
                    "grant_type": "refresh_token", "client_id": profile["client_id"],
                    "refresh_token": profile["refresh_token"], "resource": RESOURCE,
                })
            except SIWCRequestError as exc:
                if exc.code in _TERMINAL_REFRESH_ERRORS:
                    clear_tokens(profile)
                    self.store.write(document)
                    raise SIWCError("SIWC session expired or was revoked; sign in again using the saved registration.") from None
                raise
            if data.get("id_token"):
                claims = self._identity(data["id_token"], profile["client_id"], None)
                if claims["sub"] != profile["subject"]:
                    clear_tokens(profile)
                    self.store.write(document)
                    raise SIWCError("Refreshed identity changed; sign in again.")
            replacement = self._tokens(data, profile)
            clear_tokens(profile)
            profile.update(replacement)
            self.store.write(document)
            if not INFERENCE_SCOPES.issubset(profile["scopes"]):
                raise SIWCError("ChatGPT plan permission was removed; enable plan usage before inference.")
            return profile["access_token"]

    def status(self, account: str | None = None) -> dict[str, Any]:
        with self.store.locked():
            profiles = self.store.read()["profiles"]
            if account is not None:
                profiles = {account: profiles.get(account, {})}
            return {name: {"client_id": value.get("client_id"), "email": value.get("email"),
                "signed_in": bool(value.get("access_token") or value.get("id_token")), "expires_at": value.get("expires_at"),
                "plan_usage": bool(value.get("access_token")) and INFERENCE_SCOPES.issubset(value.get("scopes", []))}
                for name, value in profiles.items()}

    def logout(self, account: str = "default") -> bool:
        """Attempt remote revocation, always clear locally, retain registration."""
        confirmed = True
        with self.store.locked():
            document = self.store.read()
            profile = document["profiles"].get(account, {})
            refresh = profile.get("refresh_token")
            if refresh:
                confirmed = False
                try:
                    endpoint = self.metadata()["revocation_endpoint"]
                    for attempt in range(3):
                        try:
                            with self.http() as client:
                                response = client.post(endpoint, data={"token": refresh,
                                    "token_type_hint": "refresh_token", "client_id": profile["client_id"]})
                            if response.status_code == 200:
                                confirmed = True
                                break
                            if response.status_code < 500:
                                break
                        except httpx.HTTPError:
                            pass
                        if attempt < 2:
                            time.sleep(0.25 * 2 ** attempt)
                except SIWCError:
                    pass
            clear_tokens(profile)
            if profile:
                document["profiles"][account] = profile
            self.store.write(document)
        return confirmed

    def list_models(self, account: str = "default") -> list[dict[str, Any]]:
        token = self.access_token(account)
        data = self.request_json("GET", f"{RESOURCE}/models", operation="ChatGPT model discovery",
                                 headers={"Authorization": f"Bearer {token}"})
        public_catalog = "data" in data
        models = data.get("data") if public_catalog else data.get("models")
        if not isinstance(models, list):
            raise SIWCError("OpenAI returned an invalid ChatGPT model catalog.")
        result = []
        for model in models:
            if not isinstance(model, dict) or model.get("visibility", "list") != "list":
                continue
            slug = model.get("id" if public_catalog else "slug")
            if not isinstance(slug, str) or not slug or any(c.isspace() or ord(c) < 32 for c in slug):
                continue
            item = {"slug": slug, "display_name": model.get("display_name") or slug}
            efforts = advertised_efforts(model)
            if efforts is not None:
                item["reasoning_efforts"] = efforts
            result.append(item)
        return result
