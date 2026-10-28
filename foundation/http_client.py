"""HTTP client wrapper with session-aware request handling.

Provides a reusable, session-aware HTTP client for all foundation and agent
modules. Centralizes timeout, redirect, and connection pooling behavior,
and captures response metadata for verification and logging.
"""

import logging
import os
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from copy import deepcopy
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)
_CONTAINMENT_RECEIPTS: ContextVar[list | None] = ContextVar("containment_receipts", default=None)
HTTP_ACCOUNTING_POLICY_VERSION = "http-accounting.v1"
HTTP_PHASES = ("recon", "destination", "method", "verification", "token", "other")
HTTP_ROLES = ("detection_control", "candidate", "independent_control", "candidate_verification", "other")
_HTTP_COUNTER: ContextVar[dict | None] = ContextVar("http_request_counter", default=None)
_HTTP_SCOPE: ContextVar[dict] = ContextVar("http_request_scope", default={
    "phase": "other", "role": "other", "method": None,
})


def _blank_http_counter() -> dict:
    return {
        "total_requests": 0,
        "by_phase": {phase: 0 for phase in HTTP_PHASES},
        "by_role": {role: 0 for role in HTTP_ROLES},
        "per_method": {},
        "retries": 0,
        "redirect_hops": 0,
        "failed_requests": 0,
        "unattributed_requests": 0,
        "complete": True,
    }


@contextmanager
def http_request_accounting():
    """Create a run-scoped physical request counter for contained HTTP."""
    counter = _blank_http_counter()
    token = _HTTP_COUNTER.set(counter)
    try:
        yield counter
    finally:
        _HTTP_COUNTER.reset(token)


def snapshot_http_request_counters(counter: dict | None = None) -> dict:
    """Return the public, secret-free request accounting receipt."""
    live = counter if counter is not None else _HTTP_COUNTER.get()
    if not isinstance(live, dict):
        return {
            "policy_version": HTTP_ACCOUNTING_POLICY_VERSION,
            "scope": "run",
            "total_requests": 0,
            "by_phase": {phase: 0 for phase in HTTP_PHASES},
            "by_role": {role: 0 for role in HTTP_ROLES},
            "per_method": {},
            "retries": 0,
            "redirect_hops": 0,
            "failed_requests": 0,
            "complete": False,
            "capture_status": "unavailable",
        }
    snapshot = {
        "policy_version": HTTP_ACCOUNTING_POLICY_VERSION,
        "scope": "run",
        **deepcopy({key: value for key, value in live.items() if key != "complete"}),
        "complete": bool(live.get("complete")),
        "capture_status": "complete" if live.get("complete") else "partial",
    }
    return snapshot


def http_request_counters() -> dict | None:
    """Return the current counter snapshot, or ``None`` when not accounting."""
    if _HTTP_COUNTER.get() is None:
        return None
    return snapshot_http_request_counters()


@contextmanager
def request_scope(*, phase: str | None = None, role: str | None = None, method: str | None = None):
    """Tag contained HTTP traffic with a phase/role/method; nested scopes merge."""
    current = dict(_HTTP_SCOPE.get())
    if phase is not None:
        current["phase"] = phase if phase in HTTP_PHASES else "other"
    if role is not None:
        current["role"] = role if role in HTTP_ROLES else "other"
    if method is not None:
        current["method"] = method
    token = _HTTP_SCOPE.set(current)
    try:
        yield current
    finally:
        _HTTP_SCOPE.reset(token)


def http_accounted(*, phase: str | None = None, role: str | None = None, method: str | None = None):
    """Decorator form of :func:`request_scope` for contained call boundaries."""
    def decorator(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            with request_scope(phase=phase, role=role, method=method):
                return function(*args, **kwargs)
        return wrapped
    return decorator


def record_http_retry(count: int = 1) -> None:
    """Record a higher-level bounded retry (provider-independent HTTP retry)."""
    counter = _HTTP_COUNTER.get()
    if not isinstance(counter, dict):
        return
    counter["retries"] += max(0, int(count))
    method = _HTTP_SCOPE.get().get("method")
    if method:
        entry = counter["per_method"].setdefault(method, _blank_http_counter())
        entry["retries"] += max(0, int(count))


def _record_http_failure() -> None:
    counter = _HTTP_COUNTER.get()
    if not isinstance(counter, dict):
        return
    counter["failed_requests"] += 1
    method = _HTTP_SCOPE.get().get("method")
    if method:
        entry = counter["per_method"].setdefault(method, _blank_http_counter())
        entry["failed_requests"] += 1


def _record_http_redirect() -> None:
    """Record one followed redirect hop; the hop's own request is counted separately."""
    counter = _HTTP_COUNTER.get()
    if not isinstance(counter, dict):
        return
    counter["redirect_hops"] += 1
    method = _HTTP_SCOPE.get().get("method")
    if method:
        entry = counter["per_method"].setdefault(method, _blank_http_counter())
        entry["redirect_hops"] += 1


def _record_http_dispatch(*, redirect: bool = False, failed: bool = False) -> None:
    counter = _HTTP_COUNTER.get()
    if not isinstance(counter, dict):
        return
    scope = _HTTP_SCOPE.get()
    phase, role, method = scope.get("phase", "other"), scope.get("role", "other"), scope.get("method")
    counter["total_requests"] += 1
    counter["by_phase"][phase] = counter["by_phase"].get(phase, 0) + 1
    counter["by_role"][role] = counter["by_role"].get(role, 0) + 1
    if phase == "other" or role == "other":
        counter["unattributed_requests"] = int(counter.get("unattributed_requests", 0) or 0) + 1
        counter["complete"] = False
    if redirect:
        counter["redirect_hops"] += 1
    if failed:
        counter["failed_requests"] += 1
    if method:
        entry = counter["per_method"].setdefault(method, _blank_http_counter())
        entry["total_requests"] += 1
        entry["by_phase"][phase] = entry["by_phase"].get(phase, 0) + 1
        entry["by_role"][role] = entry["by_role"].get(role, 0) + 1
        if phase == "other" or role == "other":
            entry["unattributed_requests"] = int(entry.get("unattributed_requests", 0) or 0) + 1
            entry["complete"] = False
        if redirect:
            entry["redirect_hops"] += 1
        if failed:
            entry["failed_requests"] += 1


@contextmanager
def capture_containment_events():
    """Collect even violations swallowed by method/session error handling."""
    events: list[dict] = []
    token = _CONTAINMENT_RECEIPTS.set(events)
    try:
        yield events
    finally:
        _CONTAINMENT_RECEIPTS.reset(token)


class TransportError(Exception):
    """Raised when a network-level error occurs (DNS failure, refused connection, etc.)."""


class RequestTimeoutError(Exception):
    """Raised when an HTTP request exceeds the configured timeout."""


class ContainmentError(ValueError):
    """Raised when a request or redirect leaves the configured DVWA host."""

    def __init__(
        self,
        message: str,
        *,
        url: str | None = None,
        allowed_host: str | None = None,
        kind: str = "request",
    ) -> None:
        """Keep structured context so callers can persist an audit event.

        ``url``, ``allowed_host``, and ``kind`` remain optional for backwards
        compatibility with callers that only need an exception message.
        ``HTTPClient`` always supplies them when it raises this exception.
        """
        super().__init__(message)
        self.url = url
        self.allowed_host = allowed_host
        self.kind = kind

    def as_event(self) -> dict[str, str | None]:
        """Return a JSON-safe containment event for state/artifact logging."""
        return {
            "kind": self.kind,
            "classification": "scope_violation",
            "origin": "http_client",
            "scope": "run",
            "blocked_url": self.url,
            "allowed_host": self.allowed_host,
            "reason": str(self),
        }


@dataclass
class RequestResult:
    """Normalized wrapper around an httpx.Response with timing metadata."""

    response: httpx.Response
    elapsed_ms: float

    @property
    def status_code(self) -> int:
        """Handles status code behavior for this module."""
        return self.response.status_code

    @property
    def text(self) -> str:
        """Handles text behavior for this module."""
        return self.response.text

    @property
    def url(self) -> str:
        """Handles url behavior for this module."""
        return str(self.response.url)

    @property
    def headers(self) -> httpx.Headers:
        """Handles headers behavior for this module."""
        return self.response.headers


class HTTPClient:
    """Session-aware HTTP client built on httpx.

    Provides connection pooling, cookie persistence, and standardized
    timeout/redirect behavior. Designed for dependency injection into
    higher-level modules (session_manager, recon, agents).

    Args:
        base_url: Root URL for the target (e.g. ``http://localhost/dvwa``).
            Trailing slashes are normalized.
        timeout_connect: TCP connect timeout in seconds.
        timeout_read: Read timeout in seconds.
        timeout_write: Write timeout in seconds.
        timeout_pool: Pool acquisition timeout in seconds.
        max_connections: Total connection pool size.
        max_keepalive: Number of keep-alive connections to retain.
    """

    def __init__(
        self,
        base_url: str,
        timeout_connect: float = 5.0,
        timeout_read: float = 12.0,
        timeout_write: float = 12.0,
        timeout_pool: float = 5.0,
        max_connections: int = 20,
        max_keepalive: int = 10,
        verify_ssl: bool | None = None,
    ) -> None:
        if verify_ssl is None:
            verify_ssl = os.getenv("DVWA_VERIFY_SSL", "false").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }

        self.base_url = base_url.rstrip("/") + "/"
        parsed_base = urlparse(self.base_url)
        if not parsed_base.scheme or not parsed_base.hostname:
            raise ValueError(f"Invalid base URL: {base_url}")
        # Preserve the public containment metadata used by earlier callers.
        # ``netloc`` intentionally excludes the path (DVWA commonly lives
        # below /dvwa) and includes an explicitly configured port.
        self.allowed_host = parsed_base.netloc.lower()
        self.containment_events: list[dict[str, str | None]] = []
        self._allowed_hostname = parsed_base.hostname.lower()
        self._allowed_port = parsed_base.port
        self._client = httpx.Client(
            # Redirects are followed manually below so every hop is contained.
            follow_redirects=False,
            verify=verify_ssl,
            timeout=httpx.Timeout(
                connect=timeout_connect,
                read=timeout_read,
                write=timeout_write,
                pool=timeout_pool,
            ),
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_keepalive,
            ),
        )

    # ── Request methods ──────────────────────────────────────────

    def get(self, path: str, **kwargs) -> RequestResult:
        """Send a GET request to ``base_url + path``.

        Args:
            path: Relative URL path (leading slashes are stripped).
            **kwargs: Additional keyword arguments forwarded to ``httpx.Client.get``.

        Returns:
            A ``RequestResult`` containing the response and elapsed time.

        Raises:
            TransportError: On network-level failures.
            RequestTimeoutError: When the request times out.
        """
        url = self._resolve_url(path)
        return self._request("GET", url, **kwargs)

    def post(self, path: str, **kwargs) -> RequestResult:
        """Send a POST request to ``base_url + path``.

        Args:
            path: Relative URL path.
            **kwargs: Forwarded to ``httpx.Client.post`` (e.g. ``data``, ``files``).

        Returns:
            A ``RequestResult`` containing the response and elapsed time.

        Raises:
            TransportError: On network-level failures.
            RequestTimeoutError: When the request times out.
        """
        url = self._resolve_url(path)
        return self._request("POST", url, **kwargs)

    # ── Cookie access ────────────────────────────────────────────

    @property
    def cookies(self) -> httpx.Cookies:
        """Access the underlying cookie jar for session management."""
        return self._client.cookies

    def set_cookie(self, name: str, value: str, domain: str = "", path: str = "/") -> None:
        """Set a cookie on the client's cookie jar.

        Args:
            name: Cookie name (e.g. ``"security"``).
            value: Cookie value (e.g. ``"low"``).
            domain: Cookie domain.
            path: Cookie path.
        """
        self._client.cookies.set(name, value, domain=domain, path=path)

    # ── Lifecycle ─────────────────────────────────────────────────

    def close(self) -> None:
        """Close the underlying httpx client and release connections."""
        self._client.close()

    def __enter__(self) -> "HTTPClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── Internals ────────────────────────────────────────────────

    def _request(self, method: str, url: str, **kwargs) -> RequestResult:
        """Execute a request with error mapping.

        Maps httpx exceptions to typed domain exceptions for cleaner
        handling upstream.
        """
        # ``get``/``post`` resolve before reaching here, but keeping the check
        # at this lower boundary protects direct/internal callers as well.
        self._assert_in_scope(url, kind="request")
        try:
            current_method = method
            current_url = url
            request_kwargs = dict(kwargs)
            for _ in range(6):
                _record_http_dispatch()
                try:
                    resp = self._client.request(
                        current_method,
                        current_url,
                        follow_redirects=False,
                        **request_kwargs,
                    )
                except (httpx.TimeoutException, httpx.NetworkError):
                    _record_http_failure()
                    raise
                status_code = int(getattr(resp, "status_code", 0) or 0)
                if not 300 <= status_code < 400:
                    break
                location = resp.headers.get("location")
                if not location:
                    break
                _record_http_redirect()
                current_url = self._resolve_url(
                    urljoin(current_url, location),
                    kind="redirect",
                )
                # ``params`` belongs to the original request URL.  Passing
                # it again on every redirect can re-add the original query
                # string after a Location header intentionally replaces it.
                # DVWA's high-security brute-force module redirects from
                # ``?username=...`` to ``index.php``; retaining the query
                # makes that endpoint redirect to itself indefinitely.
                request_kwargs.pop("params", None)
                # Match browser/httpx form semantics for the redirects DVWA
                # emits after POST submissions.  Retrying a 302 as the same
                # POST resubmits the form indefinitely (notably security.php).
                # Preserve methods and bodies only for the explicit 307/308
                # method-preserving redirects.
                if status_code in {301, 302, 303} and current_method != "HEAD":
                    current_method = "GET"
                    request_kwargs.pop("data", None)
                    request_kwargs.pop("files", None)
                    request_kwargs.pop("json", None)
                    request_kwargs.pop("content", None)
            else:
                raise TransportError(f"Too many contained redirects for {method} {url}")
            elapsed_ms = resp.elapsed.total_seconds() * 1000
        except httpx.TimeoutException as exc:
            logger.warning("Request timeout: %s %s – %s", method, url, exc)
            raise RequestTimeoutError(f"Request timed out: {method} {url}") from exc
        except httpx.NetworkError as exc:
            logger.error("Transport error: %s %s – %s", method, url, exc)
            raise TransportError(f"Network error: {method} {url}") from exc
        except httpx.InvalidURL as exc:
            raise ValueError(f"Invalid URL: {url}") from exc

        return RequestResult(response=resp, elapsed_ms=elapsed_ms)

    def _is_in_scope(self, url: str) -> bool:
        """Return whether *url* stays on the configured DVWA host and port."""
        parsed = urlparse(str(url))
        if not parsed.hostname:
            # Relative URLs are resolved by ``_resolve_url`` before this check.
            return True
        return (
            parsed.scheme in {"http", "https"}
            and parsed.hostname.lower() == self._allowed_hostname
            and parsed.port == self._allowed_port
        )

    def _assert_in_scope(self, url: str, *, kind: str = "request") -> None:
        """Raise and record a structured event for an out-of-scope URL."""
        if self._is_in_scope(url):
            return
        logger.warning(
            "Containment violation (%s): %s not in %s",
            kind,
            url,
            self.allowed_host,
        )
        error = ContainmentError(
            f"Blocked out-of-scope HTTP target: {url} (allowed host: {self.allowed_host})",
            url=str(url),
            allowed_host=self.allowed_host,
            kind=kind,
        )
        self.containment_events.append(error.as_event())
        receipts = _CONTAINMENT_RECEIPTS.get()
        if receipts is not None:
            receipts.append(error.as_event())
        raise error

    def _resolve_url(self, path_or_url: str, *, kind: str = "request") -> str:
        """Resolve a relative request and reject any external host.

        The framework may navigate same-host DVWA links discovered during recon,
        but LLM output, form actions, and redirect locations cannot change the
        target host.
        """
        raw = str(path_or_url).strip()
        resolved = urljoin(self.base_url, raw if raw.startswith("//") else raw.lstrip("/"))
        self._assert_in_scope(resolved, kind=kind)
        return resolved
