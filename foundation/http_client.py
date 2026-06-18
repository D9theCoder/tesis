"""HTTP client wrapper with session-aware request handling.

Provides a reusable, session-aware HTTP client for all foundation and agent
modules. Centralizes timeout, redirect, and connection pooling behavior,
and captures response metadata for verification and logging.
"""

import logging
import os
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

logger = logging.getLogger(__name__)


class TransportError(Exception):
    """Raised when a network-level error occurs (DNS failure, refused connection, etc.)."""


class RequestTimeoutError(Exception):
    """Raised when an HTTP request exceeds the configured timeout."""


class ContainmentError(Exception):
    """Raised when a request or redirect would leave the allowed DVWA scope."""

    def __init__(self, message: str, *, url: str, allowed_host: str, kind: str) -> None:
        super().__init__(message)
        self.url = url
        self.allowed_host = allowed_host
        self.kind = kind  # "request" | "redirect"

    def as_event(self) -> dict:
        """Return a structured containment violation event for state logging."""
        return {
            "kind": self.kind,
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
        self.allowed_host = urlsplit(self.base_url).netloc.lower()
        self.containment_events: list[dict] = []
        self._max_redirects = 10
        self._client = httpx.Client(
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

    # ── Containment ──────────────────────────────────────────────

    def _is_in_scope(self, url: str) -> bool:
        """Return True when the URL targets the allowed DVWA host (or is relative)."""
        netloc = urlsplit(url).netloc.lower()
        return netloc == "" or netloc == self.allowed_host

    def _assert_in_scope(self, url: str, *, kind: str) -> None:
        """Raise ContainmentError when the URL leaves the allowed DVWA scope.

        Args:
            url: Absolute or relative URL being requested or redirected to.
            kind: Either "request" or "redirect" for event classification.

        Raises:
            ContainmentError: When the URL host differs from the allowed host.
        """
        if self._is_in_scope(url):
            return
        event = {
            "kind": kind,
            "blocked_url": url,
            "allowed_host": self.allowed_host,
            "reason": f"{kind} target outside allowed DVWA scope",
        }
        self.containment_events.append(event)
        logger.warning("Containment violation (%s): %s not in %s", kind, url, self.allowed_host)
        raise ContainmentError(
            f"{kind} to {url!r} blocked: outside allowed host {self.allowed_host!r}",
            url=url,
            allowed_host=self.allowed_host,
            kind=kind,
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
        url = urljoin(self.base_url, path.lstrip("/"))
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
        url = urljoin(self.base_url, path.lstrip("/"))
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
        """Execute a request with containment enforcement and error mapping.

        The initial URL and every redirect target are validated against the
        allowed DVWA host before a connection is made. External hosts and
        external redirects raise ``ContainmentError``. httpx exceptions are
        mapped to typed domain exceptions for cleaner handling upstream.
        """
        self._assert_in_scope(url, kind="request")
        current_method = method
        current_url = url
        try:
            resp = self._client.request(current_method, current_url, **kwargs)
            total_elapsed = resp.elapsed.total_seconds() * 1000
            redirects = 0
            # httpx returns real booleans here; the strict `is True` checks also
            # prevent test doubles (MagicMock) from being treated as redirects.
            while resp.is_redirect is True and resp.has_redirect_location is True:
                redirects += 1
                if redirects > self._max_redirects:
                    raise TransportError(f"Too many redirects: {method} {url}")
                next_url = str(resp.next_request.url) if resp.next_request else urljoin(
                    current_url, resp.headers.get("location", "")
                )
                self._assert_in_scope(next_url, kind="redirect")
                # GET/HEAD preserve method; other methods become GET on 301/302/303.
                if resp.status_code in (301, 302, 303) and current_method not in ("GET", "HEAD"):
                    current_method = "GET"
                    kwargs.pop("data", None)
                    kwargs.pop("content", None)
                    kwargs.pop("json", None)
                    kwargs.pop("files", None)
                current_url = next_url
                resp = self._client.request(current_method, current_url)
                total_elapsed += resp.elapsed.total_seconds() * 1000
            elapsed_ms = total_elapsed
        except httpx.TimeoutException as exc:
            logger.warning("Request timeout: %s %s – %s", method, url, exc)
            raise RequestTimeoutError(f"Request timed out: {method} {url}") from exc
        except httpx.NetworkError as exc:
            logger.error("Transport error: %s %s – %s", method, url, exc)
            raise TransportError(f"Network error: {method} {url}") from exc
        except httpx.InvalidURL as exc:
            raise ValueError(f"Invalid URL: {url}") from exc

        return RequestResult(response=resp, elapsed_ms=elapsed_ms)
