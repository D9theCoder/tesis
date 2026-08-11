"""HTTP client wrapper with session-aware request handling.

Provides a reusable, session-aware HTTP client for all foundation and agent
modules. Centralizes timeout, redirect, and connection pooling behavior,
and captures response metadata for verification and logging.
"""

import logging
import os
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)


class TransportError(Exception):
    """Raised when a network-level error occurs (DNS failure, refused connection, etc.)."""


class RequestTimeoutError(Exception):
    """Raised when an HTTP request exceeds the configured timeout."""


class ContainmentError(ValueError):
    """Raised when a request or redirect leaves the configured DVWA host."""


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
        try:
            current_method = method
            current_url = url
            request_kwargs = dict(kwargs)
            for _ in range(6):
                resp = self._client.request(
                    current_method,
                    current_url,
                    follow_redirects=False,
                    **request_kwargs,
                )
                status_code = int(getattr(resp, "status_code", 0) or 0)
                if not 300 <= status_code < 400:
                    break
                location = resp.headers.get("location")
                if not location:
                    break
                current_url = self._resolve_url(urljoin(current_url, location))
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

    def _resolve_url(self, path_or_url: str) -> str:
        """Resolve a relative request and reject any external host.

        The framework may navigate same-host DVWA links discovered during recon,
        but LLM output, form actions, and redirect locations cannot change the
        target host.
        """
        raw = str(path_or_url).strip()
        resolved = urljoin(self.base_url, raw if raw.startswith("//") else raw.lstrip("/"))
        parsed = urlparse(resolved)
        hostname = (parsed.hostname or "").lower()
        if (
            parsed.scheme not in {"http", "https"}
            or hostname != self._allowed_hostname
            or parsed.port != self._allowed_port
        ):
            raise ContainmentError(
                f"Blocked out-of-scope HTTP target: {resolved} (allowed host: {self._allowed_hostname})"
            )
        return resolved
