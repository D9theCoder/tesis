"""DVWA session manager — authentication, security level, and cookie management.

Handles the full DVWA login lifecycle including CSRF token extraction,
session validation, and security level configuration. Exposes an
authenticated session to downstream recon and agent modules via the
shared HTTPClient.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from bs4 import BeautifulSoup

from foundation.http_client import HTTPClient, RequestResult, TransportError, RequestTimeoutError

logger = logging.getLogger(__name__)

# Valid DVWA security levels (canonical contract from core/state.py)
VALID_LEVELS = ("low", "medium", "high")


class DVWASession:
    """Manages authentication, cookies, and security level for DVWA.

    This class wraps a persistent ``HTTPClient`` with DVWA-specific login
    and security-level logic. It must be used as a context manager or closed
    explicitly to release HTTP connections.

    Usage::

        session = DVWASession("http://localhost/dvwa")
        session.login("admin", "password")
        session.set_security_level("low")
        result = session.http.get("vulnerabilities/sqli/")
        session.close()

    Or as a context manager::

        with DVWASession("http://localhost/dvwa") as session:
            session.login()
            session.set_security_level("medium")
            ...

    Args:
        base_url: Root URL of the DVWA instance.
            Defaults to ``http://localhost/dvwa``.
    """

    def __init__(self, base_url: str = "http://localhost/dvwa") -> None:
        """Supports init behavior for this module."""
        self.http = HTTPClient(base_url)
        self._logged_in = False
        self._security_level: str = "low"
        self._username: str = ""

    # ── Authentication ───────────────────────────────────────────

    @staticmethod
    def _extract_user_token(html: str) -> str | None:
        """Extract the ``user_token`` CSRF field from a DVWA HTML page.

        Args:
            html: Raw HTML response text.

        Returns:
            The token value if found, else ``None``.
        """
        soup = BeautifulSoup(html, "html.parser")
        token_el = soup.select_one("input[name='user_token']")
        if token_el and token_el.get("value"):
            return token_el["value"]
        return None

    def login(self, username: str = "admin", password: str = "password") -> bool:
        """Authenticate to DVWA and persist the session.

        Follows the DVWA login flow:
        1. ``GET /login.php`` → extract ``user_token``.
        2. ``POST /login.php`` with credentials + token.
        3. Verify success via redirect/content signals.

        Args:
            username: DVWA username.
            password: DVWA password.

        Returns:
            ``True`` if login succeeded, ``False`` otherwise.

        Raises:
            TransportError: On network failures.
            RequestTimeoutError: On timeouts.
        """
        # Step 1: Fetch login page and extract CSRF token
        login_page = self.http.get("login.php")
        token = self._extract_user_token(login_page.text)

        # Step 2: POST credentials with token
        payload: dict[str, Any] = {
            "username": username,
            "password": password,
            "Login": "Login",
        }
        if token:
            payload["user_token"] = token

        resp = self.http.post("login.php", data=payload)

        # Step 3: Verify successful authentication
        body_lower = resp.text.lower()
        current_url = resp.url.lower()

        # DVWA redirects to index.php on success OR shows "logout" link
        logged_out_indicator = "username and/or password incorrect"
        if logged_out_indicator in body_lower:
            self._logged_in = False
            logger.warning("Login failed for user %r: credentials rejected", username)
            return False

        # Additional negative indicator: explicit login-failed message
        failure_indicators = [
            "login failed",
            "invalid username",
            "invalid password",
        ]
        if any(ind in body_lower for ind in failure_indicators):
            self._logged_in = False
            logger.warning("Login failed for user %r: explicit failure message in response", username)
            return False

        # Successful login indicators
        if ("logout" in body_lower) or ("index.php" in current_url):
            self._logged_in = True
            self._username = username
            logger.info("Login successful for user %r", username)

            # Apply security level cookie after successful login
            self._apply_security_level_cookie()
            return True

        # Ambiguous response — treat as failure
        self._logged_in = False
        logger.warning(
            "Login result ambiguous for user %r (status=%d, url=%s)",
            username,
            resp.status_code,
            resp.url,
        )
        return False

    # ── Security Level ────────────────────────────────────────────

    @property
    def security_level(self) -> str:
        """Current DVWA security level (``"low"``, ``"medium"``, ``"high"``)."""
        return self._security_level

    def set_security_level(self, level: str) -> None:
        """Set DVWA security level and persist it via cookie + form submission.

        This method:
        1. Validates the level against known values.
        2. Sets the ``security`` cookie on the HTTP client.
        3. Submits DVWA's security form to persist the change server-side.

        Args:
            level: One of ``"low"``, ``"medium"``, ``"high"``.

        Raises:
            ValueError: If *level* is not a valid DVWA security level.
        """
        normalized = level.lower().strip()
        if normalized not in VALID_LEVELS:
            raise ValueError(
                f"Invalid security level {level!r}. "
                f"Must be one of: {', '.join(VALID_LEVELS)}"
            )

        self._security_level = normalized
        self._apply_security_level_cookie()
        if not self._submit_security_form(normalized):
            logger.error("Security level form submission failed — server-side level may not match cookie")

    def detect_security_level(self) -> str:
        """Detect the current DVWA security level from cookies and page content.

        Checks in order:
        1. Parse the DVWA security settings page (authoritative server-side state).
        2. Fallback: the ``security`` cookie value.

        Returns:
            Detected security level string (normalized to ``"low"`` if unknown).
        """
        # Prefer authoritative server-side page state over cookie value.
        try:
            resp = self.http.get("security.php")
            soup = BeautifulSoup(resp.text, "html.parser")

            # Look for the selected option in the security dropdown
            select = soup.select_one("select[name='security']")
            if select:
                # Try attrs={"selected": True} first, then fallback to selected=True
                selected = select.find("option", attrs={"selected": True})
                if selected is None:
                    selected = select.find("option", selected=True)
                if selected and selected.get("value", "").lower() in VALID_LEVELS:
                    self._security_level = selected["value"].lower()
                    return self._security_level

            # Check hidden input or text indication
            level_match = re.search(r"security level.*?(low|medium|high)", resp.text.lower())
            if level_match:
                self._security_level = level_match.group(1)
                return self._security_level

        except (TransportError, RequestTimeoutError):
            logger.warning("Failed to detect security level from page content")

        # Fallback: use cookie only if server-side parse did not produce a level.
        sec_cookie = self.http.cookies.get("security")
        if sec_cookie and sec_cookie.lower() in VALID_LEVELS:
            self._security_level = sec_cookie.lower()
            return self._security_level

        return self._security_level

    # ── Convenience HTTP methods ─────────────────────────────────

    def get(self, path: str, params: dict | None = None) -> RequestResult:
        """Send an authenticated GET request (delegates to ``self.http``).

        Args:
            path: Relative URL path.
            params: Optional query parameters.

        Returns:
            ``RequestResult`` from the underlying HTTP client.
        """
        kwargs: dict[str, Any] = {}
        if params:
            kwargs["params"] = params
        return self.http.get(path, **kwargs)

    def post(
        self,
        path: str,
        data: dict | None = None,
        files: dict | None = None,
    ) -> RequestResult:
        """Send an authenticated POST request (delegates to ``self.http``).

        Args:
            path: Relative URL path.
            data: Form data payload.
            files: Multipart file upload payload.

        Returns:
            ``RequestResult`` from the underlying HTTP client.
        """
        kwargs: dict[str, Any] = {}
        if data:
            kwargs["data"] = data
        if files:
            kwargs["files"] = files
        return self.http.post(path, **kwargs)

    # ── Context manager ──────────────────────────────────────────

    def close(self) -> None:
        """Close the underlying HTTP client and release connections."""
        self.http.close()

    def __enter__(self) -> "DVWASession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── Properties ────────────────────────────────────────────────

    @property
    def is_logged_in(self) -> bool:
        """Whether the session has been successfully authenticated."""
        return self._logged_in

    # ── Internals ────────────────────────────────────────────────

    def _apply_security_level_cookie(self) -> None:
        """Set the security cookie to match the current level."""
        from urllib.parse import urlparse
        base_url = self.http.base_url
        if isinstance(base_url, str):
            parsed = urlparse(base_url)
            domain = parsed.hostname or "localhost"
            self.http.set_cookie("security", self._security_level, domain=domain)
        else:
            self.http.set_cookie("security", self._security_level)

    def _submit_security_form(self, level: str) -> bool:
        """Submit DVWA's security settings form to persist the level server-side.

        This ensures the PHP session also respects the security level,
        not just the cookie.

        Returns:
            True if the form was submitted successfully, False otherwise.
        """
        try:
            # Fetch security page to get CSRF token
            sec_page = self.http.get("security.php")
            token = self._extract_user_token(sec_page.text)

            payload: dict[str, Any] = {
                "security": level,
                "seclev_submit": "Submit",
            }
            if token:
                payload["user_token"] = token

            self.http.post("security.php", data=payload)
            logger.info("Security level set to %r (form submitted)", level)
            return True

        except (TransportError, RequestTimeoutError) as exc:
            logger.warning("Failed to submit security level form for level %r: %s", level, exc)
            return False


# Backward-compatible alias used by earlier docs/plans.
DVWASessionManager = DVWASession
