"""Recon module — crawl DVWA, enumerate modules & inputs.

Crawls DVWA to build a complete map of the attack surface before any
exploitation begins. Populates ``state.endpoints`` and ``state.input_vectors``
so all subsequent agents know exactly what URL, method, and parameters to
target without hardcoding assumptions.

Returns a partial state update compatible with ``ExploitationState`` that
includes normalized endpoints, input vectors, the detected security level,
and sets ``next_agent`` to ``"orchestrator"``.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.state import ExploitationState, SECURITY_LEVELS
from foundation.http_client import HTTPClient, TransportError, RequestTimeoutError
from foundation.session_manager import DVWASession

logger = logging.getLogger(__name__)

# ── Module name inference ──────────────────────────────────────────────

DVWA_MODULE_HINTS: dict[str, str] = {
    # Order matters: more specific patterns must be checked before shorter ones
    # e.g. "sqli_blind" must match before "sqli"
    "sqli_blind": "sqli_blind",
    "xss_r": "xss_r",
    "xss_s": "xss_s",
    "xss_d": "xss_d",
    "weak_id": "weak_session",
    "sqli": "sqli",
    "exec": "cmdi",
    "fi": "lfi",
    "upload": "upload",
    "csrf": "csrf",
    "brute": "brute",
}


def infer_module_name(url: str) -> str:
    """Infer a normalized DVWA module name from a URL path.

    Matches are checked longest-pattern-first to prevent shorter patterns
    from shadowing more specific ones (e.g. ``sqli`` matching before
    ``sqli_blind``).

    Args:
        url: Absolute or relative URL to classify.

    Returns:
        Module name string (e.g. ``"sqli"``, ``"cmdi"``), or ``"unknown"``.
    """
    path = urlparse(url).path.lower()
    # Sort by marker length descending so "sqli_blind" matches before "sqli"
    for marker, module in sorted(DVWA_MODULE_HINTS.items(), key=lambda x: len(x[0]), reverse=True):
        if marker in path:
            return module
    return "unknown"


# ── Typed record structures ────────────────────────────────────────────

class EndpointRecord(dict):
    """Normalized endpoint record matching ``ExploitationState.endpoints`` schema.

    Fields:
        url: Full URL of the form action.
        method: HTTP method (``"get"`` or ``"post"``).
        params: Sorted, deduplicated list of parameter names.
        csrf_token: Value of the ``user_token`` hidden field, if present.
        module_name: Inferred DVWA module name.
    """

    def __init__(
        self,
        url: str,
        method: str = "get",
        params: list[str] | None = None,
        csrf_token: str | None = None,
        module_name: str = "unknown",
    ) -> None:
        super().__init__(
            url=url,
            method=method.lower() if method else "get",
            params=sorted(set(params)) if params else [],
            csrf_token=csrf_token,
            module_name=module_name,
        )


class InputVectorRecord(dict):
    """Normalized input vector record matching ``ExploitationState.input_vectors`` schema.

    Fields:
        param_name: Name of the input parameter.
        param_type: Input type (``"text"``, ``"hidden"``, ``"file"``, ``"unknown"``).
        endpoint_url: URL of the form this input belongs to.
    """

    def __init__(
        self,
        param_name: str,
        param_type: str = "unknown",
        endpoint_url: str = "",
    ) -> None:
        super().__init__(
            param_name=param_name,
            param_type=param_type.lower(),
            endpoint_url=endpoint_url,
        )


# ── Form parsing ──────────────────────────────────────────────────────

def parse_forms(html: str, page_url: str) -> tuple[list[dict], list[dict]]:
    """Parse all forms from an HTML page into normalized endpoint and vector records.

    Args:
        html: Raw HTML response text.
        page_url: Base URL for resolving relative form actions.

    Returns:
        Tuple of (endpoints, vectors) — each is a list of plain dicts
        compatible with ``ExploitationState``.
    """
    soup = BeautifulSoup(html, "html.parser")
    endpoints: list[dict] = []
    vectors: list[dict] = []

    for form in soup.select("form"):
        method = (form.get("method") or "get").lower().strip()
        action = form.get("action") or page_url
        endpoint_url = urljoin(page_url, action)

        params: list[str] = []
        csrf_token: str | None = None
        seen_params: set[str] = set()

        # Single pass over all form controls to avoid duplicates
        for element in form.select("input, textarea, select"):
            name = element.get("name")
            if not name:
                continue

            # Determine element type
            tag = element.name.lower()
            if tag == "textarea":
                ptype = "textarea"
            elif tag == "select":
                ptype = "select"
            else:
                ptype = (element.get("type") or "unknown").lower()

            # Track params with deduplication
            if name not in seen_params:
                params.append(name)
                seen_params.add(name)

            # Capture CSRF token value
            if name == "user_token":
                csrf_token = element.get("value")

            vectors.append(
                InputVectorRecord(
                    param_name=name,
                    param_type=ptype,
                    endpoint_url=endpoint_url,
                )
            )

        endpoints.append(
            EndpointRecord(
                url=endpoint_url,
                method=method,
                params=params,
                csrf_token=csrf_token,
                module_name=infer_module_name(endpoint_url),
            )
        )

    return endpoints, vectors


# ── Navigation link extraction ──────────────────────────────────────────

def extract_nav_links(html: str, base_url: str) -> list[str]:
    """Extract and normalize DVWA navigation links from the sidebar/menu.

    Focuses on links under ``/vulnerabilities/`` to find module pages.

    Args:
        html: Raw HTML of the index/navigation page.
        base_url: Root URL for resolving relative links.

    Returns:
        Sorted, deduplicated list of absolute URLs pointing to DVWA module pages.
    """
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []

    for a_tag in soup.select("a[href]"):
        href = a_tag.get("href", "")
        # Only include links to DVWA vulnerability module pages
        if "/vulnerabilities/" in href or "/vulnerabilities/" in str(a_tag.get("href", "")):
            absolute = urljoin(base_url, href)
            # Strip fragment identifiers
            absolute = absolute.split("#")[0]
            links.append(absolute)

    # Deduplicate and sort for deterministic ordering
    return sorted(set(links))


# ── Security level detection ───────────────────────────────────────────

def detect_security_level_from_html(html: str) -> str | None:
    """Attempt to detect the current DVWA security level from page content.

    Looks for the security level indicator in DVWA's page output.

    Args:
        html: Raw HTML of a DVWA page.

    Returns:
        Detected level string, or ``None`` if not found.
    """
    lower = html.lower()
    # Look for "DVWA Security Level: xxx" pattern
    match = re.search(r"dvwa security level.*?(low|medium|high|impossible)", lower)
    if match:
        return match.group(1)

    # Fallback: check for security level in the page footer or body
    for level in ("impossible", "high", "medium", "low"):
        if f"security level is {level}" in lower:
            return level

    return None


# ── Server fingerprinting ────────────────────────────────────────────────

def fingerprint_server(headers: dict) -> dict[str, str]:
    """Extract server technology fingerprints from HTTP response headers.

    Implements AGENTS.md recon step 1d: "Parse response headers →
    fingerprint PHP version, server type."

    Args:
        headers: HTTP response headers (from ``RequestResult.headers``).

    Returns:
        Dict with detected technology info (e.g. ``{"server": "Apache", "php_version": "7.4.3"}``).
    """
    fingerprint: dict[str, str] = {}

    lower_headers = {k.lower(): v for k, v in headers.items()}

    # Server type (e.g. Apache, nginx)
    if "server" in lower_headers:
        fingerprint["server"] = lower_headers["server"]

    # PHP version from X-Powered-By header
    if "x-powered-by" in lower_headers:
        powered_by = lower_headers["x-powered-by"]
        if "php" in powered_by.lower() or "php" in powered_by:
            fingerprint["php_version"] = powered_by

    # X-AspNet-Version
    if "x-aspnet-version" in lower_headers:
        fingerprint["aspnet_version"] = lower_headers["x-aspnet-version"]

    return fingerprint


# ── Main recon function (LangGraph node) ────────────────────────────────

def recon(state: ExploitationState) -> dict[str, Any]:
    """LangGraph recon node — crawl DVWA and populate the attack surface.

    This function is designed to be registered as a node in the LangGraph
    ``StateGraph``. It receives the current ``ExploitationState`` and returns
    a partial state update dict.

    The recon pipeline:
    1. Authenticate to DVWA using the target URL.
    2. Detect (or confirm) the current security level.
    3. Crawl the DVWA navigation to find module pages.
    4. Parse each module page for forms, inputs, and CSRF tokens.
    5. Build normalized ``endpoints`` and ``input_vectors`` lists.
    6. Return a partial state update with ``next_agent="orchestrator"``.

    Args:
        state: The current ``ExploitationState`` dict.

    Returns:
        Partial state update dict compatible with LangGraph reducers.
    """
    target_url = state.get("target_url", "")
    requested_level = state.get("security_level", "low")

    if not target_url:
        logger.error("recon: target_url is empty — cannot proceed")
        return {
            "endpoints": [],
            "input_vectors": [],
            "security_level": requested_level,
            "next_agent": "orchestrator",
        }

    all_endpoints: list[dict] = []
    all_vectors: list[dict] = []
    server_fingerprint: dict[str, str] = {}

    session: DVWASession | None = None

    try:
        # Step 1: Create session and login
        session = DVWASession(target_url)
        try:
            login_success = session.login()
            if not login_success:
                logger.warning("recon: login failed — proceeding with unauthenticated crawl")
        except (TransportError, RequestTimeoutError) as exc:
            logger.error("recon: login request failed: %s", exc)

        # Step 2: Set/detect security level
        try:
            session.set_security_level(requested_level)
        except ValueError:
            logger.warning("recon: invalid security level %r — defaulting to 'low'", requested_level)
            session.set_security_level("low")
            requested_level = "low"

        detected_level = session.detect_security_level()
        if detected_level and detected_level in SECURITY_LEVELS:
            requested_level = detected_level

        # Step 3: Crawl DVWA navigation to find module pages
        # Also fingerprint server from response headers (AGENTS.md step 1d)
        try:
            index_result = session.http.get("index.php")
            nav_links = extract_nav_links(index_result.text, session.http.base_url)
            # Step 1d: fingerprint server technology from headers
            server_fingerprint = fingerprint_server(dict(index_result.headers))
            if server_fingerprint:
                logger.info("recon: server fingerprint: %s", server_fingerprint)
        except (TransportError, RequestTimeoutError) as exc:
            logger.error("recon: failed to fetch index page: %s", exc)
            nav_links = []

        # Step 4: Fetch each module page and parse forms
        seen_urls: set[str] = set()
        for module_url in nav_links:
            # Deduplicate by normalized URL (without query params)
            normalized = module_url.split("?")[0].split("#")[0]
            if normalized in seen_urls:
                continue
            seen_urls.add(normalized)

            try:
                result = session.http.get(module_url)
                page_endpoints, page_vectors = parse_forms(result.text, module_url)
                all_endpoints.extend(page_endpoints)
                all_vectors.extend(page_vectors)
            except (TransportError, RequestTimeoutError) as exc:
                logger.warning("recon: failed to fetch %s: %s", module_url, exc)

        # Step 5: Deduplicate and sort for deterministic output
        all_endpoints = _deduplicate_endpoints(all_endpoints)
        all_vectors = _deduplicate_vectors(all_vectors)

    except Exception as exc:
        logger.error("recon: unexpected error during crawl: %s", exc)

    finally:
        # Ensure session is closed if it was created
        if session is not None:
            try:
                session.close()
            except Exception:
                pass

    logger.info(
        "recon: discovered %d endpoints and %d input vectors at security level %r",
        len(all_endpoints),
        len(all_vectors),
        requested_level,
    )

    return {
        "endpoints": all_endpoints,
        "input_vectors": all_vectors,
        "security_level": requested_level,
        "next_agent": "orchestrator",
    }


# ── Deduplication helpers ──────────────────────────────────────────────

def _deduplicate_endpoints(endpoints: list[dict]) -> list[dict]:
    """Deduplicate endpoint records by (url, method) and sort by url.

    Args:
        endpoints: List of endpoint dicts.

    Returns:
        Sorted, deduplicated list.
    """
    seen: dict[tuple[str, str], dict] = {}
    for ep in endpoints:
        key = (ep.get("url", ""), ep.get("method", "get"))
        if key not in seen:
            seen[key] = ep
    return sorted(seen.values(), key=lambda e: (e.get("url", ""), e.get("method", "get")))


def _deduplicate_vectors(vectors: list[dict]) -> list[dict]:
    """Deduplicate input vector records by (param_name, endpoint_url) and sort.

    Args:
        vectors: List of input vector dicts.

    Returns:
        Sorted, deduplicated list.
    """
    seen: dict[tuple[str, str], dict] = {}
    for vec in vectors:
        key = (vec.get("param_name", ""), vec.get("endpoint_url", ""))
        if key not in seen:
            seen[key] = vec
    return sorted(seen.values(), key=lambda v: (v.get("endpoint_url", ""), v.get("param_name", "")))
