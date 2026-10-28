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
from foundation.http_client import ContainmentError, TransportError, RequestTimeoutError, request_scope
from foundation.session_manager import DVWASession, session_fingerprint

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
    "authbypass": "idor",
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


def _same_host(url: str, base_url: str) -> bool:
    """Return whether *url* stays on the configured DVWA host and port."""
    parsed = urlparse(url)
    base = urlparse(base_url)
    return (
        parsed.scheme in {"http", "https"}
        and base.scheme in {"http", "https"}
        and (parsed.hostname or "").lower() == (base.hostname or "").lower()
        and parsed.port == base.port
    )


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

def _recon_containment_event(
    blocked_url: str,
    base_url: str,
    *,
    kind: str,
    reason: str,
) -> dict[str, str | None]:
    """Build a bounded event for a recon target discarded before HTTP."""
    return {
        "kind": kind,
        "classification": "discarded_navigation" if kind == "navigation" else "discarded_page_reference",
        "origin": "recon",
        "scope": "run",
        "blocked_url": blocked_url,
        "allowed_host": (urlparse(base_url).netloc or None),
        "reason": reason,
    }


def _append_containment_event(
    events: list[dict],
    event_or_error: dict | ContainmentError,
) -> None:
    """Append one containment event without duplicating client-side records."""
    event = (
        event_or_error.as_event()
        if isinstance(event_or_error, ContainmentError)
        else dict(event_or_error)
    )
    if event not in events:
        events.append(event)


def _collect_client_containment_events(session: DVWASession | None, events: list[dict]) -> None:
    """Copy HTTP-client containment records into the recon state update."""
    client = getattr(session, "http", None) if session is not None else None
    client_events = getattr(client, "containment_events", ())
    if isinstance(client_events, (list, tuple)):
        for event in client_events:
            if isinstance(event, dict):
                _append_containment_event(events, event)


def probe_brute_force_destination(state: dict) -> dict:
    """Measure missing chain prerequisites once, using only benign controls.

    The router calls this inside the serialized DVWA HTTP gate after proving
    consumable source material. This is reconnaissance, not a method visit.
    """
    method = "bf_dictionary"
    if any(event.get("event") == "recon.destination.completed"
           and event.get("payload", {}).get("method") == method
           for event in state.get("telemetry_events", [])):
        return {}
    update: dict[str, Any] = {}
    containment_events: list[dict] = []
    session = None
    reason = "missing_target_url"
    try:
        if state.get("target_url"):
            session = DVWASession(state["target_url"])
            reason = "session_login_failed"
            if session.login():
                level = state.get("security_level", "low")
                session.set_security_level(level)
                measured, quarantine = _probe_with_catalog_controls(
                    state, method, session, level,
                    principal_id=getattr(session, "_username", None),
                    phase="destination_rate_probe",
                    snapshot_key="destination_rate_probe:bf_dictionary")
                _merge_control_update(update, measured)
                if quarantine:
                    from foundation.control_catalog import quarantine_update
                    _merge_control_update(update, quarantine_update(
                        state, method=method, visit_id=None,
                        control_id="bf_dictionary:destination:control",
                        control_class="detection", reason=quarantine,
                        detail="destination rate control exceeded its evidence role"))
                status = (update.get("precondition_status") or {}).get("no_rate_limit")
                reason = ("preconditions_measured" if status in {"true", "false"}
                          else "probe_evidence_unavailable")
    except ContainmentError as exc:
        _append_containment_event(containment_events, exc)
        reason = "containment_violation"
    except (TransportError, RequestTimeoutError, ValueError, RuntimeError, OSError) as exc:
        logger.warning("destination recon failed: %s", exc)
        reason = "destination_probe_failed"
    finally:
        if session is not None:
            try:
                session.close()
            except (RuntimeError, OSError) as exc:
                logger.warning("destination recon session close failed: %s", exc)
            _collect_client_containment_events(session, containment_events)
    completed = {"node": "chaining_router", "event": "recon.destination.completed",
        "payload": {"method": method, "reason": reason,
                    "observations": update.get("observations", {})}}
    update["telemetry_events"] = [*update.get("telemetry_events", []), completed]
    update["containment_events"] = [*update.get("containment_events", []), *containment_events]
    update.setdefault("observations", {})
    return update


def probe_access_control_destination(state: dict, method: str, source_ids: list[str]) -> dict:
    """Measure an AC prerequisite once per recovered source, in its own session."""
    if method not in {"ac_idor", "ac_force_browse"} or not source_ids:
        return {}
    if any(event.get("event") == "recon.destination.completed"
           and event.get("payload", {}).get("method") == method
           and event.get("payload", {}).get("source_evidence_ids") == source_ids
           for event in state.get("telemetry_events", [])):
        return {}
    from agents.access_control.session import open_access_control_session

    update: dict[str, Any] = {}
    containment_events: list[dict] = []
    session = None
    reason = "probe_evidence_unavailable"
    try:
        level = state.get("security_level", "low")
        probe_state = {**state, "active_chain_route": {"source": "authenticated_session",
            "target_agent": method, "source_evidence_ids": source_ids}}
        session, principal, initial, _ = open_access_control_session(probe_state, method, level)
        session._principal_id, session._initial_session_fingerprint = principal, initial
        measured, quarantine = _probe_with_catalog_controls(
            state, method, session, level, principal_id=principal,
            phase="destination_probe", snapshot_key=f"destination_probe:{method}")
        _merge_control_update(update, measured)
        if quarantine:
            from foundation.control_catalog import quarantine_update
            _merge_control_update(update, quarantine_update(
                state, method=method, visit_id=None,
                control_id=f"{method}:destination:control", control_class="detection",
                reason=quarantine, detail="destination control exceeded its evidence role",
                snapshot=update.get("probe_controls", {}).get(f"destination_probe:{method}")))
        if update.get("control_events"):
            reason = "preconditions_measured"
    except ContainmentError as exc:
        _append_containment_event(containment_events, exc)
        reason = "containment_violation"
    except (TransportError, RequestTimeoutError, ValueError, RuntimeError, OSError) as exc:
        logger.warning("destination recon failed: %s", type(exc).__name__)
        reason = "destination_probe_failed"
    finally:
        if session is not None:
            try:
                session.close()
            except (RuntimeError, OSError) as exc:
                logger.warning("destination recon session close failed: %s", type(exc).__name__)
            finally:
                _collect_client_containment_events(session, containment_events)
    completed = {"node": "chaining_router", "event": "recon.destination.completed",
        "payload": {"method": method, "source_evidence_ids": source_ids,
            "reason": reason, "observations": update.get("observations", {})}}
    update["telemetry_events"] = [*update.get("telemetry_events", []), completed]
    update["containment_events"] = [*update.get("containment_events", []), *containment_events]
    update.setdefault("observations", {})
    return update


def _merge_control_update(destination: dict, source: dict) -> None:
    """Merge one control measurement update without losing append-only rows."""
    for key, value in source.items():
        if key in {"observation_facts", "control_events", "quarantined_visits", "telemetry_events",
                   "containment_events"}:
            destination.setdefault(key, []).extend(value or [])
        elif key in {"probe_controls", "method_principals", "method_session_fingerprints"}:
            destination.setdefault(key, {}).update(value or {})
        elif key == "precondition_status":
            destination[key] = {**destination.get(key, {}), **(value or {})}
        elif key == "observations":
            destination[key] = {**destination.get(key, {}), **(value or {})}
        elif key not in destination:
            destination[key] = value


def _invoke_method_probe(method: str, session: Any, payloads: list[str], level: str
                         ) -> tuple[dict[str, bool], list[dict]]:
    """Run the canonical method probe helper with catalog-controlled payloads."""
    import importlib

    if method.startswith("sqli_"):
        module = importlib.import_module(f"agents.sqli.{method}_agent")
        result = module._probe_preconditions(session, payloads, set(), level)
        return (result[2], result[3]) if len(result) == 4 else (result[2], result[3])
    if method.startswith("bf_"):
        module = importlib.import_module(f"agents.brute_force.{method}_agent")
        token_fn = getattr(module, "_module_user_token", None)
        token = token_fn(session) if level == "high" and callable(token_fn) else None
        _, _, observations, events = module._probe_preconditions(
            session, payloads, set(), cached_precondition=None,
            user_token=token, security_level=level)
        return observations, events
    module = importlib.import_module(f"agents.access_control.{method}_agent")
    _, _, observations, events = module._probe_preconditions(session, payloads, set())
    return observations, events


def _probe_with_catalog_controls(
    state: dict,
    method: str,
    session: Any,
    level: str,
    *,
    principal_id: str | None,
    phase: str,
    snapshot_key: str,
) -> tuple[dict, str | None]:
    """Freeze, validate, resolve, execute, and record one control measurement."""
    from agents.state_utils import ControlPayload, probe_outcome_update
    from foundation.control_catalog import (
        freeze_detection_controls,
        resolve_catalog_controls,
        validate_detection_controls,
    )

    visit_id = f"{method}:{phase}:{state.get('execution_id') or state.get('run_id') or 'recon'}"
    snapshot = freeze_detection_controls(state, method, visit_id, phase=phase)
    if not snapshot.get("candidates"):
        return {}, None
    issues = validate_detection_controls(state, method, snapshot)
    if issues and any(issue.get("valid") is not True for issue in issues):
        return {}, None
    resolved, _skipped = resolve_catalog_controls(snapshot, principal_id)
    payloads: list[str] = [
        ControlPayload(str(row["resolved_payload"]), str(row["control_id"]))
        for row in resolved
    ]
    if not payloads:
        return {}, None
    endpoint_fragment = {"ac_idor": "/vulnerabilities/authbypass/get_user_data.php",
                         "ac_vertical_escalation": "/vulnerabilities/authbypass/get_user_data.php",
                         "ac_force_browse": "/vulnerabilities/authbypass/",
                         "bf_dictionary": "/vulnerabilities/brute/",
                         "bf_spray": "/vulnerabilities/brute/"}.get(method, "/vulnerabilities/sqli/")
    if hasattr(session, "_principal_id") or str(phase).startswith(("method_probe", "destination", "recon")):
        try:
            session._principal_id = principal_id
            session._initial_session_fingerprint = None
            session._consumed_source_evidence_id = None
        except (AttributeError, TypeError):
            pass
    with request_scope(role="detection_control", method=method):
        observations, events = _invoke_method_probe(method, session, payloads, level)
    from foundation.session_manager import session_fingerprint
    update, quarantine = probe_outcome_update(
        state, method, observations, events, principal_id=principal_id,
        session_fingerprint=session_fingerprint(session),
        snapshot=snapshot, snapshot_key=snapshot_key)
    update["telemetry_events"] = [
        {**event, "node": "recon", "event": "recon.control.probe",
         "payload": {**event.get("payload", {}), "method": method, "phase": phase}}
        for event in events if isinstance(event, dict)]
    return update, quarantine


def _measure_recon_surface_controls(
    state: dict,
    session: Any,
    level: str,
    surface: str,
    principal_id: str | None,
) -> dict:
    """Measure every surface method's declared precondition with safe controls."""
    from core.state import METHODS_BY_SURFACE

    updates: dict[str, Any] = {}
    ac_session = None
    ac_principal = None
    methods = [
        method for method in METHODS_BY_SURFACE.get(surface, [])
        if not state.get("target_method") or method == state["target_method"]
    ]
    try:
        for method in methods:
            active_session = session
            active_principal = principal_id
            if surface == "access_control":
                if ac_session is None:
                    from foundation.session_manager import open_documented_nonadmin_session
                    try:
                        ac_session, ac_principal, _initial = open_documented_nonadmin_session(
                            str(state.get("target_url") or ""), level)
                    except (ValueError, RuntimeError, TransportError, RequestTimeoutError):
                        continue
                active_session, active_principal = ac_session, ac_principal
            update, quarantine = _probe_with_catalog_controls(
                state, method, active_session, level, principal_id=active_principal,
                phase="method_probe", snapshot_key=f"recon:method_probe:{method}")
            if active_principal:
                updates.setdefault("method_principals", {})[method] = str(active_principal)
            _merge_control_update(updates, update)
            if quarantine:
                from foundation.control_catalog import quarantine_update
                _merge_control_update(updates, quarantine_update(
                    state, method=method, visit_id=None,
                    control_id=f"{method}:recon:control", control_class="detection",
                    reason=quarantine, detail="recon surface control exceeded its evidence role",
                    snapshot=update.get("probe_controls", {}).get(f"recon:method_probe:{method}")))
    finally:
        if ac_session is not None:
            try:
                ac_session.close()
            except (RuntimeError, OSError):
                pass
    return updates


def _measure_recon_force_browse(
    state: dict,
    session: Any,
    level: str,
    principal_id: str | None,
) -> dict:
    """Forced-target runs only need the bounded force-browse surface control."""
    update, quarantine = _probe_with_catalog_controls(
        state, "ac_force_browse", session, level, principal_id=principal_id,
        phase="method_probe", snapshot_key="recon:method_probe:ac_force_browse")
    if quarantine:
        from foundation.control_catalog import quarantine_update
        _merge_control_update(update, quarantine_update(
            state, method="ac_force_browse", visit_id=None,
            control_id="ac_force_browse:recon:control", control_class="detection",
            reason=quarantine, detail="recon surface control exceeded its evidence role",
            snapshot=update.get("probe_controls", {}).get("recon:method_probe:ac_force_browse")))
    return update


def parse_forms(
    html: str,
    page_url: str,
    *,
    containment_events: list[dict] | None = None,
) -> tuple[list[dict], list[dict]]:
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
        if not _same_host(endpoint_url, page_url):
            logger.warning("recon: discarded out-of-scope form action %s", endpoint_url)
            if containment_events is not None:
                containment_events.append(
                    _recon_containment_event(
                        endpoint_url,
                        page_url,
                        kind="form",
                        reason="form action outside allowed DVWA scope",
                    )
                )
            continue

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


_SQLI_SESSION_INPUT_FILENAME = "session-input.php"


def _discover_sqli_session_input(
    session: DVWASession,
    page_url: str,
    page_body: str,
    *,
    containment_events: list[dict] | None = None,
) -> dict | None:
    """Discover DVWA's high-security SQLi session-input endpoint.

    DVWA exposes the high-security SQLi handler from JavaScript/pop-up markup
    on the regular SQLi page rather than as the page's form action.  The
    marker is therefore treated as the deterministic discovery signal.  A
    same-host GET health check is made before returning the normalized POST
    endpoint used by the method agents.

    The health check is best effort: a transport failure does not erase an
    endpoint discovered from the authenticated, contained SQLi page.  A
    containment failure does prevent registration and is recorded through the
    existing recon containment-event path.
    """
    if _SQLI_SESSION_INPUT_FILENAME not in str(page_body).casefold():
        return None

    base_url = str(getattr(getattr(session, "http", None), "base_url", ""))
    endpoint_url = urljoin(
        f"{base_url.rstrip('/')}/",
        f"vulnerabilities/sqli/{_SQLI_SESSION_INPUT_FILENAME}",
    )

    # The endpoint is derived from the discovered page, but still validate it
    # explicitly before the client sees it so recon preserves its own
    # containment boundary as well as the HTTP client's boundary.
    if not _same_host(endpoint_url, base_url):
        logger.warning("recon: discarded out-of-scope SQLi session-input endpoint %s", endpoint_url)
        if containment_events is not None:
            containment_events.append(
                _recon_containment_event(
                    endpoint_url,
                    base_url,
                    kind="endpoint",
                    reason="SQLi session-input endpoint outside allowed DVWA scope",
                )
            )
        return None

    try:
        health_result = session.http.get(endpoint_url)
        logger.debug(
            "recon: discovered SQLi session-input endpoint %s from %s (health status %s)",
            endpoint_url,
            page_url,
            getattr(health_result, "status_code", "unknown"),
        )
    except ContainmentError as exc:
        if containment_events is not None:
            _append_containment_event(containment_events, exc)
        logger.warning("recon: SQLi session-input health check violated containment: %s", exc)
        return None
    except (TransportError, RequestTimeoutError, RuntimeError) as exc:
        logger.warning("recon: SQLi session-input health check failed: %s", exc)

    return EndpointRecord(
        url=endpoint_url,
        method="post",
        params=["id"],
        module_name="sqli",
    )


# ── Navigation link extraction ──────────────────────────────────────────

def extract_nav_links(
    html: str,
    base_url: str,
    *,
    containment_events: list[dict] | None = None,
) -> list[str]:
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
        href = str(a_tag.get("href", ""))
        # DVWA's sidebar uses relative paths such as ``vulnerabilities/sqli/``.
        # Resolve first so both relative and absolute links are classified by
        # their normalized path, while containment still applies to the result.
        absolute = urljoin(base_url, href)
        if not _same_host(absolute, base_url):
            logger.warning("recon: discarded out-of-scope navigation link %s", absolute)
            if containment_events is not None:
                containment_events.append(
                    _recon_containment_event(
                        absolute,
                        base_url,
                        kind="navigation",
                        reason="navigation link outside allowed DVWA scope",
                    )
                )
            continue
        if "/vulnerabilities/" not in urlparse(absolute).path.lower():
            continue

        # Strip query parameters and fragment identifiers to avoid GET side-effects
        absolute = absolute.split("?")[0].split("#")[0]
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
    """Execute the reconnaissance stage of the LangGraph workflow.

    Reads:
        Target URL and requested DVWA security level.

    Writes:
        Discovered endpoints, input vectors, observations, security level,
        server fingerprint data, telemetry events, and `next_agent`.

    Routing:
        Returns `next_agent="orchestrator"` so method selection runs next.

    Side Effects:
        Authenticates to DVWA, sets security level, crawls module pages, and
        parses forms and inputs through HTTP requests.

    Failure:
        Returns empty discovery lists and routes to orchestrator when target URL
        is missing or reconnaissance cannot complete.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update dict compatible with LangGraph reducers.
    """
    target_url = state.get("target_url", "")
    requested_level = state.get("security_level", "low")

    if not target_url:
        logger.error("recon: target_url is empty — cannot proceed")
        from foundation.readiness import build_readiness
        return {
            "endpoints": [],
            "input_vectors": [],
            "security_level": requested_level,
            "next_agent": "orchestrator",
            "readiness": build_readiness(
                state=state, login_ok=None, requested_level=requested_level,
                observed_level=None, endpoints=[], requested_principal=None,
                observed_principal=None, token_present=None,
                setup_state="target_url_missing", crawl_ok=False),
        }

    all_endpoints: list[dict] = []
    all_vectors: list[dict] = []
    containment_events: list[dict] = []
    server_fingerprint: dict[str, str] = {}

    session: DVWASession | None = None
    login_success = False
    login_attempted = False
    observed_level: str | None = None
    observed_principal: str | None = None
    observed_session_fingerprint: str | None = None
    principal = ""
    surface = str(state.get("current_surface") or "sqli")
    crawl_ok = True
    token_present: bool | None = None
    low_priv_session_available = False
    rate_probe_observations: dict[str, bool] = {}
    rate_probe_events: list[dict] = []
    control_updates: dict[str, Any] = {}
    surface_probe_observations: dict[str, bool] = {}

    try:
        # Step 1: Create session and login
        session = DVWASession(target_url)
        login_attempted = True
        try:
            login_success = bool(session.login())
            observed_session_fingerprint = session_fingerprint(session)
            if not login_success:
                logger.warning("recon: login failed — readiness will block selection")
        except ContainmentError as exc:
            _append_containment_event(containment_events, exc)
            logger.error("recon: login request violated containment: %s", exc)
        except (TransportError, RequestTimeoutError) as exc:
            logger.error("recon: login request failed: %s", exc)

        # Step 2: Set and verify the requested security level server-side.
        try:
            session.set_security_level(requested_level)
        except ContainmentError as exc:
            _append_containment_event(containment_events, exc)
            logger.error("recon: security-level request violated containment: %s", exc)
        except ValueError:
            logger.warning("recon: invalid requested security level %r", requested_level)
        observed_level = session.observed_security_level()

        # Step 3: Crawl DVWA navigation to find module pages
        # Also fingerprint server from response headers (AGENTS.md step 1d)
        try:
            index_result = session.http.get("index.php")
            nav_links = extract_nav_links(
                index_result.text,
                session.http.base_url,
                containment_events=containment_events,
            )
            from foundation.session_manager import _dvwa_identity
            observed_principal = _dvwa_identity(index_result.text)
            # Step 1d: fingerprint server technology from headers
            server_fingerprint = fingerprint_server(dict(index_result.headers))
            if server_fingerprint:
                logger.info("recon: server fingerprint: %s", server_fingerprint)
        except ContainmentError as exc:
            _append_containment_event(containment_events, exc)
            logger.error("recon: index-page request violated containment: %s", exc)
            nav_links = []
            crawl_ok = False
        except (TransportError, RequestTimeoutError) as exc:
            logger.error("recon: failed to fetch index page: %s", exc)
            nav_links = []
            crawl_ok = False

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
                normalized_page_url = module_url.split("?", 1)[0].split("#", 1)[0]
                page_endpoints, page_vectors = parse_forms(
                    result.text,
                    module_url,
                    containment_events=containment_events,
                )
                all_endpoints.extend(page_endpoints)
                all_vectors.extend(page_vectors)

                # High-security SQLi keeps the executable handler behind a
                # JavaScript/pop-up reference.  Discover that contained POST
                # endpoint from the already fetched page; low and medium use
                # the existing form-derived endpoint set unchanged.
                if requested_level == "high" and infer_module_name(normalized_page_url) == "sqli":
                    session_input_endpoint = _discover_sqli_session_input(
                        session,
                        normalized_page_url,
                        result.text,
                        containment_events=containment_events,
                    )
                    if session_input_endpoint is not None:
                        all_endpoints.append(session_input_endpoint)
            except ContainmentError as exc:
                _append_containment_event(containment_events, exc)
                logger.warning("recon: request for %s violated containment: %s", module_url, exc)
                crawl_ok = False
            except (TransportError, RequestTimeoutError) as exc:
                logger.warning("recon: failed to fetch %s: %s", module_url, exc)
                crawl_ok = False

        # Step 5: Deduplicate and sort for deterministic output
        all_endpoints = _deduplicate_endpoints(all_endpoints)
        all_vectors = _deduplicate_vectors(all_vectors)

        # Step 6: Measure preconditions with bounded catalog controls before
        # releasing the socket. Endpoint discovery alone never proves a signal.
        principal = getattr(session, "_username", "")
        low_priv_session_available = bool(
            getattr(session, "is_logged_in", False)
            and isinstance(principal, str) and principal and principal != "admin"
        )
        surface = str(state.get("current_surface") or "sqli")
        if surface == "brute_force" and any(
            endpoint.get("module_name") == "brute" for endpoint in all_endpoints
        ):
            try:
                brute_page = session.get("/vulnerabilities/brute/")
                extractor = getattr(session, "_extract_user_token", None)
                token = extractor(brute_page.text) if callable(extractor) else None
                token_present = bool(token)
            except (ContainmentError, TransportError, RequestTimeoutError, RuntimeError):
                token_present = None
        control_updates = _measure_recon_surface_controls(
            state, session, requested_level, surface, observed_principal or principal)

    except ContainmentError as exc:
        _append_containment_event(containment_events, exc)
        logger.error("recon: unexpected containment violation during crawl: %s", exc)
        crawl_ok = False
    except (TransportError, RequestTimeoutError, ValueError, RuntimeError) as exc:
        logger.error("recon: unexpected error during crawl: %s", exc)
        crawl_ok = False

    finally:
        # Ensure session is closed if it was created
        if session is not None:
            try:
                session.close()
            except (RuntimeError, OSError) as exc:
                logger.warning("recon: failed to close session cleanly: %s", exc)
            _collect_client_containment_events(session, containment_events)

    logger.info(
        "recon: discovered %d endpoints and %d input vectors at security level %r",
        len(all_endpoints),
        len(all_vectors),
        requested_level,
    )

    from foundation.control_catalog import CONTROL_POLICY_VERSION
    from foundation.preconditions import (
        derive_precondition_status,
        make_observation_fact,
        observation_update,
    )
    from foundation.readiness import build_readiness

    readiness = build_readiness(
        state={**dict(state), "current_surface": surface},
        login_ok=login_success if login_attempted else None,
        requested_level=requested_level,
        observed_level=observed_level,
        endpoints=all_endpoints,
        requested_principal=principal if isinstance(principal, str) and principal else None,
        observed_principal=observed_principal,
        token_present=token_present,
        setup_state="authenticated_crawl" if login_success else "unauthenticated_crawl",
        fixture_restoration_evidence=state.get("fixture_restoration_evidence"),
        measured_session_fingerprint=observed_session_fingerprint,
        crawl_ok=crawl_ok,
    )
    new_facts = [dict(fact) for fact in control_updates.get("observation_facts", [])
                 if isinstance(fact, dict)]
    for key, value in (("authenticated_crawl", login_success),
                       ("low_priv_session_available", low_priv_session_available)):
        new_facts.append(make_observation_fact(
            key, bool(value), source="recon_session", phase="recon",
            fixture_id=state.get("fixture_id"), protocol_version=state.get("protocol_version"),
            security_level=requested_level, principal_id=observed_principal,
            session_fingerprint=observed_session_fingerprint,
            session_scope="session",
            detail="observed during the authenticated reconnaissance crawl"))
    fact_bearing_state = {
        **dict(state),
        "security_level": requested_level,
        "readiness": readiness,
        "method_principals": {
            **dict(state.get("method_principals", {}) or {}),
            **dict(control_updates.get("method_principals", {}) or {}),
        },
        "method_session_fingerprints": {
            **dict(state.get("method_session_fingerprints", {}) or {}),
            **dict(control_updates.get("method_session_fingerprints", {}) or {}),
        },
    }
    facts_update = observation_update(fact_bearing_state, new_facts)
    derived_status = derive_precondition_status(
        {**fact_bearing_state, "observation_facts": [
            *list(state.get("observation_facts", []) or []), *new_facts]})
    telemetry_events = list(control_updates.get("telemetry_events", []))
    return {
        "endpoints": all_endpoints,
        "input_vectors": all_vectors,
        "security_level": requested_level,
        "next_agent": "orchestrator",
        "observations": facts_update["observations"],
        "observation_facts": new_facts,
        "precondition_status": derived_status,
        "readiness": readiness,
        "method_principals": dict(control_updates.get("method_principals", {})),
        "method_session_fingerprints": dict(control_updates.get("method_session_fingerprints", {})),
        "control_policy_version": CONTROL_POLICY_VERSION,
        "control_events": list(control_updates.get("control_events", [])),
        "probe_controls": dict(control_updates.get("probe_controls", {})),
        "quarantined_visits": list(control_updates.get("quarantined_visits", [])),
        "containment_events": containment_events,
        "telemetry_events": telemetry_events,
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
