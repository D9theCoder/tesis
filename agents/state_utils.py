"""Shared helpers for Stage 5 vulnerability and chain agents."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from foundation.http_client import RequestTimeoutError, TransportError


def normalize_security_level(level: str | None) -> str:
    normalized = (level or "low").strip().lower()
    return normalized if normalized in {"low", "medium", "high"} else "low"


def already_tried_payloads(state: dict[str, Any], module_name: str) -> set[str]:
    """Return payloads already attempted for a module as a set."""
    module_payloads = state.get("tried_payloads", {}).get(module_name, [])
    return {str(payload) for payload in module_payloads}


def append_error_marker(target: list[str], context: str, exc: Exception) -> None:
    """Append a deterministic error marker for observability in state output."""
    target.append(f"{context}:{type(exc).__name__}")


def prepare_agent_session(
    session: Any,
    security_level: str,
    *,
    require_login: bool = True,
) -> tuple[bool, list[str]]:
    """Prepare a DVWA session for exploit attempts.

    This helper is intentionally tolerant so existing tests with lightweight
    session fakes still work: if a fake session lacks login or security-level
    methods, the helper does not fail.
    """
    notes: list[str] = []

    login_ok = True
    if require_login:
        login_fn = getattr(session, "login", None)
        if callable(login_fn):
            try:
                login_ok = bool(login_fn())
                if not login_ok:
                    notes.append("session_login_failed")
            except (TypeError, ValueError, RuntimeError, OSError, TransportError, RequestTimeoutError) as exc:
                login_ok = False
                append_error_marker(notes, "session_login_error", exc)

    set_level_fn = getattr(session, "set_security_level", None)
    if callable(set_level_fn):
        try:
            set_level_fn(security_level)
        except (TypeError, ValueError) as exc:
            append_error_marker(notes, "security_level_invalid", exc)
        except (RuntimeError, OSError, TransportError, RequestTimeoutError) as exc:
            append_error_marker(notes, "security_level_set_error", exc)

    if require_login and not login_ok:
        return False, notes

    return True, notes


def merge_scores(state: dict[str, Any], module_name: str, new_score: int) -> dict[str, int]:
    scores = dict(state.get("scores", {}))
    scores[module_name] = max(int(scores.get(module_name, 0)), int(new_score))
    return scores


def merge_tried_payloads(
    state: dict[str, Any],
    module_name: str,
    payloads: list[str],
) -> dict[str, list[str]]:
    tried_payloads = dict(state.get("tried_payloads", {}))
    module_payloads = list(tried_payloads.get(module_name, []))
    for payload in payloads:
        if payload not in module_payloads:
            module_payloads.append(payload)
    tried_payloads[module_name] = module_payloads
    return tried_payloads


def module_endpoint(state: dict[str, Any], module_name: str, fallback_path: str) -> str:
    fallback_path_fragments = {
        "sqli": "/vulnerabilities/sqli/",
        "sqli_blind": "/vulnerabilities/sqli_blind/",
        "xss_r": "/vulnerabilities/xss_r/",
        "xss_s": "/vulnerabilities/xss_s/",
        "xss_d": "/vulnerabilities/xss_d/",
        "cmdi": "/vulnerabilities/exec/",
        "brute": "/vulnerabilities/brute/",
        "lfi": "/vulnerabilities/fi/",
        "upload": "/vulnerabilities/upload/",
        "csrf": "/vulnerabilities/csrf/",
        "weak_session": "/vulnerabilities/weak_id/",
        "idor": "/vulnerabilities/idor/",
        "sqli_union": "/vulnerabilities/sqli/",
        "sqli_error": "/vulnerabilities/sqli/",
        "sqli_boolean_blind": "/vulnerabilities/sqli_blind/",
        "sqli_time_blind": "/vulnerabilities/sqli_blind/",
        "ac_idor": "/vulnerabilities/authbypass/",
        "ac_vertical_escalation": "/vulnerabilities/authbypass/",
        "ac_force_browse": "/vulnerabilities/authbypass/",
        "bf_dictionary": "/vulnerabilities/brute/",
        "bf_spray": "/vulnerabilities/brute/",
    }

    endpoints = state.get("endpoints", [])
    expected_fragment = fallback_path_fragments.get(module_name, "")

    for endpoint in endpoints:
        if endpoint.get("module_name") != module_name:
            continue

        raw_url = str(endpoint.get("url", ""))
        parsed_path = urlparse(raw_url).path.lower()
        if expected_fragment and expected_fragment not in parsed_path:
            continue

        return str(endpoint.get("url") or fallback_path)

    for endpoint in endpoints:
        raw_url = str(endpoint.get("url", ""))
        parsed_path = urlparse(raw_url).path.lower()
        if expected_fragment and expected_fragment in parsed_path:
            return str(endpoint.get("url") or fallback_path)

    return fallback_path


def make_update(
    *,
    state: dict[str, Any],
    module_name: str,
    score: int,
    tried_payloads: list[str],
    confirmed_vulns: list[str] | None = None,
    achieved_outcomes: list[str] | None = None,
    found_credentials: list[dict[str, str]] | None = None,
    next_agent: str = "orchestrator",
    telemetry_events: list[dict] | None = None,
) -> dict[str, Any]:
    update: dict[str, Any] = {
        "scores": merge_scores(state, module_name, score),
        "tried_payloads": merge_tried_payloads(state, module_name, tried_payloads),
        "iteration_count": state.get("iteration_count", 0) + 1,
        "next_agent": next_agent,
    }

    # confirmed_vulns, achieved_outcomes, and found_credentials all use
    # Annotated[list, add] reducers. We must filter out items already
    # present in state to avoid permanent duplication across agent runs.
    if confirmed_vulns:
        existing_confirmed = set(state.get("confirmed_vulns", []))
        new_confirmed = [c for c in confirmed_vulns if c not in existing_confirmed]
        if new_confirmed:
            update["confirmed_vulns"] = new_confirmed
    if achieved_outcomes:
        existing_outcomes = set(state.get("achieved_outcomes", []))
        new_outcomes = [o for o in achieved_outcomes if o not in existing_outcomes]
        if new_outcomes:
            update["achieved_outcomes"] = new_outcomes
    if found_credentials:
        existing_creds = state.get("found_credentials", [])
        existing_creds_set = {
            (c.get("username"), c.get("password"))
            for c in existing_creds
            if isinstance(c, dict)
        }
        new_creds = [
            c for c in found_credentials
            if isinstance(c, dict) and (c.get("username"), c.get("password")) not in existing_creds_set
        ]
        if new_creds:
            update["found_credentials"] = new_creds

    # Track attempted agents for fallback diversification.
    # attempted_agents uses Annotated[list[str], add] reducer in LangGraph,
    # so we must return ONLY the new item, not the full accumulated list.
    attempted = list(state.get("attempted_agents", []))
    if module_name not in attempted:
        update["attempted_agents"] = [module_name]

    # Merge telemetry events from agents.
    # telemetry_events uses Annotated[list[dict], add] reducer,
    # so we must return ONLY the new events, not existing + new.
    if telemetry_events:
        update["telemetry_events"] = list(telemetry_events)

    return update
