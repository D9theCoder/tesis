"""Access Control Force Browse agent with real HTTP execution."""

from __future__ import annotations

import logging
from typing import Any

from agents.agent_telemetry import exploit_event, probe_event, score_event
from foundation.http_client import http_accounted
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
from agents.state_utils import normalize_force_browse_path as _normalize_probe_path
from foundation.control_catalog import quarantine_update
from core.state import ExploitationState, MODULE_TO_KG_NODE
from foundation.session_manager import DVWASession, session_fingerprint
from foundation.verifier import Verifier
from agents.access_control.session import open_access_control_session, permission_evidence_fields

logger = logging.getLogger(__name__)

AGENT_ID = "ac_force_browse"
_PROBE_OBSERVATION_KEY = "force_browse_endpoints_visible"

# Signals specific to protected pages being accessible
_ACCESSIBLE_SIGNALS = [
    "database setup",
    "create/reset database",
    "phpinfo()",
    "view source",
    "vulnerability: ",
    "source code",
    "this page should only be accessible by the admin user",
]

_EXPLOIT_SIGNALS = [
    "database setup",
    "create/reset database",
    "phpinfo()",
    "view source",
    "source code",
]

_PATH_SIGNAL_MAP = {
    "setup.php": ["database setup", "create/reset database"],
    "phpinfo.php": ["phpinfo()"],
    "view_source.php": ["view source", "source code"],
    "security.php": ["security level", "setup"],
    "authbypass/": ["this page should only be accessible by the admin user"],
}


def _signals_for_path(path: str) -> list[str]:
    for suffix, signals in _PATH_SIGNAL_MAP.items():
        if path.endswith(suffix):
            return signals
    return _EXPLOIT_SIGNALS


@http_accounted(role="detection_control", method=AGENT_ID)
def _probe_preconditions(
    session: DVWASession, payloads: list[str], already_tried: set[str]
) -> tuple[bool, list[str], dict[str, bool], list[dict]]:
    """Supports probe preconditions behavior for this module."""
    observations: dict[str, bool] = {}
    tried: list[str] = []
    events: list[dict] = []
    verifier = Verifier()
    sent_any = False

    already_tried = {_normalize_probe_path(value) for value in already_tried}
    for payload in payloads:
        candidate_id = getattr(payload, "candidate_id", None)
        path = _normalize_probe_path(payload)
        if path in already_tried:
            continue
        sent_any = True
        tried.append(payload)
        already_tried.add(path)
        try:
            resp = session.get(path)
            events.append(probe_event(AGENT_ID, path, resp.status_code, False,
                endpoint=path, response=resp,
                control_id=getattr(payload, "control_id", None)))
            events[-1]["payload"].update(permission_evidence_fields(session, session._principal_id,
                session._initial_session_fingerprint, object_id=f"dvwa-path:/{path.lstrip('/')}"))
            if resp.status_code == 200:
                result = verifier.contains_any(resp.text, _ACCESSIBLE_SIGNALS)
                if result.ok:
                    events[-1]["payload"].update(signal_detected=True, verified_grade=1, verification_reason="verified_probe_precondition")
                    observations[_PROBE_OBSERVATION_KEY] = True
                    return True, tried, observations, events
        except Exception as exc:
            logger.warning("[%s] PROBE request failed for %s: %s", AGENT_ID, path, exc)
            events.append(probe_event(AGENT_ID, path, None, False,
                endpoint=path, control_id=getattr(payload, "control_id", None)))

    if not sent_any:
        return False, tried, {}, events
    observations[_PROBE_OBSERVATION_KEY] = False
    return False, tried, observations, events


@http_accounted(phase="method", role="candidate", method=AGENT_ID)
def _attempt_exploit(
    session: DVWASession, payloads: list[str], already_tried: set[str]
) -> tuple[int, list[str], list[str], list[dict]]:
    """Confirm unauthorized access to protected pages.

    NOTE: This agent tests whether protected pages (setup.php, phpinfo.php)
    are accessible without admin authentication. A complete implementation
    would also verify that the session is authenticated as a low-priv user
    and that the target page returns 403 for unauthenticated requests.
    """
    tried: list[str] = []
    events: list[dict] = []
    confirmed: list[str] = []
    score = 0
    verifier = Verifier()

    already_tried = {_normalize_probe_path(value) for value in already_tried}
    for payload in payloads:
        candidate_id = getattr(payload, "candidate_id", None)
        path = _normalize_probe_path(payload)
        if path in already_tried:
            continue
        tried.append(payload)
        already_tried.add(path)
        try:
            resp = session.get(path)
            result = verifier.contains_any(resp.text, _signals_for_path(path)) if resp.status_code == 200 else None
            visible = bool(result and result.ok)
            events.append(exploit_event(AGENT_ID, path, resp.status_code, visible,
                endpoint=path, response=resp, candidate_id=candidate_id))
            events[-1]["payload"].update(permission_evidence_fields(session, session._principal_id,
                session._initial_session_fingerprint, object_id=f"dvwa-path:/{path.lstrip('/')}",
                consumed_source_evidence_id=getattr(session, "_consumed_source_evidence_id", None)))
            if visible:
                permission_page = path.rstrip("/").endswith("authbypass")
                events[-1]["payload"].update(signal_detected=True,
                    verified_grade=3 if permission_page else 2,
                    verification_reason="verified_permission_candidate" if permission_page
                        else "visibility_without_permission_oracle")
                if permission_page:
                    score = max(score, 3)
                    confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                    break
        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed for %s: %s", AGENT_ID, path, exc)
            events.append(exploit_event(AGENT_ID, path, None, False,
                endpoint=path, candidate_id=candidate_id))

    return score, tried, confirmed, events

def ac_force_browse_agent(state: ExploitationState) -> dict[str, Any]:
    """Execute the force-browsing static method agent.

    Reads validated path candidates, discovered endpoints, target/session
    configuration, observations, and tried payload memory. The agent probes for
    visible restricted endpoints, attempts direct path access over HTTP,
    confirms `ac_force_browse_confirmed` when restricted content is reachable,
    and applies shared chain scoring after confirmation.

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

    session = None
    try:
        session, principal, initial_fingerprint, consumed_source_evidence_id = open_access_control_session(
            state, AGENT_ID, security_level)
        session._principal_id = principal
        session._initial_session_fingerprint = initial_fingerprint
        session._consumed_source_evidence_id = consumed_source_evidence_id

        confirmed_vulns: list[str] = []
        achieved_outcomes: list[str] = []
        score = 0
        telemetry_events: list[dict[str, Any]] = []
        all_tried: list[str] = []
        observations: dict[str, bool] = {}

        # Stage 1: PROBE (safe policy-notice control; never a restricted page)
        probe_payloads = candidate_payloads_for_stage(state, AGENT_ID, security_level, "probe")
        principal_id = getattr(session, "_principal_id", None) or getattr(session, "_username", None)
        probe_payloads = resolve_stage_control_payloads(state, AGENT_ID, probe_payloads, principal_id)
        if graph_visit(state, AGENT_ID) and not probe_payloads:
            return probe_stage_blocked_update(state, AGENT_ID)
        probe_ok, tried, probe_obs, probe_events = _probe_preconditions(
            session, probe_payloads, set()
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

        # Stage 2: EXPLOIT. A candidate equal to an earlier probe is executed
        # only through its own visit-bound request, never inferred from the probe.
        all_exploit = candidate_payloads_for_stage(state, AGENT_ID, security_level, "exploit")
        exploit_done = previously_executed_exploit_payloads(
            state, AGENT_ID, state.get("selected_visit_id"))

        exploit_score, tried, confirmed, exploit_events = _attempt_exploit(
            session, all_exploit, exploit_done
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
        if session is not None:
            session.close()
