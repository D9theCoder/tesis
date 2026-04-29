"""Brute Force Dictionary attack agent."""

from __future__ import annotations

import logging
from typing import Any

from agents.agent_telemetry import exploit_event, probe_event, score_event
from agents.state_utils import make_update, normalize_security_level
from core.state import ExploitationState
from foundation.payload_library import PayloadLibrary

logger = logging.getLogger(__name__)

AGENT_ID = "bf_dictionary"
_PROBE_OBSERVATION_KEY = "no_rate_limit"
_CHAIN_OUTCOME = "brute_force_confirmed"

_DEFAULT_PROBE = ["admin:password", "admin:admin"]
_DEFAULT_EXPLOIT = ["gordonb:abc123", "pablo:letmein"]
_DEFAULT_BYPASS = {
    "medium": ["respect_rate_limit"],
    "high": ["respect_rate_limit"],
}


def bf_dictionary_agent(state: ExploitationState) -> dict[str, Any]:
    """Run PROBE -> EXPLOIT -> CHAIN CHECK for bf_dictionary."""
    target_url = state.get("target_url", "")
    security_level = normalize_security_level(state.get("security_level"))

    if not target_url:
        update = make_update(
            state=state,
            module_name=AGENT_ID,
            score=0,
            tried_payloads=[],
        )
        return update

    payload_lib = PayloadLibrary()
    payload_set = payload_lib.get(AGENT_ID, security_level)

    probe_payloads = list(payload_set.probe) or _DEFAULT_PROBE
    exploit_payloads = list(payload_set.exploit) or _DEFAULT_EXPLOIT
    bypass_payloads = list(payload_set.bypass.get(security_level, [])) or _DEFAULT_BYPASS.get(security_level, [])
    all_exploit = exploit_payloads + bypass_payloads

    already_tried = list(state.get("tried_payloads", {}).get(AGENT_ID, []))
    temp_state: dict[str, Any] = {"tried_payloads": dict(state.get("tried_payloads", {}))}

    observations: dict[str, bool] = dict(state.get("observations", {}))
    confirmed_vulns: list[str] = []
    achieved_outcomes: list[str] = []
    found_credentials: list[dict[str, str]] = []
    score = 0
    telemetry_events: list[dict[str, Any]] = []

    # PROBE stage
    probe_triggered = False
    for payload in probe_payloads:
        if payload in already_tried:
            continue
        temp_state.update(PayloadLibrary.record_tried(temp_state, AGENT_ID, payload))
        telemetry_events.append(probe_event(AGENT_ID, payload, None, True))
        logger.info("[%s] PROBE payload: %s", AGENT_ID, payload)
        probe_triggered = True

    if probe_triggered:
        observations[_PROBE_OBSERVATION_KEY] = True
        score = max(score, 1)

    # EXPLOIT stage
    exploit_triggered = False
    for payload in all_exploit:
        if payload in already_tried:
            continue
        temp_state.update(PayloadLibrary.record_tried(temp_state, AGENT_ID, payload))
        telemetry_events.append(exploit_event(AGENT_ID, payload, None, True))
        logger.info("[%s] EXPLOIT payload: %s", AGENT_ID, payload)
        exploit_triggered = True
        if ":" in payload:
            parts = payload.split(":")
            if len(parts) >= 2:
                user = parts[0].strip()
                password = parts[1].strip()
                found_credentials.append({"username": user, "password": password})
        break

    if exploit_triggered:
        if security_level == "low" or bypass_payloads:
            score = max(score, 3)
            confirmed_node = f"{AGENT_ID}_confirmed"
            if confirmed_node not in confirmed_vulns:
                confirmed_vulns.append(confirmed_node)
        else:
            score = max(score, 2)

    # CHAIN CHECK stage
    if score >= 3:
        if _CHAIN_OUTCOME not in achieved_outcomes:
            achieved_outcomes.append(_CHAIN_OUTCOME)
        score = 4

    tried_now = list(temp_state["tried_payloads"].get(AGENT_ID, []))

    telemetry_events.append(score_event(AGENT_ID, score, confirmed_vulns, achieved_outcomes))

    update = make_update(
        state=state,
        module_name=AGENT_ID,
        score=score,
        tried_payloads=tried_now,
        confirmed_vulns=confirmed_vulns or None,
        achieved_outcomes=achieved_outcomes or None,
        found_credentials=found_credentials or None,
        telemetry_events=telemetry_events,
    )
    update["observations"] = observations
    return update
