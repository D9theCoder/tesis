"""Access Control Vertical Escalation agent."""

from __future__ import annotations

import logging
from typing import Any

from agents.state_utils import make_update, normalize_security_level
from core.state import ExploitationState
from foundation.payload_library import PayloadLibrary

logger = logging.getLogger(__name__)

AGENT_ID = "ac_vertical_escalation"
_PROBE_OBSERVATION_KEY = "role_based_access_present"
_CHAIN_OUTCOME = "sqli_union_chain_enabled"

_DEFAULT_PROBE = ["role=user", "role=admin"]
_DEFAULT_EXPLOIT = ["role=admin&action=elevate"]
_DEFAULT_BYPASS = {
    "medium": ["role=admin%00user"],
    "high": ["x-elevated-role: admin"],
}


def ac_vertical_escalation_agent(state: ExploitationState) -> dict[str, Any]:
    """Run PROBE -> EXPLOIT -> CHAIN CHECK for ac_vertical_escalation."""
    target_url = state.get("target_url", "")
    security_level = normalize_security_level(state.get("security_level"))

    attempted = list(state.get("attempted_agents", []))
    if AGENT_ID in attempted:
        logger.info("%s already attempted, skipping", AGENT_ID)
        return {
            "scores": {**state.get("scores", {}), AGENT_ID: state.get("scores", {}).get(AGENT_ID, 0)},
            "attempted_agents": attempted,
        }

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
    score = 0

    # PROBE stage
    for payload in probe_payloads:
        if payload in already_tried:
            continue
        temp_state.update(PayloadLibrary.record_tried(temp_state, AGENT_ID, payload))
        logger.info("[%s] PROBE payload: %s", AGENT_ID, payload)

    observations[_PROBE_OBSERVATION_KEY] = True
    score = max(score, 1)

    # EXPLOIT stage
    exploit_triggered = False
    for payload in all_exploit:
        if payload in already_tried:
            continue
        temp_state.update(PayloadLibrary.record_tried(temp_state, AGENT_ID, payload))
        logger.info("[%s] EXPLOIT payload: %s", AGENT_ID, payload)
        exploit_triggered = True
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

    update = make_update(
        state=state,
        module_name=AGENT_ID,
        score=score,
        tried_payloads=tried_now,
        confirmed_vulns=confirmed_vulns or None,
        achieved_outcomes=achieved_outcomes or None,
    )
    update["observations"] = observations
    return update
