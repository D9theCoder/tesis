"""Access Control Force Browse agent with real HTTP execution."""

from __future__ import annotations

import logging
from typing import Any

from agents.agent_telemetry import exploit_event, probe_event, score_event
from agents.state_utils import already_tried_payloads, candidate_payloads_for_stage, chain_check as _chain_check, make_update, normalize_security_level
from core.state import ExploitationState, MODULE_TO_KG_NODE
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier

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
}


def _signals_for_path(path: str) -> list[str]:
    for suffix, signals in _PATH_SIGNAL_MAP.items():
        if path.endswith(suffix):
            return signals
    return _EXPLOIT_SIGNALS


def _normalize_probe_path(path: str) -> str:
    """Keep legacy double-slash path candidates relative to DVWA."""
    value = str(path or "").strip()
    if value.startswith("//") and "://" not in value:
        return value.lstrip("/")
    return value


def _probe_preconditions(
    session: DVWASession, payloads: list[str], already_tried: set[str]
) -> tuple[bool, list[str], dict[str, bool], list[dict]]:
    """Supports probe preconditions behavior for this module."""
    observations: dict[str, bool] = {}
    tried: list[str] = []
    events: list[dict] = []
    verifier = Verifier()
    sent_any = False

    for path in payloads:
        path = _normalize_probe_path(path)
        if path in already_tried:
            continue
        sent_any = True
        tried.append(path)
        try:
            resp = session.get(path)
            events.append(probe_event(AGENT_ID, path, resp.status_code, True))
            if resp.status_code == 200:
                result = verifier.contains_any(resp.text, _ACCESSIBLE_SIGNALS)
                if result.ok:
                    observations[_PROBE_OBSERVATION_KEY] = True
                    return True, tried, observations, events
        except Exception as exc:
            logger.warning("[%s] PROBE request failed for %s: %s", AGENT_ID, path, exc)
            events.append(probe_event(AGENT_ID, path, None, False))

    if not sent_any:
        return False, tried, {}, events
    observations[_PROBE_OBSERVATION_KEY] = False
    return False, tried, observations, events


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

    for path in payloads:
        path = _normalize_probe_path(path)
        if path in already_tried:
            continue
        tried.append(path)
        try:
            resp = session.get(path)
            events.append(exploit_event(AGENT_ID, path, resp.status_code, True))
            if resp.status_code == 200:
                result = verifier.contains_any(resp.text, _signals_for_path(path))
                if result.ok:
                    score = max(score, 3)
                    confirmed.append(MODULE_TO_KG_NODE[AGENT_ID])
                    break
        except Exception as exc:
            logger.warning("[%s] EXPLOIT request failed for %s: %s", AGENT_ID, path, exc)
            events.append(exploit_event(AGENT_ID, path, None, False))

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
        session.close()
