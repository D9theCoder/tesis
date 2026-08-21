"""Shared helpers for Stage 5 vulnerability and chain agents."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from foundation.http_client import RequestTimeoutError, TransportError
from foundation.payload_library import PayloadLibrary

# Single source of truth: agent_id → DVWA endpoint path fragment.
# Keep in sync with ALL_METHOD_AGENTS and foundation/payload_library endpoints.
_MODULE_ENDPOINT_FRAGMENTS: dict[str, str] = {
    "sqli_union": "/vulnerabilities/sqli/",
    "sqli_error": "/vulnerabilities/sqli/",
    "sqli_boolean_blind": "/vulnerabilities/sqli_blind/",
    "sqli_time_blind": "/vulnerabilities/sqli_blind/",
    "ac_idor": "/vulnerabilities/authbypass/",
    "ac_vertical_escalation": "/vulnerabilities/authbypass/",
    "ac_force_browse": "/vulnerabilities/authbypass/",
    "bf_dictionary": "/vulnerabilities/brute/",
    "bf_spray": "/vulnerabilities/brute/",
}


def normalize_security_level(level: str | None) -> str:
    """Handles normalize security level behavior for this module.

    Args:
        level: Value used by this function."""
    normalized = (level or "low").strip().lower()
    return normalized if normalized in {"low", "medium", "high"} else "low"


def already_tried_payloads(state: dict[str, Any], module_name: str) -> set[str]:
    """Return payloads already attempted for a module as a set."""
    module_payloads = state.get("tried_payloads", {}).get(module_name, [])
    return {str(payload) for payload in module_payloads}


def validated_candidate_ids(state: dict[str, Any], module_name: str) -> set[str] | None:
    """Return validated candidate IDs, or ``None`` before validation runs.

    The graph keeps candidate history for auditability. Once validation results
    exist, only candidates with an explicit ``valid`` result may enter an agent
    queue; an empty set is meaningful and blocks execution of rejected rows.
    """
    results = state.get("payload_validation_results", {}).get(module_name)
    if not isinstance(results, list) or not results:
        return None
    return {
        str(result.get("candidate_id"))
        for result in results
        if isinstance(result, dict)
        and result.get("valid") is True
        and result.get("candidate_id") is not None
    }


def validated_payload_candidates(state: dict[str, Any], module_name: str) -> list[dict]:
    """Return the executable candidate queue after validation filtering."""
    candidates = state.get("payload_candidates", {}).get(module_name, [])
    valid_ids = validated_candidate_ids(state, module_name)
    if valid_ids is None:
        return [candidate for candidate in candidates if isinstance(candidate, dict)]
    return [
        candidate
        for candidate in candidates
        if isinstance(candidate, dict)
        and str(candidate.get("candidate_id")) in valid_ids
    ]


def append_error_marker(target: list[str], context: str, exc: Exception) -> None:
    """Append a deterministic error marker for observability in state output."""
    target.append(f"{context}:{type(exc).__name__}")


def prepare_agent_session(
    session: Any,
    security_level: str,
    *,
    require_login: bool = True,
) -> tuple[bool, list[str]]:
    """Prepare a DVWA session for exploit attempts.

    This helper is intentionally tolerant so existing tests with lightweight
    session fakes still work: if a fake session lacks login or security-level
    methods, the helper does not fail.
    """
    notes: list[str] = []

    login_ok = True
    if require_login:
        login_fn = getattr(session, "login", None)
        if callable(login_fn):
            try:
                login_ok = bool(login_fn())
                if not login_ok:
                    notes.append("session_login_failed")
            except (ValueError, RuntimeError, OSError, TransportError, RequestTimeoutError) as exc:
                login_ok = False
                append_error_marker(notes, "session_login_error", exc)

    set_level_fn = getattr(session, "set_security_level", None)
    if callable(set_level_fn):
        try:
            set_level_fn(security_level)
        except ValueError as exc:
            append_error_marker(notes, "security_level_invalid", exc)
        except (RuntimeError, OSError, TransportError, RequestTimeoutError) as exc:
            append_error_marker(notes, "security_level_set_error", exc)

    if require_login and not login_ok:
        return False, notes

    return True, notes


def merge_scores(state: dict[str, Any], module_name: str, new_score: int) -> dict[str, int]:
    """Handles merge scores behavior for this module.

    Args:
        state: Value used by this function.
        module_name: Value used by this function.
        new_score: Value used by this function."""
    scores = dict(state.get("scores", {}))
    scores[module_name] = max(int(scores.get(module_name, 0)), int(new_score))
    return scores


def merge_score_map(
    state: dict[str, Any],
    map_name: str,
    module_name: str,
    new_score: int,
) -> dict[str, int]:
    """Handles merge score map behavior for this module.

    Args:
        state: Value used by this function.
        map_name: Value used by this function.
        module_name: Value used by this function.
        new_score: Value used by this function."""
    scores = dict(state.get(map_name, {}))
    scores[module_name] = max(int(scores.get(module_name, 0)), int(new_score))
    return scores


def merge_tried_payloads(
    state: dict[str, Any],
    module_name: str,
    payloads: list[str],
) -> dict[str, list[str]]:
    """Handles merge tried payloads behavior for this module.

    Args:
        state: Value used by this function.
        module_name: Value used by this function.
        payloads: Value used by this function."""
    tried_payloads = dict(state.get("tried_payloads", {}))
    module_payloads = list(tried_payloads.get(module_name, []))
    for payload in payloads:
        if payload not in module_payloads:
            module_payloads.append(payload)
    tried_payloads[module_name] = module_payloads
    return tried_payloads


def module_endpoint(state: dict[str, Any], module_name: str, fallback_path: str) -> str:
    """Handles module endpoint behavior for this module.

    Args:
        state: Value used by this function.
        module_name: Value used by this function.
        fallback_path: Value used by this function."""
    endpoints = state.get("endpoints", [])
    expected_fragment = _MODULE_ENDPOINT_FRAGMENTS.get(module_name, "")

    for endpoint in endpoints:
        if endpoint.get("module_name") != module_name:
            continue

        raw_url = str(endpoint.get("url", ""))
        parsed_path = urlparse(raw_url).path.lower()
        if expected_fragment and expected_fragment not in parsed_path:
            continue

        return str(endpoint.get("url") or fallback_path)

    for endpoint in endpoints:
        raw_url = str(endpoint.get("url", ""))
        parsed_path = urlparse(raw_url).path.lower()
        if expected_fragment and expected_fragment in parsed_path:
            return str(endpoint.get("url") or fallback_path)

    return fallback_path


def candidate_payloads_for_stage(
    state: dict[str, Any],
    module_name: str,
    security_level: str,
    stage: str,
) -> list[str]:
    """Return executable candidate payloads for a stage.

    Before validation, canonical static seeds preserve direct unit-test and
    legacy call behavior. Once validation has run, an empty valid-ID set is a
    hard stop: rejected candidate history must not be revived by a method
    agent's local fallback. If another stage has a valid candidate, canonical
    seeds may still supply the missing probe/exploit stage.
    """
    candidates = validated_payload_candidates(state, module_name)
    valid_ids = validated_candidate_ids(state, module_name)
    allowed_stages = {stage}
    if stage == "exploit":
        allowed_stages.add("bypass")
    selected = [
        str(candidate.get("payload_or_logic", ""))
        for candidate in candidates
        if isinstance(candidate, dict)
        and str(candidate.get("stage", stage)) in allowed_stages
        and candidate.get("payload_or_logic")
    ]
    if selected:
        return selected

    if valid_ids is not None and not valid_ids:
        return []

    payload_set = PayloadLibrary().get(module_name, security_level)
    if stage == "probe":
        return [
            *payload_set.probe,
            *payload_set.probe_by_level.get(security_level, []),
        ]
    if stage == "exploit":
        return list(payload_set.exploit) + list(payload_set.bypass.get(security_level, []))
    return []


def payload_score_updates(
    state: dict[str, Any],
    module_name: str,
    score: int,
    tried_payloads: list[str] | None = None,
) -> dict[str, int]:
    """Assign payload-quality scores only to candidates that were actually tried.

    ``make_update`` receives the method invocation's payloads before the
    LangGraph reducer merges them into shared state. Accept that current
    invocation explicitly so the first method call is scored in artifacts.
    """
    updates = dict(state.get("payload_scores", {}))
    tried_payloads = {
        str(payload)
        for payload in [
            *state.get("tried_payloads", {}).get(module_name, []),
            *(tried_payloads or []),
        ]
        if payload is not None
    }
    for candidate in state.get("payload_candidates", {}).get(module_name, []):
        if not isinstance(candidate, dict):
            continue
        candidate_id = candidate.get("candidate_id")
        payload_value = candidate.get("payload_or_logic")
        if candidate_id and payload_value is not None and str(payload_value) in tried_payloads:
            updates[str(candidate_id)] = max(int(updates.get(str(candidate_id), 0)), int(score))
    return updates


def _materialize_request_evidence(
    state: dict[str, Any],
    module_name: str,
    telemetry_events: list[dict],
) -> tuple[list[dict], list[dict], list[dict]]:
    """Normalize method telemetry into auditable response/timing evidence.

    Method agents emit compact request events rather than copying full response
    bodies into shared state. This helper fills the endpoint from recon when an
    event does not provide one and separates timing measurements for artifacts.
    """
    fallback_path = _MODULE_ENDPOINT_FRAGMENTS.get(module_name, "")
    endpoint = module_endpoint(state, module_name, fallback_path) if fallback_path else ""
    target_url = str(state.get("target_url") or "").rstrip("/")
    if endpoint.startswith("/") and target_url:
        endpoint = f"{target_url}{endpoint}"

    response_evidence: list[dict] = []
    timing_evidence: list[dict] = []
    normalized_events: list[dict] = []
    for event in telemetry_events:
        if not isinstance(event, dict):
            normalized_events.append(event)
            continue
        event_copy = dict(event)
        payload = event_copy.get("payload")
        if (
            event_copy.get("event") not in {"agent.probe.sent", "agent.exploit.sent"}
            or not isinstance(payload, dict)
        ):
            normalized_events.append(event_copy)
            continue

        payload_copy = dict(payload)
        event_endpoint = str(payload_copy.get("endpoint") or endpoint or "")
        if event_endpoint.startswith("/") and target_url:
            event_endpoint = f"{target_url}{event_endpoint}"
        payload_copy["endpoint"] = event_endpoint
        event_copy["payload"] = payload_copy
        normalized_events.append(event_copy)

        stage = "probe" if event_copy["event"] == "agent.probe.sent" else "exploit"
        evidence = {
            "agent_id": str(payload_copy.get("agent_id") or module_name),
            "stage": stage,
            "endpoint": payload_copy["endpoint"],
            "payload": payload_copy.get("payload"),
            "status_code": payload_copy.get("status_code"),
        }
        if "signal_detected" in payload_copy:
            evidence["signal_detected"] = payload_copy["signal_detected"]
        if "success" in payload_copy:
            evidence["success"] = payload_copy["success"]
        response_evidence.append(evidence)

        if "elapsed_ms" in payload_copy:
            timing_evidence.append({
                **evidence,
                "elapsed_ms": payload_copy.get("elapsed_ms"),
                "baseline_elapsed_ms": payload_copy.get("baseline_elapsed_ms"),
                "delay_ms": payload_copy.get("delay_ms"),
            })

    return normalized_events, response_evidence, timing_evidence


def make_update(
    *,
    state: dict[str, Any],
    module_name: str,
    score: int,
    tried_payloads: list[str],
    confirmed_vulns: list[str] | None = None,
    achieved_outcomes: list[str] | None = None,
    found_credentials: list[dict[str, str]] | None = None,
    next_agent: str = "orchestrator",
    telemetry_events: list[dict] | None = None,
    failure_agents: list[str] | None = None,
    blocked_agents: list[str] | None = None,
    task_result: str | None = None,
    incomplete_reason: str | None = None,
) -> dict[str, Any]:
    """Build a method-agent partial state update without mutating input state.

    The helper applies the 0-4 scoring rubric, deduplicates list-reducer fields,
    records tried payloads, updates payload scores for executed candidates, and
    emits routing/failure fields used by the chaining router.

    Args:
        state: Current shared LangGraph state.
        module_name: Static method agent identifier.
        score: Highest method score reached during this agent invocation.
        tried_payloads: Payload strings attempted by this invocation.
        confirmed_vulns: AKG node IDs confirmed by this invocation.
        achieved_outcomes: Outcome node IDs achieved by chain checks.
        found_credentials: Credentials recovered by brute-force agents.
        next_agent: Routing hint for the next graph stage.
        telemetry_events: Agent telemetry events to append.
        failure_agents: Method IDs to mark as failed.
        blocked_agents: Method IDs to mark as blocked.
        task_result: Optional terminal task status.
        incomplete_reason: Optional reason for incomplete execution.

    Returns:
        Partial `ExploitationState` update suitable for LangGraph reducers.
    """
    update: dict[str, Any] = {
        "scores": merge_scores(state, module_name, score),
        "exploitation_scores": merge_score_map(state, "exploitation_scores", module_name, min(score, 3)),
        "chain_scores": merge_score_map(state, "chain_scores", module_name, 4 if score >= 4 else 0),
        "payload_scores": payload_score_updates(
            state,
            module_name,
            min(score, 4),
            tried_payloads=tried_payloads,
        ),
        "tried_payloads": merge_tried_payloads(state, module_name, tried_payloads),
        "iteration_count": state.get("iteration_count", 0) + 1,
        "next_agent": next_agent,
    }

    # Validate score is within rubric bounds
    if not isinstance(score, int) or not (0 <= score <= 4):
        raise ValueError(f"score must be an int in range 0-4, got {score!r}")

    # confirmed_vulns, achieved_outcomes, and found_credentials all use
    # Annotated[list, add] reducers. We must filter out items already
    # present in state to avoid permanent duplication across agent runs.
    if confirmed_vulns:
        existing_confirmed = set(state.get("confirmed_vulns", []))
        new_confirmed = [c for c in confirmed_vulns if c not in existing_confirmed]
        if new_confirmed:
            update["confirmed_vulns"] = new_confirmed
    if achieved_outcomes:
        existing_outcomes = set(state.get("achieved_outcomes", []))
        new_outcomes = [o for o in achieved_outcomes if o not in existing_outcomes]
        if new_outcomes:
            update["achieved_outcomes"] = new_outcomes
    if found_credentials:
        existing_creds = state.get("found_credentials", [])
        existing_creds_set = {
            (c.get("username"), c.get("password"))
            for c in existing_creds
            if isinstance(c, dict)
        }
        new_creds = [
            c for c in found_credentials
            if isinstance(c, dict) and (c.get("username"), c.get("password")) not in existing_creds_set
        ]
        if new_creds:
            update["found_credentials"] = new_creds

    # Track attempted agents for fallback diversification.
    # attempted_agents uses Annotated[list[str], add] reducer in LangGraph,
    # so we must return ONLY the new item, not the full accumulated list.
    attempted = list(state.get("attempted_agents", []))
    if module_name not in attempted:
        update["attempted_agents"] = [module_name]

    # Merge telemetry events from agents and materialize auditable evidence.
    # telemetry_events uses Annotated[list[dict], add] reducer,
    # so we must return ONLY the new events, not existing + new.
    if telemetry_events:
        normalized_events, response_evidence, timing_evidence = _materialize_request_evidence(
            state, module_name, list(telemetry_events)
        )
        update["telemetry_events"] = normalized_events
        if response_evidence:
            update["response_evidence"] = response_evidence
        if timing_evidence:
            update["timing_evidence"] = timing_evidence

        # A method invocation with request telemetry is itself a verifier
        # decision, even when its evidence did not confirm the vulnerability.
        # Keep an existing confirmed decision when a later fallback invocation
        # has no new confirmation, but never leave the artifact ambiguous for
        # a first invocation that produced auditable negative evidence.
        if confirmed_vulns or not state.get("verifier_decision"):
            update["verifier_decision"] = {
                "agent_id": module_name,
                "decision": "confirmed" if confirmed_vulns else "not_confirmed",
                "confirmed_vulns": list(confirmed_vulns or []),
                "score": score,
                "evidence_count": len(response_evidence),
                "source": "method_agent_evidence",
            }

    # Track failure agents for fallback loop and adaptation metrics.
    # failure_agents uses Annotated[list[str], add] reducer.
    if failure_agents:
        existing_failures = set(state.get("failure_agents", []))
        new_failures = [a for a in failure_agents if a not in existing_failures]
        if new_failures:
            update["failure_agents"] = new_failures

    if blocked_agents:
        existing_blocked = set(state.get("blocked_agents", []))
        new_blocked = [a for a in blocked_agents if a not in existing_blocked]
        if new_blocked:
            update["blocked_agents"] = new_blocked

    if task_result is not None:
        update["task_result"] = task_result
    if incomplete_reason is not None:
        update["incomplete_reason"] = incomplete_reason

    return update


def chain_check(confirmed_node: str, state: dict[str, Any]) -> tuple[int, list[str]]:
    """Query AKG for chain edges from a confirmed node.

    A ready edge is not itself an achieved outcome. This helper therefore only
    credits a chain when its target outcome has already been proved in state;
    the chaining router is responsible for routing the next method.
    """
    from core.knowledge_graph import AttackKnowledgeGraph

    achieved: list[str] = []
    score = 0
    kg = AttackKnowledgeGraph()
    if state.get("experiment_condition", "linear_hybrid") != "akg_guided_hybrid":
        return score, achieved

    confirmed_set = set(state.get("confirmed_vulns", [])) | {confirmed_node}
    achieved_set = set(state.get("achieved_outcomes", []))
    known = confirmed_set | achieved_set

    for edge in kg.get_next_actions(confirmed_node):
        if not edge.get("is_chain"):
            continue
        preconditions = edge.get("preconditions", [])
        target = str(edge["target"])
        if all(p in known for p in preconditions) and target in achieved_set:
            achieved.append(target)
            score = 4

    return score, achieved
