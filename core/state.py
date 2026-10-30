"""ExploitationState — shared state schema for all agents and graph nodes."""

from copy import deepcopy
from typing import Any, TypedDict, Annotated, NotRequired, Literal
from operator import add

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


def _merge_dicts(a: dict[str, bool], b: dict[str, bool]) -> dict[str, bool]:
    """Reducer for observations: merge b into a; never overwrite True with False.

    Rules (in order):
    1. New keys from b are always added (even if False — first observation recorded).
    2. Existing keys in a that are True are preserved (never downgraded to False).
    3. Existing keys in a that are False are overwritten with whatever b provides.
    4. Keys only in a are left untouched.
    """
    merged = dict(a)
    for key, value in b.items():
        if key not in merged or merged[key] is False:
            # Only overwrite if key is new or currently False (never downgrade True)
            merged[key] = value
    return merged


def _merge_scores(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    merged = dict(a)
    for k, v in b.items():
        merged[k] = max(merged.get(k, 0), v)
    return merged


def _merge_output_scores(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    """An earlier clean visit cannot erase a penalty in the same method context."""
    return {**a, **{k: min(a.get(k, v), v) for k, v in b.items()}}


def _replace_score_entries(a: dict, b: dict) -> dict:
    return {**a, **b}


def _replace_value(a, b):
    """Reducer for whole receipts/receipts derived from append-only evidence."""
    return b


SCORING_RUBRIC_VERSION = "scoring.v2"


def score_decision(state: dict, dimension: str, method: str, score: int | float,
                   reason: str, *, aggregation: str = "maximum_with_evidence", **context) -> dict:
    """Append-only receipt; callers supply the evidence that actually earned a grade."""
    visit_id = context.pop("visit_id", None) or state.get("selected_visit_id") or f"{method}:legacy:{state.get('iteration_count', 0)}"
    suffix = context.get("candidate_id") or context.get("route_id") or len(state.get("scoring_decisions", []))
    return {"decision_id": f"{visit_id}:{dimension}:{suffix}", "dimension": dimension,
        "rubric_version": SCORING_RUBRIC_VERSION, "method": method, "visit_id": visit_id,
        "score": score, "reason": reason, "aggregation": aggregation,
        "evidence_refs": context.pop("evidence_refs", []), **context}


def _merge_tried_payloads(a: dict[str, list[str]], b: dict[str, list[str]]) -> dict[str, list[str]]:
    merged = {k: list(v) for k, v in a.items()}
    for k, payloads in b.items():
        existing = set(merged.get(k, []))
        merged.setdefault(k, [])
        for payload in payloads:
            if payload not in existing:
                merged[k].append(payload)
                existing.add(payload)
    return merged


def _merge_payload_maps(a: dict[str, list[dict]], b: dict[str, list[dict]]) -> dict[str, list[dict]]:
    merged = {k: list(v) for k, v in a.items()}
    for key, rows in b.items():
        def identity(item: dict) -> tuple[str, str] | None:
            candidate_id = item.get("candidate_id")
            if candidate_id is None:
                return None
            return (str(item.get("visit_id") or ""), str(candidate_id))

        existing_ids = {
            identity(item)
            for item in merged.get(key, [])
            if isinstance(item, dict) and identity(item) is not None
        }
        merged.setdefault(key, [])
        for item in rows:
            if not isinstance(item, dict):
                continue
            row_identity = identity(item)
            if row_identity is not None and row_identity in existing_ids:
                continue
            merged[key].append(dict(item))
            if row_identity is not None:
                existing_ids.add(row_identity)
    return merged


def _merge_nested_dicts(a: dict[str, dict], b: dict[str, dict]) -> dict[str, dict]:
    merged = {k: dict(v) for k, v in a.items()}
    for key, value in b.items():
        if isinstance(value, dict):
            merged[key] = {**merged.get(key, {}), **value}
    return merged


def _merge_quarantined_visits(a: list[dict], b: list[dict]) -> list[dict]:
    """Append quarantine rows but let an evidenced restoration replace a visit."""
    merged = [dict(row) for row in a if isinstance(row, dict)]
    index = {str(row.get("visit_id")): pos for pos, row in enumerate(merged)}
    for row in b:
        if not isinstance(row, dict):
            continue
        visit = str(row.get("visit_id"))
        if visit in index:
            merged[index[visit]] = dict(row)
        else:
            index[visit] = len(merged)
            merged.append(dict(row))
    return merged


def _merge_validation_maps(a: dict[str, list[dict]], b: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Keep visit-owned receipts append-only so old evidence indices stay valid."""
    merged = {method: list(rows) for method, rows in a.items()}
    for method, rows in b.items():
        history = merged.setdefault(method, [])
        seen = {(row.get("visit_id"), row.get("candidate_id")) for row in history}
        for row in rows:
            identity = (row.get("visit_id"), row.get("candidate_id"))
            if identity not in seen:
                history.append(dict(row))
                seen.add(identity)
    return merged


ExecutionStatus = Literal["completed", "failed", "interrupted"]
SecurityOutcome = Literal["confirmed", "no_finding", "unconfirmed", "fixture_limited"]
StatusReasonCode = Literal[
    "NO_CANDIDATE_CONFIRMATION", "PARTIAL_SIGNAL", "VERIFIED_NEGATIVE",
    "PERMISSION_ORACLE_UNAVAILABLE", "SESSION_ORACLE_UNAVAILABLE",
    "LLM_RUNTIME_FAILURE", "LLM_NOT_CALLED", "LLM_ACTIVITY_INCOMPLETE",
    "TARGET_TRANSPORT_FAILURE", "TARGET_REQUEST_FAILURE", "RUNNER_EXCEPTION",
    "RESUME_REFUSED", "ARTIFACT_WRITE_FAILURE", "ARTIFACT_PROCESSING_FAILURE",
    "RUNTIME_FAILURE", "CANCELLED", "CHILD_EXECUTION_FAILED", "CHILD_EXECUTION_UNKNOWN", "CHILD_OUTCOMES",
    "SESSION_LOGIN_FAILED", "METHOD_EXECUTION_FAILURE",
    "READINESS_FAILED", "READINESS_UNKNOWN", "PRECONDITION_UNMET",
    "CONTROL_CONTAMINATION", "TARGET_METHOD_INFEASIBLE", "CHAIN_INFEASIBLE",
    "SELECTION_REJECTED", "NO_SAFE_DETECTION_CONTROL",
]


class StatusReason(TypedDict):
    code: StatusReasonCode
    detail: str
    evidence_refs: list[str]


class ExploitationState(TypedDict):
    # Target context
    """Shared state passed across the LangGraph execution workflow.

    The state stores target configuration, reconnaissance results, selected attack
    method, payload candidates, execution evidence, scoring fields, guardrail
    events, and chaining history. Nodes exchange information by reading current
    fields and returning partial updates."""
    target_url: str
    security_level: str  # "low" | "medium" | "high"
    llm_provider: str
    current_surface: str  # "sqli" | "access_control" | "brute_force"
    payload_mode: str  # "static_only" | "hybrid" | "llm_mutation_only"
    payload_policy_basis: NotRequired[str]  # "live" | explicit historical reader
    recorded_payload_policy: NotRequired[dict]  # frozen policy/template-registry snapshot
    experiment_condition: str  # "linear_hybrid" | "akg_guided_hybrid"
    target_method: str | None
    repeat_index: int
    stop_policy: str
    coverage_target: float
    workflow_protocol_version: str
    workflow_stop_reason: str | None
    llm_skip_reason: str | None
    run_id: str
    execution_id: str
    fixture_id: str | None
    protocol_version: str | None
    scoring_rubric_version: str
    scoring_profile: dict
    scoring_oracles: list[dict]

    # Discovered attack surface
    endpoints: list[dict]
    input_vectors: Annotated[list[dict], add]
    # Legacy supported view: positive facts only, never downgraded. The
    # authoritative current status is ``precondition_status`` (true|false|unknown).
    # Derived current view: a later measured negative replaces an older true.
    # Immutable history lives in ``observation_facts`` only.
    observations: Annotated[dict[str, bool], _replace_value]  # current precondition view
    method_principals: Annotated[dict[str, str], _replace_score_entries]
    method_session_fingerprints: Annotated[dict[str, str], _replace_score_entries]
    fixture_restoration_evidence: NotRequired[dict | None]
    policy_epoch: NotRequired[dict]
    http_request_counters: NotRequired[dict | None]
    observation_facts: Annotated[list[dict], add]
    precondition_status: dict[str, str]
    readiness: NotRequired[dict]
    control_policy_version: NotRequired[str | None]
    control_events: Annotated[list[dict], add]
    quarantined_visits: Annotated[list[dict], _merge_quarantined_visits]
    selection_rejections: Annotated[list[dict], add]
    candidate_lifecycle: Annotated[list[dict], add]
    model_call_requirements: Annotated[list[dict], add]
    chain_assessment: NotRequired[dict | None]

    # Exploitation progress (accumulate)
    confirmed_vulns: Annotated[list[str], add]  # AKG node IDs confirmed
    achieved_outcomes: Annotated[list[str], add]
    found_credentials: Annotated[list[dict], add]

    # Memory (accumulate)
    tried_payloads: Annotated[dict[str, list[str]], _merge_tried_payloads]  # agent_id -> tried payloads

    # Payload candidate tracking (accumulate)
    payload_candidates: Annotated[dict[str, list[dict]], _merge_payload_maps]
    generated_payloads: Annotated[dict[str, list[dict]], _merge_payload_maps]
    payload_validation_results: Annotated[dict[str, list[dict]], _merge_validation_maps]
    active_payload_candidates: Annotated[dict[str, dict], _replace_score_entries]
    preparation_failures: Annotated[list[dict], add]
    # Current visit's detection controls, separate from scored exploit candidates.
    probe_controls: NotRequired[Annotated[dict[str, dict], _replace_score_entries]]
    payload_scores: Annotated[dict[str, int], _merge_scores]
    payload_provenance: Annotated[dict[str, dict], _merge_nested_dicts]
    generation_prompts: Annotated[list[dict], add]
    payload_guardrail_activations: Annotated[list[dict], add]
    candidate_budget: int

    # Scoring (overwrite — max score per agent_id)
    scores: Annotated[dict[str, int], _merge_scores]  # agent_id -> 0-4
    method_scores: Annotated[dict[str, int], _merge_scores]
    exploitation_scores: Annotated[dict[str, int], _merge_scores]
    chain_scores: Annotated[dict[str, int], _replace_score_entries]
    output_scores: Annotated[dict[str, int], _merge_output_scores]
    composite_scores: Annotated[dict[str, float], _replace_score_entries]
    selected_visit_id: str | None
    scoring_decisions: Annotated[list[dict], add]
    verifier_history: Annotated[list[dict], add]

    # Chain tracking
    current_chain: list[str]
    chain_history: Annotated[list[dict], add]
    active_chain_route: dict | None
    chain_consumption: Annotated[list[dict], add]
    weak_chain_opportunities: Annotated[list[dict], add]

    # LLM reasoning trace
    messages: Annotated[list[AnyMessage], add_messages]

    # Guardrail monitoring (accumulate)
    guardrail_activations: Annotated[list[dict], add]
    invalid_json_events: Annotated[list[dict], add]
    output_failure_events: Annotated[list[dict], add]
    fallback_events: Annotated[list[dict], add]
    containment_events: Annotated[list[dict], add]
    response_evidence: Annotated[list[dict], add]
    timing_evidence: Annotated[list[dict], add]
    verifier_decision: NotRequired[dict[str, Any] | str | None]

    # Evasion state persisted for payload-library bypass tracking
    blocked_patterns: Annotated[list[str], add]
    successful_bypasses: Annotated[list[str], add]

    # Evasion tracking (overwrite)
    consecutive_clean_responses: int  # for evasion cooldown tracker
    evasion_enabled: NotRequired[bool]
    evasion_max_retries: NotRequired[int]
    evasion_mode: NotRequired[str]  # "reactive" | "proactive" | "disabled"
    evasion_strategy: NotRequired[str]  # alias for evasion_mode
    evasion_cooldown_threshold: NotRequired[int]
    evasion_attempts: NotRequired[int]
    successful_evasions: NotRequired[int]

    # Model configuration for provider instantiation
    model_config: NotRequired[dict[str, Any]]
    llm_call_receipts: Annotated[list[dict], add]

    # Telemetry (accumulate)
    telemetry_events: NotRequired[Annotated[list[dict], add]]

    # Orchestration audit trail (accumulate)
    attempted_agents: Annotated[list[str], add]
    blocked_agents: Annotated[list[str], add]
    failure_agents: Annotated[list[str], add]
    akg_path: Annotated[list[str], add]
    fallback_depth: int

    # Control flow (overwrite)
    next_agent: str
    selected_method: str | None
    viable_methods: list[str]
    iteration_count: int
    max_iterations: int
    task_result: str | None  # None | "SUCCESS" | "INCOMPLETE"
    incomplete_reason: str | None  # "CONTENT_POLICY" | "ALL_METHODS_FAILED"
    execution_status: NotRequired[ExecutionStatus | None]
    execution_reason: NotRequired[StatusReason | None]
    security_outcome: NotRequired[SecurityOutcome | None]
    security_outcome_reason: NotRequired[StatusReason | None]
    summary: NotRequired[dict[str, Any]]
    surface_scores: NotRequired[dict[str, dict[str, Any]]]


def _default_state_template() -> dict[str, Any]:
    return {
        "target_url": "",
        "security_level": "low",
        "llm_provider": "gemini",
        "current_surface": "sqli",
        "payload_mode": "static_only",
        "payload_policy_basis": "live",
        "recorded_payload_policy": {},
        "experiment_condition": "linear_hybrid",
        "target_method": None,
        "repeat_index": 0,
        "stop_policy": "impact",
        "coverage_target": 0.70,
        "workflow_protocol_version": "workflow.v2",
        "workflow_stop_reason": None,
        "llm_skip_reason": None,
        "run_id": "",
        "execution_id": "",
        "fixture_id": None,
        "protocol_version": None,
        "scoring_rubric_version": "scoring.v4",
        "scoring_profile": {},
        "scoring_oracles": [],
        "endpoints": [],
        "input_vectors": [],
        "observations": {},
        "method_principals": {},
        "method_session_fingerprints": {},
        "fixture_restoration_evidence": None,
        "policy_epoch": {},
        "http_request_counters": None,
        "observation_facts": [],
        "precondition_status": {},
        "readiness": None,
        "control_policy_version": None,
        "control_events": [],
        "quarantined_visits": [],
        "selection_rejections": [],
        "candidate_lifecycle": [],
        "model_call_requirements": [],
        "chain_assessment": None,
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "found_credentials": [],
        "tried_payloads": {},
        "payload_candidates": {},
        "generated_payloads": {},
        "payload_validation_results": {},
        "active_payload_candidates": {},
        "preparation_failures": [],
        "probe_controls": {},
        "payload_scores": {},
        "payload_provenance": {},
        "generation_prompts": [],
        "payload_guardrail_activations": [],
        "candidate_budget": 5,
        "scores": {},
        "method_scores": {},
        "exploitation_scores": {},
        "chain_scores": {},
        "output_scores": {},
        "composite_scores": {},
        "selected_visit_id": None,
        "scoring_decisions": [],
        "verifier_history": [],
        "current_chain": [],
        "chain_history": [],
        "active_chain_route": None,
        "chain_consumption": [],
        "weak_chain_opportunities": [],
        "messages": [],
        "guardrail_activations": [],
        "invalid_json_events": [],
        "output_failure_events": [],
        "fallback_events": [],
        "containment_events": [],
        "response_evidence": [],
        "timing_evidence": [],
        "verifier_decision": None,
        "blocked_patterns": [],
        "successful_bypasses": [],
        "consecutive_clean_responses": 0,
        # NotRequired fields — always populated in default template for convenience
        "evasion_enabled": False,
        "evasion_max_retries": 3,
        "evasion_mode": "reactive",
        "evasion_strategy": "reactive",
        "evasion_cooldown_threshold": 5,
        "evasion_attempts": 0,
        "successful_evasions": 0,
        "model_config": {},
        "llm_call_receipts": [],
        "telemetry_events": [],
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "akg_path": [],
        "fallback_depth": 0,
        "next_agent": "recon",
        "selected_method": None,
        "viable_methods": [],
        "iteration_count": 0,
        "max_iterations": 30,
        "task_result": None,
        "incomplete_reason": None,
        "execution_status": None,
        "execution_reason": None,
        "security_outcome": None,
        "security_outcome_reason": None,
    }


DEFAULT_STATE: dict[str, Any] = _default_state_template()


def new_default_state() -> dict[str, Any]:
    """Builds a fresh default `ExploitationState` dictionary.

    Returns:
        Independent default state values for one LangGraph run."""
    return deepcopy(_default_state_template())


STATE_SCHEMA_VERSION = "state.v3"
CHECKPOINT_SCHEMA_VERSION = "checkpoint.v2"

# The metadata receipt retains PERSISTENT_STATE_FIELDS. Durable graph
# checkpoints use AuditCheckpointSerializer to store large audit entries once
# beside SQLite and restore them transparently, including pending writes.
# Nodes continue reading the full state; evidence indices remain stable.
ARTIFACT_ONLY_STATE_FIELDS = frozenset({
    "messages",
    "generation_prompts",
    "telemetry_events",
    "response_evidence",
    "timing_evidence",
    # Scorer-derived reports stored on the state snapshot, not inputs.
    "summary",
    "surface_scores",
})

PERSISTENT_STATE_FIELDS = frozenset({
    "repeat_index", "workflow_protocol_version", "workflow_stop_reason", "llm_skip_reason",
    "active_payload_candidates", "preparation_failures", "llm_call_receipts",
    "run_id", "execution_id", "fixture_id", "protocol_version", "scoring_rubric_version",
    "scoring_profile", "scoring_oracles", "weak_chain_opportunities",
    "target_url",
    "security_level",
    "llm_provider",
    "current_surface",
    "payload_mode",
    "payload_policy_basis",
    "recorded_payload_policy",
    "experiment_condition",
    "target_method",
    "endpoints",
    "input_vectors",
    "observations",
    "method_principals",
    "method_session_fingerprints",
    "fixture_restoration_evidence",
    "policy_epoch",
    "http_request_counters",
    "observation_facts",
    "precondition_status",
    "readiness",
    "control_policy_version",
    "control_events",
    "quarantined_visits",
    "selection_rejections",
    "candidate_lifecycle",
    "model_call_requirements",
    "chain_assessment",
    "confirmed_vulns",
    "achieved_outcomes",
    "found_credentials",
    "tried_payloads",
    "payload_candidates",
    "generated_payloads",
    "payload_validation_results",
    "probe_controls",
    "payload_scores",
    "payload_provenance",
    "payload_guardrail_activations",
    "candidate_budget",
    "scores",
    "method_scores",
    "exploitation_scores",
    "chain_scores",
    "output_scores",
    "composite_scores",
    "selected_visit_id",
    "scoring_decisions",
    "verifier_history",
    "active_chain_route",
    "chain_consumption",
    "output_failure_events",
    "current_chain",
    "chain_history",
    "guardrail_activations",
    "invalid_json_events",
    "fallback_events",
    "containment_events",
    "verifier_decision",
    "blocked_patterns",
    "successful_bypasses",
    "consecutive_clean_responses",
    # Runner-carried engagement setup (set in init_state, not in the default
    # template); persistent so a future resume keeps the same stop rule.
    "stop_policy",
    "coverage_target",
    "evasion_enabled",
    "evasion_max_retries",
    "evasion_mode",
    "evasion_strategy",
    "evasion_cooldown_threshold",
    "evasion_attempts",
    "successful_evasions",
    "model_config",
    "attempted_agents",
    "blocked_agents",
    "failure_agents",
    "akg_path",
    "fallback_depth",
    "next_agent",
    "selected_method",
    "viable_methods",
    "iteration_count",
    "max_iterations",
    "task_result",
    "incomplete_reason",
    "execution_status",
    "execution_reason",
    "security_outcome",
    "security_outcome_reason",
})


def checkpoint_safe_state(state: dict[str, Any]) -> dict[str, Any]:
    """Return a persistent-only copy honoring the explicit allowlist."""
    return {
        key: value
        for key, value in dict(state).items()
        if key in PERSISTENT_STATE_FIELDS
    }


# Surfaces
SURFACES: list[str] = ["sqli", "access_control", "brute_force"]

# Method agents by surface
METHODS_BY_SURFACE: dict[str, list[str]] = {
    "sqli": ["sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind"],
    "access_control": ["ac_idor", "ac_vertical_escalation", "ac_force_browse"],
    "brute_force": ["bf_dictionary", "bf_spray"],
}

# All method agent IDs
ALL_METHOD_AGENTS: list[str] = [
    "sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind",
    "ac_idor", "ac_vertical_escalation", "ac_force_browse",
    "bf_dictionary", "bf_spray",
]

# Surface to confirmed node prefix mapping
SURFACE_TO_KG_NODE: dict[str, str] = {
    "sqli": "sqli_confirmed",
    "access_control": "access_control_confirmed",
    "brute_force": "brute_force_confirmed",
}

# Scoring rubric (0-4)
SCORE_LABELS: dict[int, str] = {
    0: "Not Found",
    1: "Identified",
    2: "Partial Exploit",
    3: "Full Exploit",
    4: "Chain Exploit",
}

# Security levels
SECURITY_LEVELS: list[str] = ["low", "medium", "high"]

# LLM providers
LLM_PROVIDERS: list[str] = ["gemini", "openai", "claude", "openai_compatible"]

# Payload experiment modes (single registry owned by core.payload_policy)
from core.payload_policy import PAYLOAD_MODES as _POLICY_PAYLOAD_MODES  # noqa: E402

PAYLOAD_MODES: list[str] = list(_POLICY_PAYLOAD_MODES)

# Backward-compatible module names (deprecated; use ALL_METHOD_AGENTS for new code)
MODULE_NAMES: list[str] = [
    "sqli",
    "sqli_blind",
    "xss_r",
    "xss_s",
    "xss_d",
    "cmdi",
    "brute",
    "lfi",
    "upload",
    "csrf",
    "weak_session",
    "idor",
]

MODULE_TO_KG_NODE: dict[str, str] = {
    # Legacy module names
    "sqli": "sqli_confirmed",
    "sqli_blind": "blind_sqli_confirmed",
    "xss_r": "xss_reflected_confirmed",
    "xss_s": "xss_stored_confirmed",
    "xss_d": "xss_dom_confirmed",
    "cmdi": "cmd_injection_confirmed",
    "brute": "brute_force_confirmed",
    "lfi": "lfi_confirmed",
    "upload": "file_upload_confirmed",
    "csrf": "csrf_confirmed",
    "weak_session": "weak_session_confirmed",
    "idor": "idor_confirmed",
    # 3-surface deep-method agents
    "sqli_union": "sqli_union_confirmed",
    "sqli_error": "sqli_error_confirmed",
    "sqli_boolean_blind": "sqli_boolean_blind_confirmed",
    "sqli_time_blind": "sqli_time_blind_confirmed",
    "ac_idor": "ac_idor_confirmed",
    "ac_vertical_escalation": "ac_vertical_escalation_confirmed",
    "ac_force_browse": "ac_force_browse_confirmed",
    "bf_dictionary": "bf_dictionary_confirmed",
    "bf_spray": "bf_spray_confirmed",
}

KG_NODES: list[str] = [
    # Surface confirmed nodes
    "sqli_confirmed",
    "access_control_confirmed",
    "brute_force_confirmed",
    # Per-method confirmed nodes
    "sqli_union_confirmed",
    "sqli_error_confirmed",
    "sqli_boolean_blind_confirmed",
    "sqli_time_blind_confirmed",
    "ac_idor_confirmed",
    "ac_vertical_escalation_confirmed",
    "ac_force_browse_confirmed",
    "bf_dictionary_confirmed",
    "bf_spray_confirmed",
    # Legacy confirmed nodes (backward compatibility)
    "blind_sqli_confirmed",
    "xss_reflected_confirmed",
    "xss_stored_confirmed",
    "xss_dom_confirmed",
    "cmd_injection_confirmed",
    "lfi_confirmed",
    "file_upload_confirmed",
    "csrf_confirmed",
    "weak_session_confirmed",
    "idor_confirmed",
    # Intermediate chain nodes
    "authenticated_session",
    "unauthenticated",
    # Outcome nodes
    "credentials_extracted",
    "admin_session_obtained",
    "data_exfiltrated",
]
