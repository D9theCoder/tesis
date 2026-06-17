"""ExploitationState — shared state schema for all agents and graph nodes."""

from copy import deepcopy
from typing import Any, TypedDict, Annotated, NotRequired
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
        existing_ids = {
            str(item.get("candidate_id"))
            for item in merged.get(key, [])
            if isinstance(item, dict) and item.get("candidate_id") is not None
        }
        merged.setdefault(key, [])
        for item in rows:
            if not isinstance(item, dict):
                continue
            candidate_id = item.get("candidate_id")
            if candidate_id is not None and str(candidate_id) in existing_ids:
                continue
            merged[key].append(dict(item))
            if candidate_id is not None:
                existing_ids.add(str(candidate_id))
    return merged


def _merge_nested_dicts(a: dict[str, dict], b: dict[str, dict]) -> dict[str, dict]:
    merged = {k: dict(v) for k, v in a.items()}
    for key, value in b.items():
        if isinstance(value, dict):
            merged[key] = {**merged.get(key, {}), **value}
    return merged


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

    # Discovered attack surface
    endpoints: list[dict]
    input_vectors: Annotated[list[dict], add]
    observations: Annotated[dict[str, bool], _merge_dicts]  # precondition signals

    # Exploitation progress (accumulate)
    confirmed_vulns: Annotated[list[str], add]  # AKG node IDs confirmed
    achieved_outcomes: Annotated[list[str], add]
    found_credentials: Annotated[list[dict], add]

    # Memory (accumulate)
    tried_payloads: Annotated[dict[str, list[str]], _merge_tried_payloads]  # agent_id -> tried payloads

    # Payload candidate tracking (accumulate)
    payload_candidates: Annotated[dict[str, list[dict]], _merge_payload_maps]
    generated_payloads: Annotated[dict[str, list[dict]], _merge_payload_maps]
    payload_validation_results: Annotated[dict[str, list[dict]], _merge_payload_maps]
    payload_scores: Annotated[dict[str, int], _merge_scores]
    payload_provenance: Annotated[dict[str, dict], _merge_nested_dicts]
    generation_prompts: Annotated[list[dict], add]
    payload_guardrail_activations: Annotated[list[dict], add]
    candidate_budget: int

    # Scoring (overwrite — max score per agent_id)
    scores: Annotated[dict[str, int], _merge_scores]  # agent_id -> 0-4
    method_scores: Annotated[dict[str, int], _merge_scores]
    exploitation_scores: Annotated[dict[str, int], _merge_scores]
    chain_scores: Annotated[dict[str, int], _merge_scores]

    # Chain tracking
    current_chain: list[str]
    chain_history: Annotated[list[dict], add]

    # LLM reasoning trace
    messages: Annotated[list[AnyMessage], add_messages]

    # Guardrail monitoring (accumulate)
    guardrail_activations: Annotated[list[dict], add]

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
    iteration_count: int
    max_iterations: int
    task_result: str | None  # None | "SUCCESS" | "INCOMPLETE"
    incomplete_reason: str | None  # "CONTENT_POLICY" | "ALL_METHODS_FAILED"


def _default_state_template() -> dict[str, Any]:
    return {
        "target_url": "",
        "security_level": "low",
        "llm_provider": "gemini",
        "current_surface": "sqli",
        "payload_mode": "static_only",
        "endpoints": [],
        "input_vectors": [],
        "observations": {},
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "found_credentials": [],
        "tried_payloads": {},
        "payload_candidates": {},
        "generated_payloads": {},
        "payload_validation_results": {},
        "payload_scores": {},
        "payload_provenance": {},
        "generation_prompts": [],
        "payload_guardrail_activations": [],
        "candidate_budget": 5,
        "scores": {},
        "method_scores": {},
        "exploitation_scores": {},
        "chain_scores": {},
        "current_chain": [],
        "chain_history": [],
        "messages": [],
        "guardrail_activations": [],
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
        "telemetry_events": [],
        "attempted_agents": [],
        "blocked_agents": [],
        "failure_agents": [],
        "akg_path": [],
        "fallback_depth": 0,
        "next_agent": "recon",
        "selected_method": None,
        "iteration_count": 0,
        "max_iterations": 30,
        "task_result": None,
        "incomplete_reason": None,
    }


DEFAULT_STATE: dict[str, Any] = _default_state_template()


def new_default_state() -> dict[str, Any]:
    """Builds a fresh default `ExploitationState` dictionary.

    Returns:
        Independent default state values for one LangGraph run."""
    return deepcopy(_default_state_template())


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

# Payload experiment modes
PAYLOAD_MODES: list[str] = ["static_only", "hybrid", "llm_mutation_only"]

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
    "sqli_union": "sqli_confirmed",
    "sqli_error": "sqli_confirmed",
    "sqli_boolean_blind": "sqli_confirmed",
    "sqli_time_blind": "sqli_confirmed",
    "ac_idor": "access_control_confirmed",
    "ac_vertical_escalation": "ac_vertical_escalation_confirmed",
    "ac_force_browse": "access_control_confirmed",
    "bf_dictionary": "brute_force_confirmed",
    "bf_spray": "brute_force_confirmed",
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
