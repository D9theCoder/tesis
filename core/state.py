"""ExploitationState — shared state schema for all agents and graph nodes."""

from copy import deepcopy
from typing import Any, TypedDict, Annotated, NotRequired
from operator import add

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


def _merge_dicts(a: dict, b: dict) -> dict:
    """Reducer for observations: merge b into a without overwriting existing keys to False."""
    merged = dict(a)
    merged.update(b)
    return merged


class ExploitationState(TypedDict):
    # Target context
    target_url: str
    security_level: str  # "low" | "medium" | "high"
    llm_provider: str
    current_surface: str  # "sqli" | "access_control" | "brute_force"

    # Discovered attack surface
    endpoints: list[dict]
    observations: Annotated[dict[str, bool], _merge_dicts]  # precondition signals

    # Exploitation progress (accumulate)
    confirmed_vulns: Annotated[list[str], add]  # AKG node IDs confirmed
    achieved_outcomes: Annotated[list[str], add]
    found_credentials: Annotated[list[dict], add]

    # Memory (accumulate)
    tried_payloads: dict[str, list[str]]  # agent_id -> tried payloads
    blocked_patterns: Annotated[list[str], add]
    successful_bypasses: Annotated[list[str], add]

    # Scoring (overwrite — max score per agent_id)
    scores: dict[str, int]  # agent_id -> 0-4

    # Chain tracking
    current_chain: list[str]
    chain_history: Annotated[list[dict], add]

    # LLM reasoning trace
    messages: Annotated[list[AnyMessage], add_messages]

    # Guardrail monitoring (accumulate)
    guardrail_activations: Annotated[list[dict], add]

    # Evasion tracking (overwrite)
    consecutive_clean_responses: int  # for evasion cooldown tracker
    evasion_enabled: NotRequired[bool]
    evasion_max_retries: NotRequired[int]
    evasion_mode: NotRequired[str]  # "reactive" | "proactive" | "disabled"
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
    akg_path: list[str]
    fallback_depth: int

    # Control flow (overwrite)
    next_agent: str
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
        "endpoints": [],
        "observations": {},
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "found_credentials": [],
        "tried_payloads": {},
        "blocked_patterns": [],
        "successful_bypasses": [],
        "scores": {},
        "current_chain": [],
        "chain_history": [],
        "messages": [],
        "guardrail_activations": [],
        "consecutive_clean_responses": 0,
        "evasion_enabled": False,
        "evasion_max_retries": 3,
        "evasion_mode": "reactive",
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
        "iteration_count": 0,
        "max_iterations": 30,
        "task_result": None,
        "incomplete_reason": None,
    }


DEFAULT_STATE: dict[str, Any] = _default_state_template()


def new_default_state() -> dict[str, Any]:
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
    "sqli_boolean_blind": "blind_sqli_confirmed",
    "sqli_time_blind": "blind_sqli_confirmed",
    "ac_idor": "access_control_confirmed",
    "ac_vertical_escalation": "ac_vertical_escalation_confirmed",
    "ac_force_browse": "access_control_confirmed",
    "bf_dictionary": "brute_force_confirmed",
    "bf_spray": "brute_force_confirmed",
}

KG_NODES: list[str] = [
    "sqli_confirmed",
    "blind_sqli_confirmed",
    "xss_reflected_confirmed",
    "xss_stored_confirmed",
    "xss_dom_confirmed",
    "cmd_injection_confirmed",
    "brute_force_confirmed",
    "lfi_confirmed",
    "file_upload_confirmed",
    "csrf_confirmed",
    "weak_session_confirmed",
    "idor_confirmed",
    "credentials_extracted",
    "admin_session_obtained",
    "log_access_confirmed",
    "rce_achieved",
    "user_compromised",
    "data_exfiltrated",
    "session_hijack",
]
