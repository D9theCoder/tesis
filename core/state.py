"""ExploitationState — shared state schema for all agents and graph nodes.

This is the single most critical contract in the framework. Every agent
receives this state, performs its work, and returns a partial state update.
No agent modifies state directly — all updates flow through LangGraph's
immutable state model via reducers.

Field reducer strategy:
  - Overwrite (default): singleton values set once or replaced each step
  - Annotated[list, add]: accumulated across agents — new entries are appended
  - Annotated[list[AnyMessage], add_messages]: LangGraph's standard message reducer
"""

from copy import deepcopy
from typing import Any, TypedDict, Annotated
from operator import add

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages


class ExploitationState(TypedDict):
    # ── Target context (overwrite — set once) ──
    target_url: str
    security_level: str  # "low" | "medium" | "high"
    llm_provider: str  # "gemini"

    # ── Discovered attack surface (overwrite — set by recon) ──
    endpoints: list[dict]  # {url, method, params, csrf_token, module_name}
    input_vectors: list[dict]  # {param_name, param_type, endpoint_url}

    # ── Exploitation progress (accumulate across agents) ──
    confirmed_vulns: Annotated[list[str], add]  # knowledge graph nodes confirmed
    achieved_outcomes: Annotated[list[str], add]  # high-impact outcomes reached
    found_credentials: Annotated[list[dict], add]  # {username, password} pairs

    # ── Memory (accumulate across iterations) ──
    tried_payloads: dict[str, list[str]]  # module → list of tried payloads
    blocked_patterns: Annotated[list[str], add]
    successful_bypasses: Annotated[list[str], add]

    # ── Scoring (overwrite — max score per module) ──
    scores: dict[str, int]  # module_name → score 0-4

    # ── Chain tracking ──
    current_chain: list[str]  # active path (overwritten each step)
    chain_history: Annotated[list[dict], add]  # completed chains (accumulate)

    # ── LLM reasoning trace (accumulate with add_messages) ──
    messages: Annotated[list[AnyMessage], add_messages]

    # ── Guardrail monitoring (accumulate) ──
    guardrail_activations: Annotated[list[dict], add]  # {provider, context, snippet}

    # ── Control flow (overwrite) ──
    next_agent: str  # overwritten each step by orchestrator/chaining
    iteration_count: int  # overwritten each step
    max_iterations: int  # set once at init


def _default_state_template() -> dict[str, Any]:
    """Build a fresh default state template.

    Keeping this in a function avoids accidental shared mutable objects between
    independent runs when callers need a clean initial state.
    """
    return {
        "target_url": "",
        "security_level": "low",
        "llm_provider": "gemini",
        "endpoints": [],
        "input_vectors": [],
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
        "next_agent": "recon",
        "iteration_count": 0,
        "max_iterations": 30,
    }


# Backward-compatible exported default snapshot.
DEFAULT_STATE: dict[str, Any] = _default_state_template()


def new_default_state() -> dict[str, Any]:
    """Return a deep-copied default state for a new engagement."""
    return deepcopy(_default_state_template())

# Module names matching DVWA Coverage Matrix in summary.md
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

# Canonical mapping from MODULE_NAMES to their corresponding KG_NODES entry
# in confirmed_vulns.  This is needed because the naming conventions differ
# (e.g., "sqli_blind" → "blind_sqli_confirmed", not "sqli_blind_confirmed").
MODULE_TO_KG_NODE: dict[str, str] = {
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
}

# Knowledge graph node names used in confirmed_vulns
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
LLM_PROVIDERS: list[str] = ["gemini"]
