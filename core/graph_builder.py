"""LangGraph workflow assembly (3-surface deep-method)."""

from __future__ import annotations

import logging

from langgraph.graph import END, START, StateGraph

from agents.orchestrator import orchestrator
from agents.sqli.sqli_union_agent import sqli_union_agent
from agents.sqli.sqli_error_agent import sqli_error_agent
from agents.sqli.sqli_boolean_blind_agent import sqli_boolean_blind_agent
from agents.sqli.sqli_time_blind_agent import sqli_time_blind_agent
from agents.access_control.ac_idor_agent import ac_idor_agent
from agents.access_control.ac_vertical_escalation_agent import ac_vertical_escalation_agent
from agents.access_control.ac_force_browse_agent import ac_force_browse_agent
from agents.brute_force.bf_dictionary_agent import bf_dictionary_agent
from agents.brute_force.bf_spray_agent import bf_spray_agent
from core.chaining_coordinator import chaining_router_node
from core.state import ExploitationState
from foundation.recon import recon


RUNTIME_AGENT_NODE_NAMES: tuple[str, ...] = (
    "sqli_union",
    "sqli_error",
    "sqli_boolean_blind",
    "sqli_time_blind",
    "ac_idor",
    "ac_vertical_escalation",
    "ac_force_browse",
    "bf_dictionary",
    "bf_spray",
)

RUNTIME_AGENT_HANDLERS = {
    "sqli_union": sqli_union_agent,
    "sqli_error": sqli_error_agent,
    "sqli_boolean_blind": sqli_boolean_blind_agent,
    "sqli_time_blind": sqli_time_blind_agent,
    "ac_idor": ac_idor_agent,
    "ac_vertical_escalation": ac_vertical_escalation_agent,
    "ac_force_browse": ac_force_browse_agent,
    "bf_dictionary": bf_dictionary_agent,
    "bf_spray": bf_spray_agent,
}


def route_from_orchestrator(state: ExploitationState) -> str:
    next_agent = state.get("next_agent", "scorer")
    if next_agent in RUNTIME_AGENT_NODE_NAMES or next_agent == "scorer":
        return next_agent
    logging.getLogger(__name__).warning("Unknown next_agent %r — falling back to scorer", next_agent)
    return "scorer"


def route_from_chaining_router(state: ExploitationState) -> str:
    next_agent = state.get("next_agent", "scorer")
    if next_agent in RUNTIME_AGENT_NODE_NAMES or next_agent in {"orchestrator", "scorer"}:
        return next_agent
    return "scorer"


# NOTE: llm_provider and surface are accepted for API compatibility but currently
# do not alter graph topology. Future per-surface or per-provider customization
# may use these parameters.
def build_framework(llm_provider: str = "gemini", surface: str = "sqli"):
    # Lazy import to avoid circular dependency: scorer imports from core.state
    # which is imported by graph_builder.
    from core.scorer import scorer
    graph = StateGraph(ExploitationState)
    graph.add_node("recon", recon)
    graph.add_node("orchestrator", orchestrator)
    graph.add_node("chaining_router", chaining_router_node)
    graph.add_node("scorer", scorer)
    for name in RUNTIME_AGENT_NODE_NAMES:
        graph.add_node(name, RUNTIME_AGENT_HANDLERS[name])
        graph.add_edge(name, "chaining_router")
    graph.add_edge(START, "recon")
    graph.add_edge("recon", "orchestrator")
    graph.add_conditional_edges("orchestrator", route_from_orchestrator)
    graph.add_conditional_edges("chaining_router", route_from_chaining_router)
    graph.add_edge("scorer", END)
    from langgraph.checkpoint.memory import MemorySaver
    return graph.compile(checkpointer=MemorySaver())
