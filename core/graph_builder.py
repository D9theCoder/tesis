"""LangGraph workflow assembly (Stage 4)."""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from agents.orchestrator import orchestrator
from agents.tier1.cmdi_agent import cmdi_agent
from agents.tier1.sqli_agent import sqli_agent
from agents.tier1.sqli_blind_agent import sqli_blind_agent
from agents.tier1.xss_dom_agent import xss_dom_agent
from agents.tier1.xss_reflected_agent import xss_reflected_agent
from agents.tier1.xss_stored_agent import xss_stored_agent
from agents.tier2.brute_agent import brute_agent
from agents.tier2.csrf_agent import csrf_agent
from agents.tier2.idor_agent import idor_agent
from agents.tier2.lfi_agent import lfi_agent
from agents.tier2.upload_agent import upload_agent
from agents.tier2.weak_session_agent import weak_session_agent
from agents.tier3.lfi_to_rce_chain import lfi_to_rce_chain
from agents.tier3.sqli_to_creds_chain import sqli_to_creds_chain
from agents.tier3.upload_to_rce_chain import upload_to_rce_chain
from agents.tier3.xss_to_csrf_chain import xss_to_csrf_chain
from core.chaining_coordinator import route_after_agent
from core.state import ExploitationState
from foundation.recon import recon


RUNTIME_AGENT_NODE_NAMES: tuple[str, ...] = (
	"sqli_agent",
	"sqli_blind_agent",
	"xss_reflected_agent",
	"xss_stored_agent",
	"xss_dom_agent",
	"cmdi_agent",
	"brute_agent",
	"lfi_agent",
	"upload_agent",
	"csrf_agent",
	"weak_session_agent",
	"idor_agent",
	"sqli_to_creds_chain",
	"upload_to_rce_chain",
	"xss_to_csrf_chain",
	"lfi_to_rce_chain",
)


RUNTIME_AGENT_HANDLERS = {
	"sqli_agent": sqli_agent,
	"sqli_blind_agent": sqli_blind_agent,
	"xss_reflected_agent": xss_reflected_agent,
	"xss_stored_agent": xss_stored_agent,
	"xss_dom_agent": xss_dom_agent,
	"cmdi_agent": cmdi_agent,
	"brute_agent": brute_agent,
	"lfi_agent": lfi_agent,
	"upload_agent": upload_agent,
	"csrf_agent": csrf_agent,
	"weak_session_agent": weak_session_agent,
	"idor_agent": idor_agent,
	"sqli_to_creds_chain": sqli_to_creds_chain,
	"upload_to_rce_chain": upload_to_rce_chain,
	"xss_to_csrf_chain": xss_to_csrf_chain,
	"lfi_to_rce_chain": lfi_to_rce_chain,
}


def _scorer_placeholder(state: ExploitationState) -> dict:
	"""Temporary scorer node until Stage 6 scorer implementation lands."""
	return {"next_agent": "END"}


def route_from_orchestrator(state: ExploitationState) -> str:
	"""Map orchestrator decision to a known graph node safely."""
	next_agent = state.get("next_agent", "scorer")
	if next_agent in RUNTIME_AGENT_NODE_NAMES or next_agent == "scorer":
		return next_agent
	return "scorer"


def build_framework(llm_provider: str = "gemini"):
	"""Build and compile the Stage 4 execution graph."""
	# Keep the argument for API compatibility and future provider-specific wiring.
	_ = llm_provider

	graph = StateGraph(ExploitationState)

	graph.add_node("recon", recon)
	graph.add_node("orchestrator", orchestrator)
	graph.add_node("scorer", _scorer_placeholder)

	for name in RUNTIME_AGENT_NODE_NAMES:
		graph.add_node(name, RUNTIME_AGENT_HANDLERS[name])
		graph.add_conditional_edges(name, route_after_agent)

	graph.add_edge(START, "recon")
	graph.add_edge("recon", "orchestrator")
	graph.add_conditional_edges("orchestrator", route_from_orchestrator)
	graph.add_edge("scorer", END)

	return graph.compile()
