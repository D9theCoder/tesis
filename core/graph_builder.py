"""LangGraph workflow assembly (Stage 4)."""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from agents.orchestrator import orchestrator
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


def _scorer_placeholder(state: ExploitationState) -> dict:
	"""Temporary scorer node until Stage 6 scorer implementation lands."""
	return {"next_agent": "END"}


def _make_agent_placeholder(name: str):
	"""Build placeholder nodes for not-yet-implemented Tier/chain agents."""

	def _run(state: ExploitationState) -> dict:
		max_iterations = state.get("max_iterations", 30)
		return {
			"next_agent": "orchestrator",
			# Fast-fail placeholder execution so Stage-4 runtime remains bounded
			# until real Tier/chain agents are implemented in Stage 5.
			"iteration_count": max_iterations,
		}

	_run.__name__ = f"{name}_placeholder"
	return _run


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

	# Temporary placeholders until Stage 5 agent implementations are added.
	for name in RUNTIME_AGENT_NODE_NAMES:
		graph.add_node(name, _make_agent_placeholder(name))
		graph.add_conditional_edges(name, route_after_agent)

	graph.add_edge(START, "recon")
	graph.add_edge("recon", "orchestrator")
	graph.add_conditional_edges("orchestrator", route_from_orchestrator)
	graph.add_edge("scorer", END)

	return graph.compile()
