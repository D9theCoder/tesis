"""Orchestrator agent — Stage 4 runtime implementation.

Selects the next runtime node using AKG viable paths and LLM guidance,
with deterministic fallback behavior when the model fails or refuses.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage

from core.knowledge_graph import AttackKnowledgeGraph
from llm.guardrail_monitor import is_guardrail_refusal, make_guardrail_event
from llm.prompts.orchestrator_prompt import build_orchestrator_prompt
from llm.provider import get_llm

CRITICAL_OUTCOMES = set(AttackKnowledgeGraph.HIGH_IMPACT_OUTCOMES)

# Mapping from KG state nodes to executable runtime nodes.
KG_NODE_TO_AGENT: dict[str, str] = {
	"sqli_confirmed": "sqli_agent",
	"blind_sqli_confirmed": "sqli_blind_agent",
	"xss_reflected_confirmed": "xss_reflected_agent",
	"xss_stored_confirmed": "xss_stored_agent",
	"xss_dom_confirmed": "xss_dom_agent",
	"cmd_injection_confirmed": "cmdi_agent",
	"brute_force_confirmed": "brute_agent",
	"lfi_confirmed": "lfi_agent",
	"file_upload_confirmed": "upload_agent",
	"csrf_confirmed": "csrf_agent",
	"weak_session_confirmed": "weak_session_agent",
	"idor_confirmed": "idor_agent",
	"credentials_extracted": "sqli_to_creds_chain",
	"admin_session_obtained": "upload_to_rce_chain",
	"log_access_confirmed": "lfi_to_rce_chain",
	"user_compromised": "xss_to_csrf_chain",
}

STARTER_AGENT_ORDER: list[str] = [
	"sqli_agent",
	"brute_agent",
	"xss_reflected_agent",
]

ALLOWED_RUNTIME_NODES: set[str] = {
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
	"scorer",
}

CHAIN_RUNTIME_NODES: set[str] = {
	"sqli_to_creds_chain",
	"upload_to_rce_chain",
	"xss_to_csrf_chain",
	"lfi_to_rce_chain",
}


def _extract_response_text(raw_content: Any) -> str:
	"""Normalize heterogeneous LLM content payloads into plain text."""
	if isinstance(raw_content, str):
		return raw_content
	if isinstance(raw_content, list):
		parts: list[str] = []
		for item in raw_content:
			if isinstance(item, str):
				parts.append(item)
			elif isinstance(item, dict):
				text = item.get("text")
				if isinstance(text, str):
					parts.append(text)
		if parts:
			return "\n".join(parts)
	return str(raw_content)


def _find_ready_chain_agent(
	*,
	kg: AttackKnowledgeGraph,
	path: list[str],
	confirmed: set[str],
	known_outcomes: set[str],
) -> str | None:
	"""Pick a chain agent when a chain edge on the chosen path is executable."""
	for source, target in zip(path, path[1:]):
		if source not in confirmed:
			continue

		for edge in kg.get_next_actions(source):
			if edge.get("target") != target:
				continue
			if not edge.get("is_chain"):
				continue
			if target in known_outcomes:
				continue

			preconditions = set(edge.get("preconditions", []))
			if not preconditions.issubset(confirmed):
				continue

			target_agent = edge.get("target_agent")
			if isinstance(target_agent, str) and target_agent:
				return target_agent

	return None


def _fallback_next_agent(
	viable_paths: list[list[str]],
	confirmed_vulns: list[str],
	achieved_outcomes: list[str] | None = None,
) -> tuple[str, list[str]]:
	"""Choose a deterministic next runtime node without relying on the LLM."""
	confirmed = set(confirmed_vulns)
	known_outcomes = confirmed | set(achieved_outcomes or [])
	kg = AttackKnowledgeGraph()

	if viable_paths:
		chosen = viable_paths[0]

		# Prefer direct chain continuation whenever preconditions are met.
		chain_agent = _find_ready_chain_agent(
			kg=kg,
			path=chosen,
			confirmed=confirmed,
			known_outcomes=known_outcomes,
		)
		if chain_agent:
			return chain_agent, chosen

		# Otherwise continue probing from already-confirmed steps on this path.
		for node in chosen:
			if node in confirmed:
				mapped = KG_NODE_TO_AGENT.get(node)
				if mapped:
					return mapped, chosen

		# Last resort for path-based fallback: map first unmet state.
		for node in chosen:
			if node not in confirmed:
				mapped = KG_NODE_TO_AGENT.get(node)
				if mapped:
					return mapped, chosen

	# Fresh-state fallback: always start with a deterministic Tier-1 agent.
	if not confirmed:
		return STARTER_AGENT_ORDER[0], []

	# If we have confirmations but no viable path, keep progressing if possible.
	for node in sorted(confirmed):
		mapped = KG_NODE_TO_AGENT.get(node)
		if mapped:
			return mapped, []

	return "scorer", []


def _chain_candidate_is_ready(
	*,
	candidate: str,
	confirmed: set[str],
	achieved_outcomes: set[str],
	viable_paths: list[list[str]],
) -> bool:
	"""Return True when a proposed chain runtime node is currently executable."""
	if candidate not in CHAIN_RUNTIME_NODES:
		return True

	known_outcomes = confirmed | achieved_outcomes
	kg = AttackKnowledgeGraph()

	for path in viable_paths:
		ready = _find_ready_chain_agent(
			kg=kg,
			path=path,
			confirmed=confirmed,
			known_outcomes=known_outcomes,
		)
		if ready == candidate:
			return True

	for node in sorted(confirmed):
		for edge in kg.get_next_actions(node):
			if not edge.get("is_chain"):
				continue
			if edge.get("target_agent") != candidate:
				continue
			if edge.get("target") in known_outcomes:
				continue

			preconditions = set(edge.get("preconditions", []))
			if preconditions.issubset(confirmed):
				return True

	return False


def _chain_for_agent(
	*,
	agent_name: str,
	viable_paths: list[list[str]],
	confirmed: set[str],
	achieved_outcomes: set[str],
) -> list[str]:
	"""Return the most relevant viable path for a selected runtime agent."""
	if not viable_paths:
		return []

	kg = AttackKnowledgeGraph()
	known_outcomes = confirmed | achieved_outcomes

	for path in viable_paths:
		if agent_name in CHAIN_RUNTIME_NODES:
			ready = _find_ready_chain_agent(
				kg=kg,
				path=path,
				confirmed=confirmed,
				known_outcomes=known_outcomes,
			)
			if ready == agent_name:
				return path

		for node in path:
			if KG_NODE_TO_AGENT.get(node) == agent_name:
				return path

	return []


def orchestrator(state: dict[str, Any]) -> dict[str, Any]:
	"""LangGraph node: select the next agent based on AKG + LLM strategy."""
	iteration_count = state.get("iteration_count", 0)
	max_iterations = state.get("max_iterations", 30)
	confirmed_vulns = state.get("confirmed_vulns", [])
	confirmed_set = set(confirmed_vulns)
	achieved_outcomes = state.get("achieved_outcomes", [])
	achieved_set = set(achieved_outcomes)

	if iteration_count >= max_iterations:
		return {"next_agent": "scorer"}

	if (achieved_set | confirmed_set) & CRITICAL_OUTCOMES:
		return {"next_agent": "scorer"}

	kg = AttackKnowledgeGraph()
	viable_paths = kg.get_viable_chains(
		confirmed_vulns=confirmed_vulns,
		achieved_outcomes=achieved_outcomes,
		max_paths=5,
	)

	fallback_agent, fallback_chain = _fallback_next_agent(
		viable_paths=viable_paths,
		confirmed_vulns=confirmed_vulns,
		achieved_outcomes=achieved_outcomes,
	)

	prompt = build_orchestrator_prompt(
		confirmed_vulns=confirmed_vulns,
		achieved_outcomes=achieved_outcomes,
		viable_paths=viable_paths,
		security_level=state.get("security_level", "low"),
		iteration_count=iteration_count,
		max_iterations=max_iterations,
	)

	try:
		llm = get_llm(state.get("llm_provider", "gemini"))
		response = llm.invoke([HumanMessage(content=prompt)])
		text = _extract_response_text(getattr(response, "content", ""))

		if is_guardrail_refusal(text):
			return {
				"next_agent": fallback_agent,
				"current_chain": fallback_chain,
				"guardrail_activations": [
					make_guardrail_event(
						provider=state.get("llm_provider", "gemini"),
						context="orchestrator",
						response=text,
					)
				],
				"messages": [
					HumanMessage(content=prompt),
					AIMessage(content=text),
				],
			}

		parsed = json.loads(text)
		candidate: Any
		candidate = parsed.get("next_agent", fallback_agent) if isinstance(parsed, dict) else fallback_agent
		if not isinstance(candidate, str):
			candidate = fallback_agent

		if not _chain_candidate_is_ready(
			candidate=candidate,
			confirmed=confirmed_set,
			achieved_outcomes=achieved_set,
			viable_paths=viable_paths,
		):
			candidate = fallback_agent

		next_agent = candidate if candidate in ALLOWED_RUNTIME_NODES else fallback_agent
		selected_chain = _chain_for_agent(
			agent_name=next_agent,
			viable_paths=viable_paths,
			confirmed=confirmed_set,
			achieved_outcomes=achieved_set,
		)

		return {
			"next_agent": next_agent,
			"current_chain": selected_chain or (fallback_chain if next_agent == fallback_agent else []),
			"messages": [
				HumanMessage(content=prompt),
				AIMessage(content=text),
			],
		}
	except Exception as exc:
		return {
			"next_agent": fallback_agent,
			"current_chain": fallback_chain,
			"messages": [
				HumanMessage(content=prompt),
				AIMessage(content=f"orchestrator_fallback:{type(exc).__name__}"),
			],
		}
