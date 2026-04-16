"""Chaining Coordinator — Stage 4 conditional edge routing.

Routes execution after Tier/chain nodes complete by consulting AKG metadata.
"""

from __future__ import annotations

from core.knowledge_graph import AttackKnowledgeGraph

HIGH_IMPACT_OUTCOMES = set(AttackKnowledgeGraph.HIGH_IMPACT_OUTCOMES)


def critical_outcome_achieved(state: dict) -> bool:
	"""Return True when any high-impact outcome is already achieved."""
	achieved = set(state.get("achieved_outcomes", []))
	confirmed = set(state.get("confirmed_vulns", []))
	return bool((achieved | confirmed) & HIGH_IMPACT_OUTCOMES)


def route_after_agent(state: dict) -> str:
	"""Conditional-edge router executed after vulnerability/chain agents."""
	iteration_count = state.get("iteration_count", 0)
	max_iterations = state.get("max_iterations", 30)

	if iteration_count >= max_iterations:
		return "scorer"

	confirmed = set(state.get("confirmed_vulns", []))
	achieved = set(state.get("achieved_outcomes", []))
	known = confirmed | achieved
	kg = AttackKnowledgeGraph()

	for node in sorted(confirmed):
		for edge in kg.get_next_actions(node):
			if not edge.get("is_chain"):
				continue
			if edge.get("target") in known:
				continue

			preconditions = set(edge.get("preconditions", []))
			if not preconditions.issubset(confirmed):
				continue

			target_agent = edge.get("target_agent")
			if isinstance(target_agent, str) and target_agent:
				return target_agent

	if critical_outcome_achieved(state):
		return "scorer"

	return "orchestrator"
