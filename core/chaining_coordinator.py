"""Chaining Coordinator — Stage 4 conditional edge routing.

Routes execution after Tier/chain nodes complete by consulting AKG metadata.
"""

from __future__ import annotations

from core.knowledge_graph import AttackKnowledgeGraph

HIGH_IMPACT_OUTCOMES = set(AttackKnowledgeGraph.HIGH_IMPACT_OUTCOMES)
CHAIN_ATTEMPT_MARKERS: dict[str, str] = {
	"sqli_to_creds_chain": "chain:sqli_to_creds",
	"upload_to_rce_chain": "chain:upload_to_rce",
	"xss_to_csrf_chain": "chain:xss_to_csrf",
	"lfi_to_rce_chain": "chain:lfi_to_rce",
}


def critical_outcome_achieved(state: dict) -> bool:
	"""Return True when any high-impact outcome is already achieved."""
	achieved = set(state.get("achieved_outcomes", []))
	confirmed = set(state.get("confirmed_vulns", []))
	return bool((achieved | confirmed) & HIGH_IMPACT_OUTCOMES)


def _chain_already_attempted(state: dict, target_agent: str) -> bool:
	"""Return True when a chain marker is already present in tried_payloads."""
	marker = CHAIN_ATTEMPT_MARKERS.get(target_agent)
	if not marker:
		return False

	tried_payloads = state.get("tried_payloads", {})
	if not isinstance(tried_payloads, dict):
		return False

	for payloads in tried_payloads.values():
		if isinstance(payloads, list) and marker in payloads:
			return True

	return False


def route_after_agent(state: dict) -> str:
	"""Conditional-edge router executed after vulnerability/chain agents."""
	next_agent, _ = evaluate_chain_route(state)
	return next_agent


def evaluate_chain_route(state: dict) -> tuple[str, dict]:
	"""Evaluate next route and return a telemetry event for the decision."""
	iteration_count = state.get("iteration_count", 0)
	max_iterations = state.get("max_iterations", 30)
	stop_policy_raw = str(state.get("stop_policy", "impact") or "impact").strip().lower()
	stop_policy = stop_policy_raw if stop_policy_raw in {"impact", "coverage"} else "impact"

	if iteration_count >= max_iterations:
		next_agent = "scorer"
		return next_agent, {
			"node": "chaining_router",
			"iteration": iteration_count,
			"event": "akg.route.selected",
			"next_agent": next_agent,
			"reason": "budget_exhausted",
		}

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
			if isinstance(target_agent, str) and target_agent and not _chain_already_attempted(state, target_agent):
				return target_agent, {
					"node": "chaining_router",
					"iteration": iteration_count,
					"event": "akg.route.selected",
					"next_agent": target_agent,
					"reason": "chain_ready",
					"source": node,
					"target": edge.get("target"),
				}

	if stop_policy == "impact" and critical_outcome_achieved(state):
		next_agent = "scorer"
		return next_agent, {
			"node": "chaining_router",
			"iteration": iteration_count,
			"event": "akg.route.selected",
			"next_agent": next_agent,
			"reason": "critical_outcome",
			"stop_policy": stop_policy,
		}

	next_agent = "orchestrator"
	return next_agent, {
		"node": "chaining_router",
		"iteration": iteration_count,
		"event": "akg.route.selected",
		"next_agent": next_agent,
		"reason": "no_chain",
		"stop_policy": stop_policy,
	}


def chaining_router_node(state: dict) -> dict:
	"""LangGraph node wrapper that emits routing telemetry and sets next_agent."""
	next_agent, event = evaluate_chain_route(state)
	return {
		"next_agent": next_agent,
		"telemetry_events": [event],
	}
