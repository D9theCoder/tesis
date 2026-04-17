"""Attack Knowledge Graph built on NetworkX (Stage 3).

This module provides deterministic, contract-aligned AKG query helpers used by
later runtime components (Stage 4 consumers).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict

import networkx as nx

from core.state import KG_NODES


class RawTransition(TypedDict, total=False):
	"""Raw transition shape used for graph definition and normalization."""

	source: str
	target: str
	is_chain: bool
	preconditions: list[str]  # canonical
	precondition: str | list[str]  # compatibility alias
	target_agent: str  # canonical
	agent: str  # compatibility alias
	priority: int


@dataclass(frozen=True, slots=True)
class Transition:
	"""Normalized transition metadata used internally by the AKG."""

	source: str
	target: str
	is_chain: bool
	preconditions: tuple[str, ...]
	target_agent: str | None
	priority: int = 100


class AttackKnowledgeGraph:
	"""Deterministic attack-state graph for Stage 3 domain logic."""

	HIGH_IMPACT_OUTCOMES: tuple[str, ...] = (
		"admin_session_obtained",
		"rce_achieved",
		"user_compromised",
		"data_exfiltrated",
		"session_hijack",
	)

	def __init__(self) -> None:
		self.graph: nx.DiGraph = nx.DiGraph()
		self._build_graph()
		self._validate_graph()

	@staticmethod
	def _as_preconditions(value: str | list[str] | None) -> list[str]:
		"""Coerce canonical/alias preconditions into list form."""

		if value is None:
			return []
		if isinstance(value, str):
			return [value]
		return [item for item in value if isinstance(item, str)]

	def _normalize_transition(self, raw: RawTransition) -> Transition:
		"""Normalize compatibility aliases to canonical transition metadata."""

		preconditions_raw = raw.get("preconditions", raw.get("precondition"))
		target_agent_raw = raw.get("target_agent", raw.get("agent"))

		preconditions = tuple(sorted(set(self._as_preconditions(preconditions_raw))))
		is_chain = bool(raw.get("is_chain", False))
		priority = int(raw.get("priority", 100))

		return Transition(
			source=str(raw["source"]),
			target=str(raw["target"]),
			is_chain=is_chain,
			preconditions=preconditions,
			target_agent=str(target_agent_raw) if target_agent_raw is not None else None,
			priority=priority,
		)

	def _build_graph(self) -> None:
		"""Build AKG using canonical KG_NODES vocabulary and transitions."""

		self.graph.add_nodes_from(sorted(KG_NODES))

		transitions: list[RawTransition] = [
			# Non-chain transitions
			{
				"source": "sqli_confirmed",
				"target": "credentials_extracted",
				"is_chain": False,
				"priority": 20,
			},
			{
				"source": "brute_force_confirmed",
				"target": "credentials_extracted",
				"is_chain": False,
				"priority": 20,
			},
			{
				"source": "blind_sqli_confirmed",
				"target": "data_exfiltrated",
				"is_chain": False,
				"priority": 30,
			},
			{
				"source": "idor_confirmed",
				"target": "data_exfiltrated",
				"is_chain": False,
				"priority": 30,
			},
			{
				"source": "csrf_confirmed",
				"target": "user_compromised",
				"is_chain": False,
				"priority": 30,
			},
			{
				"source": "weak_session_confirmed",
				"target": "session_hijack",
				"is_chain": False,
				"priority": 30,
			},
			{
				"source": "cmd_injection_confirmed",
				"target": "rce_achieved",
				"is_chain": False,
				"priority": 30,
			},
			{
				"source": "file_upload_confirmed",
				"target": "rce_achieved",
				"is_chain": False,
				"priority": 30,
			},
			{
				"source": "lfi_confirmed",
				"target": "log_access_confirmed",
				"is_chain": False,
				"priority": 20,
			},
			# Chain transitions
			{
				"source": "credentials_extracted",
				"target": "admin_session_obtained",
				"is_chain": True,
				"preconditions": ["credentials_extracted"],
				"target_agent": "sqli_to_creds_chain",
				"priority": 10,
			},
			{
				"source": "admin_session_obtained",
				"target": "rce_achieved",
				"is_chain": True,
				"preconditions": ["admin_session_obtained"],
				"target_agent": "upload_to_rce_chain",
				"priority": 10,
			},
			{
				"source": "xss_stored_confirmed",
				"target": "user_compromised",
				"is_chain": True,
				"preconditions": ["xss_stored_confirmed"],
				"target_agent": "xss_to_csrf_chain",
				"priority": 10,
			},
			{
				"source": "log_access_confirmed",
				"target": "rce_achieved",
				"is_chain": True,
				"preconditions": ["lfi_confirmed", "log_access_confirmed"],
				"target_agent": "lfi_to_rce_chain",
				"priority": 10,
			},
		]

		for raw in transitions:
			normalized = self._normalize_transition(raw)
			self.graph.add_edge(
				normalized.source,
				normalized.target,
				is_chain=normalized.is_chain,
				preconditions=list(normalized.preconditions),
				target_agent=normalized.target_agent,
				priority=normalized.priority,
			)

	def _validate_graph(self) -> None:
		"""Run fail-fast validation checks for graph integrity."""

		self._validate_nodes_in_kg_nodes()
		self._validate_chain_metadata()
		self._validate_preconditions_known()
		self._validate_high_impact_nodes_exist()

	def _validate_nodes_in_kg_nodes(self) -> None:
		"""Ensure graph nodes remain within canonical KG_NODES vocabulary."""

		allowed = set(KG_NODES)
		unknown = sorted(node for node in self.graph.nodes if node not in allowed)
		if unknown:
			raise ValueError(f"Unknown graph nodes not in KG_NODES: {unknown}")

	def _validate_chain_metadata(self) -> None:
		"""Require complete metadata on chain edges."""

		for source, target, meta in self.graph.edges(data=True):
			if not bool(meta.get("is_chain", False)):
				continue
			if "preconditions" not in meta:
				raise ValueError(
					f"Chain edge {source}->{target} missing preconditions"
				)
			preconditions = meta.get("preconditions")
			if not isinstance(preconditions, list) or not all(
				isinstance(item, str) for item in preconditions
			):
				raise ValueError(
					f"Chain edge {source}->{target} has invalid preconditions"
				)
			if not meta.get("target_agent"):
				raise ValueError(f"Chain edge {source}->{target} missing target_agent")

	def _validate_preconditions_known(self) -> None:
		"""Ensure all preconditions reference known KG nodes."""

		allowed = set(KG_NODES)
		for source, target, meta in self.graph.edges(data=True):
			for required in meta.get("preconditions", []):
				if required not in allowed:
					raise ValueError(
						f"Edge {source}->{target} has unknown precondition: {required}"
					)

	def _validate_high_impact_nodes_exist(self) -> None:
		"""Ensure high-impact terminal outcome nodes exist in graph."""

		missing = [node for node in self.HIGH_IMPACT_OUTCOMES if node not in self.graph]
		if missing:
			raise ValueError(f"Missing high-impact outcomes in graph: {missing}")

	def get_next_actions(self, node: str) -> list[dict]:
		"""Return deterministic outgoing transitions for a given node."""

		if node not in self.graph:
			return []

		actions: list[tuple[int, dict]] = []
		for _, target, meta in self.graph.out_edges(node, data=True):
			normalized = self._normalize_transition(
				{
					"source": node,
					"target": target,
					"is_chain": bool(meta.get("is_chain", False)),
					"preconditions": list(meta.get("preconditions", [])),
					"target_agent": meta.get("target_agent"),
					"priority": int(meta.get("priority", 100)),
				}
			)
			actions.append(
				(
					normalized.priority,
					{
						"source": normalized.source,
						"target": normalized.target,
						"is_chain": normalized.is_chain,
						"preconditions": list(normalized.preconditions),
						"target_agent": normalized.target_agent,
					},
				)
			)

		ordered = sorted(
			actions,
			key=lambda item: (
				item[0],
				item[1]["target"],
				item[1]["target_agent"] or "",
			),
		)
		return [action for _, action in ordered]

	def _path_is_viable(self, path: list[str], known_nodes: set[str]) -> bool:
		"""Check whether all chain-edge preconditions in a path are satisfied."""

		for source, target in zip(path, path[1:]):
			edge = self.graph[source][target]
			if not bool(edge.get("is_chain", False)):
				continue
			required = set(edge.get("preconditions", []))
			if not required.issubset(known_nodes):
				return False
		return True

	def get_viable_chains(
		self,
		confirmed_vulns: list[str],
		achieved_outcomes: list[str] | None = None,
		max_paths: int = 5,
	) -> list[list[str]]:
		"""Return deterministic viable paths from known states to high-impact outcomes."""

		if max_paths <= 0:
			return []

		achieved = set(achieved_outcomes or [])
		known = set(confirmed_vulns) | achieved
		targets = [
			outcome for outcome in self.HIGH_IMPACT_OUTCOMES if outcome not in achieved
		]

		candidates: set[tuple[str, ...]] = set()
		for start in sorted(set(confirmed_vulns)):
			if start not in self.graph:
				continue
			for target in sorted(targets):
				if target not in self.graph or start == target:
					continue
				for path in nx.all_simple_paths(
					self.graph,
					source=start,
					target=target,
					cutoff=6,
				):
					if self._path_is_viable(path, known):
						candidates.add(tuple(path))

		ordered = sorted(candidates, key=lambda path: (len(path), path))
		return [list(path) for path in ordered[:max_paths]]
