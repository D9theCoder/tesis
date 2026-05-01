"""Attack Knowledge Graph built on NetworkX (3-surface deep-method architecture)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict

import networkx as nx

from core.state import METHODS_BY_SURFACE, MODULE_TO_KG_NODE, ALL_METHOD_AGENTS


class RawTransition(TypedDict, total=False):
    source: str
    target: str
    is_chain: bool
    preconditions: list[str]
    precondition: str | list[str]
    target_agent: str
    agent: str
    priority: int


@dataclass(frozen=True, slots=True)
class Transition:
    source: str
    target: str
    is_chain: bool
    preconditions: tuple[str, ...]
    target_agent: str | None
    priority: int = 100


class AttackKnowledgeGraph:
    HIGH_IMPACT_OUTCOMES: tuple[str, ...] = (
        "admin_session_obtained",
        "data_exfiltrated",
    )

    # Method preconditions: what observation keys must be True
    METHOD_PRECONDITIONS: dict[str, list[str]] = {
        "sqli_union": ["union_select_possible"],
        "sqli_error": ["error_messages_enabled"],
        "sqli_boolean_blind": ["response_diff_detectable"],
        "sqli_time_blind": ["response_delay_measurable"],
        "ac_idor": ["object_ids_enumerable"],
        "ac_vertical_escalation": ["role_based_access_present"],
        "ac_force_browse": ["force_browse_endpoints_visible"],
        "bf_dictionary": ["no_rate_limit"],
        "bf_spray": ["no_rate_limit"],
    }

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self._build_graph()
        self._validate_graph()

    @staticmethod
    def _as_preconditions(value: str | list[str] | None) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [item for item in value if isinstance(item, str)]

    def _normalize_transition(self, raw: RawTransition) -> Transition:
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
        # Nodes: surfaces, methods, confirmed methods, outcomes
        nodes = [
            # Entry node
            "unauthenticated",
            # Surface nodes
            "sqli", "access_control", "brute_force",
            # Intermediate chain nodes
            "authenticated_session",
            # Method nodes
            "sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind",
            "ac_idor", "ac_vertical_escalation", "ac_force_browse",
            "bf_dictionary", "bf_spray",
            # Confirmed nodes
            "sqli_union_confirmed", "sqli_error_confirmed",
            "sqli_boolean_blind_confirmed", "sqli_time_blind_confirmed",
            "ac_idor_confirmed", "ac_vertical_escalation_confirmed", "ac_force_browse_confirmed",
            "bf_dictionary_confirmed", "bf_spray_confirmed",
            # Surface confirmed nodes
            "sqli_confirmed", "access_control_confirmed", "brute_force_confirmed",
            # Outcome nodes
            "credentials_extracted", "admin_session_obtained",
            "data_exfiltrated",
        ]
        self.graph.add_nodes_from(sorted(set(nodes)))

        transitions: list[RawTransition] = [
            # Entry -> surface (discovery edges)
            {"source": "unauthenticated", "target": "sqli", "priority": 100},
            {"source": "unauthenticated", "target": "access_control", "priority": 100},
            {"source": "unauthenticated", "target": "brute_force", "priority": 100},
            # Surface -> method (non-chain, discovery edges)
            {"source": "sqli", "target": "sqli_union", "priority": 100},
            {"source": "sqli", "target": "sqli_error", "priority": 100},
            {"source": "sqli", "target": "sqli_boolean_blind", "priority": 100},
            {"source": "sqli", "target": "sqli_time_blind", "priority": 100},
            {"source": "access_control", "target": "ac_idor", "priority": 100},
            {"source": "access_control", "target": "ac_vertical_escalation", "priority": 100},
            {"source": "access_control", "target": "ac_force_browse", "priority": 100},
            {"source": "brute_force", "target": "bf_dictionary", "priority": 100},
            {"source": "brute_force", "target": "bf_spray", "priority": 100},
            # Method -> confirmed (non-chain)
            {"source": "sqli_union", "target": "sqli_union_confirmed", "priority": 50},
            {"source": "sqli_error", "target": "sqli_error_confirmed", "priority": 50},
            {"source": "sqli_boolean_blind", "target": "sqli_boolean_blind_confirmed", "priority": 50},
            {"source": "sqli_time_blind", "target": "sqli_time_blind_confirmed", "priority": 50},
            {"source": "ac_idor", "target": "ac_idor_confirmed", "priority": 50},
            {"source": "ac_vertical_escalation", "target": "ac_vertical_escalation_confirmed", "priority": 50},
            {"source": "ac_force_browse", "target": "ac_force_browse_confirmed", "priority": 50},
            {"source": "bf_dictionary", "target": "bf_dictionary_confirmed", "priority": 50},
            {"source": "bf_spray", "target": "bf_spray_confirmed", "priority": 50},
            # Method confirmed -> surface confirmed
            {"source": "sqli_union_confirmed", "target": "sqli_confirmed", "priority": 40},
            {"source": "sqli_error_confirmed", "target": "sqli_confirmed", "priority": 40},
            {"source": "sqli_boolean_blind_confirmed", "target": "sqli_confirmed", "priority": 40},
            {"source": "sqli_time_blind_confirmed", "target": "sqli_confirmed", "priority": 40},
            {"source": "ac_idor_confirmed", "target": "access_control_confirmed", "priority": 40},
            {"source": "ac_vertical_escalation_confirmed", "target": "access_control_confirmed", "priority": 40},
            {"source": "ac_force_browse_confirmed", "target": "access_control_confirmed", "priority": 40},
            {"source": "bf_dictionary_confirmed", "target": "brute_force_confirmed", "priority": 40},
            {"source": "bf_spray_confirmed", "target": "brute_force_confirmed", "priority": 40},
            # Non-chain outcomes
            {"source": "sqli_confirmed", "target": "credentials_extracted", "priority": 30},
            {"source": "sqli_confirmed", "target": "data_exfiltrated", "priority": 30},
            {"source": "brute_force_confirmed", "target": "credentials_extracted", "priority": 30},
            {"source": "access_control_confirmed", "target": "data_exfiltrated", "priority": 30},
            # Cross-surface chains
            {
                "source": "brute_force_confirmed",
                "target": "authenticated_session",
                "is_chain": True,
                "preconditions": ["brute_force_confirmed"],
                "target_agent": "ac_idor",
                "priority": 10,
            },
            {
                "source": "authenticated_session",
                "target": "ac_idor",
                "is_chain": True,
                "preconditions": ["authenticated_session"],
                "target_agent": "ac_idor",
                "priority": 10,
            },
            {
                "source": "sqli_confirmed",
                "target": "credentials_extracted",
                "is_chain": True,
                "preconditions": ["sqli_confirmed"],
                "target_agent": "bf_dictionary",
                "priority": 10,
            },
            {
                "source": "credentials_extracted",
                "target": "brute_force_confirmed",
                "is_chain": True,
                "preconditions": ["credentials_extracted"],
                "target_agent": "bf_dictionary",
                "priority": 10,
            },
            {
                "source": "ac_vertical_escalation_confirmed",
                "target": "admin_session_obtained",
                "is_chain": True,
                "preconditions": ["ac_vertical_escalation_confirmed"],
                "target_agent": "sqli_union",
                "priority": 10,
            },
            {
                "source": "admin_session_obtained",
                "target": "sqli_union",
                "is_chain": True,
                "preconditions": ["admin_session_obtained"],
                "target_agent": "sqli_union",
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
        self._validate_chain_metadata()
        self._validate_preconditions_known()
        self._validate_high_impact_nodes_exist()
        self._validate_agent_kg_node_mappings()

    def _validate_chain_metadata(self) -> None:
        for source, target, meta in self.graph.edges(data=True):
            if not bool(meta.get("is_chain", False)):
                continue
            if "preconditions" not in meta:
                raise ValueError(f"Chain edge {source}->{target} missing preconditions")
            preconditions = meta.get("preconditions")
            if not isinstance(preconditions, list) or not all(isinstance(item, str) for item in preconditions):
                raise ValueError(f"Chain edge {source}->{target} has invalid preconditions")
            if not meta.get("target_agent"):
                raise ValueError(f"Chain edge {source}->{target} missing target_agent")

    def _validate_preconditions_known(self) -> None:
        allowed = set(self.graph.nodes)
        for source, target, meta in self.graph.edges(data=True):
            for required in meta.get("preconditions", []):
                if required not in allowed:
                    raise ValueError(f"Edge {source}->{target} has unknown precondition: {required}")

    def _validate_high_impact_nodes_exist(self) -> None:
        missing = [node for node in self.HIGH_IMPACT_OUTCOMES if node not in self.graph]
        if missing:
            raise ValueError(f"Missing high-impact outcomes in graph: {missing}")

    def _validate_agent_kg_node_mappings(self) -> None:
        """Validate that every MODULE_TO_KG_NODE value for method agents
        exists as a node in the AKG graph.

        This prevents the class of bug where an agent maps to a confirmed
        node that doesn't exist in the graph (e.g., blind_sqli_confirmed
        before Stage 9C fix), causing silent chain lookup failures.
        """
        graph_nodes = set(self.graph.nodes)
        for agent in ALL_METHOD_AGENTS:
            kg_node = MODULE_TO_KG_NODE.get(agent)
            if kg_node is None:
                continue  # unknown agents are not validated here
            if kg_node not in graph_nodes:
                raise ValueError(
                    f"MODULE_TO_KG_NODE[{agent!r}] maps to {kg_node!r} "
                    f"which does not exist in the AKG graph"
                )

    def get_viable_methods(self, surface: str, observations: dict) -> list[str]:
        """Return method nodes for a surface whose preconditions are satisfied."""
        methods = METHODS_BY_SURFACE.get(surface, [])
        viable = []
        for method in methods:
            preconditions = self.METHOD_PRECONDITIONS.get(method, [])
            if all(observations.get(p, False) for p in preconditions):
                viable.append(method)
        return viable

    def check_preconditions(self, method_node: str, observations: dict) -> bool:
        preconditions = self.METHOD_PRECONDITIONS.get(method_node, [])
        return all(observations.get(p, False) for p in preconditions)

    def get_next_actions(self, node: str) -> list[dict]:
        if node not in self.graph:
            return []
        actions: list[tuple[int, dict]] = []
        for _, target, meta in self.graph.out_edges(node, data=True):
            actions.append((
                int(meta.get("priority", 100)),
                {
                    "source": node,
                    "target": target,
                    "is_chain": bool(meta.get("is_chain", False)),
                    "preconditions": list(meta.get("preconditions", [])),
                    "target_agent": meta.get("target_agent"),
                },
            ))
        ordered = sorted(actions, key=lambda item: (item[0], item[1]["target"], item[1]["target_agent"] or ""))
        return [action for _, action in ordered]

    def _path_is_viable(self, path: list[str], known_nodes: set[str]) -> bool:
        has_chain_edge = False
        for source, target in zip(path, path[1:]):
            edge = self.graph[source][target]
            if bool(edge.get("is_chain", False)):
                has_chain_edge = True
            required = set(edge.get("preconditions", []))
            if not required.issubset(known_nodes):
                return False
        return has_chain_edge

    def get_viable_chains(self, confirmed_vulns: list[str], achieved_outcomes: list[str] | None = None, max_paths: int = 5) -> list[list[str]]:
        if max_paths <= 0:
            return []
        achieved = set(achieved_outcomes or [])
        known = set(confirmed_vulns) | achieved
        targets = [outcome for outcome in self.HIGH_IMPACT_OUTCOMES if outcome not in achieved]
        candidates: set[tuple[str, ...]] = set()
        for start in sorted(set(confirmed_vulns)):
            if start not in self.graph:
                continue
            for target in sorted(targets):
                if target not in self.graph or start == target:
                    continue
                for path in nx.all_simple_paths(self.graph, source=start, target=target, cutoff=6):
                    if self._path_is_viable(path, known):
                        candidates.add(tuple(path))
        ordered = sorted(candidates, key=lambda path: (len(path), path))
        return [list(path) for path in ordered[:max_paths]]
