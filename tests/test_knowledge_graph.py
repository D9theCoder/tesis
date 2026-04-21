"""Tests for Stage 3 AttackKnowledgeGraph behavior and contracts."""

import networkx as nx
import pytest

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import KG_NODES


@pytest.fixture()
def kg() -> AttackKnowledgeGraph:
    return AttackKnowledgeGraph()


def test_graph_is_digraph_and_uses_canonical_nodes(kg: AttackKnowledgeGraph):
    assert isinstance(kg.graph, nx.DiGraph)
    assert set(kg.graph.nodes) == set(KG_NODES)


def test_get_next_actions_unknown_node_returns_empty(kg: AttackKnowledgeGraph):
    assert kg.get_next_actions("unknown_node") == []


def test_get_next_actions_returns_canonical_metadata_keys(kg: AttackKnowledgeGraph):
    actions = kg.get_next_actions("credentials_extracted")
    assert actions

    for action in actions:
        assert set(action.keys()) == {
            "source",
            "target",
            "is_chain",
            "preconditions",
            "target_agent",
        }
        assert "precondition" not in action
        assert "agent" not in action


def test_alias_normalization_works_for_summary_pseudocode_names(
    kg: AttackKnowledgeGraph,
):
    normalized = kg._normalize_transition(
        {
            "source": "credentials_extracted",
            "target": "admin_session_obtained",
            "is_chain": True,
            "precondition": "sqli_confirmed",
            "agent": "sqli_to_creds_chain",
        }
    )

    assert normalized.preconditions == ("sqli_confirmed",)
    assert normalized.target_agent == "sqli_to_creds_chain"


def test_preconditions_are_normalized_sorted_and_deduplicated(kg: AttackKnowledgeGraph):
    normalized = kg._normalize_transition(
        {
            "source": "log_access_confirmed",
            "target": "rce_achieved",
            "is_chain": True,
            "preconditions": ["log_access_confirmed", "lfi_confirmed", "lfi_confirmed"],
            "target_agent": "lfi_to_rce_chain",
        }
    )

    assert normalized.preconditions == ("lfi_confirmed", "log_access_confirmed")


def test_get_next_actions_sorting_is_deterministic(kg: AttackKnowledgeGraph):
    # Add another non-chain edge from the same source with equal priority to assert
    # lexical tie-break ordering by target.
    kg.graph.add_edge(
        "sqli_confirmed",
        "admin_session_obtained",
        is_chain=False,
        preconditions=[],
        target_agent=None,
        priority=20,
    )

    first = kg.get_next_actions("sqli_confirmed")
    second = kg.get_next_actions("sqli_confirmed")

    assert first == second
    assert [action["target"] for action in first] == sorted(
        action["target"] for action in first
    )


def test_get_viable_chains_is_deterministic(kg: AttackKnowledgeGraph):
    confirmed = ["sqli_confirmed", "credentials_extracted", "admin_session_obtained"]

    first = kg.get_viable_chains(confirmed_vulns=confirmed, achieved_outcomes=[])
    second = kg.get_viable_chains(confirmed_vulns=confirmed, achieved_outcomes=[])

    assert first == second


def test_chain_from_credentials_to_admin_is_viable_with_credentials_only(kg: AttackKnowledgeGraph):
    paths = kg.get_viable_chains(
        confirmed_vulns=["credentials_extracted"],
        achieved_outcomes=[],
        max_paths=10,
    )

    assert any(path[-1] == "admin_session_obtained" for path in paths)


def test_max_paths_and_achieved_outcome_filtering(kg: AttackKnowledgeGraph):
    paths = kg.get_viable_chains(
        confirmed_vulns=[
            "sqli_confirmed",
            "credentials_extracted",
            "admin_session_obtained",
            "lfi_confirmed",
            "log_access_confirmed",
        ],
        achieved_outcomes=["rce_achieved"],
        max_paths=1,
    )

    assert len(paths) <= 1
    assert all(path[-1] != "rce_achieved" for path in paths)


def test_non_positive_max_paths_returns_empty(kg: AttackKnowledgeGraph):
    assert kg.get_viable_chains(confirmed_vulns=["sqli_confirmed"], max_paths=0) == []


class InvalidPreconditionAKG(AttackKnowledgeGraph):
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_edge(
            "xss_reflected_confirmed",
            "session_hijack",
            is_chain=True,
            preconditions=["unknown_node"],
            target_agent="bad_chain",
            priority=1,
        )


class MissingTargetAgentAKG(AttackKnowledgeGraph):
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_edge(
            "xss_reflected_confirmed",
            "session_hijack",
            is_chain=True,
            preconditions=["xss_reflected_confirmed"],
            priority=1,
        )


class MissingPreconditionsAKG(AttackKnowledgeGraph):
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_edge(
            "xss_reflected_confirmed",
            "session_hijack",
            is_chain=True,
            target_agent="missing_preconditions_chain",
            priority=1,
        )


class InvalidPreconditionsTypeAKG(AttackKnowledgeGraph):
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_edge(
            "xss_reflected_confirmed",
            "session_hijack",
            is_chain=True,
            preconditions=None,
            target_agent="invalid_preconditions_type_chain",
            priority=1,
        )


class UnknownNodeAKG(AttackKnowledgeGraph):
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_node("totally_unknown_node")


class MissingHighImpactOutcomeAKG(AttackKnowledgeGraph):
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.remove_node("session_hijack")


def test_validation_fails_for_unknown_precondition():
    with pytest.raises(ValueError, match="unknown precondition"):
        InvalidPreconditionAKG()


def test_validation_fails_for_missing_target_agent_on_chain():
    with pytest.raises(ValueError, match="missing target_agent"):
        MissingTargetAgentAKG()


def test_validation_fails_for_missing_preconditions_on_chain():
    with pytest.raises(ValueError, match="missing preconditions"):
        MissingPreconditionsAKG()


def test_validation_fails_for_invalid_preconditions_type_on_chain():
    with pytest.raises(ValueError, match="invalid preconditions"):
        InvalidPreconditionsTypeAKG()


def test_validation_fails_for_unknown_nodes_not_in_kg_nodes():
    with pytest.raises(ValueError, match="Unknown graph nodes"):
        UnknownNodeAKG()


def test_validation_fails_for_missing_high_impact_outcome_node():
    with pytest.raises(ValueError, match="Missing high-impact outcomes"):
        MissingHighImpactOutcomeAKG()
