"""Tests for 3-surface AttackKnowledgeGraph."""

import pytest

from core.knowledge_graph import AttackKnowledgeGraph


@pytest.fixture()
def kg() -> AttackKnowledgeGraph:
    return AttackKnowledgeGraph()


def test_graph_is_digraph(kg: AttackKnowledgeGraph):
    import networkx as nx
    assert isinstance(kg.graph, nx.DiGraph)


def test_get_next_actions_unknown_node_returns_empty(kg: AttackKnowledgeGraph):
    assert kg.get_next_actions("unknown_node") == []


def test_get_next_actions_returns_canonical_metadata_keys(kg: AttackKnowledgeGraph):
    actions = kg.get_next_actions("sqli")
    assert actions
    for action in actions:
        assert set(action.keys()) == {
            "source",
            "target",
            "is_chain",
            "preconditions",
            "target_agent",
        }


def test_get_viable_methods_sqli(kg: AttackKnowledgeGraph):
    observations = {
        "error_messages_enabled": True,
        "union_select_possible": True,
        "response_diff_detectable": True,
        "response_delay_measurable": True,
    }
    viable = kg.get_viable_methods("sqli", observations)
    assert "sqli_error" in viable
    assert "sqli_union" in viable


def test_get_viable_methods_none_when_preconditions_unmet(kg: AttackKnowledgeGraph):
    observations = {}
    viable = kg.get_viable_methods("sqli", observations)
    assert viable == []


def test_check_preconditions(kg: AttackKnowledgeGraph):
    assert kg.check_preconditions("sqli_error", {"error_messages_enabled": True})
    assert not kg.check_preconditions("sqli_error", {})


def test_get_viable_chains_deterministic(kg: AttackKnowledgeGraph):
    confirmed = ["sqli_confirmed", "credentials_extracted"]
    first = kg.get_viable_chains(confirmed_vulns=confirmed, achieved_outcomes=[])
    second = kg.get_viable_chains(confirmed_vulns=confirmed, achieved_outcomes=[])
    assert first == second


def test_non_positive_max_paths_returns_empty(kg: AttackKnowledgeGraph):
    assert kg.get_viable_chains(confirmed_vulns=["sqli_confirmed"], max_paths=0) == []


class InvalidPreconditionAKG(AttackKnowledgeGraph):
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_edge(
            "sqli_union_confirmed",
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
            "sqli_union_confirmed",
            "session_hijack",
            is_chain=True,
            preconditions=["sqli_union_confirmed"],
            priority=1,
        )


class MissingPreconditionsAKG(AttackKnowledgeGraph):
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_edge(
            "sqli_union_confirmed",
            "session_hijack",
            is_chain=True,
            target_agent="missing_preconditions_chain",
            priority=1,
        )


class InvalidPreconditionsTypeAKG(AttackKnowledgeGraph):
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_edge(
            "sqli_union_confirmed",
            "session_hijack",
            is_chain=True,
            preconditions=None,
            target_agent="invalid_preconditions_type_chain",
            priority=1,
        )


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


def test_validation_fails_for_missing_high_impact_outcome_node():
    with pytest.raises(ValueError, match="Missing high-impact outcomes"):
        MissingHighImpactOutcomeAKG()
