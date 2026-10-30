"""Tests for 3-surface AttackKnowledgeGraph."""

import pytest

from core.knowledge_graph import AttackKnowledgeGraph

@pytest.fixture()
def kg() -> AttackKnowledgeGraph:
    """Return a fresh AttackKnowledgeGraph for each AKG regression test."""
    return AttackKnowledgeGraph()

def test_get_viable_methods_none_when_preconditions_unmet(kg: AttackKnowledgeGraph):
    """Verifies get viable methods none when preconditions unmet behavior."""
    observations = {}
    viable = kg.get_viable_methods("sqli", observations)
    assert viable == []

class InvalidPreconditionAKG(AttackKnowledgeGraph):
    """AKG fixture with a chain edge that references an unknown precondition."""
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_edge(
            "sqli_union_confirmed",
            "data_exfiltrated",
            is_chain=True,
            preconditions=["unknown_node"],
            target_agent="bad_chain",
            priority=1,
        )

class MissingTargetAgentAKG(AttackKnowledgeGraph):
    """AKG fixture with a chain edge missing required target-agent metadata."""
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_edge(
            "sqli_union_confirmed",
            "data_exfiltrated",
            is_chain=True,
            preconditions=["sqli_union_confirmed"],
            priority=1,
        )


def test_validation_fails_for_unknown_precondition():
    """Verifies validation fails for unknown precondition behavior."""
    with pytest.raises(ValueError, match="unknown precondition"):
        InvalidPreconditionAKG()

def test_validation_fails_for_missing_target_agent_on_chain():
    """Verifies validation fails for missing target agent on chain behavior."""
    with pytest.raises(ValueError, match="missing target_agent"):
        MissingTargetAgentAKG()
