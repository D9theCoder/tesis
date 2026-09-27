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

class MissingPreconditionsAKG(AttackKnowledgeGraph):
    """AKG fixture with a chain edge missing required precondition metadata."""
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_edge(
            "sqli_union_confirmed",
            "data_exfiltrated",
            is_chain=True,
            target_agent="missing_preconditions_chain",
            priority=1,
        )

class InvalidPreconditionsTypeAKG(AttackKnowledgeGraph):
    """AKG fixture with a chain edge containing invalid precondition metadata."""
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.add_edge(
            "sqli_union_confirmed",
            "data_exfiltrated",
            is_chain=True,
            preconditions=None,
            target_agent="invalid_preconditions_type_chain",
            priority=1,
        )

class MissingHighImpactOutcomeAKG(AttackKnowledgeGraph):
    """AKG fixture with a required high-impact outcome node removed."""
    def _build_graph(self) -> None:
        super()._build_graph()
        self.graph.remove_node("admin_session_obtained")

def test_validation_fails_for_unknown_precondition():
    """Verifies validation fails for unknown precondition behavior."""
    with pytest.raises(ValueError, match="unknown precondition"):
        InvalidPreconditionAKG()

def test_validation_fails_for_missing_target_agent_on_chain():
    """Verifies validation fails for missing target agent on chain behavior."""
    with pytest.raises(ValueError, match="missing target_agent"):
        MissingTargetAgentAKG()

def test_validation_fails_for_missing_preconditions_on_chain():
    """Verifies validation fails for missing preconditions on chain behavior."""
    with pytest.raises(ValueError, match="missing preconditions"):
        MissingPreconditionsAKG()

def test_validation_fails_for_invalid_preconditions_type_on_chain():
    """Verifies validation fails for invalid preconditions type on chain behavior."""
    with pytest.raises(ValueError, match="invalid preconditions"):
        InvalidPreconditionsTypeAKG()

def test_validation_fails_for_missing_high_impact_outcome_node():
    """Verifies validation fails for missing high impact outcome node behavior."""
    with pytest.raises(ValueError, match="Missing high-impact outcomes"):
        MissingHighImpactOutcomeAKG()

def test_authenticated_session_intermediate_chain_node(kg: AttackKnowledgeGraph):
    """Verifies authenticated session intermediate chain node behavior."""
    assert "authenticated_session" in kg.graph
    # Check incoming from brute_force_confirmed
    predecessors = set(kg.graph.predecessors("authenticated_session"))
    assert "brute_force_confirmed" in predecessors
    # Check outgoing to ac_idor
    successors = set(kg.graph.successors("authenticated_session"))
    assert "ac_idor" in successors

def test_admin_session_obtained_intermediate_chain_node(kg: AttackKnowledgeGraph):
    """Verifies admin session obtained intermediate chain node behavior."""
    assert "admin_session_obtained" in kg.graph
    predecessors = set(kg.graph.predecessors("admin_session_obtained"))
    assert "ac_vertical_escalation_confirmed" in predecessors
    successors = set(kg.graph.successors("admin_session_obtained"))
    assert "sqli_union" in successors
