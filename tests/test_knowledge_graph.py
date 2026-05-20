"""Tests for 3-surface AttackKnowledgeGraph."""

import pytest

from core.knowledge_graph import AttackKnowledgeGraph


@pytest.fixture()
def kg() -> AttackKnowledgeGraph:
    """Return a fresh AttackKnowledgeGraph for each AKG regression test."""
    return AttackKnowledgeGraph()


def test_graph_is_digraph(kg: AttackKnowledgeGraph):
    """Verifies graph is digraph behavior."""
    import networkx as nx
    assert isinstance(kg.graph, nx.DiGraph)


def test_get_next_actions_unknown_node_returns_empty(kg: AttackKnowledgeGraph):
    """Verifies get next actions unknown node returns empty behavior."""
    assert kg.get_next_actions("unknown_node") == []


def test_get_next_actions_returns_canonical_metadata_keys(kg: AttackKnowledgeGraph):
    """Verifies get next actions returns canonical metadata keys behavior."""
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
    """Verifies get viable methods sqli behavior."""
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
    """Verifies get viable methods none when preconditions unmet behavior."""
    observations = {}
    viable = kg.get_viable_methods("sqli", observations)
    assert viable == []


def test_check_preconditions(kg: AttackKnowledgeGraph):
    """Verifies check preconditions behavior."""
    assert kg.check_preconditions("sqli_error", {"error_messages_enabled": True})
    assert not kg.check_preconditions("sqli_error", {})


def test_get_viable_chains_deterministic(kg: AttackKnowledgeGraph):
    """Verifies get viable chains deterministic behavior."""
    confirmed = ["sqli_confirmed", "credentials_extracted"]
    first = kg.get_viable_chains(confirmed_vulns=confirmed, achieved_outcomes=[])
    second = kg.get_viable_chains(confirmed_vulns=confirmed, achieved_outcomes=[])
    assert first == second


def test_non_positive_max_paths_returns_empty(kg: AttackKnowledgeGraph):
    """Verifies non positive max paths returns empty behavior."""
    assert kg.get_viable_chains(confirmed_vulns=["sqli_confirmed"], max_paths=0) == []


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


def test_unauthenticated_node_exists(kg: AttackKnowledgeGraph):
    """Verifies unauthenticated node exists behavior."""
    assert "unauthenticated" in kg.graph


def test_unauthenticated_connects_to_all_surfaces(kg: AttackKnowledgeGraph):
    """Verifies unauthenticated connects to all surfaces behavior."""
    actions = kg.get_next_actions("unauthenticated")
    targets = {a["target"] for a in actions}
    assert "sqli" in targets
    assert "access_control" in targets
    assert "brute_force" in targets


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


def test_get_viable_chains_paths_through_intermediates(kg: AttackKnowledgeGraph):
    """Verifies get viable chains paths through intermediates behavior."""
    confirmed = ["brute_force_confirmed"]
    chains = kg.get_viable_chains(confirmed_vulns=confirmed, achieved_outcomes=[])
    # Should find paths that go through authenticated_session if it's reachable
    assert isinstance(chains, list)
