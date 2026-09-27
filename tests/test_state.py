"""State isolation, accumulation, monotonic observations and method mappings."""

from core.state import ExploitationState, new_default_state, _merge_tried_payloads
from langchain_core.messages import HumanMessage, AIMessage


class TestDefaultState:
    """Validate DEFAULT_STATE has sensible initial values."""

    def test_new_default_state_returns_fresh_objects(self):
        """new_default_state should not share nested mutable objects."""
        first = new_default_state()
        second = new_default_state()

        first["confirmed_vulns"].append("sqli_confirmed")
        first["scores"]["sqli"] = 4

        assert second["confirmed_vulns"] == []
        assert second["scores"] == {}


class TestMergeTriedPayloadsReducer:
    """Verify _merge_tried_payloads deduplicates across and within batches."""

    def test_deduplicates_within_b(self):
        """Verifies deduplicates within b behavior."""
        result = _merge_tried_payloads({"agent1": ["a"]}, {"agent1": ["c", "c"]})
        assert result == {"agent1": ["a", "c"]}

    def test_deduplicates_across_a_and_b(self):
        """Verifies deduplicates across a and b behavior."""
        result = _merge_tried_payloads(
            {"agent1": ["a", "b"]},
            {"agent1": ["a", "c"]},
        )
        assert result == {"agent1": ["a", "b", "c"]}


class TestLangGraphIntegration:
    """Smoke test: verify ExploitationState works with LangGraph StateGraph."""

    def test_accumulation_with_multiple_nodes(self):
        """Verify that Annotated[list, add] fields accumulate across nodes."""
        from langgraph.graph import StateGraph, START, END

        def node_a(state: ExploitationState) -> dict:
            """Supports regression tests for test state."""
            return {"confirmed_vulns": ["sqli_confirmed"]}

        def node_b(state: ExploitationState) -> dict:
            """Supports regression tests for test state."""
            return {"confirmed_vulns": ["xss_reflected_confirmed"]}

        graph = StateGraph(ExploitationState)
        graph.add_node("node_a", node_a)
        graph.add_node("node_b", node_b)
        graph.add_edge(START, "node_a")
        graph.add_edge("node_a", "node_b")
        graph.add_edge("node_b", END)

        app = graph.compile()
        result = app.invoke(new_default_state())
        # With add reducer, both confirmees should be present
        assert "sqli_confirmed" in result["confirmed_vulns"]
        assert "xss_reflected_confirmed" in result["confirmed_vulns"]

    def test_messages_accumulation(self):
        """Verify that messages field accumulates with add_messages reducer."""
        from langgraph.graph import StateGraph, START, END

        def add_human_msg(state: ExploitationState) -> dict:
            """Supports regression tests for test state."""
            return {"messages": [HumanMessage(content="test recon")]}

        def add_ai_msg(state: ExploitationState) -> dict:
            """Supports regression tests for test state."""
            return {"messages": [AIMessage(content="test response")]}

        graph = StateGraph(ExploitationState)
        graph.add_node("add_human", add_human_msg)
        graph.add_node("add_ai", add_ai_msg)
        graph.add_edge(START, "add_human")
        graph.add_edge("add_human", "add_ai")
        graph.add_edge("add_ai", END)

        app = graph.compile()
        result = app.invoke(new_default_state())
        assert len(result["messages"]) == 2
        assert isinstance(result["messages"][0], HumanMessage)
        assert isinstance(result["messages"][1], AIMessage)


class TestMergeDictsReducer:
    """Validate _merge_dicts never overwrites True with False."""

    def test_merge_dicts_preserves_true_over_false(self):
        """Verifies merge dicts preserves true over false behavior."""
        from core.state import _merge_dicts
        a = {"key1": True, "key2": False}
        b = {"key1": False, "key3": True}
        result = _merge_dicts(a, b)
        assert result["key1"] is True
        assert result["key2"] is False
        assert result["key3"] is True

    def test_merge_dicts_allows_false_to_true(self):
        """Verifies merge dicts allows false to true behavior."""
        from core.state import _merge_dicts
        a = {"key1": False}
        b = {"key1": True}
        result = _merge_dicts(a, b)
        assert result["key1"] is True


class TestModuleToKgNodeMappings:
    """Validate MODULE_TO_KG_NODE maps agents to existing AKG nodes."""

    def test_all_method_agents_map_to_existing_kg_nodes(self):
        """Verifies all method agents map to existing kg nodes behavior."""
        from core.state import MODULE_TO_KG_NODE, ALL_METHOD_AGENTS, KG_NODES
        for agent in ALL_METHOD_AGENTS:
            node = MODULE_TO_KG_NODE.get(agent)
            assert node is not None, f"{agent} has no MODULE_TO_KG_NODE mapping"
            assert node in KG_NODES, f"{agent} maps to {node} which is not in KG_NODES"
