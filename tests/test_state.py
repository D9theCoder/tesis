"""State isolation, accumulation, monotonic observations and method mappings."""

from core.state import _merge_tried_payloads


class TestMergeTriedPayloadsReducer:
    """Verify _merge_tried_payloads deduplicates across and within batches."""


    def test_deduplicates_across_a_and_b(self):
        """Verifies deduplicates across a and b behavior."""
        result = _merge_tried_payloads(
            {"agent1": ["a", "b"]},
            {"agent1": ["a", "c"]},
        )
        assert result == {"agent1": ["a", "b", "c"]}


class TestModuleToKgNodeMappings:
    """Validate MODULE_TO_KG_NODE maps agents to existing AKG nodes."""

    def test_all_method_agents_map_to_existing_kg_nodes(self):
        """Verifies all method agents map to existing kg nodes behavior."""
        from core.state import MODULE_TO_KG_NODE, ALL_METHOD_AGENTS, KG_NODES
        for agent in ALL_METHOD_AGENTS:
            node = MODULE_TO_KG_NODE.get(agent)
            assert node is not None, f"{agent} has no MODULE_TO_KG_NODE mapping"
            assert node in KG_NODES, f"{agent} maps to {node} which is not in KG_NODES"
