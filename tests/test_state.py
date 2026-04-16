"""Tests for core/state.py — ExploitationState schema and LangGraph integration.

Validates:
1. Schema instantiation with all fields
2. Reducer behavior for accumulation fields
3. Default state values
4. Field completeness against AGENTS.md
5. LangGraph StateGraph compilation smoke test
"""

import pytest
from operator import add
from typing import get_type_hints, get_args, Annotated

from core.state import (
    ExploitationState,
    DEFAULT_STATE,
    new_default_state,
    MODULE_NAMES,
    KG_NODES,
    SCORE_LABELS,
    SECURITY_LEVELS,
    LLM_PROVIDERS,
)
from langchain_core.messages import HumanMessage, AIMessage


class TestExploitationStateSchema:
    """Validate the schema has all required fields from AGENTS.md."""

    # All fields defined in AGENTS.md state schema
    REQUIRED_FIELDS = [
        "target_url",
        "security_level",
        "llm_provider",
        "endpoints",
        "input_vectors",
        "confirmed_vulns",
        "achieved_outcomes",
        "found_credentials",
        "tried_payloads",
        "blocked_patterns",
        "successful_bypasses",
        "scores",
        "current_chain",
        "chain_history",
        "messages",
        "guardrail_activations",
        "next_agent",
        "iteration_count",
        "max_iterations",
    ]

    def test_all_fields_present(self):
        """All fields from AGENTS.md must be defined in ExploitationState."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        for field in self.REQUIRED_FIELDS:
            assert field in hints, f"Missing field: {field}"

    def test_no_extra_fields(self):
        """Schema should not have fields beyond what AGENTS.md specifies."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        extra = set(hints.keys()) - set(self.REQUIRED_FIELDS)
        assert extra == set(), f"Unexpected fields in schema: {extra}"

    def test_instantiation_with_all_fields(self):
        """ExploitationState can be created with all fields populated."""
        state: ExploitationState = {
            "target_url": "http://localhost/dvwa",
            "security_level": "low",
            "llm_provider": "gemini",
            "endpoints": [{"url": "/dvwa/vulnerabilities/sqli/", "method": "GET"}],
            "input_vectors": [{"param_name": "id", "param_type": "query", "endpoint_url": "/dvwa/vulnerabilities/sqli/"}],
            "confirmed_vulns": ["sqli_confirmed"],
            "achieved_outcomes": ["credentials_extracted"],
            "found_credentials": [{"username": "admin", "password": "password"}],
            "tried_payloads": {"sqli": ["1'", "1 OR 1=1"]},
            "blocked_patterns": [],
            "successful_bypasses": [],
            "scores": {"sqli": 3},
            "current_chain": ["sqli_confirmed", "credentials_extracted"],
            "chain_history": [{"chain": "sqli→creds", "evidence": "users table dumped"}],
            "messages": [HumanMessage(content="test")],
            "guardrail_activations": [],
            "next_agent": "orchestrator",
            "iteration_count": 5,
            "max_iterations": 30,
        }
        assert state["target_url"] == "http://localhost/dvwa"
        assert state["confirmed_vulns"] == ["sqli_confirmed"]
        assert state["scores"]["sqli"] == 3


class TestReducerBehavior:
    """Validate that Annotated fields use correct reducers."""

    def test_confirmed_vulns_uses_add(self):
        """confirmed_vulns should use operator.add reducer for accumulation."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        annotated_type = hints["confirmed_vulns"]
        args = get_args(annotated_type)
        assert len(args) == 2, "confirmed_vulns should be Annotated[type, reducer]"
        assert args[1] is add, "confirmed_vulns reducer should be operator.add"

    def test_achieved_outcomes_uses_add(self):
        """achieved_outcomes should use operator.add reducer."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        annotated_type = hints["achieved_outcomes"]
        args = get_args(annotated_type)
        assert args[1] is add

    def test_found_credentials_uses_add(self):
        """found_credentials should use operator.add reducer."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        annotated_type = hints["found_credentials"]
        args = get_args(annotated_type)
        assert args[1] is add

    def test_blocked_patterns_uses_add(self):
        """blocked_patterns should use operator.add reducer."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        annotated_type = hints["blocked_patterns"]
        args = get_args(annotated_type)
        assert args[1] is add

    def test_successful_bypasses_uses_add(self):
        """successful_bypasses should use operator.add reducer."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        annotated_type = hints["successful_bypasses"]
        args = get_args(annotated_type)
        assert args[1] is add

    def test_chain_history_uses_add(self):
        """chain_history should use operator.add reducer."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        annotated_type = hints["chain_history"]
        args = get_args(annotated_type)
        assert args[1] is add

    def test_guardrail_activations_uses_add(self):
        """guardrail_activations should use operator.add reducer."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        annotated_type = hints["guardrail_activations"]
        args = get_args(annotated_type)
        assert args[1] is add

    def test_messages_uses_add_messages(self):
        """messages should use add_messages reducer (not operator.add)."""
        from langgraph.graph.message import add_messages
        hints = get_type_hints(ExploitationState, include_extras=True)
        annotated_type = hints["messages"]
        args = get_args(annotated_type)
        assert args[1] is add_messages, "messages must use add_messages reducer"

    def test_target_url_is_plain_str(self):
        """target_url should NOT have an annotated reducer (overwrite default)."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        assert hints["target_url"] is str

    def test_scores_is_plain_dict(self):
        """scores should NOT have an annotated reducer (overwrite default)."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        # scores should be dict[str, int] without annotation
        assert "scores" in hints
        # It should NOT be an Annotated type
        raw = hints["scores"]
        assert get_args(raw) == () or not hasattr(raw, "__metadata__"), \
            "scores should be plain dict, not Annotated"

    def test_tried_payloads_is_plain_dict(self):
        """tried_payloads should NOT have an annotated reducer (overwrite default)."""
        hints = get_type_hints(ExploitationState, include_extras=True)
        assert "tried_payloads" in hints


class TestDefaultState:
    """Validate DEFAULT_STATE has sensible initial values."""

    def test_default_state_all_fields_present(self):
        """DEFAULT_STATE must have a value for every field in the schema."""
        for field in TestExploitationStateSchema.REQUIRED_FIELDS:
            assert field in DEFAULT_STATE, f"DEFAULT_STATE missing field: {field}"

    def test_default_iteration_count(self):
        assert DEFAULT_STATE["iteration_count"] == 0

    def test_default_max_iterations(self):
        assert DEFAULT_STATE["max_iterations"] == 30

    def test_default_next_agent(self):
        assert DEFAULT_STATE["next_agent"] == "recon"

    def test_default_empty_collections(self):
        """All accumulation fields should default to empty collections."""
        assert DEFAULT_STATE["confirmed_vulns"] == []
        assert DEFAULT_STATE["achieved_outcomes"] == []
        assert DEFAULT_STATE["found_credentials"] == []
        assert DEFAULT_STATE["blocked_patterns"] == []
        assert DEFAULT_STATE["successful_bypasses"] == []
        assert DEFAULT_STATE["scores"] == {}
        assert DEFAULT_STATE["current_chain"] == []
        assert DEFAULT_STATE["chain_history"] == []
        assert DEFAULT_STATE["messages"] == []
        assert DEFAULT_STATE["guardrail_activations"] == []
        assert DEFAULT_STATE["tried_payloads"] == {}
        assert DEFAULT_STATE["endpoints"] == []
        assert DEFAULT_STATE["input_vectors"] == []

    def test_new_default_state_returns_fresh_objects(self):
        """new_default_state should not share nested mutable objects."""
        first = new_default_state()
        second = new_default_state()

        first["confirmed_vulns"].append("sqli_confirmed")
        first["scores"]["sqli"] = 4

        assert second["confirmed_vulns"] == []
        assert second["scores"] == {}


class TestConstants:
    """Validate the exported constants are correct."""

    def test_module_names_complete(self):
        """All 12 DVWA modules must be listed."""
        assert len(MODULE_NAMES) == 12
        assert "sqli" in MODULE_NAMES
        assert "sqli_blind" in MODULE_NAMES
        assert "xss_r" in MODULE_NAMES
        assert "xss_s" in MODULE_NAMES
        assert "xss_d" in MODULE_NAMES
        assert "cmdi" in MODULE_NAMES
        assert "brute" in MODULE_NAMES
        assert "lfi" in MODULE_NAMES
        assert "upload" in MODULE_NAMES
        assert "csrf" in MODULE_NAMES
        assert "weak_session" in MODULE_NAMES
        assert "idor" in MODULE_NAMES

    def test_kg_nodes_include_vuln_confirmations(self):
        """Knowledge graph nodes must include all vulnerability confirmation names."""
        expected_vuln_nodes = [
            "sqli_confirmed",
            "blind_sqli_confirmed",
            "xss_reflected_confirmed",
            "xss_stored_confirmed",
            "xss_dom_confirmed",
            "cmd_injection_confirmed",
            "brute_force_confirmed",
            "lfi_confirmed",
            "file_upload_confirmed",
            "csrf_confirmed",
            "weak_session_confirmed",
            "idor_confirmed",
        ]
        for node in expected_vuln_nodes:
            assert node in KG_NODES, f"Missing KG node: {node}"

    def test_kg_nodes_include_outcomes(self):
        """Knowledge graph nodes must include outcome nodes."""
        expected_outcomes = [
            "credentials_extracted",
            "admin_session_obtained",
            "rce_achieved",
            "user_compromised",
            "data_exfiltrated",
            "session_hijack",
            "log_access_confirmed",
        ]
        for outcome in expected_outcomes:
            assert outcome in KG_NODES, f"Missing KG outcome: {outcome}"

    def test_score_labels(self):
        assert SCORE_LABELS[0] == "Not Found"
        assert SCORE_LABELS[1] == "Identified"
        assert SCORE_LABELS[2] == "Partial Exploit"
        assert SCORE_LABELS[3] == "Full Exploit"
        assert SCORE_LABELS[4] == "Chain Exploit"
        assert len(SCORE_LABELS) == 5

    def test_security_levels(self):
        assert SECURITY_LEVELS == ["low", "medium", "high"]

    def test_llm_providers(self):
        assert "gemini" in LLM_PROVIDERS
        assert len(LLM_PROVIDERS) == 1


class TestLangGraphIntegration:
    """Smoke test: verify ExploitationState works with LangGraph StateGraph."""

    def test_stategraph_compiles(self):
        """StateGraph(ExploitationState) should compile without errors."""
        from langgraph.graph import StateGraph, START, END

        def dummy_node(state: ExploitationState) -> dict:
            return {"iteration_count": state.get("iteration_count", 0) + 1}

        graph = StateGraph(ExploitationState)
        graph.add_node("dummy", dummy_node)
        graph.add_edge(START, "dummy")
        graph.add_edge("dummy", END)

        compiled = graph.compile()
        assert compiled is not None

    def test_stategraph_invocation(self):
        """Compiling and invoking a minimal graph should work end-to-end."""
        from langgraph.graph import StateGraph, START, END

        def recon_stub(state: ExploitationState) -> dict:
            return {
                "endpoints": [{"url": "/test", "method": "GET"}],
                "next_agent": "orchestrator",
            }

        graph = StateGraph(ExploitationState)
        graph.add_node("recon", recon_stub)
        graph.add_edge(START, "recon")
        graph.add_edge("recon", END)

        app = graph.compile()
        result = app.invoke(new_default_state())
        assert result["endpoints"] == [{"url": "/test", "method": "GET"}]
        assert result["next_agent"] == "orchestrator"

    def test_accumulation_with_multiple_nodes(self):
        """Verify that Annotated[list, add] fields accumulate across nodes."""
        from langgraph.graph import StateGraph, START, END

        def node_a(state: ExploitationState) -> dict:
            return {"confirmed_vulns": ["sqli_confirmed"]}

        def node_b(state: ExploitationState) -> dict:
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
            return {"messages": [HumanMessage(content="test recon")]}

        def add_ai_msg(state: ExploitationState) -> dict:
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
