"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""


from core.graph_builder import (
    route_from_orchestrator,
    route_from_payload_validator,
)


def test_route_from_orchestrator_unknown_agent_defaults_to_scorer():
    """Verifies route from orchestrator unknown agent defaults to scorer behavior."""
    state = {"next_agent": "not_a_real_node"}
    assert route_from_orchestrator(state) == "scorer"

def test_payload_validator_does_not_route_rejected_candidate_to_method_agent():
    """Rejected payload history must not become an executable candidate queue."""
    state = {
        "selected_method": "ac_force_browse",
        "payload_candidates": {
            "ac_force_browse": [{"candidate_id": "blocked-candidate"}],
        },
        "payload_validation_results": {
            "ac_force_browse": [{
                "candidate_id": "blocked-candidate",
                "valid": False,
                "reason": "out_of_scope_target",
            }],
        },
    }

    assert route_from_payload_validator(state) == "chaining_router"
