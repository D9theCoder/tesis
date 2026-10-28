"""Focused workflow contracts and offline graph continuations; no external I/O."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage

from agents.orchestrator import orchestrator
from agents.state_utils import make_update, method_selection_update, validated_payload_candidates
from core.checkpoint_audit import AuditCheckpointSerializer
from core.checkpoint_store import coordinate_fingerprint
from core.chaining_coordinator import chaining_router_node, evaluate_chain_route
from core.graph_builder import build_framework
from core.state import _merge_validation_maps, new_default_state
from core.workflow_policy import eligible_methods, stop_reason, workflow_progress
from evaluation.runner import run_single_engagement
from foundation.payload_generator import build_payload_candidates
from foundation.payload_library import PayloadLibrary
from foundation.payload_validator import payload_validator_node
from tests.support import READY_RECEIPT, ready_state


def stub_graph(monkeypatch):
    monkeypatch.setattr("core.graph_builder.recon", lambda state: {
        "readiness": deepcopy(READY_RECEIPT),
        "observations": {"union_select_possible": True, "error_messages_enabled": True},
        "next_agent": "orchestrator"})
    received = []
    def method(state):
        received.append(deepcopy(state))
        return make_update(state=state, module_name="sqli_union", score=0, tried_payloads=[])
    monkeypatch.setitem(__import__("core.graph_builder", fromlist=["RUNTIME_AGENT_HANDLERS"]).RUNTIME_AGENT_HANDLERS,
        "sqli_union", method)
    return received


def test_fresh_checkpointed_coordinate_has_no_prior_findings_or_payloads(tmp_path, monkeypatch):
    received = stub_graph(monkeypatch)
    options = dict(target_url="http://localhost/dvwa", security_level="low", llm_provider="openai_compatible",
        target_method="sqli_union", checkpoint_dir=str(tmp_path), output_dir=str(tmp_path), experiment_id="isolation")
    first = run_single_engagement(**options)
    second = run_single_engagement(**options)
    assert first["execution_status"] == second["execution_status"] == "completed"
    assert first["graph_thread_id"] != second["graph_thread_id"]
    assert len(received) == 2
    assert all(state["attempted_agents"] == [] and state["verifier_history"] == [] for state in received)


@pytest.mark.parametrize("field,changed", [
    ("effective_llm_runtime", {"roles": {"payload_generator": {"reasoning_effort": "high", "model_name": "other"}}}),
    ("scoring_profile", {"sha256": "changed"}), ("scoring_oracles", [{"sha256": "changed"}]),
    ("scoring_rubric_version", "scoring.v4"), ("fixture_id", "other-fixture"),
    ("protocol_version", "other-protocol"), ("evasion_max_retries", 2),
])
def test_resume_fingerprint_binds_effective_roles_and_research_inputs(field, changed):
    coordinate = {"provider": "fixture", "target_url": "http://localhost/dvwa"}
    assert coordinate_fingerprint(coordinate) != coordinate_fingerprint({**coordinate, field: changed})


def test_current_queue_replaces_membership_without_rewriting_validation_history():
    method = "sqli_union"
    seed = next(row for row in PayloadLibrary().load_seed_candidates(method, "low") if row["stage"] == "exploit")
    state = {**new_default_state(), "selected_method": method, "selected_visit_id": "visit-2",
        "payload_candidates": {method: [seed]},
        "payload_validation_results": {method: [{"candidate_id": seed["candidate_id"], "valid": True, "visit_id": "visit-1"}]},
        "active_payload_candidates": {method: {"visit_id": "visit-2", "status": "pending", "candidate_ids": []}}}
    before = deepcopy(state)
    update = payload_validator_node(state)
    state["payload_validation_results"] = _merge_validation_maps(state["payload_validation_results"], update["payload_validation_results"])
    state["active_payload_candidates"] = update["active_payload_candidates"]
    assert validated_payload_candidates(state, method) == []
    assert state["payload_validation_results"][method][0] == before["payload_validation_results"][method][0]
    assert update["preparation_failures"][0]["visit_id"] == "visit-2"


@pytest.mark.parametrize("valid", [False, True])
def test_latest_visit_validation_can_both_accept_and_revoke_a_candidate(valid):
    candidate = {"candidate_id": "fixture", "payload_or_logic": "fixture-value"}
    history = _merge_validation_maps({"sqli_union": [{"candidate_id": "fixture", "visit_id": "v1", "valid": not valid}]},
        {"sqli_union": [{"candidate_id": "fixture", "visit_id": "v2", "valid": valid}]})
    state = {"selected_visit_id": "v2", "payload_candidates": {"sqli_union": [candidate]},
        "payload_validation_results": history,
        "active_payload_candidates": {"sqli_union": {"visit_id": "v2", "status": "validated", "candidate_ids": ["fixture"]}}}
    assert validated_payload_candidates(state, "sqli_union") == ([candidate] if valid else [])
    assert len(history["sqli_union"]) == 2


def test_replay_revalidation_preserves_visit_ownership_and_historical_receipts(tmp_path, monkeypatch):
    from evaluation.payload_replay import replay_method_inputs
    from core.graph_builder import RUNTIME_AGENT_HANDLERS

    method = "sqli_union"
    seeds = [row for row in PayloadLibrary().load_seed_candidates(method, "low") if row["stage"] == "exploit"][:2]
    state = {**new_default_state(), "target_url": "http://localhost/dvwa", "security_level": "low",
        "selected_method": method, "selected_visit_id": "visit-2", "payload_candidates": {method: seeds}}
    state.update(build_payload_candidates(state))
    state.update(payload_validator_node(state))
    saved_ids = [candidate["candidate_id"] for candidate in state["payload_candidates"][method]]
    historical = {"candidate_id": saved_ids[0], "visit_id": "visit-1", "valid": False,
        "reason": "previous_visit_rejected"}
    state["payload_validation_results"][method].insert(0, historical)
    source = tmp_path / "execution.json"
    source.write_text(json.dumps({"config": {"target_url": state["target_url"]},
        "method_execution_inputs": [{"method": method, "state": state}]}))
    original = source.read_bytes()
    received = []
    def method_handler(replayed):
        received.extend(validated_payload_candidates(replayed, method))
        assert replayed["payload_validation_results"][method][0] == historical
        assert all(row["visit_id"] == "visit-2" for row in replayed["payload_validation_results"][method]
                   if row["valid"])
        return {}
    monkeypatch.setitem(RUNTIME_AGENT_HANDLERS, method, method_handler)

    replay = replay_method_inputs(source, output_path=tmp_path / "replay.json",
        candidate_ids=[saved_ids[0]])

    assert replay["validation_rejections"] == []
    assert [candidate["candidate_id"] for candidate in received] == [saved_ids[0]]
    assert replay["fresh_provider_calls"] == 0
    assert source.read_bytes() == original


def test_coverage_policy_continues_after_impact_and_stops_at_fixed_denominator():
    state = {**new_default_state(), "stop_policy": "coverage", "coverage_target": 0.5,
        "attempted_agents": ["sqli_union"], "achieved_outcomes": ["data_exfiltrated"]}
    assert stop_reason(state) is None
    state["attempted_agents"].append("sqli_error")
    assert stop_reason(state) == "coverage_target_reached"
    assert workflow_progress(state)["method_coverage"] == {
        "attempted": 2, "total": 4, "ratio": 0.5, "methods": ["sqli_union", "sqli_error"]}
    assert stop_reason({**state, "stop_policy": "impact"}) == "critical_outcome"


def test_empty_chain_preparation_is_not_selected_again():
    state = {**new_default_state(), "experiment_condition": "akg_guided_hybrid",
        "achieved_outcomes": ["credentials_extracted"], "observations": {"no_rate_limit": True},
        "preparation_failures": [{"method": "bf_dictionary", "visit_id": "v", "reason": "NO_VALID_PAYLOADS"}]}
    route, _ = evaluate_chain_route(state)
    assert route != "bf_dictionary"
    assert "bf_dictionary" not in eligible_methods(state, "brute_force")


def test_linear_failed_visit_falls_back_without_akg_viability():
    route, event = evaluate_chain_route({**new_default_state(), "attempted_agents": ["sqli_union"],
        "failure_agents": ["sqli_union"], "observations": {}})
    assert route == "sqli_error"
    assert event["reason"] == "fallback_next_method"


def test_unsupported_chain_consumption_is_recorded_without_dispatch():
    state = {**ready_state(), "current_surface": "access_control", "experiment_condition": "akg_guided_hybrid",
        "confirmed_vulns": ["ac_vertical_escalation_confirmed"], "attempted_agents": ["ac_vertical_escalation"],
        "observations": {"union_select_possible": True, "role_based_access_present": True}}
    update = chaining_router_node(state)
    assert update["next_agent"] == "scorer"
    assert any(row.get("reason") == "source_consumption_adapter_unavailable" for row in update["chain_history"])


def test_source_bound_plaintext_candidate_is_validated_and_ranked_first():
    from foundation.payload_generator import build_payload_candidates
    state = {**new_default_state(), "selected_method": "bf_dictionary", "selected_visit_id": "destination",
        "active_chain_route": {"source": "credentials_extracted", "target_agent": "bf_dictionary", "source_evidence_ids": ["source"]},
        "found_credentials": [{"username": "fixture-user", "password": "fixture-value", "representation": "plaintext",
            "source_evidence_id": "source", "source_visit_id": "origin", "source_candidate_id": "source-candidate"}],
        "response_evidence": [{"evidence_id": "source", "visit_id": "origin", "candidate_id": "source-candidate"}]}
    state.update(build_payload_candidates(state))
    update = payload_validator_node(state)
    first = update["payload_candidates"]["bf_dictionary"][0]
    assert first["source"] == "chain_derived"
    assert first["payload_or_logic"] == "fixture-user:fixture-value"
    assert update["active_chain_route"]["source_bindings"][0]["candidate_id"] == first["candidate_id"]


def test_one_visit_budget_survives_graph_and_preserves_scorer_outputs(monkeypatch):
    received = stub_graph(monkeypatch)
    result = build_framework().invoke({**new_default_state(), "target_method": "sqli_union", "max_iterations": 1},
        config={"configurable": {"thread_id": "bounded"}})
    assert len(received) == 1
    assert result["iteration_count"] == 1
    assert result["summary"]["workflow"]["iteration_unit"] == "method_visit"
    assert set(result["surface_scores"]) == {"sqli", "access_control", "brute_force"}


def test_planning_schema_rejects_a_repeated_method_and_uses_remaining_work(monkeypatch):
    class Model:
        def invoke(self, _messages):
            return AIMessage(content='{"next_agent":"sqli_union"}')
    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: Model())
    update = orchestrator({**ready_state(), "attempted_agents": ["sqli_union"]})
    assert update["selected_method"] == "sqli_error"
    assert update["fallback_events"][0]["reason"] == "disallowed_method"


def test_infeasible_akg_stop_is_completed_without_model_calls(tmp_path, monkeypatch):
    monkeypatch.setattr("core.graph_builder.recon", lambda state: {
        "readiness": deepcopy(READY_RECEIPT), "observations": {}, "next_agent": "orchestrator"})
    artifact = run_single_engagement(target_url="http://localhost/dvwa", security_level="low", llm_provider="openai_compatible",
        experiment_condition="akg_guided_hybrid", output_dir=str(tmp_path))
    assert artifact["execution_status"] == "completed"
    assert artifact["incomplete_reason"] == "NO_VIABLE_METHODS"
    assert artifact["llm_activity"]["started"] == 0


def test_audit_checkpoint_deduplicates_entries_and_restores_messages(tmp_path):
    serializer = AuditCheckpointSerializer(tmp_path)
    message = AIMessage(content="large fixture evidence " * 2048)
    checkpoint = {"id": "fixture", "channel_values": {"messages": [message], "iteration_count": 1}}
    stored = serializer.dumps_typed(checkpoint)
    assert len(stored[1]) < 1024
    restored = serializer.loads_typed(stored)
    assert restored["channel_values"]["messages"] == [message]
    serializer.dumps_typed(checkpoint)
    assert len(list(tmp_path.iterdir())) == 1
    blob = next(tmp_path.iterdir())
    blob.write_bytes(b"corrupted")
    with pytest.raises(ValueError, match="hash mismatch"):
        serializer.loads_typed(stored)


def test_model_backed_partial_resume_restores_receipts_without_calling_provider(tmp_path, monkeypatch):
    from core.checkpoint_store import ExperimentCheckpointStore
    from langgraph.checkpoint.sqlite import SqliteSaver
    from llm.runtime import LLMRuntime
    import sqlite3

    received = stub_graph(monkeypatch)
    class Model:
        def invoke(self, messages, **kwargs):
            return AIMessage(content='{"next_agent":"sqli_union","reason_code":"best_viable"}')
    monkeypatch.setattr("llm.runtime.get_llm", lambda *args, **kwargs: Model())
    options = dict(target_url="http://localhost/dvwa", security_level="low", llm_provider="openai_compatible",
        payload_mode="static_only", checkpoint_dir=str(tmp_path), output_dir=str(tmp_path), experiment_id="resume",
        max_iterations=1)
    first = run_single_engagement(**options)
    assert first["llm_activity"]["completed"] == 1
    # Remove only the completed-run receipt, leaving the saved graph and its call receipts.
    conn = sqlite3.connect(tmp_path / "checkpoints.sqlite3")
    conn.execute("UPDATE checkpoints SET completion_receipt=0")
    conn.commit(); conn.close()
    monkeypatch.setattr("llm.runtime.get_llm", lambda *args, **kwargs: pytest.fail("resume must not call a provider"))
    resumed = run_single_engagement(**options, resume=True)
    assert resumed["execution_status"] == "completed", resumed.get("error")
    assert resumed["llm_activity"]["completed"] == 1
    assert resumed["execution_id"] == first["execution_id"]
    assert resumed["resumed_from_checkpoint"] is True
    assert len(received) == 1
