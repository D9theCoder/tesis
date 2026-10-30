"""Focused workflow contracts and offline graph continuations; no external I/O."""

from copy import deepcopy
import json


from agents.state_utils import make_update, validated_payload_candidates
from core.graph_builder import build_framework
from core.state import new_default_state
from evaluation.runner import run_single_engagement
from foundation.payload_generator import build_payload_candidates
from foundation.payload_library import PayloadLibrary
from foundation.payload_validator import payload_validator_node
from tests.support import READY_RECEIPT


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


def test_one_visit_budget_survives_graph_and_preserves_scorer_outputs(monkeypatch):
    received = stub_graph(monkeypatch)
    result = build_framework().invoke({**new_default_state(), "target_method": "sqli_union", "max_iterations": 1},
        config={"configurable": {"thread_id": "bounded"}})
    assert len(received) == 1
    assert result["iteration_count"] == 1
    assert result["summary"]["workflow"]["iteration_unit"] == "method_visit"
    assert set(result["surface_scores"]) == {"sqli", "access_control", "brute_force"}


def test_infeasible_akg_stop_is_completed_without_model_calls(tmp_path, monkeypatch):
    monkeypatch.setattr("core.graph_builder.recon", lambda state: {
        "readiness": deepcopy(READY_RECEIPT), "observations": {}, "next_agent": "orchestrator"})
    artifact = run_single_engagement(target_url="http://localhost/dvwa", security_level="low", llm_provider="openai_compatible",
        experiment_condition="akg_guided_hybrid", output_dir=str(tmp_path))
    assert artifact["execution_status"] == "completed"
    assert artifact["incomplete_reason"] == "NO_VIABLE_METHODS"
    assert artifact["llm_activity"]["started"] == 0
