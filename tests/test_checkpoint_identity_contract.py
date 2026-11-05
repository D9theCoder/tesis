"""Canonical metadata persists and old identities never bypass resume gates."""
import pytest

from foundation.preconditions import make_observation_fact
from core.checkpoint_store import (
    ExperimentCheckpointStore, stable_thread_id, validate_checkpoint_identity, validate_resume,
)
from core.historical_contracts import HISTORICAL_LABELS
from core.state import WORKFLOW_PROTOCOL_VERSION, new_default_state
from core.workflow_policy import workflow_progress


def test_current_checkpoint_metadata_round_trips_and_resumes_only_exact_coordinate(tmp_path):
    coordinate = {"target_url": "http://localhost/dvwa", "surface": "sqli",
                  "provider": "example", "security_level": "low",
                  "payload_mode": "hybrid", "experiment_condition": "linear_hybrid",
                  "repeat_index": 0, "workflow_protocol_version": WORKFLOW_PROTOCOL_VERSION}
    thread = stable_thread_id("example", coordinate)
    with ExperimentCheckpointStore(tmp_path / "checkpoint.sqlite3", experiment_id="example") as store:
        store.save_completed(thread_id=thread, final_state=new_default_state(), artifact={"execution_id": "example"},
                             coordinate=coordinate)
        stored = store.load(thread)
        assert stored["state_schema_version"] == "exploitation-state"
        assert stored["checkpoint_schema_version"] == "execution-checkpoint"
        assert stored["graph_build_version"] == "execution-graph"
        assert validate_resume(stored, coordinate=coordinate) == (True, "compatible")
        assert not validate_resume(stored, coordinate={**coordinate, "candidate_budget": 20})[0]
        assert not validate_resume(stored, coordinate={**coordinate, "target_url": "http://localhost/other"})[0]
        for field, role in (("state_schema_version", "state_schema"),
                            ("checkpoint_schema_version", "checkpoint_schema"),
                            ("graph_build_version", "graph_build")):
            historical = next(iter(HISTORICAL_LABELS[role]))
            altered = {**stored, field: historical}
            valid, reason = validate_checkpoint_identity(altered, coordinate=coordinate, experiment_id="example")
            assert valid is False
            assert field in reason
            assert altered[field] == historical
        assert store.load(thread) == stored


@pytest.mark.parametrize("measured", [True, False, None])
def test_observation_header_preserves_tri_state_and_source_scope(measured):
    fact = make_observation_fact("object_ids_enumerable", measured, source="offline_test",
                                 method="ac_idor", fixture_id="fixture", protocol_version="fixture-protocol",
                                 evidence_refs=["fixture:control"], principal_id="test-principal")
    assert fact["policy_version"] == "method-preconditions"
    assert fact["value"] is measured
    assert fact["source"] == "offline_test"
    assert fact["scope"]["fixture_id"] == "fixture"
    assert fact["scope"]["principal_id"] == "test-principal"
    assert fact["evidence_refs"] == ["fixture:control"]


def test_state_and_workflow_use_one_canonical_protocol():
    state = new_default_state()
    assert state["workflow_protocol_version"] == "method-workflow"
    progress = workflow_progress(state)
    assert progress["protocol_version"] == state["workflow_protocol_version"]
    assert progress["iteration_count"] == 0
    assert progress["method_coverage"]["attempted"] == 0
