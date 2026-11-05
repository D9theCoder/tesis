"""Canonical artifact writes and original-byte historical discovery (offline)."""
import json
from hashlib import sha256

import pytest

from core.historical_contracts import HISTORICAL_LABELS
from core.knowledge_graph import get_attack_knowledge_graph
from core.run_status import reason
from evaluation.containment import containment_summary
from evaluation.failure_logger import write_failure_artifact
from llm.cache_metrics import cache_performance_summary
from tesis.artifact_catalog import ArtifactCatalog
from tesis.live_runtime import (
    akg_snapshot, build_runtime_descriptor, descriptor_from_dict, write_descriptor,
)


def test_runtime_and_snapshot_producers_write_canonical_contracts(tmp_path):
    descriptor = build_runtime_descriptor(experiment_dir=tmp_path, execution_id="execution")
    path = write_descriptor(descriptor)
    document = json.loads(path.read_bytes())
    assert document["schema_version"] == "runtime-descriptor"
    assert document["execution_id"] == "execution"
    assert document["status"] == "active"
    snapshot = akg_snapshot(get_attack_knowledge_graph())
    assert snapshot["schema_version"] == "akg-snapshot"
    assert snapshot == akg_snapshot(get_attack_knowledge_graph())


@pytest.mark.parametrize("historical", [False, True])
def test_catalog_discovers_runtime_and_snapshot_without_relabeling(tmp_path, historical):
    descriptor_schema = (next(iter(HISTORICAL_LABELS["runtime_descriptor"]))
                         if historical else "runtime-descriptor")
    snapshot_schema = (next(iter(HISTORICAL_LABELS["akg_snapshot"]))
                       if historical else "akg-snapshot")
    execution = {"execution_id": "execution", "status": "completed", "final_state": {}, "config": {}}
    descriptor = {"schema_version": descriptor_schema, "execution_id": "execution", "status": "finished"}
    snapshot = {"schema_version": snapshot_schema, "nodes": [], "edges": []}
    for name, document in (("execution.json", execution), ("runtime.json", descriptor), ("akg.snapshot.json", snapshot)):
        (tmp_path / name).write_text(json.dumps(document))
    original = (tmp_path / "runtime.json").read_bytes()
    catalog = ArtifactCatalog({"source": tmp_path}, {}).scan()
    assert len(catalog.runs) == 1
    assert catalog.runs[0].detail["observer"]["status"] == "finished"
    assert catalog.runs[0].detail["observer"]["sha256"] == sha256(original).hexdigest()
    assert not any(row["code"] == "unsupported_schema" for row in catalog.diagnostics)
    assert catalog.read(tmp_path / "runtime.json")["schema_version"] == descriptor_schema
    assert (tmp_path / "runtime.json").read_bytes() == original
    catalog.verify_unchanged()


def test_historical_descriptors_are_read_only_even_at_a_new_output_path(tmp_path):
    legacy = next(iter(HISTORICAL_LABELS["runtime_descriptor"]))
    restored = descriptor_from_dict({"schema_version": legacy, "execution_id": "old"})
    assert restored.schema_version == legacy
    with pytest.raises(ValueError, match="read-only"):
        write_descriptor(restored, tmp_path / "derived.json")
    target = tmp_path / "runtime.json"
    original = json.dumps({"schema_version": legacy, "execution_id": "old"}).encode()
    target.write_bytes(original)
    current = build_runtime_descriptor(experiment_dir=tmp_path, execution_id="new")
    with pytest.raises(ValueError, match="overwrite a historical"):
        write_descriptor(current, target)
    assert target.read_bytes() == original
    assert not (tmp_path / "derived.json").exists()


def test_failure_report_preserves_evidence_with_canonical_schema(tmp_path):
    state = {"execution_status": "failed", "execution_reason": reason("EXAMPLE_FAILURE")}
    path = write_failure_artifact(output_dir=tmp_path, run_id="example", error="failure",
                                  final_state=state, recent_events=[])
    document = json.loads(path.read_bytes())
    assert document["schema_version"] == "execution-failure"
    assert document["error"] == "failure"
    assert document["final_state"] == state
    assert document["execution_status"] == "failed"


def test_containment_and_cache_headers_do_not_change_availability_or_counts():
    summary = containment_summary([
        {"kind": "request", "classification": "scope_violation"},
        {"kind": "navigation", "classification": "discarded_navigation"},
    ])
    assert summary["policy_version"] == "containment-summary"
    assert summary["attack_relevant"] == summary["navigation_discards"] == 1
    assert summary["total"] == 2
    cache = cache_performance_summary([])
    assert cache["cache_metrics_version"] == "provider-input-tokens"
    assert cache["cache_hit_rate"] is None
    assert cache["provider_cache_usage_status"] == "no_provider_calls"
