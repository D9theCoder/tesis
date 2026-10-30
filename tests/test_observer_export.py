"""Pure publication/catalog/review adapter checks; no graph or external I/O."""
from hashlib import sha256
import json


from core.run_status import reason
from evaluation.observer_export import build_projection
from evaluation.reporter import write_json_report
from tesis.artifact_catalog import ArtifactCatalog


def write(path, data):
    write_json_report(path, data)
    return path


def run_record(eid="older-test-id", **fields):
    return {"schema_version": "tui.v1", "execution_id": eid, "run_id": "repeated-run-id",
            "status": "success", "config": {"surface": "sqli", "security_level": "high"},
            "final_state": {}, **fields}


def test_metrics_and_stored_runtime_dimensions_preserve_nulls(tmp_path):
    write(tmp_path / "one.json", run_record("one", method_score=2, exploitation_score=1,
        selected_method=None, final_state={"selected_method": "sqli_union"},
        composite_score=1.25, consistency_score=0,
        report={"summary": {"token_cost": 0.5, "metric_availability": {"token_cost": True}}}))
    write(tmp_path / "two.json", run_record("two", token_cost=0))
    projection = build_projection(ArtifactCatalog({"flat": tmp_path}, {}))
    one = next(r for r in projection["runs"] if r["identity"]["execution_id"] == "one")
    assert one["identity"]["selected_method"] == "sqli_union"
    assert one["runtime_scores"]["components"]["Smethod"] == 2
    assert one["runtime_scores"]["components"]["Spayload"] is None
    assert one["runtime_scores"]["components"]["Srun"] == 1.25
    assert projection["metrics"]["token_cost"] == {
        "mean": .5, "n_available": 1, "n_unavailable": 1, "unavailable_reasons": {"legacy_numeric": 1}}


def test_config_secrets_in_status_details_are_redacted_without_changing_hash(tmp_path):
    record = run_record(execution_status="failed", security_outcome="unconfirmed",
        execution_reason=reason("RUNTIME_FAILURE", "service rejected secret-value"),
        config={"api_key": "secret-value"})
    path = write(tmp_path / "source.json", record)
    projection = build_projection(ArtifactCatalog({"source": tmp_path}, {}))
    assert "secret-value" not in json.dumps(projection)
    assert projection["runs"][0]["source"]["sha256"] == sha256(path.read_bytes()).hexdigest()
