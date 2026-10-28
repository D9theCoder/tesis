"""Pure publication/catalog/review adapter checks; no graph or external I/O."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from core.run_status import EXECUTION_STATUSES, SECURITY_OUTCOMES, reason
from evaluation.observer_export import build_projection, main
from evaluation.reporter import write_json_report
from evaluation.thesis_scoring import finalize_reviews, review_queue
from tesis.artifact_catalog import ArtifactCatalog
from tesis.artifact_layout import ExperimentArtifactLayout
from tests.test_execution_security_status import evidence_artifact


def write(path, data):
    write_json_report(path, data)
    return path


def run_record(eid="older-test-id", **fields):
    return {"schema_version": "tui.v1", "execution_id": eid, "run_id": "repeated-run-id",
            "status": "success", "config": {"surface": "sqli", "security_level": "high"},
            "final_state": {}, **fields}


@pytest.mark.parametrize("execution", EXECUTION_STATUSES)
@pytest.mark.parametrize("outcome", SECURITY_OUTCOMES)
def test_projection_preserves_all_status_pairs_and_candidate_vocabulary(tmp_path, execution, outcome):
    record = run_record(execution_status=execution, security_outcome=outcome,
                        candidate_dispositions=[{"execution_status": "executed"}])
    path = write(tmp_path / "source.json", record)
    projection = build_projection(ArtifactCatalog({"flat": tmp_path}, {}))
    row = projection["runs"][0]
    assert row["execution"]["status"] == execution
    assert row["security"]["outcome"] == outcome
    assert row["source"]["sha256"] == sha256(path.read_bytes()).hexdigest()
    assert row["detail"]["candidate_dispositions"]["available"]
    assert projection["coverage"]["execution_status_counts"][execution] == 1


def test_matrix_standalone_embedded_membership_and_unknown_ids(tmp_path):
    child = run_record("child", repeat_index=7)
    write(tmp_path / "unusual-child.json", child)
    write(tmp_path / "parent.json", {"schema_version": "stage8.v1", "execution_id": "parent",
        "runs": [child, {"status": "skipped", "config": {}}, run_record("embedded")],
        "cancellation": {"total_runs": 5, "completed_runs": 3, "not_started_runs": 2}})
    write(tmp_path / "child.rich.json", {"schema_version": "stage7.rich.v1", "execution_id": "child"})
    write(tmp_path / "child.resume.json", run_record("child"))
    write(tmp_path / "review.json", {"artifact_type": "thesis_review_status", "execution_id": "review"})
    projection = build_projection(ArtifactCatalog({"research": tmp_path}, {}))
    assert len(projection["runs"]) == 3
    children = {r["identity"]["execution_id"]: r for r in projection["runs"]}
    assert children["child"]["identity"]["matrix_execution_id"] == "parent"
    assert children["child"]["identity"]["coordinate_index"] == 0
    assert children["child"]["identity"]["repeat_index"] == 7
    assert children[None]["identity"]["run_id"] is None
    assert children[None]["execution"]["status"] is None
    assert children["embedded"]["source"]["pointer"] == "/runs/2"
    counts = projection["matrices"][0]["coverage"]
    assert (counts["planned_runs"], counts["represented_runs"], counts["completed_runs"], counts["unstarted_runs"]) == (5, 3, 2, 2)


def test_ambiguous_copies_missing_manifest_primary_and_external_symlink(tmp_path):
    source = tmp_path / "sources"
    write(source / "one.json", run_record())
    write(source / "copy.json", run_record())
    external = write(tmp_path / "external.json", run_record("external"))
    (source / "escape.json").symlink_to(external)
    write(source / "manifest.json", {"artifact_type": "experiment_manifest", "runs": [
        {"execution_id": "missing", "artifact": "missing.json", "index": 1},
        {"execution_id": "external", "artifact": "../external.json", "index": 2}]})
    projection = build_projection(ArtifactCatalog({"default": source}, {}))
    assert len(projection["runs"]) == 2 and all(r["ambiguous"] for r in projection["runs"])
    assert projection["coverage"]["total_runs"] == 0
    assert {d["code"] for d in projection["diagnostics"]} >= {
        "ambiguous_execution_id", "missing_or_ambiguous_primary", "scope_violation", "invalid_manifest_path"}


def test_manifest_metadata_and_shared_detail_ownership(tmp_path):
    layout = ExperimentArtifactLayout.allocate(tmp_path, "matrix")
    child = layout.child_directory({}, 0)
    record = run_record("child", model="model", model_profile="profile", repeat_index=4,
                        timing={"started_at": "2026-10-12T00:00:00Z", "duration_ms": 42})
    write(child / "child.json", record)
    write(layout.root / "parent.matrix.json", {"schema_version": "stage8.v1", "execution_id": "parent", "runs": [record]})
    write(layout.root / "akg.snapshot.json", {"schema_version": "akg-snapshot.v1"})
    (layout.root / "runtime.events.jsonl").write_text('{"event_type":"run.finished"}\n')
    manifest = layout.write_manifest(artifacts=[record], aggregate={"execution_id": "parent"})
    row = json.loads(manifest.read_bytes())["runs"][0]
    assert (row["model"], row["model_profile"], row["repeat_index"], row["matrix_execution_id"], row["index"]) == (
        "model", "profile", 4, "parent", 1)
    assert row["timing"]["duration_ms"] == 42
    projection = build_projection(ArtifactCatalog({"experiment": layout.root}, {}))
    details = projection["runs"][0]["detail"]
    assert details["snapshot"]["path"] == "akg.snapshot.json"
    assert details["journal"]["owner_execution_id"] == "parent"


def test_completed_child_does_not_end_active_parent(tmp_path):
    child = run_record("child", execution_status="completed", security_outcome="confirmed")
    write(tmp_path / "parent.json", {"schema_version": "stage8.v1", "execution_id": "parent",
        "status": "active", "runs": [child]})
    matrix = build_projection(ArtifactCatalog({"root": tmp_path}, {}))["matrices"][0]
    assert matrix["execution"]["status"] is None
    assert matrix["security"]["outcome"] == "confirmed"


def test_flat_root_shared_snapshot_without_invocation_identity_is_unavailable(tmp_path):
    write(tmp_path / "one.json", run_record("one"))
    write(tmp_path / "two.json", run_record("two"))
    write(tmp_path / "akg.snapshot.json", {"schema_version": "akg-snapshot.v1"})
    rows = build_projection(ArtifactCatalog({"flat": tmp_path}, {}))["runs"]
    assert all(row["detail"]["snapshot"] is None for row in rows)


def test_atomic_publication_and_failed_replace_retain_complete_old_json(tmp_path, monkeypatch):
    target = write(tmp_path / "artifact.json", {"old": "complete"})
    before = target.read_bytes()
    def fail_replace(source, destination):
        assert target.read_bytes() == before
        assert json.loads(Path(source).read_bytes()) == {"new": "complete"}
        raise OSError("publication failure")
    monkeypatch.setattr("evaluation.reporter.os.replace", fail_replace)
    with pytest.raises(OSError, match="publication failure"):
        write_json_report(target, {"new": "complete"})
    assert target.read_bytes() == before
    assert list(tmp_path.iterdir()) == [target]


def test_polling_readers_only_see_complete_json_during_concurrent_writes(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    target = write(tmp_path / "artifact.json", {"writer": -1, "value": "x" * 10000})
    stopped = Event()
    def publish(writer):
        for _ in range(10):
            write_json_report(target, {"writer": writer, "value": "x" * 10000})
    def poll():
        while not stopped.is_set():
            data = json.loads(target.read_bytes())
            assert data["writer"] in {-1, 0, 1}
            assert data["value"] == "x" * 10000
    with ThreadPoolExecutor(max_workers=3) as pool:
        reader = pool.submit(poll)
        writers = [pool.submit(publish, writer) for writer in (0, 1)]
        try:
            for future in writers:
                future.result()
        finally:
            stopped.set()
        reader.result()
    assert not list(tmp_path.glob("*.tmp"))


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


def test_review_metadata_pending_epoch_and_valid_final_precedence(tmp_path, monkeypatch):
    source = write(tmp_path / "source.json", evidence_artifact())
    queue = review_queue(source)
    queue["components"].update(Smethod=3, Sexploit=0, Schain=0, Soutput=3)
    queue["component_pending_reasons"] = {}
    monkeypatch.setattr("evaluation.thesis_scoring.review_queue", lambda _: deepcopy(queue))
    monkeypatch.setattr("evaluation.observer_reviews.review_queue", lambda _: deepcopy(queue))
    old = tmp_path / "old"
    final = finalize_reviews(source, [], output_dir=old, isolated_output=True)
    assert all(final[k] == queue[k] for k in ("execution_id", "run_id", "source_path", "selection"))
    assert final["generated_at"]
    assert final["workflows"]["human"]["components"]["Spayload"] == 0
    assert final["workflows"]["human"]["denominator"] == 1
    pending_queue = deepcopy(queue)
    pending_queue["components"]["Soutput"] = None
    monkeypatch.setattr("evaluation.thesis_scoring.review_queue", lambda _: deepcopy(pending_queue))
    new = tmp_path / "new"
    pending = finalize_reviews(source, [], output_dir=new, isolated_output=True)
    assert pending["workflows"]["human"]["Srun_final"] is None
    # Newer unrelated source hash and incorrect arithmetic cannot erase final.
    receipt = json.loads(Path(final["receipts"]["human"]).read_bytes())
    write(new / "wrong-hash.json", {**receipt, "source_sha256": "0" * 64})
    write(new / "bad-arithmetic.json", {**receipt, "Srun_final": 4})
    projection = build_projection(ArtifactCatalog({"source": source}, {"old": old, "new": new}))
    human = projection["runs"][0]["thesis_review"]["human"]
    assert human["status"] == "final" and human["Srun_final"] == 1.2
    assert human["receipt"]["root_id"] == "old"
    assert projection["runs"][0]["thesis_review"]["ai"]["status"] == "not_selected"
    assert any(d["code"] == "invalid_review_binding" for d in projection["diagnostics"])


def test_historical_labels_are_hash_bound_and_never_change_outcomes(tmp_path):
    path = write(tmp_path / "source.json", run_record(security_outcome="fixture_limited"))
    write(tmp_path / "audit.json", {"artifact_type": "historical_audit", "rows": [{
        "execution_id": "older-test-id", "source_path": str(path), "source_sha256": sha256(path.read_bytes()).hexdigest(),
        "classification": "executed_without_candidate_confirmation"}]})
    projection = build_projection(ArtifactCatalog({"epoch": tmp_path}, {}), historical_analysis=["epoch:audit.json"])
    security = projection["runs"][0]["security"]
    assert security["outcome"] == "fixture_limited"
    assert security["historical_analysis"]["source"]["path"] == "audit.json"


def test_inputs_cannot_change_during_projection_or_be_overwritten(tmp_path, monkeypatch):
    source = write(tmp_path / "source.json", run_record())
    catalog = ArtifactCatalog({"source": source}, {})
    catalog.raw(source)
    source.write_text('{}')
    with pytest.raises(ValueError, match="changed"):
        catalog.verify_unchanged()
    monkeypatch.chdir(tmp_path)
    write(tmp_path / "results" / "existing.json", {})
    with pytest.raises(SystemExit):
        main(["--source-root", f"source={source}", "--output", "results/existing.json"])


def test_invalid_canonical_nested_fields_remain_unknown_in_coverage(tmp_path):
    write(tmp_path / "invalid.json", run_record(final_state={"execution_status": "executed"}))
    projection = build_projection(ArtifactCatalog({"source": tmp_path}, {}))
    assert projection["runs"][0]["execution"]["status"] is None
    assert projection["coverage"]["execution_unknown_runs"] == 1
    assert sum(projection["coverage"]["security_outcome_counts"].values()) == 0


def test_config_secrets_in_status_details_are_redacted_without_changing_hash(tmp_path):
    record = run_record(execution_status="failed", security_outcome="unconfirmed",
        execution_reason=reason("RUNTIME_FAILURE", "service rejected secret-value"),
        config={"api_key": "secret-value"})
    path = write(tmp_path / "source.json", record)
    projection = build_projection(ArtifactCatalog({"source": tmp_path}, {}))
    assert "secret-value" not in json.dumps(projection)
    assert projection["runs"][0]["source"]["sha256"] == sha256(path.read_bytes()).hexdigest()


def test_legacy_pending_status_requires_contained_validated_ledger(tmp_path):
    source = write(tmp_path / "source.json", evidence_artifact())
    reviews = tmp_path / "review-epoch"
    pending = finalize_reviews(source, [], output_dir=reviews, isolated_output=True)
    status_path = next(reviews.glob('*.review-status.json'))
    legacy = {k: v for k, v in pending.items() if k not in {
        "execution_id", "run_id", "source_path", "selection", "generated_at"}}
    write(status_path, legacy)
    row = build_projection(ArtifactCatalog({"source": source}, {"epoch": reviews}))["runs"][0]
    assert row["thesis_review"]["human"]["status"] == "pending"
    write(status_path, {**legacy, "decision_ledger_path": str(tmp_path / "outside.json")})
    row = build_projection(ArtifactCatalog({"source": source}, {"epoch": reviews}))["runs"][0]
    assert row["thesis_review"]["human"]["Srun_final"] is None
    assert row["thesis_review"]["human"]["status"] == "missing"


def test_fractional_final_components_and_independent_roles(tmp_path, monkeypatch):
    record = evidence_artifact(decision="confirmed", signal="verified_account_extraction")
    state = record["final_state"]
    method = record["selected_method"]
    state["payload_candidates"][method].append({**state["payload_candidates"][method][0], "candidate_id": "second"})
    state["payload_validation_results"][method].append({"candidate_id": "second", "valid": True})
    state["payload_provenance"]["second"] = dict(state["payload_provenance"]["candidate"])
    state["response_evidence"].append({**state["response_evidence"][0], "candidate_id": "second", "evidence_id": "response2"})
    state["verifier_history"][0]["evidence_refs"].append("#/final_state/response_evidence/1")
    record["config"].update(scoring_mode="both", scoring_evaluator={
        "provider": "offline", "model": "judge", "max_attempts": 1, "max_tokens": 512, "timeout": 5})
    source = write(tmp_path / "source.json", record)
    queue = review_queue(source)
    queue["components"].update(Smethod=2.5, Sexploit=3, Schain=0, Soutput=3)
    queue["component_pending_reasons"] = {}
    monkeypatch.setattr("evaluation.thesis_scoring.review_queue", lambda _: deepcopy(queue))
    monkeypatch.setattr("evaluation.observer_reviews.review_queue", lambda _: deepcopy(queue))
    decisions = [{"decision_id": f'{mode}:{row["candidate_id"]}', "scoring_mode": mode,
        "candidate_id": row["candidate_id"], "score": index + 1,
        "source_sha256": queue["source_sha256"], "run_id": queue["run_id"],
        "rubric_version": queue["rubric_version"], "reason": "fixture evidence",
        "evidence_refs": row["evidence_refs"], "reviewer_id": "offline/judge" if mode == "ai" else "fixture-human",
        "review_version": "judge.v1", "timestamp": "2026-10-12T00:00:00+00:00"}
        for mode in ("human", "ai") for index, row in enumerate(queue["candidates"])]
    reviews = tmp_path / "epoch"
    finalize_reviews(source, decisions, output_dir=reviews, isolated_output=True)
    row = build_projection(ArtifactCatalog({"source": source}, {"epoch": reviews}))["runs"][0]
    for mode in ("human", "ai"):
        workflow = row["thesis_review"][mode]
        assert workflow["status"] == "final"
        assert workflow["components"]["Smethod"] == 2.5
        assert workflow["Spayload_final"] == 1.5
        assert workflow["Srun_final"] == 2.3
        assert (workflow["numerator"], workflow["denominator"]) == (3, 2)
