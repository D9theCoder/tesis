"""Pure contracts for accepted artifact discovery, graded reporting and review sheets.

No UI, provider call, graph execution or live experiment is exercised here.
"""
import json
from pathlib import Path

from evaluation.manual_scoring_sheet import manual_scoring_rows
from evaluation.observer_export import _graded_scores, build_projection
from tesis.artifact_catalog import ArtifactCatalog
from tesis.artifact_repository import ArtifactRepository
from tesis.report_formatters import format_module_scores_table, format_provider_comparison_table


def write_artifact(path: Path, record: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def run_record(execution_id: str, **fields) -> dict:
    return {"schema_version": "tui.v1", "execution_id": execution_id,
            "run_id": f"run-{execution_id}", "status": "success",
            "config": {"surface": "sqli", "security_level": "low"},
            "final_state": {}, "report": {}, **fields}


def v4_artifact(execution_id: str = "exec-graded") -> dict:
    return {
        "schema_version": "tui.v1",
        "execution_id": execution_id,
        "run_id": "run-graded",
        "status": "success",
        "execution_status": "completed",
        "config": {
            "scoring_mode": "human",
            "scoring_rubric_version": "scoring.v4",
            "scoring_profile": {},
            "scoring_oracles": [],
            "scoring_evaluator": {},
        },
        "final_state": {
            "selected_method": None,
            "scoring_decisions": [],
            "payload_candidates": {},
            "response_evidence": [],
            "timing_evidence": [],
            "chain_history": [],
            "weak_chain_opportunities": [],
            "model_call_requirements": [],
        },
        "score_epoch": {"thesis_final": "scoring.v4"},
        "llm_performance": [],
        "composite_score": None,
        "composite_score_status": "runtime_provisional_scoring.v2",
    }


def test_catalogue_and_repository_exclude_superseded_trees(tmp_path):
    accepted = write_artifact(tmp_path / "accepted" / "exec.json", run_record("accepted"))
    superseded = write_artifact(tmp_path / "_superseded_matrix-2026-10-30" / "run" / "exec.json",
                                run_record("superseded"))

    catalog = ArtifactCatalog({"source": tmp_path}, {}).scan()
    assert [entry.record["execution_id"] for entry in catalog.runs] == ["accepted"]
    # Audit copies are never removed.
    assert accepted.exists() and superseded.exists()

    rooted = ArtifactCatalog({"source": tmp_path / "_superseded_matrix-2026-10-30"}, {}).scan()
    assert rooted.runs == []
    assert rooted.diagnostics[0]["code"] == "superseded_root_excluded"
    rooted_file = ArtifactCatalog({"source": superseded}, {}).scan()
    assert rooted_file.runs == []

    repository = ArtifactRepository(tmp_path)
    assert [item.execution_id for item in repository.scan()] == ["accepted"]
    assert ArtifactRepository(tmp_path / "_superseded_matrix-2026-10-30").scan() == []
    assert ArtifactRepository(superseded).scan() == []


def test_never_run_composite_zero_is_not_published_as_srun(tmp_path):
    write_artifact(tmp_path / "skipped.json", run_record(
        "skipped", status="skipped", composite_score=0,
        composite_score_status="runtime_provisional_scoring.v2"))
    projection = build_projection(ArtifactCatalog({"source": tmp_path}, {}))
    run = projection["runs"][0]
    assert run["runtime_scores"]["components"]["Srun"] is None
    assert run["runtime_scores"]["stored_composite"] == 0
    assert run["runtime_scores"]["legacy"] is True
    assert run["runtime_scores"]["legacy_label"] == "runtime_provisional_scoring.v2"
    assert run["graded_scores"]["status"] == "unavailable"


def test_cancelled_partial_runtime_score_requires_execution_evidence(tmp_path):
    write_artifact(tmp_path / "partial.json", run_record(
        "partial-cancelled", status="cancelled", composite_score=1.5,
        final_state={"selected_method": "sqli_union",
                     "response_evidence": [{"candidate_id": "candidate-1"}]}))
    write_artifact(tmp_path / "empty.json", run_record(
        "empty-cancelled", status="cancelled", composite_score=0,
        target_method="sqli_union"))
    projection = build_projection(ArtifactCatalog({"source": tmp_path}, {}))
    runs = {run["identity"]["execution_id"]: run for run in projection["runs"]}
    assert runs["partial-cancelled"]["runtime_scores"]["components"]["Srun"] == 1.5
    assert runs["empty-cancelled"]["runtime_scores"]["components"]["Srun"] is None
    assert runs["empty-cancelled"]["runtime_scores"]["stored_composite"] == 0


def test_projection_publishes_graded_vector_and_keeps_workflows_distinct(tmp_path):
    artifact = v4_artifact()
    artifact["metrics"] = {
        "schema_version": "research-metrics.v2", "metrics_epoch": "recorded-epoch",
        "values": {"token_cost": 1.25}, "availability": {"token_cost": True},
        "unavailable_reason": {}, "denominators": {"token_cost": None},
    }
    artifact["scoring_policy"] = {"policy_version": "recorded-policy"}
    write_artifact(tmp_path / "graded.json", artifact)
    catalog = ArtifactCatalog({"source": tmp_path}, {}).scan()
    projection = build_projection(catalog)
    run = projection["runs"][0]
    graded = run["graded_scores"]
    assert graded["rubric_version"] == "scoring.v4"
    assert graded["components"] == {
        "Smethod": None, "Spayload": None, "Sexploit": None, "Schain": 0, "Soutput": None}
    assert graded["component_pending_reasons"]["Smethod"].startswith("ranking_unavailable")
    assert graded["component_pending_reasons"]["Spayload"] == "no_eligible_candidate"
    assert set(graded["workflows"]) == {"human", "ai"}
    assert graded["workflows"]["human"]["label"].startswith("HUMAN workflow")
    assert "not final thesis human signoff" in graded["workflows"]["ai"]["label"]
    assert run["runtime_scores"]["legacy"] is True

    # Current queue recomputation is exposed separately; recorded artifact
    # metrics/policy stay byte-for-byte in their original fields, labelled.
    assert graded["metrics_origin"] == "review_queue_current_sources"
    assert graded["scoring_policy_origin"] == "review_queue_current_sources"
    assert isinstance(graded["metrics"], dict) and "values" in graded["metrics"]
    assert graded["scoring_policy"] is not None
    assert run["metrics"]["research"]["origin"] == "recorded_artifact"
    assert run["metrics"]["research"]["values"]["token_cost"]["value"] == 1.25
    assert run["metrics"]["scoring_policy"] == {"policy_version": "recorded-policy"}
    assert run["metrics"]["scoring_policy_origin"] == "recorded_artifact"
    assert run["identity"]["scoring_policy_origin"] == "recorded_artifact"
    assert run["runtime_scores"]["research_metrics_origin"] == "recorded_artifact"

    # A validated workflow may carry numeric Spayload while the overall vector
    # still keeps Spayload null; human and ai values are never collapsed.
    workflows = {
        "human": {"status": "pending", "reason": "pending_candidate_grades",
                  "components": {"Smethod": 3, "Spayload": 4, "Sexploit": 3,
                                 "Schain": 0, "Soutput": 3},
                  "component_pending_reasons": {}, "Spayload_final": 4.0, "Srun_final": None},
        "ai": {"status": "pending", "reason": "pending_candidate_grades",
               "components": {"Smethod": 3, "Spayload": 1, "Sexploit": 3,
                              "Schain": 0, "Soutput": 3},
               "component_pending_reasons": {}, "Spayload_final": 1.0, "Srun_final": None},
    }
    merged = _graded_scores(catalog, catalog.runs[0], workflows)
    assert merged["components"]["Spayload"] is None
    assert merged["workflows"]["human"]["Spayload_final"] == 4.0
    assert merged["workflows"]["ai"]["Spayload_final"] == 1.0


def test_human_report_tables_put_graded_first_and_label_runtime_legacy():
    graded = {"rubric_version": "scoring.v4",
              "components": {"Smethod": None, "Spayload": None, "Sexploit": 3,
                             "Schain": 0, "Soutput": 3},
              "component_pending_reasons": {"Smethod": "ranking_unavailable:no_profile",
                                            "Spayload": "pending_candidate_grades"},
              "workflows": {"human": {
                                "status": "pending", "reason": "pending_candidate_grades",
                                "components": {"Smethod": None, "Spayload": None,
                                               "Sexploit": 3, "Schain": 0, "Soutput": 3},
                                "component_pending_reasons": {
                                    "Smethod": "ranking_unavailable:no_profile",
                                    "Spayload": "pending_candidate_grades"},
                                "Spayload_final": None, "Srun_final": None},
                            "ai": {"status": "missing", "reason": "missing_review"}}}
    run = {"config": {"provider": "fixture"},
           "report": {"module_scores": {"sqli_union": {"score": 3, "label": "confirmed"}}},
           "graded_scores": graded}
    text = format_module_scores_table({"runs": [run]})
    assert text.index("Graded thesis components") < text.index("Runtime module scores (legacy scoring.v2")
    assert "ranking_unavailable:no_profile" in text
    assert "Runtime score (legacy scoring.v2)" in text
    assert "HUMAN workflow (human review required; provisional until final receipt): pending" in text
    assert "AI workflow (experimental/provisional; not final thesis human signoff): missing" in text
    assert "Smethod=N/A (ranking_unavailable:no_profile)" in text
    assert "Sexploit=3" in text and "Spayload mean: N/A (pending_candidate_grades)" in text

    runtime_only = format_module_scores_table({"runs": [
        {"config": {}, "report": {"module_scores": {"sqli_union": {"score": 3, "label": "confirmed"}}}}]})
    assert "Graded thesis components" not in runtime_only
    assert "Runtime module scores (legacy scoring.v2" in runtime_only


def test_provider_table_keeps_every_run_observation_and_identity():
    runs = [
        {"execution_id": "exec-a", "run_id": "run-a",
         "config": {"provider": "fixture", "model_name": "model-a",
                    "experiment_condition": "cond-a", "surface": "sqli",
                    "security_level": "low", "payload_mode": "hybrid",
                    "target_method": "sqli_union", "repeat_index": 0},
         "report": {"module_scores": {"sqli_union": {"score": 4, "label": "a"}}}},
        {"execution_id": "exec-b", "run_id": "run-b",
         "config": {"provider": "fixture", "model_name": "model-b",
                    "experiment_condition": "cond-b", "surface": "sqli",
                    "security_level": "high", "payload_mode": "static_only",
                    "selected_method": "sqli_error", "repeat_index": 1},
         "report": {"module_scores": {"sqli_union": {"score": 1, "label": "b"}}}},
    ]
    text = format_provider_comparison_table({"runs": runs})
    observation_rows = [line for line in text.splitlines() if "sqli_union" in line]
    assert len(observation_rows) == 2
    assert "exec-a / run-a" in text and "exec-b / run-b" in text
    assert "model-a" in text and "model-b" in text
    assert "cond-a" in text and "cond-b" in text
    assert "hybrid" in text and "static_only" in text
    assert "1/4 (n=2)" not in text
    assert "no de-duplication" in text and "best-of-N" in text
    assert "Runtime score (legacy scoring.v2)" in text
    assert "Evasion (legacy per-run)" not in text


def test_manual_scoring_sheet_does_not_prefill_reviewer_scores():
    artifact = {
        "config": {},
        "final_state": {
            "payload_provenance": {"executed": {"method": "sqli_union", "source": "static_seed"}},
            "payload_candidates": {"sqli_union": [{"candidate_id": "executed", "payload_or_logic": "probe"}]},
            "payload_validation_results": {"sqli_union": [
                {"candidate_id": "executed", "valid": True, "reason": "ok"}]},
            "payload_scores": {"executed": 3},
            "method_scores": {"sqli_union": 2},
            "exploitation_scores": {"sqli_union": 4},
            "chain_scores": {"sqli_union": 1},
        },
        "execution_log": [
            {"event_type": "agent.probe.sent", "data": {"agent_id": "sqli_union", "payload": "probe"}}],
        "response_evidence": [{"agent_id": "sqli_union", "payload": "probe"}],
        "timing_evidence": [{"agent_id": "sqli_union", "payload": "probe", "elapsed_ms": 10}],
        "verifier_decision": {"agent_id": "sqli_union", "decision": "confirmed"},
    }
    rows = {row["candidate_id"]: row for row in manual_scoring_rows(artifact)}
    row = rows["executed"]
    for key in ("score_0_4", "payload_score_0_4", "method_score_0_4",
                "exploitation_score_0_4", "chain_score_0_4"):
        assert row[key] is None, key
    assert row["scoring_reason"] == ""
    assert row["runtime_legacy"] == {
        "score_epoch": "runtime_provisional_scoring.v2",
        "payload_score_0_4": 3,
        "method_score_0_4": 2,
        "exploitation_score_0_4": 4,
        "chain_score_0_4": 1,
        "scoring_reason": "",
    }
    # Review workflows still receive the evidence reference, not a score.
    assert row["response_evidence_ref"] == ["#/response_evidence/0"]
