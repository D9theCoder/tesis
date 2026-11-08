"""Offline runtime producer -> artifact -> receipt -> observer -> analysis path.

The diagnostic uses a separately identified synthetic selection plan (not the
108-coordinate primary plan) and a bounded subset of its minimum legal six
coordinates: repeat 0 of both primary conditions.  Target sessions, the graph
execution, and model transport are replaced at their I/O boundaries only; the
real research-plan builder/verifier, matrix scheduler, single-run artifact
writer, review queue, receipt finalizer, observer discovery, and analysis
readers are exercised.

No live DVWA request, provider call, matrix launch, freeze, or retained-artifact
write occurs here.  The retained restored-epoch sources are read only to prove
they remain unbound and byte-identical.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from core.graph_builder import build_framework
from evaluation import research_plan
from evaluation.multi_llm_runner import run_provider_matrix
from evaluation.observer_reviews import _validate_epoch_claims, discover_reviews
from evaluation.research_analysis import (
    _receipt_epoch_problem,
    analyze_plan,
    plan_requires_receipt_epoch_binding,
)
from evaluation.research_plan import (
    _reconcile_coordinates,
    _validate_artifact_plan_identities,
    build_research_plan,
    verify_plan,
)
from evaluation.scoring_evidence import evidence_hash
from evaluation.thesis_scoring import (
    _binding_digest,
    compare_receipts,
    finalize_reviews,
    review_queue,
    seal_epoch_binding,
    validate_epoch_binding,
)
from tests.test_autoresearch_profile import _protocol_source, synthetic_profile
from tests.test_scoring_remediation_e2e import FixtureRuntime, ScoringFixture
from tesis.artifact_catalog import ArtifactCatalog


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESTORED = REPOSITORY_ROOT / "results/runs/restored-primary-2026-11-06"
RESTORED_REVIEWS = REPOSITORY_ROOT / "results/reviews/restored-primary-2026-11-06"
EVIDENCE_ROOT = (
    Path(os.environ["TESIS_RECEIPT_PIPELINE_EVIDENCE"])
    if os.environ.get("TESIS_RECEIPT_PIPELINE_EVIDENCE")
    else None
)
EPOCH = "offline-receipt-pipeline-2026-11-07"
PROFILE_ID = "offline-fixture-profile"
MODEL_NAME = "fixture-model"
FIXTURE_ID = "synthetic-dwva"
PROTOCOL_VERSION = "offline-protocol"
COMPONENTS = ("Smethod", "Spayload", "Sexploit", "Schain", "Soutput")
MOCK_BOUNDARIES = (
    "httpx.Client.request -> in-memory DVWA fixture",
    "llm.runtime.get_llm / agents.orchestrator.get_llm / "
    "foundation.payload_generator.get_llm -> offline ScoringFixture",
    "evaluation.runner.build_framework -> per-coordinate deterministic graph",
    "evaluation.runner.default_source_identity and "
    "evaluation.multi_llm_runner.default_source_identity -> frozen plan source identity",
)


def _sha256(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _schedule():
    return {
        "schedule_id": "offline-receipt-pipeline-control",
        "version": "token-prices",
        "currency": "USD",
        "effective_at": "2026-09-01T00:00:00+00:00",
        "prices": {
            "offline/model": {"input_per_million": 1.0, "output_per_million": 2.0},
        },
    }


def _profile():
    """Synthetic five-scenario generator plus the two selected surface levels.

    ``synthetic_profile`` is the maintained offline schema/reachability
    fixture.  The diagnostic runs only ``sqli:low``; the AKG-guided coordinate
    may select a brute-force method, so its low scenario is added with the
    generator's own entry shape.  No fit value is invented for a real method.
    """
    profile = synthetic_profile()
    profile["scenarios"]["sqli:low"] = {
        method: dict(entry)
        for method, entry in profile["scenarios"]["sqli:high"].items()
    }
    profile["scenarios"]["brute_force:low"] = {
        method: dict(entry)
        for method, entry in profile["scenarios"]["brute_force:medium"].items()
    }
    profile["sha256"] = evidence_hash(
        {key: value for key, value in profile.items() if key != "sha256"}
    )
    return profile


def _fixture_restoration(epoch, source_hashes_sha256):
    document = {
        "policy_version": "fixture-restoration",
        "evidence_id": "offline-receipt-pipeline-restoration",
        "kind": "operator_attestation",
        "fixture_id": FIXTURE_ID,
        "protocol_version": PROTOCOL_VERSION,
        "security_level": "low",
        "epoch_id": epoch,
        "source_hashes_sha256": source_hashes_sha256,
        "restoration": "reset",
        "authorized_protocol": "offline synthetic producer-path control",
        "evidence_refs": ["control:offline-receipt-pipeline-restoration"],
        "observed_at": "2026-11-07T00:00:00+00:00",
        "operator": "offline-control",
    }
    document["evidence_sha256"] = evidence_hash(document)
    return document


def _study_document(epoch, restoration_path):
    return {
        "research_config_version": research_plan.RESEARCH_CONFIG_VERSION,
        "epoch_id": epoch,
        "primary_conditions": list(research_plan.PRIMARY_CONDITIONS),
        "payload_mode": "hybrid",
        "blocks": {
            "selection": {
                "target_method": None,
                "unit": "offline producer-to-receipt path control",
            },
        },
        "repeats": 3,
        "levels": ["low"],
        "surfaces": ["sqli"],
        "model_profiles": [{
            "profile_id": PROFILE_ID,
            "provider": "openai_compatible",
            "model_name": MODEL_NAME,
            "reasoning_effort": research_plan.PRIMARY_REASONING_EFFORT,
        }],
        "design": {
            "pairing": "offline synthetic repeat identity",
            "multiple_comparisons": research_plan.CONDITION_CONTRAST_MULTIPLICITY,
            "condition_contrast_family": {
                "stratum": "model x surface x level",
                "contrast": "linear_hybrid vs akg_guided_hybrid",
                "outcomes": list(research_plan.CONDITION_CONTRAST_OUTCOMES),
                "multiplicity": research_plan.CONDITION_CONTRAST_MULTIPLICITY,
                "family_size": 6,
                "missing_outcome_policy": research_plan.CONDITION_CONTRAST_MISSING_POLICY,
                "declaration_source": (
                    "frozen research_config hashed into the plan before selection"
                ),
                "supplementary_families": list(
                    research_plan.CONDITION_CONTRAST_SUPPLEMENTARY_FAMILIES
                ),
            },
            "diagnostic_scope": (
                "Bounded offline producer-path control: the minimum legal plan has "
                "six coordinates; only repeat 0 of both conditions is executed. "
                "This is not the primary research plan and not a thesis result."
            ),
        },
        "scoring": {
            "rubric_version": "thesis-scoring",
            "runtime_provisional": "runtime-scoring",
            "final_source": "thesis_score_receipt only",
        },
        "frozen_inputs_required": list(research_plan.REQUIRED_FROZEN_INPUTS),
        "fixture_restoration": str(restoration_path),
    }


def _resolved_config(profile, protocol, schedule, epoch):
    return SimpleNamespace(
        token_price_schedule=schedule,
        payload_mode="hybrid",
        scoring_profile=profile,
        scoring_oracles=[protocol],
        scoring_rubric_version="thesis-scoring",
        scoring_mode="human",
        fixture_id=FIXTURE_ID,
        protocol_version=PROTOCOL_VERSION,
        candidate_budget=5,
        scoring_policy_epoch={"epoch_id": epoch},
        models={
            PROFILE_ID: SimpleNamespace(
                provider="openai_compatible",
                model_name=MODEL_NAME,
                reasoning_effort=research_plan.PRIMARY_REASONING_EFFORT,
            ),
        },
        providers=[PROFILE_ID],
        target_url="http://localhost/dwva",
        iterations=12,
        stop_policy="impact",
        coverage_target=0.7,
        enriched_reporting=False,
        diagnose=False,
        evasion_enabled=False,
        evasion_mode="reactive",
        evasion_max_retries=3,
        evasion_cooldown_threshold=5,
        llm_max_concurrency=1,
        llm_cache=False,
        llm_runtime=SimpleNamespace(
            roles={
                "orchestrator": SimpleNamespace(),
                "payload_generator": SimpleNamespace(),
            }
        ),
        levels=["low"],
        surfaces=["sqli"],
    )


def _decisions(queue):
    decisions = []
    for row in queue["candidates"]:
        if row["status"] != "pending_review":
            continue
        assert isinstance(row.get("base_proof"), int), row
        decisions.append({
            "decision_id": f"human:{row['candidate_id']}",
            "run_id": queue["run_id"],
            "source_sha256": queue["source_sha256"],
            "rubric_version": queue["rubric_version"],
            "scoring_mode": "human",
            "candidate_id": row["candidate_id"],
            "score": row["base_proof"],
            "reason": "offline producer-path assessment",
            "evidence_refs": row["evidence_refs"],
            "reviewer_id": "offline-reviewer",
            "review_version": "manual-assessment",
            "timestamp": "2026-11-07T00:00:00+00:00",
        })
    return decisions


def _artifact_path(artifact):
    return Path(artifact["_artifact_path"])


def _retained_sources():
    paths = []
    plan = RESTORED / "research-plan.json"
    if plan.is_file():
        paths.append(plan)
    run_dir = RESTORED / "selection/run-007"
    if run_dir.is_dir():
        artifact = next(
            (path for path in run_dir.glob("exec-*.json")
             if not path.name.endswith(".rich.json")),
            None,
        )
        if artifact is not None:
            paths.append(artifact)
    if RESTORED_REVIEWS.is_dir():
        for receipt in sorted(RESTORED_REVIEWS.glob("*.ai-verified.json")):
            try:
                document = json.loads(receipt.read_bytes())
            except (OSError, ValueError):
                continue
            if "run-007" in str(document.get("source_path", "")):
                paths.append(receipt)
                break
    return paths


def _retained_hashes(paths):
    return {
        str(path.relative_to(REPOSITORY_ROOT)): _sha256(path)
        for path in paths
    }


def _write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _persist_evidence(pipeline):
    if EVIDENCE_ROOT is None:
        return
    base = EVIDENCE_ROOT
    (base / "inputs").mkdir(parents=True, exist_ok=True)
    (base / "artifacts").mkdir(parents=True, exist_ok=True)
    (base / "receipts").mkdir(parents=True, exist_ok=True)
    for source, name in (
        (pipeline.config_path, "config.yaml"),
        (pipeline.study_path, "study.json"),
        (pipeline.restoration_path, "restoration.json"),
        (pipeline.plan_path, "research-plan.json"),
        (pipeline.payload_policy_path, "payload-policy-snapshot.json"),
    ):
        (base / "inputs" / name).write_bytes(Path(source).read_bytes())
    for condition, artifact in pipeline.artifacts.items():
        path = _artifact_path(artifact)
        (base / "artifacts" / f"{condition}-{path.name}").write_bytes(path.read_bytes())
    for condition, receipt_path in pipeline.receipt_paths.items():
        (base / "receipts" / f"{condition}-{Path(receipt_path).name}").write_bytes(
            Path(receipt_path).read_bytes()
        )
    _write_json(base / "analysis.json", pipeline.analysis)
    _write_json(base / "source-hashes-before.json", pipeline.source_hashes_before)
    _write_json(base / "source-hashes-after.json", pipeline.source_hashes_after)
    _write_json(
        base / "retained-source-hashes-before.json",
        pipeline.retained_hashes_before,
    )
    _write_json(
        base / "retained-source-hashes-after.json",
        pipeline.retained_hashes_after,
    )
    _write_json(base / "summary.json", pipeline.summary)


@pytest.fixture(scope="session")
def pipeline(tmp_path_factory):
    monkeypatch = pytest.MonkeyPatch()
    root = tmp_path_factory.mktemp("research-receipt-pipeline")
    config_path = root / "config.yaml"
    config_path.write_text(
        "reasoning_catalog:\n"
        f"  {MODEL_NAME}: [low, {research_plan.PRIMARY_REASONING_EFFORT}]\n",
        encoding="utf-8",
    )
    output_epoch = root / "epoch"
    study_path = root / "study.json"
    restoration_path = root / "restoration.json"

    profile = _profile()
    protocol = _protocol_source()
    schedule = _schedule()
    source_info = research_plan.source_identity(
        repository_root=REPOSITORY_ROOT, config_path=config_path,
    )
    restoration = _fixture_restoration(EPOCH, source_info["source_hashes_sha256"])
    _write_json(restoration_path, restoration)
    _write_json(study_path, _study_document(EPOCH, restoration_path))
    resolved = _resolved_config(profile, protocol, schedule, EPOCH)

    retained_paths = _retained_sources()
    retained_before = _retained_hashes(retained_paths)
    source_hashes_before = dict(source_info["source_hashes"])

    try:
        with pytest.MonkeyPatch.context() as plan_patch:
            plan_patch.setattr(research_plan, "_repository_root", lambda _path: REPOSITORY_ROOT)
            plan_patch.setattr(
                research_plan, "load_and_resolve_config", lambda **_kwargs: resolved,
            )
            plan = build_research_plan(
                config_path=str(config_path),
                output_epoch=str(output_epoch),
                epoch_id=EPOCH,
                research_config_path=str(study_path),
            )
            verify_error = None
            try:
                verified = verify_plan(output_epoch / "research-plan.json")
                assert verified["plan_sha256"] == plan["plan_sha256"]
            except ValueError as exc:  # concurrent source drift
                verify_error = f"{type(exc).__name__}: {exc}"

        plan_path = output_epoch / "research-plan.json"
        payload_policy_path = output_epoch / "payload-policy-snapshot.json"
        plan_identity = {
            "plan_sha256": plan["plan_sha256"],
            "epoch_id": plan["epoch_id"],
        }
        artifacts = {}
        queues = {}
        receipt_paths = {}
        receipts = {}

        for condition in research_plan.PRIMARY_CONDITIONS:
            graph = build_framework()
            fixture = ScoringFixture("sqli_union", "mixed_candidates")
            runtime = FixtureRuntime(fixture)
            try:
                with pytest.MonkeyPatch.context() as run_patch:
                    run_patch.setattr(
                        httpx.Client,
                        "request",
                        lambda client, *args, **kwargs: fixture.request(
                            client, *args, **kwargs,
                        ),
                    )
                    run_patch.setattr("llm.runtime.get_llm", lambda *a, **k: fixture)
                    run_patch.setattr("agents.orchestrator.get_llm", lambda *a, **k: fixture)
                    run_patch.setattr(
                        "foundation.payload_generator.get_llm", lambda *a, **k: fixture,
                    )
                    run_patch.setattr(
                        "evaluation.runner.build_framework",
                        lambda **kwargs: graph,
                    )
                    run_patch.setattr(
                        "evaluation.runner.default_source_identity",
                        lambda: source_info,
                    )
                    run_patch.setattr(
                        "evaluation.multi_llm_runner.default_source_identity",
                        lambda: source_info,
                    )
                    artifacts_list, aggregate = run_provider_matrix(
                        target_url="http://localhost/dwva",
                        providers=[PROFILE_ID],
                        security_levels=["low"],
                        surfaces=["sqli"],
                        payload_modes=["hybrid"],
                        repeats=1,
                        max_iterations=12,
                        candidate_budget=5,
                        stop_policy="impact",
                        coverage_target=0.7,
                        output_dir=str(root / "runs" / condition),
                        include_aggregate=True,
                        model_configs={
                            PROFILE_ID: {
                                "provider": "openai_compatible",
                                "model_name": MODEL_NAME,
                            },
                        },
                        execution_id=f"{EPOCH}-selection-{condition}",
                        experiment_conditions=[condition],
                        experiment_block="selection",
                        llm_max_concurrency=1,
                        scoring_mode="human",
                        scoring_rubric_version="thesis-scoring",
                        scoring_profile=profile,
                        scoring_oracles=[protocol],
                        scoring_policy_epoch={"epoch_id": EPOCH},
                        token_price_schedule=schedule,
                        source_hashes_sha256=plan["source_hashes_sha256"],
                        research_plan_identity=plan_identity,
                        fixture_id=FIXTURE_ID,
                        protocol_version=PROTOCOL_VERSION,
                        fixture_restoration_evidence=(
                            plan["constraints"]["fixture_restoration"]["by_level"]
                        ),
                        payload_policy_snapshot=plan["payload_policy_snapshot"],
                        llm_runtime=runtime,
                        llm_role_configs={
                            role: {"structured_output": "off"}
                            for role in ("orchestrator", "payload_generator")
                        },
                    )
            finally:
                runtime.close()
            assert len(artifacts_list) == 1, aggregate
            artifact = artifacts_list[0]
            artifact["_artifact_path"] = str(
                root / "runs" / condition / f"{artifact['execution_id']}.json"
            )
            artifacts[condition] = artifact
            if artifact.get("selected_method", "").startswith("ac_"):
                pytest.skip(
                    "runtime selected an Access Control method; the offline pipeline "
                    "does not model the independent permission oracle"
                )
            queue = review_queue(_artifact_path(artifact))
            queues[condition] = queue
            result = finalize_reviews(
                _artifact_path(artifact),
                _decisions(queue),
                output_dir=root / "reviews" / condition,
                isolated_output=True,
            )
            if result["workflows"]["human"]["status"] != "final":
                pytest.fail(
                    "offline producer path did not reach a final receipt for "
                    f"{condition}: {result['workflows']['human']}"
                )
            receipt_path = result["receipts"]["human"]
            receipt_paths[condition] = receipt_path
            receipts[condition] = json.loads(Path(receipt_path).read_bytes())

        catalog = ArtifactCatalog(
            {"runs": str(root / "runs")},
            {"reviews": str(root / "reviews")},
        )
        catalog.scan()
        entries = {
            entry.record.get("experiment_condition"): entry
            for entry in catalog.runs
            if entry.record.get("execution_id") in {
                artifact["execution_id"] for artifact in artifacts.values()
            }
        }
        discovered = {
            condition: discover_reviews(catalog, entry)
            for condition, entry in entries.items()
        }
        analysis = analyze_plan(
            plan,
            source_roots={"runs": str(root / "runs")},
            review_roots={"reviews": str(root / "reviews")},
        )
        source_hashes_after = research_plan.source_tree_hashes(REPOSITORY_ROOT)
        retained_after = _retained_hashes(retained_paths)
        drift = sorted(
            path for path in set(source_hashes_before) | set(source_hashes_after)
            if source_hashes_before.get(path) != source_hashes_after.get(path)
        )
        summary = {
            "artifact": "research_receipt_pipeline_diagnostic",
            "diagnostic_scope": (
                "Bounded offline producer-to-artifact-to-receipt-to-analysis path. "
                "Minimum legal synthetic plan has 6 coordinates; only repeat 0 of "
                "both primary conditions was executed. Not a research epoch."
            ),
            "epoch_id": plan["epoch_id"],
            "plan_sha256": plan["plan_sha256"],
            "plan_planned_counts": plan["planned_counts"],
            "plan_verified": verify_error is None,
            "plan_verification_error": verify_error,
            "plan_epoch_binding_required": plan_requires_receipt_epoch_binding(plan),
            "analysis_epoch_contract_mode": analysis["epoch_contract"]["mode"],
            "executed_conditions": list(artifacts),
            "executed_repeat_index": 0,
            "unexecuted_planned_repeats": 4,
            "mock_boundaries": list(MOCK_BOUNDARIES),
            "artifacts": {
                condition: {
                    "path": str(_artifact_path(artifact)),
                    "sha256": _sha256(_artifact_path(artifact)),
                    "research_plan_identity": artifact.get("research_plan_identity"),
                    "selected_method": artifact.get("selected_method"),
                    "source_sha256": queues[condition]["source_sha256"],
                    "epoch_sha256": queues[condition]["epoch_sha256"],
                    "components": queues[condition]["components"],
                    "pending_reasons": queues[condition]["component_pending_reasons"],
                }
                for condition, artifact in artifacts.items()
            },
            "receipts": {
                condition: {
                    "path": str(receipt_paths[condition]),
                    "sha256": _sha256(receipt_paths[condition]),
                    "epoch_sha256": receipts[condition]["epoch_sha256"],
                    "source_sha256": receipts[condition]["source_sha256"],
                    "components": receipts[condition]["components"],
                    "Srun_final": receipts[condition]["Srun_final"],
                }
                for condition in receipt_paths
            },
            "analysis": {
                "status_counts": analysis["status_counts"],
                "receipt_status_counts": analysis["epoch_binding"]["receipt_status_counts"],
                "refused_observations": analysis["epoch_binding"]["refused_observations"],
                "group_exclusions": analysis["group_exclusions"],
                "groups": len(analysis["groups"]),
                "analysis_declaration": {
                    "status": analysis["analysis_declaration"]["status"],
                    "role": analysis["analysis_declaration"]["role"],
                    "declared_before_analysis": analysis["analysis_declaration"]["declared_before_analysis"],
                    "problems": analysis["analysis_declaration"]["problems"],
                    "chronology": analysis["analysis_declaration"]["chronology"],
                    "source": analysis["analysis_declaration"]["source"],
                },
            },
            "population": {
                "shared_epoch": len({receipt["epoch_sha256"] for receipt in receipts.values()}) == 1,
                "distinct_source_hashes": len({receipt["source_sha256"] for receipt in receipts.values()}) == len(receipts),
            },
            "source_hashes_sha256": source_info["source_hashes_sha256"],
            "source_hashes_before": source_hashes_before,
            "source_hashes_after": source_hashes_after,
            "source_hashes_drift": drift,
            "retained_source_hashes_before": retained_before,
            "retained_source_hashes_after": retained_after,
            "retained_sources_unchanged": retained_before == retained_after,
            "limits": [
                "Synthetic offline fixture; no live DVWA/provider execution, readiness, or primary result.",
                "Only 2 of 6 minimum legal plan coordinates were executed; 4 planned repeats remain unexecuted.",
                "run_research_plan block scheduling was not run end-to-end; its real plan verifier and artifact identity validator were exercised.",
            ],
        }
        pipeline = SimpleNamespace(
            root=root,
            config_path=config_path,
            study_path=study_path,
            restoration_path=restoration_path,
            plan=plan,
            plan_path=plan_path,
            payload_policy_path=payload_policy_path,
            plan_identity=plan_identity,
            plan_verified=verify_error is None,
            plan_verification_error=verify_error,
            artifacts=artifacts,
            queues=queues,
            receipts=receipts,
            receipt_paths=receipt_paths,
            discovered=discovered,
            analysis=analysis,
            source_hashes_before=source_hashes_before,
            source_hashes_after=source_hashes_after,
            retained_paths=retained_paths,
            retained_hashes_before=retained_before,
            retained_hashes_after=retained_after,
            summary=summary,
        )
        _persist_evidence(pipeline)
        if verify_error is not None:
            pytest.skip(
                "concurrent source drift invalidated the frozen-plan verification: "
                + verify_error
            )
        return pipeline
    finally:
        monkeypatch.undo()


def test_artifact_identity_is_written_before_hashing_and_reaches_a_final_receipt(pipeline):
    assert pipeline.plan_verified, pipeline.plan_verification_error
    assert pipeline.plan["planned_counts"] == {"selection": 6, "total": 6}
    artifacts = list(pipeline.artifacts.values())
    assert _validate_artifact_plan_identities(pipeline.plan, artifacts) == pipeline.plan_identity
    reconciliation = _reconcile_coordinates(
        pipeline.plan["blocks"]["selection"], artifacts,
    )
    assert reconciliation["planned"] == 6
    assert reconciliation["observed"] == 2
    assert len(reconciliation["missing"]) == 4
    assert reconciliation["extra"] == [] and reconciliation["duplicates"] == []

    for condition, artifact in pipeline.artifacts.items():
        assert artifact["experiment_condition"] == condition
        assert artifact["repeat_index"] == 0
        assert artifact["research_plan_identity"] == pipeline.plan_identity
        assert set(artifact["research_plan_identity"]) == {"plan_sha256", "epoch_id"}
        assert "plan_identity" not in artifact
        raw = _artifact_path(artifact).read_bytes()
        assert b'"research_plan_identity"' in raw
        queue = pipeline.queues[condition]
        assert queue["source_sha256"] == sha256(raw).hexdigest()
        assert queue["prospective_study"] is True
        assert queue["epoch_binding_problems"] == []
        assert queue["epoch_binding"]["plan"] == {
            "status": "bound",
            "plan_sha256": pipeline.plan["plan_sha256"],
            "epoch_id": pipeline.plan["epoch_id"],
            "source": "research_plan_identity",
        }
        assert queue["epoch_binding"]["source_execution_sha256"] == queue["source_sha256"]
        assert queue["epoch_binding"]["experiment_epoch_id"] == pipeline.plan["epoch_id"]
        # The queue exposes the automatic components; Spayload is computed
        # from the assessed candidate grades during finalization.
        assert set(queue["components"]) == set(COMPONENTS) - {"Spayload"}
        assert all(isinstance(value, (int, float)) for value in queue["components"].values())
        assert queue["component_pending_reasons"] == {}
        receipt = pipeline.receipts[condition]
        assert receipt["artifact_type"] == "thesis_score_receipt"
        assert receipt["status"] == "final"
        assert receipt["source_sha256"] == queue["source_sha256"]
        assert receipt["epoch_sha256"] == queue["epoch_sha256"]
        assert set(receipt["components"]) == set(COMPONENTS)
        assert all(isinstance(value, (int, float)) for value in receipt["components"].values())
        assert isinstance(receipt["Srun_final"], (int, float))
        assert _artifact_path(artifact).read_bytes() == raw


def test_observer_and_analysis_share_the_population_epoch_and_keep_source_hashes(pipeline):
    linear = pipeline.queues["linear_hybrid"]
    akg = pipeline.queues["akg_guided_hybrid"]
    linear_receipt = pipeline.receipts["linear_hybrid"]
    akg_receipt = pipeline.receipts["akg_guided_hybrid"]

    assert linear_receipt["epoch_sha256"] == akg_receipt["epoch_sha256"]
    assert linear_receipt["source_sha256"] != akg_receipt["source_sha256"]
    assert linear_receipt["source_sha256"] == linear["source_sha256"]
    assert akg_receipt["source_sha256"] == akg["source_sha256"]
    assert linear_receipt["epoch_binding"]["source_execution_sha256"] == linear_receipt["source_sha256"]
    assert akg_receipt["epoch_binding"]["source_execution_sha256"] == akg_receipt["source_sha256"]
    assert validate_epoch_binding(linear_receipt, linear)["status"] == "current"
    assert validate_epoch_binding(akg_receipt, akg)["status"] == "current"
    with pytest.raises(ValueError, match="source_execution"):
        validate_epoch_binding(linear_receipt, akg)

    compared = compare_receipts(list(pipeline.receipt_paths.values()))
    assert len(compared["groups"]) == 2
    assert all(group["n_final"] == 1 for group in compared["groups"])

    assert set(pipeline.discovered) == {"linear_hybrid", "akg_guided_hybrid"}
    for condition, discovered in pipeline.discovered.items():
        assert discovered["human"]["status"] == "final"
        assert discovered["human"]["epoch_sha256"] == pipeline.receipts[condition]["epoch_sha256"]
        assert discovered["human"]["Srun_final"] == pipeline.receipts[condition]["Srun_final"]

    analysis = pipeline.analysis
    assert analysis["status_counts"]["final"] == 2
    assert analysis["status_counts"]["missing"] == 4
    assert analysis["status_counts"]["epoch_mismatch"] == 0
    assert analysis["status_counts"]["identity_incomplete"] == 0
    assert analysis["epoch_binding"]["receipt_status_counts"] == {"explicit": 2}
    assert analysis["epoch_binding"]["refused_observations"] == {}
    assert analysis["group_exclusions"] == []
    for observation in analysis["observations"]:
        if observation["state"] == "final":
            assert observation["epoch_binding_status"] == ["explicit"]


def test_missing_mismatched_experiment_plan_and_rules_are_refused(pipeline):
    linear_artifact = pipeline.artifacts["linear_hybrid"]
    linear_queue = pipeline.queues["linear_hybrid"]
    linear_receipt = pipeline.receipts["linear_hybrid"]
    entry = SimpleNamespace(source={"sha256": linear_queue["source_sha256"]})

    # Missing runtime plan identity: the producer validator and finalizer both fail closed.
    missing = deepcopy(linear_artifact)
    missing.pop("research_plan_identity")
    with pytest.raises(ValueError, match="research_plan_identity"):
        _validate_artifact_plan_identities(pipeline.plan, [missing])
    missing_path = pipeline.root / "negative-controls/planless-artifact.json"
    _write_json(missing_path, missing)
    missing_queue = review_queue(missing_path)
    assert missing_queue["prospective_study"] is True
    assert {"plan_sha256_invalid", "plan_unavailable"} <= set(
        missing_queue["epoch_binding_problems"]
    )
    refused_dir = pipeline.root / "negative-controls/planless-reviews"
    with pytest.raises(ValueError, match="prospective_epoch_binding_incomplete"):
        finalize_reviews(
            missing_path,
            _decisions(missing_queue),
            output_dir=refused_dir,
            isolated_output=True,
        )
    assert not list(refused_dir.glob("*-verified.json"))

    # Mismatched runtime plan identity: the plan runner rejects the artifact.
    mismatched = deepcopy(linear_artifact)
    mismatched["research_plan_identity"] = {
        "plan_sha256": "d" * 64,
        "epoch_id": pipeline.plan["epoch_id"],
    }
    with pytest.raises(ValueError, match="does not match the frozen plan"):
        _validate_artifact_plan_identities(pipeline.plan, [mismatched])

    # Analysis compares explicit receipt identity with the frozen plan.
    other_epoch = {**pipeline.plan, "epoch_id": "offline-other-epoch"}
    problem, _ = _receipt_epoch_problem(
        linear_receipt, other_epoch, entry, pipeline.plan["constraints"],
    )
    assert problem == "receipt_experiment_epoch_mismatch"
    other_plan = {**pipeline.plan, "plan_sha256": "d" * 64}
    problem, _ = _receipt_epoch_problem(
        linear_receipt, other_plan, entry, pipeline.plan["constraints"],
    )
    assert problem == "receipt_plan_identity_mismatch"
    other_rule = deepcopy(linear_receipt)
    other_rule["scoring_rule_sha256"] = "e" * 64
    problem, _ = _receipt_epoch_problem(
        other_rule, pipeline.plan, entry, pipeline.plan["constraints"],
    )
    assert problem == "receipt_scoring_rule_identity_mismatch"
    problem, _ = _receipt_epoch_problem(
        linear_receipt,
        pipeline.plan,
        SimpleNamespace(source={"sha256": "f" * 64}),
        pipeline.plan["constraints"],
    )
    assert problem == "receipt_source_execution_mismatch"

    # End-to-end analysis refuses a receipt population paired with a foreign plan.
    refused = analyze_plan(
        other_plan,
        source_roots={"runs": str(pipeline.root / "runs")},
        review_roots={"reviews": str(pipeline.root / "reviews")},
    )
    assert refused["status_counts"]["final"] == 0
    assert refused["status_counts"]["epoch_mismatch"] == 2
    assert refused["epoch_binding"]["refused_observations"] == {
        "receipt_plan_identity_mismatch": 2,
    }


def test_retained_restored_sources_are_read_only_and_not_retrofitted(pipeline):
    if not pipeline.retained_paths:
        pytest.skip("retained restored-epoch sources are not present in this checkout")
    before = dict(pipeline.retained_hashes_before)
    assert before == pipeline.retained_hashes_after
    assert pipeline.retained_hashes_before == _retained_hashes(pipeline.retained_paths)

    run_artifact = next(
        path for path in pipeline.retained_paths
        if path.name.startswith("exec-") and path.suffix == ".json"
    )
    run_bytes = run_artifact.read_bytes()
    run_listing = sorted(
        str(path.relative_to(run_artifact.parent))
        for path in run_artifact.parent.rglob("*")
        if path.is_file()
    )
    artifact = json.loads(run_bytes)
    assert "research_plan_identity" not in artifact
    assert "plan_identity" not in artifact
    queue = review_queue(run_artifact)
    assert queue["prospective_study"] is True
    assert "plan_unavailable" in queue["epoch_binding_problems"]
    assert queue["epoch_binding"]["plan"]["status"] == "unavailable"

    retained_receipt = next(
        path for path in pipeline.retained_paths
        if path.name.endswith(".ai-verified.json")
    )
    receipt_bytes = retained_receipt.read_bytes()
    receipt = json.loads(receipt_bytes)
    assert validate_epoch_binding(receipt, queue)["status"] == "historical_unbound"
    assert run_artifact.read_bytes() == run_bytes
    assert retained_receipt.read_bytes() == receipt_bytes
    assert _retained_hashes(pipeline.retained_paths) == before
    assert sorted(
        str(path.relative_to(run_artifact.parent))
        for path in run_artifact.parent.rglob("*")
        if path.is_file()
    ) == run_listing


def test_observer_prospective_binding_does_not_use_the_self_digest_shortcut(pipeline):
    queue = pipeline.queues["linear_hybrid"]
    receipt = pipeline.receipts["linear_hybrid"]
    _validate_epoch_claims(receipt, queue)

    stale = deepcopy(receipt)
    binding = stale["epoch_binding"]
    binding["plan_sha256"] = "d" * 64
    binding["plan"]["plan_sha256"] = "d" * 64
    stale["epoch_binding"] = seal_epoch_binding(binding)
    stale["epoch_sha256"] = stale["epoch_binding"]["epoch_sha256"]
    # The stale binding is internally self-consistent, so only the full epoch
    # projection comparison can reject it.
    assert stale["epoch_binding"]["binding_sha256"] == _binding_digest(
        {key: value for key, value in stale["epoch_binding"].items()
         if key != "binding_sha256"}
    )
    with pytest.raises(ValueError, match="receipt_epoch_binding_mismatch"):
        _validate_epoch_claims(stale, queue)

    historical = None
    status = None
    for path in sorted(
        (REPOSITORY_ROOT / "results/validation/thesis-scoring").rglob(
            "*.review-status.json"
        )
    ):
        document = json.loads(path.read_bytes())
        binding = document.get("epoch_binding")
        if not isinstance(binding, dict) or document.get("receipt_contract") != "epoch-bound-receipt":
            continue
        if (binding.get("plan") or {}).get("status") != "unavailable":
            continue
        if (binding.get("experiment_epoch") or {}).get("status") != "unavailable":
            continue
        historical, status = path, document
        break
    if historical is None:
        pytest.skip("no preserved historical epoch-bound review status is present")
    raw = historical.read_bytes()
    assert status["epoch_binding"]["plan"]["status"] == "unavailable"
    _validate_epoch_claims(status, {"prospective_study": False})
    assert historical.read_bytes() == raw
    tampered = deepcopy(status)
    tampered["epoch_binding"]["binding_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="receipt_binding_digest_mismatch"):
        _validate_epoch_claims(tampered, {"prospective_study": False})


def test_generated_plan_declares_prospective_receipt_epoch_binding(pipeline):
    assert pipeline.plan.get("epoch_binding_required") is True
    assert plan_requires_receipt_epoch_binding(pipeline.plan) is True
    assert pipeline.analysis["epoch_contract"]["receipt_epoch_binding_required"] is True
    assert pipeline.analysis["epoch_contract"]["mode"] == "prospective_bound"
    assert pipeline.analysis["epoch_contract"]["read_only"] is False
    declaration = pipeline.analysis["analysis_declaration"]
    assert declaration["status"] == "verified"
    assert declaration["declared_before_analysis"] is True
    assert declaration["role"] == "prospective_preregistered_family"
    assert declaration["problems"] == []
    assert declaration["family"]["family_size"] == 6
    assert declaration["family"]["outcomes"] == [
        "Smethod", "Spayload", "Sexploit", "Schain", "Soutput", "Srun",
    ]
    assert declaration["source"]["recorded_sha256"] == declaration["source"]["observed_sha256"]
    assert declaration["chronology"]["plan_precedes_final_receipts"] is True
