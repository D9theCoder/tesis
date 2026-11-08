"""Epoch-binding aggregation refusal and explicit Mann-Whitney family reporting."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import evaluation.research_analysis as analysis
from evaluation.research_plan import (
    CONDITION_CONTRAST_MISSING_POLICY,
    CONDITION_CONTRAST_MULTIPLICITY,
    CONDITION_CONTRAST_OUTCOMES,
    CONDITION_CONTRAST_SUPPLEMENTARY_FAMILIES,
)


def _receipt(binding=None, **overrides):
    document = {
        "artifact_type": "thesis_score_receipt",
        "status": "final",
        "rubric_version": "thesis-scoring",
        "scoring_rule_sha256": "a" * 64,
        "scoring_mode": "ai",
        "metrics_epoch": "scoring-policy",
        "review_history": [{
            "candidate_id": "candidate-1",
            "decision_id": "decision-1",
            "scoring_mode": "ai",
            "reviewer_id": "ai/independent-judge",
            "review_version": "artifact-judge",
            "score": 3,
        }],
    }
    if binding is not None:
        document["receipt_contract"] = "epoch-bound-receipt"
        document["epoch_binding"] = binding
    document.update(overrides)
    return document


def _binding(**overrides):
    value = {
        "binding_version": "scoring-epoch-binding",
        "epoch_sha256": "e" * 64,
        "scoring_epoch_id": "a" * 64,
        "scoring_rule_sha256": "a" * 64,
        "source_execution_sha256": "b" * 64,
        "experiment_epoch_id": "epoch-current",
        "plan_sha256": "c" * 64,
        "binding_sha256": "f" * 64,
    }
    value.update(overrides)
    return value


def _entry(sha="b" * 64):
    return SimpleNamespace(source={"sha256": sha})


def test_epoch_binding_statuses_are_explicit_or_legacy_never_invented():
    assert analysis._epoch_binding({})["status"] == analysis.EPOCH_BINDING_LEGACY
    info = analysis._epoch_binding(_receipt(_binding()))
    assert info["status"] == analysis.EPOCH_BINDING_EXPLICIT
    assert info["binding"]["experiment_epoch_id"] == "epoch-current"
    invalid = analysis._epoch_binding(_receipt({
        "experiment_epoch_id": "", "source_execution_sha256": "not-a-digest",
        "epoch_sha256": "",
    }))
    assert invalid["status"] == analysis.EPOCH_BINDING_INVALID
    assert "epoch_sha256_missing" in invalid["problems"]
    assert "scoring_epoch_id_missing" in invalid["problems"]
    assert "source_execution_sha256_invalid" in invalid["problems"]
    assert "experiment_epoch_id_invalid" in invalid["problems"]


def test_binding_without_the_receipt_contract_is_refused():
    document = _receipt()
    document["epoch_binding"] = _binding()
    info = analysis._epoch_binding(document)
    assert info["status"] == analysis.EPOCH_BINDING_INVALID
    assert "receipt_contract_missing_or_unknown" in info["problems"]


def test_mixed_bound_and_unbound_receipts_are_refused_not_pooled():
    assert analysis._epoch_population_problem(
        [_receipt(_binding()), _receipt()]
    ) == "receipt_epoch_binding_mixed"
    assert analysis._epoch_population_problem(
        [_receipt(_binding()), _receipt(_binding(epoch_sha256="d" * 64))]
    ) == "receipt_epoch_binding_mismatch"
    # Different per-receipt source hashes still belong to one epoch population.
    assert analysis._epoch_population_problem(
        [_receipt(_binding(source_execution_sha256="b" * 64)),
         _receipt(_binding(source_execution_sha256="d" * 64))]
    ) is None
    # Historical all-unbound populations remain readable within their epoch.
    assert analysis._epoch_population_problem([_receipt(), _receipt()]) is None
    assert analysis._receipt_identity_problem(
        _receipt(_binding()), _receipt()
    ) == "receipt_epoch_binding_mixed"


def test_receipt_binding_must_match_plan_execution_and_rule_identity():
    plan = {"epoch_id": "epoch-current", "plan_sha256": "c" * 64}
    constraints = {"fixture_id": "fixture-a", "protocol_version": "protocol-a"}
    problem, info = analysis._receipt_epoch_problem(
        _receipt(_binding(fixture_id="fixture-a", protocol_version="protocol-a")),
        plan, _entry(), constraints,
    )
    assert problem is None and info["status"] == analysis.EPOCH_BINDING_EXPLICIT

    problem, _ = analysis._receipt_epoch_problem(
        _receipt(_binding(experiment_epoch_id="epoch-other")), plan, _entry(), constraints,
    )
    assert problem == "receipt_experiment_epoch_mismatch"

    problem, _ = analysis._receipt_epoch_problem(
        _receipt(_binding(source_execution_sha256="d" * 64)), plan, _entry(), constraints,
    )
    assert problem == "receipt_source_execution_mismatch"

    problem, _ = analysis._receipt_epoch_problem(
        _receipt(_binding(fixture_id="fixture-b")), plan, _entry(), constraints,
    )
    assert problem == "receipt_epoch_fixture_id_mismatch"


def test_historical_unbound_receipt_is_readable_but_never_claims_current_epoch():
    plan = {"epoch_id": "epoch-current"}
    problem, info = analysis._receipt_epoch_problem(
        _receipt(), plan, _entry(), {},
    )
    assert problem is None
    assert info["status"] == analysis.EPOCH_BINDING_LEGACY
    assert info["binding"] is None


def test_prospective_plan_refuses_unbound_or_plan_less_receipts():
    plan = {
        "epoch_id": "epoch-current",
        "plan_sha256": "c" * 64,
        "epoch_binding_required": True,
    }
    problem, info = analysis._receipt_epoch_problem(
        _receipt(), plan, _entry(), {},
    )
    assert problem == "receipt_epoch_binding_missing"
    assert info["status"] == analysis.EPOCH_BINDING_LEGACY
    no_plan = {
        "binding_version": "scoring-epoch-binding",
        "epoch_sha256": "e" * 64,
        "scoring_epoch_id": "a" * 64,
        "scoring_rule_sha256": "a" * 64,
        "source_execution_sha256": "b" * 64,
        "experiment_epoch_id": "epoch-current",
        "binding_sha256": "f" * 64,
    }
    problem, _ = analysis._receipt_epoch_problem(
        _receipt(no_plan), plan, _entry(), {},
    )
    assert problem == "receipt_plan_identity_missing"
    problem, _ = analysis._receipt_epoch_problem(
        _receipt(_binding(plan_sha256="d" * 64)), plan, _entry(), {},
    )
    assert problem == "receipt_plan_identity_mismatch"
    assert len({_binding(source_execution_sha256="b" * 64)["epoch_sha256"],
                _binding(source_execution_sha256="d" * 64)["epoch_sha256"]}) == 1
    assert analysis.plan_requires_receipt_epoch_binding(plan) is True
    assert analysis.plan_requires_receipt_epoch_binding({}) is False


def test_structured_prospective_binding_marker_is_equivalent():
    plan = {
        "epoch_id": "epoch-current",
        "plan_sha256": "c" * 64,
        "receipt_epoch_binding": {"required": True},
    }
    assert analysis.plan_requires_receipt_epoch_binding(plan) is True
    problem, _ = analysis._receipt_epoch_problem(_receipt(), plan, _entry(), {})
    assert problem == "receipt_epoch_binding_missing"


def test_refuse_epoch_pooling_rejects_mixed_or_unidentified_documents():
    with pytest.raises(ValueError, match="Refusing to pool declared epochs"):
        analysis.refuse_epoch_pooling([
            {"epoch_id": "epoch-a"}, {"epoch_id": "epoch-b"},
        ])
    with pytest.raises(ValueError, match="does not declare epoch_id"):
        analysis.refuse_epoch_pooling([{"epoch_id": "epoch-a"}, {}])
    assert analysis.refuse_epoch_pooling([
        {"epoch_id": "epoch-a"}, {"epoch_id": "epoch-a"},
    ]) == "epoch-a"


def test_condition_contrast_reports_the_predeclared_six_outcome_family():
    observations = []
    for condition, value in (
        ("linear_hybrid", 2.0), ("akg_guided_hybrid", 3.0),
    ):
        for repeat in range(3):
            observations.append({
                "coordinate": {
                    "block": "selection", "policy_epoch_id": "p", "fixture_id": "f",
                    "protocol_version": "v", "candidate_budget": 3, "provider": "prov",
                    "model": "model-a", "surface": "sqli", "security_level": "low",
                    "target_method": None, "payload_mode": "hybrid",
                    "guardrail_retry_enabled": True, "guardrail_handling": "reactive",
                    "experiment_condition": condition, "repeat_index": repeat,
                },
                "state": "final", "ready": True,
                "documents": {"ai": (
                    f"/fake/{condition}-{repeat}.json",
                    _receipt(
                        components={name: value for name in analysis.COMPONENT_NAMES[:-1]},
                        Srun_final=value,
                    ),
                )},
            })
    declaration = {
        "status": "verified", "declared_before_analysis": True,
        "role": "prospective_preregistered_family",
        "family": analysis._implemented_family(),
        "source": {"recorded_sha256": "a" * 64},
        "chronology": {"plan_precedes_final_receipts": True},
        "problems": [], "reason": None,
    }
    result = analysis._condition_contrasts(observations, {"repeats": 3}, declaration)
    assert result["family_declaration"]["declared_before_analysis"] is True
    assert result["family_declaration"]["declaration_status"] == "verified"
    assert result["family_declaration"]["outcomes"] == list(analysis.FAMILY_OUTCOMES)
    assert result["family_declaration"]["family_size"] == 6
    row = result["results"][0]
    assert row["status"] == "analyzed"
    assert row["family"]["outcomes"] == list(analysis.FAMILY_OUTCOMES)
    for name in analysis.COMPONENT_NAMES:
        metric = row["metrics"][name]
        assert metric["outcome"] == analysis.OUTCOME_LABELS[name]
        assert "p_value_raw" in metric
        assert "p_value_holm" in metric
        assert metric["p_value_holm"] == metric["holm_adjusted_p"]
        assert metric["n_left"] == 3 and metric["n_right"] == 3
        assert metric["median_left"] == 2.0
        assert metric["iqr_left"] == 0.0
        assert metric["signed_rank_biserial"] == metric["effect_size"]


def _declaration_design():
    return {
        "pairing": "same coordinate",
        "multiple_comparisons": CONDITION_CONTRAST_MULTIPLICITY,
        "condition_contrast_family": {
            "stratum": "model x surface x level",
            "contrast": "linear_hybrid vs akg_guided_hybrid",
            "family_size": 6,
            "multiplicity": CONDITION_CONTRAST_MULTIPLICITY,
            "missing_outcome_policy": CONDITION_CONTRAST_MISSING_POLICY,
            "declaration_source": (
                "frozen research_config hashed into the plan before selection"
            ),
            "outcomes": list(CONDITION_CONTRAST_OUTCOMES),
            "supplementary_families": list(
                CONDITION_CONTRAST_SUPPLEMENTARY_FAMILIES
            ),
        },
    }


def _prospective_plan(tmp_path, *, mutate_design=None, receipt_time=None):
    design = _declaration_design()
    if mutate_design is not None:
        mutate_design(design)
    path = Path(tmp_path) / "study.json"
    path.write_text(json.dumps({"design": design}))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    plan = {
        "plan_sha256": "p" * 64,
        "epoch_id": "epoch-current",
        "generated_at": "2026-11-01T00:00:00+00:00",
        "epoch_binding_required": True,
        "research_config": {
            "path": str(path),
            "sha256": digest,
            "declaration": {"design": design},
        },
    }
    observations = []
    if receipt_time is not None:
        observations = [{
            "documents": {"ai": (
                "/fake/receipt.json", {"generated_at": receipt_time},
            )},
        }]
    return plan, observations


def test_holm_keeps_declared_family_size_with_missing_outcomes():
    adjusted = analysis._holm(
        [0.01, 0.02, None, None, None, None], family_size=6)
    assert adjusted == [0.06, 0.1, None, None, None, None]
    assert analysis._holm([0.01, None, 0.04, 0.03]) == [
        0.04, None, 0.09, 0.09,
    ]
    with pytest.raises(ValueError, match="smaller than"):
        analysis._holm([0.01, 0.02], family_size=1)


def test_historical_plan_never_claims_a_preregistered_family():
    plan = {
        "plan_sha256": "p" * 64,
        "epoch_id": "restored-primary",
        "generated_at": "2026-11-01T00:00:00+00:00",
        "research_config": {
            "path": "/nonexistent/historical.json",
            "sha256": "a" * 64,
            "declaration": {"design": {"multiple_comparisons": "historical text"}},
        },
    }
    declaration = analysis._analysis_declaration(plan, [])
    assert declaration["status"] == "historical_unverified"
    assert declaration["declared_before_analysis"] is False
    assert declaration["role"] == "historical_recomputation_diagnostic"
    assert declaration["family"]["family_size"] == 6


def test_prospective_declaration_requires_source_bound_plan_and_chronology(tmp_path):
    plan, observations = _prospective_plan(
        tmp_path, receipt_time="2026-11-02T00:00:00+00:00")
    assert analysis.plan_requires_receipt_epoch_binding(plan) is True
    declaration = analysis._analysis_declaration(plan, observations)
    assert declaration["status"] == "verified"
    assert declaration["declared_before_analysis"] is True
    assert declaration["source"]["observed_sha256"] == (
        declaration["source"]["recorded_sha256"]
    )
    assert declaration["chronology"]["plan_precedes_final_receipts"] is True

    late_plan, late_observations = _prospective_plan(
        tmp_path, receipt_time="2026-10-31T00:00:00+00:00")
    late = analysis._analysis_declaration(late_plan, late_observations)
    assert late["status"] == "invalid"
    assert "plan_not_before_final_receipts" in late["problems"]

    def arbitrary_text(design):
        design["multiple_comparisons"] = "deliberately incompatible synthetic family"

    invalid_plan, invalid_observations = _prospective_plan(
        tmp_path, mutate_design=arbitrary_text,
        receipt_time="2026-11-02T00:00:00+00:00")
    invalid = analysis._analysis_declaration(invalid_plan, invalid_observations)
    assert invalid["status"] == "invalid"
    assert any("condition_contrast_family" in problem
               for problem in invalid["problems"])

    def remove_family(design):
        design.pop("condition_contrast_family")

    missing_plan, missing_observations = _prospective_plan(
        tmp_path, mutate_design=remove_family,
        receipt_time="2026-11-02T00:00:00+00:00")
    missing = analysis._analysis_declaration(missing_plan, missing_observations)
    assert missing["status"] == "invalid"
    assert "condition_contrast_family_missing" in missing["problems"]


def test_analysis_refuses_a_prospective_plan_without_a_declaration():
    plan = {
        "artifact_type": "chapter3_research_plan",
        "plan_version": "study-plan",
        "source_hashes_sha256": "h" * 64,
        "epoch_binding_required": True,
        "blocks": {},
        "constraints": {},
    }
    with pytest.raises(ValueError, match="analysis declaration is not source-bound"):
        analysis.analyze_plan(plan, source_roots={}, review_roots={})


def test_bound_receipt_without_a_plan_identity_is_refused():
    binding = _binding()
    problem, _info = analysis._receipt_epoch_problem(
        _receipt(binding), {"epoch_id": "epoch-current"}, _entry(), {},
    )
    assert problem == "receipt_plan_identity_unavailable_for_bound_receipt"
    # Historical unbound receipts remain readable without a plan.
    problem, info = analysis._receipt_epoch_problem(
        _receipt(), {"epoch_id": "epoch-current"}, _entry(), {},
    )
    assert problem is None and info["status"] == analysis.EPOCH_BINDING_LEGACY


def test_distinct_execution_hashes_are_validated_per_receipt():
    plan = {"epoch_id": "epoch-current", "plan_sha256": "c" * 64}
    left = analysis._receipt_epoch_problem(
        _receipt(_binding(source_execution_sha256="b" * 64)),
        plan, _entry("b" * 64), {},
    )
    right = analysis._receipt_epoch_problem(
        _receipt(_binding(source_execution_sha256="d" * 64)),
        plan, _entry("d" * 64), {},
    )
    assert left[0] is None and right[0] is None
    wrong = analysis._receipt_epoch_problem(
        _receipt(_binding(source_execution_sha256="d" * 64)),
        plan, _entry("b" * 64), {},
    )
    assert wrong[0] == "receipt_source_execution_mismatch"


def test_condition_contrast_refuses_partial_final_receipts():
    observations = []
    for condition, value in (
        ("linear_hybrid", 2.0), ("akg_guided_hybrid", 3.0),
    ):
        for repeat in range(3):
            components = {name: value for name in analysis.COMPONENT_NAMES[:-1]}
            if condition == "linear_hybrid" and repeat == 0:
                components.pop("Smethod")
            observations.append({
                "coordinate": {
                    "block": "selection", "policy_epoch_id": "p", "fixture_id": "f",
                    "protocol_version": "v", "candidate_budget": 3, "provider": "prov",
                    "model": "model-a", "surface": "sqli", "security_level": "low",
                    "target_method": None, "payload_mode": "hybrid",
                    "guardrail_retry_enabled": True, "guardrail_handling": "reactive",
                    "experiment_condition": condition, "repeat_index": repeat,
                },
                "state": "final", "ready": True,
                "documents": {"ai": (
                    f"/fake/{condition}-{repeat}.json",
                    _receipt(components=components, Srun_final=value),
                )},
            })
    declaration = {
        "status": "verified", "declared_before_analysis": True,
        "role": "prospective_preregistered_family",
        "family": analysis._implemented_family(),
        "source": {"recorded_sha256": "a" * 64},
        "chronology": {"plan_precedes_final_receipts": True},
        "problems": [], "reason": None,
    }
    result = analysis._condition_contrasts(
        observations, {"repeats": 3}, declaration)
    assert result["results"][0]["status"] == "unsupported"
    assert result["results"][0]["reason"] == "linear_hybrid:partial_final_receipt"


def test_grader_identity_helpers_fail_closed_without_assertions():
    assert analysis._grader_difference({}, {}) == ["grader_identity"]
    problem = analysis._grader_identity_problem({}, {})
    assert problem is not None and problem.startswith("receipt_grader_identity_unavailable")
    report = analysis._grader_report([{}])
    assert report["status"] == "unavailable"
    assert "reasons" in report
