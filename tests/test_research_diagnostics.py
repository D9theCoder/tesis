"""Supplementary diagnostic denominators, availability and provenance contracts."""

import evaluation.research_diagnostics as diagnostics
from evaluation.thesis_scoring import WEIGHTS


def _receipt(value=2.0, candidate_ids=("candidate-1",), **overrides):
    components = {name: value for name in diagnostics.COMPONENTS}
    grades = [{
        "candidate_id": candidate_id,
        "score": value,
        "proof_ceiling": 4,
        "payload_source": "llm_generated",
        "evidence_refs": ["#/final_state/response_evidence/0"],
    } for candidate_id in candidate_ids]
    receipt = {
        "artifact_type": "thesis_score_receipt",
        "status": "final",
        "execution_id": "exec-1",
        "source_sha256": "a" * 64,
        "components": components,
        "numerator": value * len(grades),
        "denominator": len(grades),
        "candidate_grades": grades,
        "Spayload_final": round(value, 4),
        "Srun_final": round(sum(value * weight for weight in WEIGHTS.values()), 4),
    }
    receipt.update(overrides)
    return receipt


def _record(**overrides):
    record = {
        "coordinate": {
            "model": "model-a", "surface": "sqli", "security_level": "low",
            "experiment_condition": "linear_hybrid",
        },
        "state": "final",
    }
    record.update(overrides)
    return record


def _valid(record):
    record["receipt_validation"] = {"valid": True, "binding_status": "historical_unbound"}
    return record


def test_empty_population_is_unavailable_not_zero():
    document = diagnostics.build_diagnostics([], epoch_id="epoch-empty", planned=0)
    metrics = document["metrics"]
    assert metrics["execution_coverage"]["value"] is None
    assert metrics["execution_coverage"]["unavailable_reason"] == "no_planned_coordinates"
    assert metrics["final_score_coverage"]["value"] is None
    assert metrics["payload_quality"]["value"] is None
    assert metrics["payload_quality"]["unavailable_reason"] == (
        "no_distinct_eligible_executed_candidate"
    )
    assert metrics["chain_participation_coverage"]["value"] is None
    assert metrics["verified_participation_rate"]["value"] is None
    assert metrics["repeat_stability"]["majority_rate"]["value"] is None
    assert document["epoch_id"] == "epoch-empty"


def test_normal_population_reports_explicit_denominators_and_provenance():
    observations = [
        _valid(_record(
            receipt=_receipt(3.0), local_proof=3,
            participation={"complete": True, "role": "consumer"},
            chain={"assessment_available": True,
                   "opportunities_assessed": 2, "opportunities_supported": 1,
                   "completed_transitions": 1, "causal_transitions": 1,
                   "transition_ids": ["route:0"],
                   "unknown_prerequisites": 0, "destination_unproved": 1,
                   "static_unsupported": 0, "source_blocked": 0},
            candidates=[
                {"candidate_id": "generated", "grade": 3, "origin_kind": "seed_mutation",
                 "validated": True, "executed": True, "eligible": True,
                 "confirmed": True, "captured": True},
                {"candidate_id": "static", "grade": 1, "origin_kind": "static_seed",
                 "validated": True, "executed": True, "eligible": True,
                 "confirmed": False, "captured": False},
            ],
            generated_candidates={"captured": 2, "valid": 1, "executed": 1},
            controls={"assessed": 2, "measured_negative": True,
                      "explicit_denial": 1, "redirect": 0, "detection_signal": 0,
                      "exploit_control_success": 0,
                      "no_signal": 1, "control_error": 0, "unknown": 0},
            roles=[{"role": "orchestrator", "opportunities": 2, "valid": 2,
                    "repaired": 0, "fallback": 0, "guardrail": 0,
                    "invalid_json": 0, "invalid_output": 0}],
            efficiency={"telemetry_complete": True, "requests": 10, "retries": 1,
                        "tokens": 100, "time_s": 2.0, "cost": 0.25, "successes": 1},
            repeat_cell="sqli:low:linear", repeat_grade=3.0)),
        _record(state="pending_review", local_proof=None,
                repeat_cell="sqli:low:linear", repeat_grade=3.0),
        _record(state="error", repeat_cell="sqli:low:linear"),
        _record(state="missing", repeat_cell="sqli:low:linear"),
    ]
    document = diagnostics.build_diagnostics(observations, epoch_id="epoch-normal", planned=4)
    metrics = document["metrics"]
    assert metrics["execution_coverage"]["numerator"] == 3
    assert metrics["execution_coverage"]["denominator"] == 4
    assert metrics["execution_coverage"]["failed"] == 1
    assert metrics["execution_coverage"]["unstarted"] == 1
    assert metrics["final_score_coverage"]["numerator"] == 1
    assert metrics["final_score_coverage"]["numeric_completion_claimed"] is False
    payload = metrics["payload_quality"]
    assert payload["numerator"] == 4.0 and payload["denominator"] == 2
    assert payload["value"] == 2.0
    assert payload["generated"]["n"] == 1
    assert payload["static"]["n"] == 1
    participation = metrics["chain_participation_coverage"]
    assert participation["numerator"] == 1
    assert participation["denominator"] == 1
    assert participation["status_counts"] == {"consumer": 1}
    assert metrics["verified_participation_rate"]["value"] == 1.0
    chain = metrics["chain_success_and_depth"]
    assert chain["numerator"] == 1 and chain["denominator"] == 1
    assert chain["unknown_prerequisites"] == 0
    assert chain["destination_unproved_opportunities"] == 1
    assert metrics["negative_control_outcomes"]["assessed"] == 2
    assert metrics["negative_control_outcomes"]["measured_negative_runs"] == 1
    assert metrics["output_guardrail_recovery_rates"]["valid_rate"]["value"] == 1.0
    assert metrics["efficiency"]["costs"]["available"] is True
    # A pending/error/missing record never supplies a validated final receipt.
    stability = metrics["repeat_stability"]["cells"]["sqli:low:linear"]
    assert stability["available"] is False
    assert stability["n_scored"] == 1
    assert all(
        reading["provenance"] for name, reading in metrics.items()
        if isinstance(reading, dict) and name not in {"score_distribution"}
    )


def test_unvalidated_or_pending_receipts_are_never_numeric_completion():
    fake = _receipt(999.0)
    fake["status"] = "pending_review"
    observations = [
        _record(receipt=fake, receipt_validation={"valid": False,
                                                  "problems": ["receipt_not_final"]}),
        _record(receipt=_receipt(3.0, Srun_final=999.0),
                receipt_validation={"valid": False,
                                    "problems": ["receipt_srun_arithmetic_mismatch"]}),
    ]
    metrics = diagnostics.build_diagnostics(observations, epoch_id="epoch-fake", planned=2)["metrics"]
    assert metrics["final_score_coverage"]["numerator"] == 0
    assert metrics["final_score_coverage"]["unavailable_coordinates"] == 2
    assert metrics["final_score_coverage"]["incomplete_receipts"][0]["problems"]
    assert metrics["score_distribution"]["cells"] == {}


def test_duplicate_candidates_are_excluded_and_eligibility_must_be_explicit():
    record = _valid(_record(candidates=[
        {"candidate_id": "c", "grade": 3, "origin_kind": "seed_mutation",
         "validated": True, "executed": True, "eligible": True},
        {"candidate_id": "c", "grade": 3, "origin_kind": "seed_mutation",
         "validated": True, "executed": True, "eligible": True},
        {"candidate_id": "d", "grade": 3, "origin_kind": "seed_mutation",
         "validated": True, "executed": True},
    ]))
    payload = diagnostics.payload_quality([record])
    assert payload["denominator"] == 1
    assert payload["excluded"]["duplicate_candidate_id"] == 1
    assert payload["excluded"]["eligibility_unstated"] == 1


def test_adapter_requires_explicit_queue_eligibility():
    artifact = {
        "execution_id": "exec-1",
        "final_state": {"payload_provenance": {
            "candidate-1": {"origin_kind": "seed_mutation"},
        }},
        "candidate_dispositions": [{
            "candidate_id": "candidate-1",
            "validation_status": "valid",
            "execution_status": "executed",
        }],
    }
    record = diagnostics.diagnostic_record(
        {
            "coordinate": {
                "model": "model-a", "surface": "sqli", "security_level": "low",
                "experiment_condition": "linear_hybrid",
            },
            "state": "final", "execution_id": "exec-1",
        },
        artifact=artifact,
        receipt=_receipt(3.0),
        queue={"candidates": []},
        artifact_sha256="a" * 64,
    )
    assert record["receipt_validation"]["valid"] is True
    assert record["candidates"][0]["eligible"] is False
    assert diagnostics.payload_quality([record])["denominator"] == 0


def test_static_capture_is_not_a_generated_payload_denominator():
    record = _record(
        generated_candidates={"captured": 2, "valid": 1, "executed": 1},
        candidates=[
            {"candidate_id": "static", "captured": True, "origin_kind": "static_seed",
             "eligible": True, "executed": True, "assessable": True,
             "confirmed": True},
            {"candidate_id": "gen", "captured": True, "origin_kind": "seed_mutation",
             "eligible": True, "executed": True, "assessable": True,
             "confirmed": False},
        ],
    )
    metric = diagnostics.payload_validity_execution_success([record])
    assert metric["populations"]["generated_captured"] == 2
    assert metric["populations"]["generated_valid"] == 1
    assert metric["populations"]["static_captured_excluded"] == 1
    assert metric["validity"]["denominator"] == 2
    assert metric["generated_execution_confirmation"]["denominator"] == 1
    assert metric["generated_execution_confirmation"]["numerator"] == 0


def test_missing_controls_and_telemetry_stay_unresolved():
    observations = [
        _record(
            local_proof=3,
            participation={"status": "unavailable", "reason": "chain_history_unavailable"},
            controls={"assessed": 1, "unknown": 1},
            efficiency={"telemetry_complete": False},
            candidates=[{"candidate_id": "c", "grade": None,
                         "origin_kind": "seed_mutation", "validated": True,
                         "executed": True, "eligible": True}],
            repeat_cell="cell", repeat_grade=3.0,
        ),
        _record(state="final", local_proof=None, repeat_cell="cell", repeat_grade=3.0),
    ]
    metrics = diagnostics.build_diagnostics(observations, epoch_id="epoch-gaps")["metrics"]
    participation = metrics["chain_participation_coverage"]
    assert participation["value"] == 0.0
    assert participation["status_counts"] == {"unavailable_assessment": 1}
    assert participation["unavailable_assessments"] == 1
    assert metrics["verified_participation_rate"]["value"] is None
    assert metrics["verified_participation_rate"]["unavailable_assessments"] == 1
    assert metrics["verified_participation_rate"]["locally_unassessable"] == 1
    assert metrics["negative_control_outcomes"]["unknown_rate"]["value"] == 1.0
    assert metrics["negative_control_outcomes"]["measured_negative_runs"] == 0
    efficiency = metrics["efficiency"]
    # An empty telemetry population has no observed zero subtotal.
    assert efficiency["physical_requests"] is None
    assert efficiency["tokens"] is None
    assert efficiency["observed_subtotal_available"] is False
    assert efficiency["observed_subtotal_scope"] == 'unavailable_no_complete_telemetry'
    assert efficiency["executions_with_telemetry"] == 0
    assert efficiency["executions_without_telemetry"] == 2
    assert efficiency["cost_per_confirmed_success"]["value"] is None
    assert metrics["repeat_stability"]["cells"]["cell"]["stability"] is None


def test_scorer_shaped_participation_and_evaluator_roles_are_mapped_explicitly():
    record = _record(
        local_proof=3,
        participation={"status": "verified", "role": "consumer",
                       "evidence_refs": ["#/final_state/chain_history/0"]},
        roles=[
            {"role": "orchestrator", "opportunities": 2, "valid": 1,
             "repaired": 0, "fallback": 0, "guardrail": 0,
             "invalid_json": 0, "invalid_output": 1},
            {"role": "evaluator", "opportunities": 9, "valid": 0,
             "repaired": 0, "fallback": 0, "guardrail": 0,
             "invalid_json": 9, "invalid_output": 9},
        ],
    )
    metrics = diagnostics.build_diagnostics([record], epoch_id="epoch-map")["metrics"]
    assert metrics["chain_participation_coverage"]["numerator"] == 1
    assert metrics["verified_participation_rate"]["value"] == 1.0
    output = metrics["output_guardrail_recovery_rates"]
    assert output["opportunities"] == 2
    assert output["evaluator_roles_excluded"] == 1
    assert output["invalid_json_rate"]["denominator"] == 2
    assert output["invalid_output_rate"]["numerator"] == 1


def test_output_fallback_counts_require_an_unusable_output_reason():
    record = _record(
        roles=[{"role": "payload_generator", "opportunities": 2, "valid": 1,
                "repaired": 0, "fallback": 1, "guardrail": 0,
                "invalid_json": 0, "invalid_output": 0}],
    )
    rate = diagnostics.output_guardrail_recovery_rates([record])
    assert rate["fallback_rate"]["value"] == 0.5
    # A provider failure is operational, not an experiment-model output defect.
    from evaluation.research_diagnostics import _role_rows
    artifact = {
        "llm_performance": [{"role": "payload_generator", "parse_status": "ok",
                             "validation_status": "valid"}],
        "final_state": {
            "fallback_events": [
                {"role": "payload_generator",
                 "event": "payload_generation.static_seed_fallback",
                 "reason": "no_valid_generated_candidates",
                 "provider_failure": False},
                {"role": "payload_generator",
                 "event": "payload_generation.static_seed_fallback",
                 "reason": "no_valid_generated_candidates",
                 "provider_failure": True},
            ],
        },
    }
    rows = _role_rows(artifact)
    assert rows[0]["fallback"] == 1


def test_historical_unbound_inputs_never_claim_numeric_completion():
    observations = [_record(state="unassessable")]
    document = diagnostics.build_diagnostics(observations, epoch_id=None)
    assert document["epoch_id"] is None
    coverage = document["metrics"]["final_score_coverage"]
    assert coverage["numerator"] == 0
    assert coverage["denominator"] == 1
    assert coverage["numeric_completion_claimed"] is False


def test_malformed_final_receipts_are_refused():
    base = _receipt(3.0)
    mismatch = _receipt(3.0)
    mismatch["components"]["Spayload"] = 1
    mismatch["Srun_final"] = round(
        sum(mismatch["components"][name] * weight
            for name, weight in WEIGHTS.items()), 4)
    nonfinite = {**base, "Srun_final": float("nan")}
    missing_payload_final = {key: value for key, value in base.items()
                             if key != "Spayload_final"}
    nan_component = _receipt(3.0)
    nan_component["components"]["Spayload"] = float("nan")
    wrong_rounding = {**base, "Srun_final": round(base["Srun_final"] + 0.01, 4)}
    numerator_mismatch = {**base, "numerator": 2}
    denominator_mismatch = {**base, "denominator": 2}
    cases = [
        (mismatch, "receipt_spayload_component_mismatch"),
        (nonfinite, "receipt_srun_missing"),
        (missing_payload_final, "receipt_spayload_final_invalid"),
        (nan_component, "receipt_component_invalid:Spayload"),
        (wrong_rounding, "receipt_srun_arithmetic_mismatch"),
        (numerator_mismatch, "receipt_numerator_candidate_mismatch"),
        (denominator_mismatch, "receipt_denominator_candidate_mismatch"),
    ]
    for receipt, problem in cases:
        result = diagnostics.validate_final_receipt(receipt)
        assert result["valid"] is False, problem
        assert problem in result["problems"]


def _adapter_receipt(execution_id, epoch_id, *, smethod=3):
    return {
        **_receipt(3.0),
        "execution_id": execution_id,
        "components": {**_receipt(3.0)["components"], "Smethod": smethod},
    }


def _adapter_record(execution_id, epoch_id, *, repeat=0, plan_sha256=None):
    artifact = {
        "execution_id": execution_id,
        "policy_epoch": {"epoch_id": epoch_id},
        "config": {"policy_epoch": {"epoch_id": epoch_id}},
        "final_state": {},
    }
    if plan_sha256:
        artifact["research_plan_identity"] = {
            "plan_sha256": plan_sha256, "epoch_id": epoch_id,
        }
    coordinate = {
        "model": "model-a", "surface": "access_control",
        "security_level": "high", "experiment_condition": "linear_hybrid",
        "repeat_index": repeat,
    }
    receipt = _adapter_receipt(execution_id, epoch_id)
    # Keep Srun consistent with the possibly changed Smethod component.
    receipt["Srun_final"] = round(
        sum(receipt["components"][name] * weight
            for name, weight in WEIGHTS.items()), 4)
    return diagnostics.diagnostic_record(
        {"coordinate": coordinate, "state": "final", "execution_id": execution_id},
        artifact=artifact,
        receipt=receipt,
        queue={"candidates": []},
        artifact_sha256="a" * 64,
    )


def test_adapter_preserves_identity_and_excludes_mixed_epochs():
    first = _adapter_record("exec-a", "epoch-a")
    second = _adapter_record("exec-b", "epoch-b", repeat=1)
    assert first["repeat_index"] == 0
    assert first["recorded_epoch_id"] == "epoch-a"
    document = diagnostics.build_diagnostics(
        [first, second], epoch_id="epoch-a", planned=2)
    assert document["epoch_identity"]["status"] == "mixed_excluded"
    assert document["epoch_identity"]["included_epoch_id"] == "epoch-a"
    assert len(document["excluded_records"]) == 1
    assert document["excluded_records"][0]["problems"] == ["recorded_epoch_mismatch"]
    coverage = document["metrics"]["final_score_coverage"]
    assert coverage["numerator"] == 1
    assert coverage["denominator"] == 2
    assert coverage["unavailable_coordinates"] == 1
    assert coverage["value"] == 0.5


def test_adapter_deduplicates_identical_executions_and_rejects_conflicts():
    record = _adapter_record("exec-a", "epoch-a")
    deduplicated = diagnostics.build_diagnostics(
        [record, dict(record)], epoch_id="epoch-a", planned=1)
    assert deduplicated["coordinate_reconciliation"][
        "deduplicated_exact_duplicates"] == 1
    coverage = deduplicated["metrics"]["final_score_coverage"]
    assert coverage["numerator"] == 1 and coverage["denominator"] == 1
    assert coverage["unavailable_coordinates"] == 0
    assert coverage["value"] == 1.0

    conflicting = dict(record)
    conflicting["receipt"] = {
        **_adapter_receipt("exec-a", "epoch-a"),
        "components": {**_receipt(3.0)["components"], "Smethod": 2},
    }
    conflicting = diagnostics.diagnostic_record(
        {"coordinate": record["coordinate"], "state": "final",
         "execution_id": "exec-a"},
        artifact={
            "execution_id": "exec-a",
            "policy_epoch": {"epoch_id": "epoch-a"},
            "config": {"policy_epoch": {"epoch_id": "epoch-a"}},
            "final_state": {},
        },
        receipt=conflicting["receipt"], queue={"candidates": []},
        artifact_sha256="a" * 64,
    )
    document = diagnostics.build_diagnostics(
        [record, conflicting], epoch_id="epoch-a", planned=1)
    assert document["coordinate_reconciliation"]["excluded_conflicts"] == 2
    coverage = document["metrics"]["final_score_coverage"]
    assert coverage["numerator"] == 0 and coverage["denominator"] == 1
    assert coverage["unavailable_coordinates"] == 1
    assert any(row["reason"] == "duplicate_execution_conflict"
               for row in document["excluded_records"])


def test_adapter_refuses_multiple_plan_identities():
    first = _adapter_record("exec-a", "epoch-a", plan_sha256="1" * 64)
    second = _adapter_record("exec-b", "epoch-a", repeat=1, plan_sha256="2" * 64)
    try:
        diagnostics.build_diagnostics(
            [first, second], epoch_id="epoch-a", planned=2)
    except ValueError as exc:
        assert "multiple recorded plan identities" in str(exc)
    else:
        raise AssertionError("mixed plan identities must be refused")


def test_adapter_excludes_coordinate_repeat_conflict():
    first = _adapter_record("exec-a", "epoch-a", repeat=0)
    second = _adapter_record("exec-b", "epoch-a", repeat=0)
    document = diagnostics.build_diagnostics(
        [first, second], epoch_id="epoch-a", planned=1)
    assert any(row["reason"] == "duplicate_coordinate_repeat_conflict"
               for row in document["excluded_records"])
    coverage = document["metrics"]["final_score_coverage"]
    assert coverage["numerator"] == 0
    assert coverage["unavailable_coordinates"] == 1


def test_validate_final_receipt_checks_identity_and_arithmetic():
    receipt = _receipt(3.0)
    valid = diagnostics.validate_final_receipt(
        receipt, record={"execution_id": "exec-1", "artifact_sha256": "a" * 64})
    assert valid["valid"] is True
    assert valid["binding_status"] == "historical_unbound"
    wrong = diagnostics.validate_final_receipt(
        receipt, record={"execution_id": "exec-other", "artifact_sha256": "a" * 64})
    assert wrong["valid"] is False
    assert "receipt_execution_identity_mismatch" in wrong["problems"]
    broken = {**receipt, "Srun_final": 999.0}
    assert diagnostics.validate_final_receipt(broken)["valid"] is False
    pending = {**receipt, "status": "pending_review"}
    assert diagnostics.validate_final_receipt(pending)["valid"] is False
    empty = {**receipt, "denominator": 0, "numerator": 0,
             "candidate_grades": [], "Spayload_final": None}
    empty_validation = diagnostics.validate_final_receipt(empty)
    assert empty_validation["valid"] is False
    assert "receipt_denominator_empty" in empty_validation["problems"]
    bound_without_queue = {
        **receipt, "receipt_contract": "epoch-bound-receipt",
        "epoch_binding": {"epoch_sha256": "b" * 64},
    }
    bound_validation = diagnostics.validate_final_receipt(bound_without_queue)
    assert bound_validation["valid"] is False
    assert bound_validation["binding_status"] == "binding_unvalidated"
    assert "receipt_epoch_binding_unvalidated" in bound_validation["problems"]
