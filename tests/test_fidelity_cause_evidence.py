"""F3 cause admission: proof links must substantiate the stated cause."""

import pytest

from core.payload_policy import MODEL_ORIGIN_KINDS
from evaluation.fidelity_ledger import (
    _attribution_rows,
    _merge_attribution_rows,
    cause_evidence_problem,
)
from evaluation.scoring_evidence import evidence_hash


def _context(**overrides):
    record = {
        "execution_id": "exec-1",
        "llm_performance": [{
            "call_id": "call-1", "role": "orchestrator", "method": "sqli_union",
            "parse_status": "ok", "validation_status": "valid",
            "input": {"observations": {}}, "output": {"method": "sqli_union"},
        }],
        "final_state": {
            "payload_provenance": {
                "generated": {"origin_kind": "seed_mutation", "method": "sqli_union"},
                "static": {"origin_kind": "static_seed", "method": "sqli_union"},
            },
            "payload_candidates": {"sqli_union": [
                {"candidate_id": "generated", "status": "signal_absent"},
                {"candidate_id": "static", "status": "signal_absent"},
            ]},
            "scoring_decisions": [{
                "dimension": "Smethod", "method": "sqli_union", "reason": "ranking_unavailable",
                "reason_refs": [], "plan": None, "precondition_status": {"sqli": "false"},
                "proof_ceiling": 3,
            }],
            "verifier_history": [{
                "agent_id": "sqli_union", "decision": "not_confirmed",
                "verification_reason": "signal_absent",
            }],
            "chain_history": [{
                "route_id": "route-1", "status": "rejected",
                "reason": "route ordering rejected the destination",
            }],
            "candidate_lifecycle": [{
                "candidate_id": "generated", "status": "budget_exhausted",
                "reason": "candidate budget exhausted",
            }],
        },
        "measured_negative": {
            "complete": True, "reason": "every_precondition_false",
            "verdicts": {"sqli_union": "not_vulnerable"},
        },
        "control_events": [{"decision": "denied", "method": "sqli_union"}],
    }
    record.update(overrides)
    queue = {
        "components": {"Smethod": 2, "Spayload": 1, "Sexploit": 3, "Schain": 0, "Soutput": 3},
        "component_pending_reasons": {
            "Smethod": "ranking_unavailable:missing_selection_snapshot",
            "Spayload": "no_eligible_candidate",
        },
        "candidates": [],
    }
    return record, queue


def test_component_value_or_pending_reason_alone_never_substantiates_a_cause():
    record, queue = _context()
    assert "component value alone" in cause_evidence_problem(
        "model_output_quality", ["queue:#/components/Spayload"], record, queue,
    )
    assert cause_evidence_problem(
        "fixture_infeasible", ["queue:#/components/Spayload"], record, queue,
    ) is not None


def _invalid_call_record():
    call = {
        "call_id": "call-bad", "role": "payload_generator", "method": "sqli_union",
        "visit_id": "sqli_union:visit:1", "parse_status": "invalid",
        "validation_status": "invalid", "failure_class": "schema_rejected",
        "input": {"seeds": []}, "output": {"variants": []},
    }
    record = {"execution_id": "exec-1", "llm_performance": [call]}
    return record


def _reference_broken_call_record():
    inputs = {"observations": {"viable_methods": True}, "precondition_status": {}}
    output = {"next_agent": "sqli_union", "reason_code": "best_viable"}
    call = {
        "call_id": "call-ref", "role": "orchestrator", "method": "sqli_union",
        "visit_id": "sqli_union:visit:1", "parse_status": "ok",
        "validation_status": "valid", "failure_class": None,
        "input": inputs, "output": output,
        "input_sha256": evidence_hash(inputs), "output_sha256": evidence_hash(output),
        "provider": "p", "model": "m", "started_at": "2026-10-30T12:00:00+00:00",
        "schema_version": "schema",
    }
    return {"execution_id": "exec-1", "llm_performance": [call]}


def test_model_output_quality_requires_a_specific_output_defect_not_provenance():
    record, queue = _context()
    # A valid, parseable call record is not by itself an output defect.
    assert cause_evidence_problem(
        "model_output_quality", ["#/llm_performance/0"], record, queue,
    ) is not None
    # Model provenance alone is not a cause; the documented review
    # counterexample must stay unresolved.
    origin_only = {
        "final_state": {
            "payload_candidates": [{
                "origin_kind": next(iter(MODEL_ORIGIN_KINDS)),
                "status": "signal_absent",
            }],
        },
    }
    assert cause_evidence_problem(
        "model_output_quality",
        ["#/final_state/payload_candidates"], origin_only, {},
    ) is not None
    assert cause_evidence_problem(
        "model_output_quality",
        ["#/final_state/payload_provenance/generated"],
        record, queue,
    ) is not None
    assert cause_evidence_problem(
        "model_output_quality",
        ["#/final_state/payload_provenance/static"],
        record, queue,
    ) is not None
    # A fixture negative is not evidence of model-output quality.
    assert cause_evidence_problem(
        "model_output_quality", ["#/measured_negative"], record, queue,
    ) is not None
    # A scoring value or a generic Smethod reason is not a model-output defect.
    assert cause_evidence_problem(
        "model_output_quality", ["#/final_state/scoring_decisions/0"], record, queue,
    ) is not None
    # Explicit invalid/unparseable evaluated-model output is admissible.
    bad = _invalid_call_record()
    assert cause_evidence_problem(
        "model_output_quality", ["#/llm_performance/0"], bad, {},
    ) is None
    # A hash-valid selection output whose required references do not resolve is
    # an evaluated-model output defect.
    broken = _reference_broken_call_record()
    assert cause_evidence_problem(
        "model_output_quality", ["#/llm_performance/0"], broken, {},
    ) is None
    # A generated candidate rejected at validation is model output quality; a
    # validated/executed candidate that merely produced no signal is not.
    rejected_candidate = {
        "final_state": {"payload_candidates": [{
            "candidate_id": "c1", "origin_kind": "seed_mutation",
            "validation_status": "invalid", "status": "rejected",
        }]},
    }
    assert cause_evidence_problem(
        "model_output_quality",
        ["#/final_state/payload_candidates/0"], rejected_candidate, {},
    ) is None
    asserted = {
        "final_state": {"payload_candidates": [{
            "candidate_id": "c1", "origin_kind": "seed_mutation",
            "validation_status": "valid", "execution_status": "executed",
            "status": "signal_absent",
        }]},
    }
    assert cause_evidence_problem(
        "model_output_quality",
        ["#/final_state/payload_candidates/0"], asserted, {},
    ) is not None
    # An explicit model-output fallback with a recorded unusable-output reason
    # is admissible; a provider failure is not a model-output defect.
    fallback = {
        "final_state": {"fallback_events": [{
            "event": "payload_generation.static_seed_fallback",
            "reason": "no_valid_generated_candidates",
            "role": "payload_generator", "provider_failure": False,
        }]},
    }
    assert cause_evidence_problem(
        "model_output_quality", ["#/final_state/fallback_events/0"],
        fallback, {}, dimension="Soutput",
    ) is None
    provider_fallback = {
        "final_state": {"fallback_events": [{
            "event": "payload_generation.static_seed_fallback",
            "reason": "no_valid_generated_candidates",
            "role": "payload_generator", "provider_failure": True,
        }]},
    }
    assert cause_evidence_problem(
        "model_output_quality", ["#/final_state/fallback_events/0"],
        provider_fallback, {}, dimension="Soutput",
    ) is not None


def test_selection_evidence_must_prove_the_model_choice_was_below_the_rubric():
    selection = {
        "status": "assessed", "selection_source": "model_orchestrator",
        "reason": "higher_ranked_comparison_exists",
        "top_methods": ["sqli_union"],
        "comparison": {
            "sqli_union": {"eligible": True, "fit_level": 3},
            "sqli_time_blind": {"eligible": True, "fit_level": 1},
        },
    }
    queue = {"method": "sqli_time_blind", "components": {"Smethod": 2}}
    record = {"final_state": {"selection_evidence": selection}}
    assert cause_evidence_problem(
        "model_output_quality", ["#/final_state/selection_evidence"],
        record, queue, dimension="Smethod",
    ) is None
    no_comparison = {
        "status": "assessed", "selection_source": "model_orchestrator",
        "reason": "higher_ranked_comparison_exists", "top_methods": ["sqli_union"],
    }
    record = {"final_state": {"selection_evidence": no_comparison}}
    assert cause_evidence_problem(
        "model_output_quality", ["#/final_state/selection_evidence"],
        record, queue, dimension="Smethod",
    ) is not None
    # A route-selected method is not a model selection-quality finding.
    route = {**selection, "selection_source": "akg_route"}
    record = {"final_state": {"selection_evidence": route}}
    assert cause_evidence_problem(
        "model_output_quality", ["#/final_state/selection_evidence"],
        record, queue, dimension="Smethod",
    ) is not None


def test_fixture_infeasible_requires_a_complete_negative_or_explicit_denial():
    record, queue = _context()
    assert cause_evidence_problem(
        "fixture_infeasible", ["#/measured_negative"], record, queue,
    ) is None
    # A bare method-labelled denial is not a bound fixture finding.
    assert cause_evidence_problem(
        "fixture_infeasible", ["#/control_events/0"], record, queue,
    ) is not None
    bound_denial = {
        "control_events": [{
            "decision": "denied", "method": "sqli_union",
            "principal": "gordonb", "object": "admin_user_manager",
            "policy": "admin_only_user_record", "expected_allowed": False,
            "positive_control": {"principal": "admin", "allowed": True},
            "http_status": 403, "response_sha256": "b" * 64,
        }],
    }
    assert cause_evidence_problem(
        "fixture_infeasible", ["#/control_events/0"], bound_denial, queue,
    ) is None
    incomplete, _ = _context(measured_negative={"complete": False})
    assert cause_evidence_problem(
        "fixture_infeasible", ["#/measured_negative"], incomplete, queue,
    ) is not None
    # A complete flag plus a successful control is a contradiction, not proof
    # of fixture infeasibility (documented review counterexample).
    positive_control = {
        "measured_negative": {
            "complete": True, "reason": "positive_control_succeeded",
        },
    }
    assert cause_evidence_problem(
        "fixture_infeasible", ["#/measured_negative"], positive_control, {},
    ) is not None
    mixed_verdicts, _ = _context()
    mixed_verdicts["measured_negative"]["verdicts"] = {
        "sqli_union": {"verdict": "vulnerable", "signal_detected": True},
    }
    assert cause_evidence_problem(
        "fixture_infeasible", ["#/measured_negative"], mixed_verdicts, queue,
    ) is not None
    # A candidate response without a bound control does not prove fixture infeasibility.
    response_only, _ = _context(
        measured_negative={"complete": False},
        control_events=[],
        final_state={"response_evidence": [{"status_code": 403, "signal_detected": False}]},
    )
    assert cause_evidence_problem(
        "fixture_infeasible", ["#/final_state/response_evidence/0"], response_only, queue,
    ) is not None


def test_fixture_infeasible_edge_closure_is_static_and_dimension_bound():
    static_edge = {
        "final_state": {
            "chain_assessment": {
                "assessed": True,
                "edges": [{
                    "edge_supported": False,
                    "reason": "chain_edge_declared_unsupported",
                    "unsupported_reason": "no adapter branch maps the source to the target",
                }],
            },
        },
    }
    assert cause_evidence_problem(
        "fixture_infeasible", ["#/final_state/chain_assessment"],
        static_edge, {"method": "sqli_time_blind", "components": {"Sexploit": 3}},
        dimension="Sexploit",
    ) is None
    open_edge = {
        "final_state": {
            "chain_assessment": {
                "assessed": True,
                "edges": [{
                    "edge_supported": True,
                    "status": "available",
                    "destination_rejection": {
                        "code": "destination_preconditions_not_proved",
                    },
                }],
            },
        },
    }
    assert cause_evidence_problem(
        "fixture_infeasible", ["#/final_state/chain_assessment"],
        open_edge, {"method": "sqli_time_blind", "components": {"Sexploit": 3}},
        dimension="Sexploit",
    ) is not None
    # A level-4 deduction below the cap can coexist with numeric Sexploit 3;
    # edge closure is the cause, not a null contradiction.
    assert cause_evidence_problem(
        "fixture_infeasible", ["#/final_state/chain_assessment"],
        static_edge, {"method": "sqli_time_blind", "components": {"Sexploit": 3},
                      "candidates": [{"eligible": True, "executed": True}]},
        dimension="Sexploit",
    ) is None
    # Measured-negative closure is not evidence for a numeric exploitation deduction.
    measured = _context()[0]
    assert cause_evidence_problem(
        "fixture_infeasible", ["#/measured_negative"], measured,
        {"method": "sqli_union", "components": {"Sexploit": 3}},
        dimension="Sexploit",
    ) is not None


def test_provider_failure_requires_a_transport_or_provider_signal():
    record, queue = _context(llm_performance=[{
        "role": "orchestrator", "failure_class": "transport_error", "call_id": "c",
    }])
    assert cause_evidence_problem(
        "provider_failure", ["#/llm_performance/0"], record, queue,
    ) is None
    invalid_json, _ = _context(llm_performance=[{
        "role": "orchestrator", "failure_class": "invalid_json", "call_id": "c",
    }])
    assert cause_evidence_problem(
        "provider_failure", ["#/llm_performance/0"], invalid_json, queue,
    ) is not None


def test_budget_and_ordering_need_an_explicit_effect_not_just_configuration():
    record, queue = _context()
    assert cause_evidence_problem(
        "harness_budget", ["#/final_state/candidate_lifecycle/0"], record, queue,
    ) is None
    config_only, _ = _context(final_state={"candidate_budget": 10})
    assert cause_evidence_problem(
        "harness_budget", ["#/final_state/candidate_budget"], config_only, queue,
    ) is not None
    assert cause_evidence_problem(
        "harness_ordering", ["#/final_state/chain_history/0"], record, queue,
    ) is None
    silent_route, _ = _context(final_state={"chain_history": [{"route_id": "r"}]})
    assert cause_evidence_problem(
        "harness_ordering", ["#/final_state/chain_history/0"], silent_route, queue,
    ) is not None


def test_scoring_ceiling_and_label_causes_require_their_own_records():
    record, queue = _context()
    # A not_confirmed/signal_absent verifier decision is a negative outcome,
    # not a scoring-path failure.
    assert cause_evidence_problem(
        "harness_scoring", ["#/final_state/verifier_history/0"], record, queue,
    ) is not None
    # An explicit scoring-path defect (ranking unavailable) is admissible.
    assert cause_evidence_problem(
        "harness_scoring", ["#/final_state/scoring_decisions/0"], record, queue,
    ) is None
    # A precondition fact plus a model call is not a scoring-path defect.
    no_scoring, _ = _context(final_state={"precondition_status": {"sqli": "false"}})
    assert cause_evidence_problem(
        "harness_scoring", ["#/final_state/precondition_status"], no_scoring, queue,
    ) is not None
    # A scoring pending reason is direct evidence of the scoring path; a
    # fixture/candidate pending reason cannot be relabelled as harness_scoring.
    assert cause_evidence_problem(
        "harness_scoring",
        ["queue:#/component_pending_reasons/Smethod"], record, queue,
    ) is None
    fixture_queue = {
        **queue,
        "component_pending_reasons": {"Spayload": "no_eligible_candidate"},
    }
    assert cause_evidence_problem(
        "harness_scoring",
        ["queue:#/component_pending_reasons/Spayload"], record, fixture_queue,
    ) is not None
    assert cause_evidence_problem(
        "rubric_ceiling", ["#/final_state/scoring_decisions/0"], record, queue,
    ) is None
    no_ceiling, _ = _context(final_state={
        "scoring_decisions": [{
            "dimension": "Smethod", "method": "sqli_union",
            "reason": "no_opportunity", "plan": None,
        }],
    })
    assert cause_evidence_problem(
        "rubric_ceiling", ["#/final_state/scoring_decisions/0"], no_ceiling, queue,
    ) is not None
    labelled, _ = _context(final_state={
        "security_outcome_reason": {"code": "label_mismatch", "detail": "incorrect label"},
    })
    assert cause_evidence_problem(
        "label", ["#/final_state/security_outcome_reason"], labelled, queue,
    ) is None
    assert cause_evidence_problem(
        "label", ["queue:#/components/Smethod"], record, queue,
    ) is not None


def _admit(record, queue, dimension, cause, proof, *, evidence=None,
           candidate_ids=None):
    record = {**record, "execution_id": "offline-review-only"}
    proposal = {
        "run": "offline-review-only", "dimension": dimension, "cause": cause,
        "evidence_refs": evidence or [f"queue:#/components/{dimension}"],
        "proof_links": [proof],
    }
    if candidate_ids is not None:
        proposal["candidate_ids"] = candidate_ids
    rows = _attribution_rows(
        [proposal],
        {"offline-review-only": (record, None)}, {}, {}, {},
        {"offline-review-only": queue},
    )
    decisions, _normalised = _merge_attribution_rows(rows)
    return decisions["offline-review-only", dimension]


def test_actual_admission_rejects_cause_without_component_scope():
    queue = {
        "method": "ac_idor", "components": {"Sexploit": 3},
        "candidates": [], "component_evidence_refs": {},
    }
    cases = [
        ("Sexploit", "model_output_quality", {
            "llm_performance": [{
                "role": "payload_generator", "method": "bf_dictionary",
                "visit_id": "unrelated-bf-visit", "call_id": "unrelated-call",
                "parse_status": "invalid", "validation_status": "invalid",
                "failure_class": "schema_rejected",
            }],
        }, "#/llm_performance/0"),
        ("Schain", "harness_ordering", {
            "final_state": {"chain_history": [{
                "route_id": "completed-route", "status": "completed",
                "success": True, "reason": "all controls passed",
            }]},
        }, "#/final_state/chain_history/0"),
        ("Sexploit", "fixture_infeasible", {
            "control_events": [{"decision": "denied", "method": "ac_idor"}],
        }, "#/control_events/0"),
        ("Sexploit", "rubric_ceiling", {
            "final_state": {"scoring_decisions": [{
                "dimension": "Smethod", "method": "ac_idor", "proof_ceiling": 2,
            }]},
        }, "#/final_state/scoring_decisions/0"),
    ]
    for dimension, cause, record, proof in cases:
        scoped_queue = {
            **queue, "components": {**queue["components"], dimension: 3},
        }
        with pytest.raises(ValueError, match="does not substantiate"):
            _admit(record, scoped_queue, dimension, cause, proof,
                   evidence=[f"queue:#/components/{dimension}"])


def test_actual_admission_keeps_supported_component_causes():
    record, queue = _context()
    measured_queue = {
        **queue, "components": {"Sexploit": None},
        "candidates": [],
    }
    decision = _admit(
        record, measured_queue, "Sexploit", "fixture_infeasible",
        "#/measured_negative", evidence=["#/measured_negative"],
    )
    assert decision["cause"] == "fixture_infeasible"

    static_edge = {
        "final_state": {"chain_assessment": {
            "assessed": True,
            "edges": [{
                "edge_supported": False,
                "reason": "chain_edge_declared_unsupported",
                "unsupported_reason": "no adapter branch maps source to target",
            }],
        }},
    }
    edge_queue = {
        "method": "sqli_time_blind", "components": {"Sexploit": 3},
        "candidates": [], "component_evidence_refs": {},
    }
    decision = _admit(
        static_edge, edge_queue, "Sexploit", "fixture_infeasible",
        "#/final_state/chain_assessment",
        evidence=["#/final_state/chain_assessment"],
    )
    assert decision["cause"] == "fixture_infeasible"

    ordering = {
        "final_state": {"chain_history": [{
            "route_id": "route-1", "status": "rejected",
            "reason": "route ordering rejected the destination",
        }]},
    }
    ordering_queue = {
        "method": "ac_idor", "components": {"Schain": 3},
        "candidates": [], "component_evidence_refs": {},
    }
    decision = _admit(
        ordering, ordering_queue, "Schain", "harness_ordering",
        "#/final_state/chain_history/0",
        evidence=["#/final_state/chain_history/0"],
    )
    assert decision["cause"] == "harness_ordering"

    ceiling = {
        "final_state": {"scoring_decisions": [{
            "dimension": "Smethod", "method": "ac_idor", "proof_ceiling": 2,
        }]},
    }
    ceiling_queue = {
        "method": "ac_idor", "components": {"Smethod": 2},
        "candidates": [], "component_evidence_refs": {},
    }
    decision = _admit(
        ceiling, ceiling_queue, "Smethod", "rubric_ceiling",
        "#/final_state/scoring_decisions/0",
        evidence=["#/final_state/scoring_decisions/0"],
    )
    assert decision["cause"] == "rubric_ceiling"

    denial = {
        "control_events": [{
            "decision": "denied", "method": "ac_idor",
            "principal": "gordonb", "object": "admin_user_manager",
            "policy": "admin_only_user_record", "expected_allowed": False,
            "positive_control": {"principal": "admin", "allowed": True},
            "http_status": 403, "response_sha256": "b" * 64,
        }],
    }
    denial_queue = {
        "method": "ac_idor", "components": {"Sexploit": None},
        "candidates": [], "component_evidence_refs": {},
    }
    decision = _admit(
        denial, denial_queue, "Sexploit", "fixture_infeasible",
        "#/control_events/0", evidence=["#/control_events/0"],
    )
    assert decision["cause"] == "fixture_infeasible"

    selection = {
        "final_state": {"selection_evidence": {
            "status": "assessed", "selection_source": "model_orchestrator",
            "reason": "higher_ranked_comparison_exists",
            "top_methods": ["ac_idor"],
            "comparison": {
                "ac_idor": {"eligible": True, "fit_level": 3},
                "ac_force_browse": {"eligible": True, "fit_level": 1},
            },
        }},
        "execution_id": "offline-review-only",
    }
    selection_queue = {
        "method": "ac_force_browse", "components": {"Smethod": 2},
        "candidates": [], "component_evidence_refs": {
            "Smethod": ["#/final_state/selection_evidence"],
        },
    }
    decision = _admit(
        selection, selection_queue, "Smethod", "model_output_quality",
        "#/final_state/selection_evidence",
        evidence=["#/final_state/selection_evidence"],
    )
    assert decision["cause"] == "model_output_quality"

    rejected_candidate = {
        "final_state": {"payload_candidates": {"ac_idor": [{
            "candidate_id": "c1", "method": "ac_idor",
            "origin_kind": "seed_mutation", "validation_status": "invalid",
            "status": "rejected",
        }]}},
    }
    candidate_queue = {
        "method": "ac_idor", "components": {"Spayload": 1},
        "candidates": [{"candidate_id": "c1", "eligible": True, "executed": False}],
        "component_evidence_refs": {"Spayload": ["#/final_state/payload_candidates"]},
    }
    decision = _admit(
        rejected_candidate, candidate_queue, "Spayload", "model_output_quality",
        "#/final_state/payload_candidates",
        evidence=["#/final_state/payload_candidates"], candidate_ids=["c1"],
    )
    assert decision["cause"] == "model_output_quality"


def test_attribution_candidate_ids_must_bind_the_graded_population():
    record, queue = _context()
    record["final_state"]["scoring_decisions"] = [{
        "dimension": "Spayload", "method": "sqli_union",
        "reason": "grading_path_unavailable",
    }]
    proposal = {
        "run": "offline-review-only", "dimension": "Spayload",
        "cause": "harness_scoring",
        "evidence_refs": ["#/final_state/scoring_decisions/0"],
        "proof_links": ["#/final_state/scoring_decisions/0"],
        "candidate_ids": ["not-a-real-candidate"],
    }
    record["execution_id"] = "offline-review-only"
    with pytest.raises(ValueError, match="do not bind the graded candidate population"):
        _attribution_rows(
            [proposal], {"offline-review-only": (record, None)}, {}, {}, {},
            {"offline-review-only": queue},
        )


def test_candidate_rows_are_deduped_to_one_component_decision():
    rows = [
        {
            "run_ref": "run-1", "execution_id": "exec-1", "dimension": "Spayload",
            "cause": "model_output_quality",
            "evidence_refs": ["#/final_state/payload_provenance/generated"],
            "proof_links": ["#/final_state/payload_provenance/generated"],
            "candidate_ids": ["candidate-a"], "primary": True, "note": None,
        },
        {
            "run_ref": "run-1", "execution_id": "exec-1", "dimension": "Spayload",
            "cause": "model_output_quality",
            "evidence_refs": ["#/final_state/payload_candidates"],
            "proof_links": ["#/final_state/payload_candidates"],
            "candidate_ids": ["candidate-b"], "primary": False, "note": None,
        },
        {
            "run_ref": "run-1", "execution_id": "exec-1", "dimension": "Spayload",
            "cause": "rubric_ceiling",
            "evidence_refs": ["#/final_state/scoring_decisions/0"],
            "proof_links": ["#/final_state/scoring_decisions/0"],
            "candidate_ids": ["candidate-b"], "primary": False, "note": None,
        },
    ]
    decisions, rows_out = _merge_attribution_rows(rows)
    assert len(decisions) == 1 and len(rows_out) == 1
    decision = decisions["run-1", "Spayload"]
    assert decision["primary_cause"] == "model_output_quality"
    assert [entry["cause"] for entry in decision["secondary_causes"]] == ["rubric_ceiling"]
    assert decision["candidate_ids"] == ["candidate-a", "candidate-b"]
    assert decision["n_candidate_rows"] == 3
    assert len(decision["proof_links"]) == 3
