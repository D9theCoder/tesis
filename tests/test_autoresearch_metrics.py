"""Offline metric-reader integrity controls (no graph/provider/target calls).

Covers the canonical scoring digest, reader-only physical request totals,
graded-versus-runtime component evidence, derived candidate assessment, and
nullable persisted ``report.summary`` rates.
"""
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

import pytest

from core.scorer import build_score_report
from evaluation.contracts import ScoreSummary
from evaluation.metrics import metric_reading
from evaluation.research_metrics import (
    PROVISIONAL_LABEL,
    SCORING_POLICY_VERSION,
    SCORING_RULE_DIGEST_DEFINITION,
    SCORING_SOURCE_FILES,
    compute_run_metrics,
    scoring_policy,
    scoring_rule_hash,
)

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# F9 — one canonical scoring-rule digest
# --------------------------------------------------------------------------- #


def test_scoring_policy_returns_the_canonical_four_file_digest():
    policy = scoring_policy()
    expected = sha256(''.join(
        sha256((ROOT / path).read_bytes()).hexdigest() for path in SCORING_SOURCE_FILES
    ).encode()).hexdigest()
    assert 'foundation/verifier.py' in SCORING_SOURCE_FILES
    assert set(policy['source_hashes']) == set(SCORING_SOURCE_FILES)
    assert policy['scoring_rule_sha256'] == scoring_rule_hash() == expected
    assert policy['digest_definition'] == SCORING_RULE_DIGEST_DEFINITION
    assert policy['source_files'] == list(SCORING_SOURCE_FILES)
    assert policy['policy_version'] == SCORING_POLICY_VERSION


def test_scoring_policy_keeps_the_recorded_epoch_digest_as_history():
    recorded = 'a' * 64
    policy = scoring_policy({
        'config': {'scoring_rubric_version': 'scoring.v4'},
        'score_epoch': {'scoring_rule_sha256': recorded},
    })
    assert policy['recorded_scoring_rule_sha256'] == recorded
    # Historical identity is echoed, never relabelled as the canonical digest.
    assert policy['scoring_rule_sha256'] == scoring_rule_hash()
    assert policy['scoring_rule_sha256'] != recorded


# --------------------------------------------------------------------------- #
# F3 — captured physical totals versus incomplete attribution
# --------------------------------------------------------------------------- #


def counters(**overrides):
    document = {
        'policy_version': 'http-accounting.v1',
        'scope': 'run',
        'total_requests': 200,
        'by_phase': {'recon': 0, 'destination': 0, 'method': 0,
                     'verification': 50, 'token': 0, 'other': 150},
        'by_role': {'detection_control': 0, 'candidate': 0, 'independent_control': 0,
                    'candidate_verification': 50, 'other': 150},
        'per_method': {},
        'retries': 3,
        'redirect_hops': 1,
        'failed_requests': 2,
        'unattributed_requests': 150,
        'complete': False,
        'capture_status': 'partial',
    }
    document.update(overrides)
    return document


def artifact(*, state=None, config=None, **top_level):
    document = {
        'config': {'scoring_rubric_version': 'scoring.v4', **(config or {})},
        'final_state': {'selected_method': None, **(state or {})},
    }
    document.update(top_level)
    return document


def test_partial_attribution_still_reports_proven_physical_totals():
    document = compute_run_metrics(artifact(http_request_counters=counters()))
    detail = document['denominators']['physical_requests_total']
    assert document['values']['physical_requests_total'] == 200
    assert document['values']['request_retries'] == 3
    assert document['values']['redirect_hops'] == 1
    assert document['values']['failed_requests'] == 2
    # Attribution is still incomplete; the old capture is never relabelled complete.
    assert detail['capture_status'] == 'partial'
    assert detail['attribution_complete'] is False
    assert detail['attribution_reason'] == 'http_request_capture_partial'
    assert detail['run_totals_available'] is True
    assert detail['phase_total_requests'] == 200
    assert detail['unattributed_requests'] == 150


@pytest.mark.parametrize(('override', 'reason'), [
    ({'total_requests': 199}, 'http_counter_conservation_mismatch'),
    ({'total_requests': -1}, 'http_counter_total_invalid'),
    ({'total_requests': '200'}, 'http_counter_total_invalid'),
    ({'by_phase': {}}, 'http_counter_phase_totals_invalid'),
    ({'by_phase': {'method': '1'}}, 'http_counter_phase_totals_invalid'),
    ({'by_role': {'candidate': '1'}}, 'http_counter_role_totals_invalid'),
    ({'by_role': ['candidate']}, 'http_counter_role_totals_invalid'),
    ({'by_role': {'candidate': 199}}, 'http_counter_role_conservation_mismatch'),
    ({'capture_status': 'unavailable'}, 'http_request_capture_unavailable'),
    ({'capture_status': None}, 'http_request_capture_status_unknown'),
    ({'capture_status': 'mystery'}, 'http_request_capture_status_unknown'),
])
def test_missing_invalid_or_nonconserving_totals_stay_unavailable(override, reason):
    document = compute_run_metrics(artifact(http_request_counters=counters(**override)))
    for name in ('physical_requests_total', 'request_retries', 'redirect_hops', 'failed_requests'):
        assert document['values'][name] is None, name
        assert document['unavailable_reason'][name] == reason, name


def test_absent_counters_and_legitimate_zero_totals_are_distinguished():
    absent = compute_run_metrics(artifact())
    assert absent['values']['physical_requests_total'] is None
    assert absent['unavailable_reason']['physical_requests_total'] == 'http_request_counters_unavailable'

    zero = counters(total_requests=0, by_phase={'recon': 0, 'destination': 0, 'method': 0,
                                                'verification': 0, 'token': 0, 'other': 0},
                    by_role={'detection_control': 0, 'candidate': 0, 'independent_control': 0,
                             'candidate_verification': 0, 'other': 0},
                    retries=0, redirect_hops=0, failed_requests=0, unattributed_requests=0,
                    complete=True, capture_status='complete')
    document = compute_run_metrics(artifact(http_request_counters=zero))
    assert document['values']['physical_requests_total'] == 0
    assert document['availability']['physical_requests_total'] is True
    assert document['denominators']['physical_requests_total']['attribution_complete'] is True


# --------------------------------------------------------------------------- #
# F4 — graded flags never come from runtime components
# --------------------------------------------------------------------------- #


def test_runtime_components_are_labeled_legacy_and_never_graded():
    document = artifact(composite_components={
        'Smethod': 3, 'Spayload': 3, 'Sexploit': 4, 'Schain': 3, 'Soutput': 4,
    })
    metrics = compute_run_metrics(document)
    # No retained candidate proof exists, so the graded flag stays unavailable
    # even though the runtime vector claims a full exploit.
    assert metrics['values']['full_exploit_flag'] is None
    assert metrics['values']['chain_enabled_exploit_flag'] is None
    assert metrics['unavailable_reason']['full_exploit_flag'] == 'exploit_evidence_unavailable'
    legacy = metrics['legacy_runtime_components']
    assert legacy['label'] == PROVISIONAL_LABEL
    assert legacy['score_epoch'] == 'runtime_provisional_scoring.v2'
    assert legacy['source'] == 'artifact.composite_components'
    assert legacy['components']['Sexploit'] == 4
    assert legacy['flags']['full_exploit_flag_legacy'] == 1.0
    assert legacy['flags']['chain_enabled_exploit_flag_legacy'] == 1.0


def test_supplied_graded_components_are_the_only_flag_evidence():
    document = compute_run_metrics(artifact(), components={'Sexploit': 3, 'Schain': 2})
    assert document['values']['full_exploit_flag'] == 1.0
    assert document['values']['chain_enabled_exploit_flag'] == 0.0
    assert 'legacy_runtime_components' not in document


def test_review_rows_without_components_are_graded_through_the_scoring_api():
    document = compute_run_metrics(artifact(), rows=[
        {'candidate_id': 'candidate-a', 'eligible': True, 'base_proof': 3},
    ])
    assert document['values']['full_exploit_flag'] == 1.0
    assert 'legacy_runtime_components' not in document


# --------------------------------------------------------------------------- #
# F5 — derived candidate assessment via the scoring API
# --------------------------------------------------------------------------- #


def candidate_artifact(*, reason='verified_error_extraction'):
    evidence = {
        'candidate_id': 'candidate-a', 'agent_id': 'sqli_union', 'stage': 'exploit',
        'visit_id': 'visit-1', 'evidence_id': 'evidence-a', 'status_code': 200,
        'response_sha256': sha256(b'response').hexdigest(),
        'verification_reason': reason,
    }
    return artifact(state={
        'selected_method': 'sqli_union',
        'payload_candidates': {'sqli_union': [
            {'candidate_id': 'candidate-a', 'stage': 'exploit', 'payload_or_logic': 'fixture'}]},
        'payload_provenance': {'candidate-a': {'method': 'sqli_union', 'source': 'static_seed'}},
        'payload_validation_results': {'sqli_union': [{'candidate_id': 'candidate-a', 'valid': True}]},
        'response_evidence': [evidence],
        'verifier_history': [{
            'agent_id': 'sqli_union', 'visit_id': 'visit-1', 'source': 'method_agent_evidence',
            'decision': 'confirmed', 'evidence_refs': ['#/final_state/response_evidence/0'],
        }],
    })


def test_candidate_assessment_is_derived_without_review_rows():
    document = compute_run_metrics(candidate_artifact())
    assert document['values']['payload_validity_rate'] == 1.0
    # candidate_base assessed the executed candidate at confirmed tier.
    assert document['values']['payload_execution_success_rate'] == 1.0
    assert document['availability']['payload_execution_success_rate'] is True
    # The derived view feeds the central graded API, so the flag is numeric.
    assert document['values']['full_exploit_flag'] == 1.0
    assert document['availability']['full_exploit_flag'] is True


def test_poisoned_runtime_vector_never_overrides_retained_graded_proof():
    document = candidate_artifact()
    document['composite_components'] = {
        'Smethod': 0, 'Spayload': 0, 'Sexploit': 0, 'Schain': 0, 'Soutput': 0,
    }
    metrics = compute_run_metrics(document)
    assert metrics['values']['full_exploit_flag'] == 1.0
    assert metrics['legacy_runtime_components']['components']['Sexploit'] == 0
    assert metrics['legacy_runtime_components']['flags']['full_exploit_flag_legacy'] == 0.0


def test_tier_one_candidate_is_assessed_but_not_confirmed_success():
    document = compute_run_metrics(candidate_artifact(reason='probe_signal'))
    # Tier 1 is assessed, so the rate is a measured zero over the valid candidate.
    assert document['values']['payload_execution_success_rate'] == 0.0
    assert document['availability']['payload_execution_success_rate'] is True
    assert document['values']['full_exploit_flag'] == 0.0
    assert document['availability']['full_exploit_flag'] is True


def test_candidate_payload_scores_are_never_used_as_proof():
    document = candidate_artifact()
    document['final_state']['payload_scores'] = {'candidate-a': 4}
    document['final_state']['response_evidence'][0]['verification_reason'] = None
    metrics = compute_run_metrics(document)
    assert metrics['values']['payload_execution_success_rate'] is None
    detail = metrics['denominators']['payload_execution_success_rate']
    assert detail['reason'] == 'unassessable_executed_candidate'
    assert detail['unassessed_candidates'] == [{
        'candidate_id': 'candidate-a', 'reason': 'candidate_proof_evidence_unavailable'}]
    # An unassessable executed candidate cannot become a zero or a success.
    assert metrics['values']['full_exploit_flag'] is None
    assert metrics['availability']['full_exploit_flag'] is False


# --------------------------------------------------------------------------- #
# F12 — report.summary rates are null, not zero, without a denominator
# --------------------------------------------------------------------------- #


def test_empty_denominators_are_null_with_reasons_not_zero():
    summary = asdict(build_score_report({}).summary)
    expected = {
        'method_selection_accuracy': 'no_attempted_method',
        'adaptation_rate': 'no_adaptation_opportunity',
        'mean_attempts_to_success': 'no_successful_payload_attempt',
        'payload_validity_rate': 'no_validation_rows',
        'payload_execution_success_rate': 'no_payload_scores',
        'payload_improvement_rate': 'no_generated_candidate_with_method',
        'guardrail_activation_rate': 'no_iterations',
    }
    for name, reason in expected.items():
        assert summary[name] is None, name
        assert summary['metric_availability'][name] is False, name
        assert summary['metric_unavailable_reason'][name] == reason, name
        assert metric_reading(summary, name) == (None, False, reason), name


def summary_kwargs(**overrides):
    base = {
        'llm_provider': 'fixture', 'security_level': 'low', 'total_modules_tested': 0,
        'score_distribution': {}, 'chain_exploits_achieved': 0,
        'highest_impact_outcome': None, 'guardrail_activations': 0,
        'total_iterations_used': 0, 'longest_chain': None,
    }
    base.update(overrides)
    return base


def test_summary_rates_fail_closed_without_explicit_availability():
    with pytest.raises(ValueError):
        ScoreSummary(**summary_kwargs(payload_validity_rate=0.0))
    with pytest.raises(ValueError):
        ScoreSummary(**summary_kwargs(metric_availability={'payload_validity_rate': True}))
    ScoreSummary(**summary_kwargs(
        metric_availability={'payload_validity_rate': False},
        metric_unavailable_reason={'payload_validity_rate': 'no_validation_rows'},
    ))


def test_measured_non_events_keep_legitimate_zero():
    state = {
        'attempted_agents': ['sqli_union'],
        'scores': {'sqli_union': 3},
        'tried_payloads': {'sqli_union': ['payload-1', 'payload-2']},
        'payload_validation_results': {'sqli_union': [
            {'candidate_id': 'candidate-static', 'valid': False}]},
        'payload_scores': {'candidate-generated': 1, 'candidate-static': 2},
        'payload_provenance': {
            'candidate-generated': {'method': 'sqli_union', 'source': 'seed_mutation'},
            'candidate-static': {'method': 'sqli_union', 'source': 'static_seed'},
        },
        'guardrail_activations': [],
        'iteration_count': 3,
    }
    summary = asdict(build_score_report(state).summary)
    assert summary['payload_validity_rate'] == 0.0
    assert summary['payload_execution_success_rate'] == 0.0
    assert summary['payload_improvement_rate'] == 0.0
    assert summary['guardrail_activation_rate'] == 0.0
    assert summary['mean_attempts_to_success'] == 2.0
    assert summary['method_selection_accuracy'] == 1.0
    # Fewer than two attempts is still no re-selection opportunity.
    assert summary['adaptation_rate'] is None
    for name in ('payload_validity_rate', 'payload_execution_success_rate',
                 'payload_improvement_rate', 'guardrail_activation_rate',
                 'mean_attempts_to_success', 'method_selection_accuracy'):
        assert summary['metric_availability'][name] is True, name
        assert metric_reading(summary, name)[1] is True, name
