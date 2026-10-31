"""Offline fidelity-ledger controls; no graph, target, provider or review execution.

The ledger is a reader/writer over saved artifacts.  These tests build synthetic
artifacts, call the public callable API and assert the P-1 / P0 / P1 contract.
"""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE
from evaluation.fidelity_ledger import (
    DIMENSIONS,
    RUNTIME_PROVISIONAL_LABEL,
    build_ledger,
    rank_hypotheses,
    write_ledger,
)
from evaluation.scoring_evidence import evidence_hash
from evaluation.thesis_scoring import finalize_reviews, review_queue


def profile(surface='sqli'):
    document = {'kind': 'offline_reference_protocol', 'controls': 'synthetic equal-budget protocols'}
    methods = {
        method: {
            'preconditions': AttackKnowledgeGraph.METHOD_PRECONDITIONS[method],
            'fit_predicates': [{'key': AttackKnowledgeGraph.METHOD_PRECONDITIONS[method][0], 'equals': True}],
            'planned_request_count': 10,
            'protocol_refs': ['protocol'],
            'allowed_plans': ['stop_after_target', 'stop_at_budget', 'continue_same_surface'],
        }
        for method in METHODS_BY_SURFACE[surface]
    }
    result = {
        'profile_id': 'offline-ranking', 'version': 'ranking.v1',
        'fixture_id': 'synthetic-dwva', 'protocol_version': 'offline.v1',
        'frozen_at': '2026-09-01T00:00:00+00:00', 'candidate_budget': 5,
        'sources': [{'source_id': 'protocol', 'origin': 'offline_control',
                     'document': document, 'sha256': evidence_hash(document)}],
        'scenarios': {f'{surface}:low': methods},
    }
    result['sha256'] = evidence_hash(result)
    return result


def artifact(execution_id='e1', **overrides):
    document = {
        'run_id': f'run-{execution_id}',
        'execution_id': execution_id,
        'validation_scope': 'offline_synthetic_fixture',
        'config': {
            'scoring_mode': 'human', 'scoring_rubric_version': 'scoring.v4',
            'scoring_profile': {}, 'scoring_oracles': [],
            'experiment_condition': 'linear_hybrid', 'model': 'model-a',
            'provider': 'provider-a', 'surface': 'sqli', 'security_level': 'low',
            'repeat_index': 0,
        },
        'score_epoch': {'thesis_final': 'scoring.v4', 'scoring_rule_sha256': 'recorded'},
        'final_state': {},
    }
    document.update(overrides)
    return document


def write_doc(root, name, document, *, subdir='runs'):
    path = Path(root) / subdir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document))
    return path


def evidence_row(candidate_id, method):
    return {
        'candidate_id': candidate_id, 'agent_id': method, 'stage': 'exploit',
        'visit_id': 'visit-1', 'evidence_id': candidate_id, 'status_code': 200,
        'response_sha256': sha256(candidate_id.encode()).hexdigest(),
        'verification_reason': 'partial_union_data', 'signal_detected': True,
    }


def candidate_state(candidate_id='candidate-a', *, source='static_seed'):
    return {
        'selected_method': 'sqli_union',
        'payload_candidates': {'sqli_union': [{'candidate_id': candidate_id, 'stage': 'exploit'}]},
        'payload_provenance': {candidate_id: {'method': 'sqli_union', 'source': source}},
        'payload_validation_results': {'sqli_union': [{'candidate_id': candidate_id, 'valid': True}]},
        'response_evidence': [evidence_row(candidate_id, 'sqli_union')],
        'verifier_history': [{'agent_id': 'sqli_union', 'visit_id': 'visit-1',
                              'source': 'method_agent_evidence', 'decision': 'unverified',
                              'evidence_refs': ['#/final_state/response_evidence/0']}],
    }


def full_artifact(execution_id='full', *, scoring_mode='human'):
    ranking = profile()
    document = artifact(
        execution_id,
        config={
            'scoring_mode': scoring_mode, 'scoring_rubric_version': 'scoring.v4',
            'scoring_profile': ranking, 'scoring_oracles': [],
            'fixture_id': ranking['fixture_id'], 'protocol_version': ranking['protocol_version'],
            'candidate_budget': ranking['candidate_budget'],
            'experiment_condition': 'linear_hybrid', 'model': 'model-a',
            'provider': 'provider-a', 'surface': 'sqli', 'security_level': 'low',
            'repeat_index': 0, 'target_method': None,
            'scoring_evaluator': {'provider': 'offline', 'model': 'judge',
                                  'max_attempts': 1, 'max_tokens': 10, 'timeout': 1},
        },
    )
    observations = {key: True for keys in AttackKnowledgeGraph.METHOD_PRECONDITIONS.values() for key in keys}
    state = {
        'selected_method': 'sqli_union',
        'scoring_decisions': [{
            'dimension': 'Smethod', 'method': 'sqli_union', 'surface': 'sqli',
            'observations': observations, 'profile_sha256': ranking['sha256'],
            'selected_at': '2026-10-01T00:00:00+00:00',
            'reason_refs': ['union_select_possible'],
            'plan': {'kind': 'stop_at_budget'}, 'visit_id': 'visit-1',
        }],
        'chain_assessment': {'assessed': True, 'status': 'assessed', 'reason': 'no_opportunity',
                             'edges': [], 'routes_evaluated': 0,
                             'policy_version': 'chain-assessment.v1'},
    }
    state.update(candidate_state())
    document['final_state'] = state
    document['llm_performance'] = [{
        'call_id': 'call:1', 'role': 'orchestrator', 'method': 'sqli_union',
        'visit_id': 'visit-1', 'parse_status': 'ok', 'validation_status': 'valid',
        'attempt': 1, 'input': {}, 'output': {},
    }]
    return document


def review_decisions(queue, mode='human'):
    reviewer = 'human-1' if mode == 'human' else 'offline/judge'
    version = 'review.v1' if mode == 'human' else 'judge.v1'
    return [{
        'decision_id': f'decision-{index}', 'candidate_id': row['candidate_id'],
        'scoring_mode': mode, 'score': 2, 'reason': 'Synthetic review evidence',
        'source_sha256': queue['source_sha256'], 'run_id': queue['run_id'],
        'rubric_version': queue['rubric_version'], 'reviewer_id': reviewer,
        'review_version': version, 'timestamp': '2026-10-31T00:00:00+00:00',
        'evidence_refs': row['evidence_refs'],
    } for index, row in enumerate(queue['candidates']) if row['eligible']]


def test_graded_vector_reports_all_five_dimensions_and_pending_payload(tmp_path):
    document = artifact('e1')
    document['final_state']['chain_assessment'] = {
        'assessed': True, 'status': 'assessed', 'reason': 'no_opportunity',
        'edges': [], 'routes_evaluated': 0, 'policy_version': 'chain-assessment.v1',
    }
    write_doc(tmp_path, 'e1.json', document)
    ledger = build_ledger(tmp_path)
    run = ledger['runs'][0]
    assert set(run['graded']['components']) == set(DIMENSIONS)
    assert run['graded']['components'] == {
        'Smethod': None, 'Spayload': None, 'Sexploit': None, 'Schain': 0, 'Soutput': None,
    }
    assert run['graded']['component_pending_reasons']['Spayload'] == 'no_eligible_candidate'
    assert run['graded']['component_pending_reasons']['Smethod']
    assert run['graded']['Srun_final'] is None
    assert run['graded']['Srun_final_source'] is None
    assert run['graded']['selected_payload_review'] is False
    assert run['legacy_runtime']['label'] == RUNTIME_PROVISIONAL_LABEL
    assert ledger['phase_a']['complete'] is False
    assert ledger['phase_a']['payload_reviewed_runs'] == 0
    assert ledger['phase_a']['payload_required_runs'] == 0
    assert ledger['phase_a']['payload_no_eligible_runs'] == 1
    assert ledger['phase_a']['null_components_without_closed_cause']['Spayload'] == 1
    assert ledger['phase_a']['deduction_components_without_closed_cause']['Schain'] == 1
    assert ledger['convergence']['converged'] is False


def test_reviewed_numeric_payload_survives_pending_srun_and_blocks_phase_a(tmp_path):
    document = artifact('partial')
    document['final_state'].update(candidate_state())
    document['final_state']['chain_assessment'] = {
        'assessed': True, 'status': 'assessed', 'reason': 'no_opportunity',
        'edges': [], 'routes_evaluated': 0, 'policy_version': 'chain-assessment.v1',
    }
    document['llm_performance'] = [{
        'call_id': 'call:1', 'role': 'orchestrator', 'method': 'sqli_union',
        'visit_id': 'visit-1', 'parse_status': 'ok', 'validation_status': 'valid',
        'attempt': 1, 'input': {}, 'output': {},
    }]
    path = write_doc(tmp_path, 'partial.json', document)
    queue = review_queue(path)
    review_dir = tmp_path / 'reviews'
    result = finalize_reviews(path, review_decisions(queue, 'human'), output_dir=review_dir,
                              isolated_output=True)
    assert result['workflows']['human']['status'] == 'pending'
    assert result['workflows']['human']['components']['Spayload'] == 2.0
    assert result['workflows']['human']['Srun_final'] is None
    ledger = build_ledger(tmp_path, receipts=review_dir)
    run = ledger['runs'][0]
    assert run['graded']['components']['Spayload'] == 2.0
    assert run['graded']['Srun_final'] is None
    assert run['graded']['Srun_final_reason'].startswith('pending_selected_workflow:')
    assert run['graded']['workflow_status'] == 'pending'
    assert ledger['phase_a']['complete'] is False
    assert ledger['phase_a']['deduction_components_without_closed_cause'] == {
        'Spayload': 1, 'Sexploit': 1, 'Schain': 1, 'Soutput': 1,
    }
    assert any('Spayload_deduction_without_closed_cause=1'
               for reason in ledger['phase_a']['blocking_reasons'])


def test_human_receipt_is_authoritative_and_ai_receipt_is_separate(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    path = write_doc(source, 'full.json', full_artifact(scoring_mode='both'))
    queue = review_queue(path)

    ai_dir = tmp_path / 'reviews-ai'
    finalize_reviews(path, review_decisions(queue, 'ai'), output_dir=ai_dir, isolated_output=True)
    ai_only = build_ledger(source, receipts=ai_dir)['runs'][0]
    assert ai_only['graded']['components']['Spayload'] is None
    assert ai_only['graded']['component_pending_reasons']['Spayload'] == 'pending_candidate_grades'
    assert ai_only['graded']['Srun_final'] is None
    assert ai_only['graded']['parallel_ai_workflow']['components']['Spayload'] == 2.0
    assert ai_only['graded']['parallel_ai_workflow']['Srun_final'] == 2.4
    assert ai_only['graded']['selected_final_receipt'] is False

    human_dir = tmp_path / 'reviews-human'
    finalize_reviews(path, review_decisions(queue, 'human'), output_dir=human_dir, isolated_output=True)
    human_ledger = build_ledger(source, receipts=human_dir)
    assert human_ledger['phase_a']['complete'] is False
    assert human_ledger['phase_a']['deduction_components_without_closed_cause'] == {
        'Spayload': 1, 'Sexploit': 1, 'Schain': 1, 'Soutput': 1,
    }
    attributed = build_ledger(source, receipts=human_dir, attributions=[
        {'run': 'full', 'dimension': 'Spayload', 'cause': 'harness_scoring',
         'evidence_refs': ['#/final_state/response_evidence/0']},
        {'run': 'full', 'dimension': 'Sexploit', 'cause': 'harness_scoring',
         'evidence_refs': ['#/final_state/response_evidence/0']},
        {'run': 'full', 'dimension': 'Schain', 'cause': 'rubric_ceiling',
         'evidence_refs': ['#/final_state/chain_assessment']},
        {'run': 'full', 'dimension': 'Soutput', 'cause': 'harness_scoring',
         'evidence_refs': ['#/llm_performance/0']},
    ])
    assert attributed['phase_a']['complete'] is True
    human = attributed['runs'][0]
    assert human['graded']['components']['Spayload'] == 2.0
    assert human['graded']['components']['Smethod'] == 4
    assert human['graded']['Srun_final'] == 2.4
    assert human['graded']['Srun_final_source'] == 'validated_final_selected_receipt'
    assert human['graded']['selected_payload_review'] is True
    assert human['graded']['selected_final_receipt'] is True
    assert ((human['graded']['parallel_ai_workflow'] or {}).get('components') or {}).get('Spayload') is None


def test_ai_selection_receipt_is_selected_authority(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    path = write_doc(source, 'ai.json', full_artifact('ai', scoring_mode='ai'))
    queue = review_queue(path)
    review_dir = tmp_path / 'reviews'
    result = finalize_reviews(path, review_decisions(queue, 'ai'), output_dir=review_dir,
                              isolated_output=True)
    assert result['workflows']['ai']['status'] == 'final'
    ledger = build_ledger(source, receipts=review_dir)
    run = ledger['runs'][0]
    assert run['graded']['authoritative_mode'] == 'ai'
    assert run['graded']['components']['Spayload'] == 2.0
    assert run['graded']['Srun_final'] == 2.4
    assert run['graded']['Srun_final_source'] == 'validated_final_selected_receipt'
    assert run['graded']['Srun_final_reason'] is None
    assert run['graded']['selected_payload_review'] is True
    assert run['graded']['selected_final_receipt'] is True
    assert run['graded']['parallel_ai_workflow'] is None
    assert ledger['phase_a']['payload_reviewed_runs'] == 1
    assert ledger['phase_a']['payload_missing_review_runs'] == []
    assert not any('payload_reviews_missing' in reason
                   for reason in ledger['phase_a']['blocking_reasons'])


def test_closed_cause_attribution_and_invalid_bindings(tmp_path):
    write_doc(tmp_path, 'e1.json', artifact('e1'))
    ledger = build_ledger(tmp_path)
    assert ledger['fidelity']['F3']['value'] == 0.0
    assert ledger['fidelity']['F3']['unknown'] == 5
    assert ledger['convergence']['converged'] is False

    attributed = build_ledger(tmp_path, attributions=[{
        'run': 'e1', 'dimension': 'Smethod', 'cause': 'harness_scoring',
        'evidence_refs': ['#/config/scoring_profile'],
    }])
    assert attributed['fidelity']['F3']['numerator'] == 1
    assert attributed['fidelity']['F3']['unknown'] == 4

    queue_attributed = build_ledger(tmp_path, attributions=[{
        'run': 'e1', 'dimension': 'Smethod', 'cause': 'label',
        'evidence_refs': ['queue:#/components/Smethod'],
    }])
    assert queue_attributed['fidelity']['F3']['numerator'] == 1

    with pytest.raises(ValueError, match='closed list'):
        build_ledger(tmp_path, attributions=[{
            'run': 'e1', 'dimension': 'Smethod', 'cause': 'not_a_cause',
            'evidence_refs': ['#/config/scoring_profile'],
        }])
    with pytest.raises(ValueError, match='does not bind'):
        build_ledger(tmp_path, attributions=[{
            'run': 'e1', 'dimension': 'Smethod', 'cause': 'harness_scoring',
            'evidence_refs': ['#/missing'],
        }])
    with pytest.raises(ValueError, match='does not resolve'):
        build_ledger(tmp_path, attributions=[{
            'run': 'e1', 'dimension': 'Smethod', 'cause': 'harness_scoring',
            'evidence_refs': ['#/config/scoring_profile', '#/missing_component'],
        }])


def test_attribution_cannot_bind_full_credit_component(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    write_doc(source, 'full.json', full_artifact())
    with pytest.raises(ValueError, match='does not bind a deduction or null'):
        build_ledger(source, attributions=[{
            'run': 'full', 'dimension': 'Smethod', 'cause': 'rubric_ceiling',
            'evidence_refs': ['#/final_state/scoring_decisions/0'],
        }])


def test_null_discipline_and_arithmetic_consistency(tmp_path):
    null_artifact = artifact('null')
    null_artifact['composite_score'] = None
    null_artifact['metric_availability'] = {'composite_score': False}
    null_artifact['metric_unavailable_reason'] = {'composite_score': 'measured_negative'}
    null_artifact['measured_negative'] = {'complete': True, 'reason': 'every_precondition_false'}
    scored = artifact('scored', composite_score=2.9, composite_components={
        'Smethod': 3, 'Spayload': 3, 'Sexploit': 3, 'Schain': 0, 'Soutput': 4,
    })
    write_doc(tmp_path, 'null.json', null_artifact)
    write_doc(tmp_path, 'scored.json', scored)
    ledger = build_ledger(tmp_path)
    assert ledger['fidelity']['F4']['value'] == 1.0
    assert ledger['fidelity']['F4']['denominator'] == 1
    assert ledger['fidelity']['F5']['value'] == 1.0
    assert ledger['fidelity']['F5']['denominator'] == 1

    null_artifact['metric_unavailable_reason'] = {}
    write_doc(tmp_path, 'null.json', null_artifact)
    failed = build_ledger(tmp_path)
    assert failed['fidelity']['F4']['value'] == 0.0
    assert failed['fidelity']['F4']['failures'][0][
        'metric_unavailable_reason_composite_score'] is False


def test_arithmetic_mismatch_is_reported_not_corrected(tmp_path):
    scored = artifact('scored', composite_score=2.7, composite_components={
        'Smethod': 3, 'Spayload': 3, 'Sexploit': 3, 'Schain': 0, 'Soutput': 4,
    })
    write_doc(tmp_path, 'scored.json', scored)
    ledger = build_ledger(tmp_path)
    metric = ledger['fidelity']['F5']
    assert metric['value'] == 0.0
    assert metric['failures'][0]['recomputed'] == 2.9
    assert metric['failures'][0]['stored'] == 2.7


def test_label_consistency_flags_epoch_and_measured_negative_labels(tmp_path):
    document = artifact('labels')
    document['score_epoch']['thesis_final'] = 'scoring.v3'
    document['measured_negative'] = {'complete': True, 'reason': 'every_precondition_false'}
    document['security_outcome_reason'] = {'code': 'NO_CANDIDATE_CONFIRMATION'}
    document['report'] = {'surface_scores': {'access_control': {
        'attempts': 0, 'label': 'Not Found', 'score': 0,
    }}}
    document['probe_controls'] = {'recon:method_probe:ac_idor': {'candidates': [
        {'method': 'ac_idor', 'candidate_id': 'control:ac_idor'},
    ]}}
    control_event = {'status': 'sent', 'physical_requests': 1, 'method': 'ac_idor',
                     'visit_id': 'ac_idor:visit:1', 'control_id': 'control:ac_idor:high:method_probe:0',
                     'at': '2026-10-30T12:00:00+00:00', 'phase': 'method_probe'}
    document['control_events'] = [control_event]
    document['final_state']['control_events'] = [dict(control_event)]
    write_doc(tmp_path, 'labels.json', document)
    ledger = build_ledger(tmp_path)
    metric = ledger['fidelity']['F6']
    assert metric['numerator'] == 1
    assert metric['n_codes'] == 2
    assert set(metric['codes']) == {
        'epoch_rubric_mismatch',
        'measured_negative_described_as_missing_proof',
    }
    assert ledger['convergence']['converged'] is False


def test_planned_probe_catalog_without_sent_events_does_not_flag(tmp_path):
    document = artifact('planned')
    document['report'] = {'surface_scores': {'access_control': {
        'attempts': 0, 'label': 'Not Found', 'score': 0,
    }}}
    document['probe_controls'] = {'recon:method_probe:ac_idor': {'candidates': [
        {'method': 'ac_idor', 'control_id': 'control:ac_idor:planned',
         'status': None, 'physical_requests_used': 0},
    ]}}
    document['measured_negative'] = {
        'complete': False, 'control_events_sent': 0, 'surface': 'access_control',
    }
    write_doc(tmp_path, 'planned.json', document)
    metric = build_ledger(tmp_path)['fidelity']['F6']
    assert metric['numerator'] == 0
    assert metric['codes'] == {}


def test_sent_control_is_not_an_exploit_attempt_conflict(tmp_path):
    # Owner direction 2026-10-31: a sent detection control is not an exploit
    # attempt; attempts=0 with controls is consistent, not a label conflict.
    document = artifact('sent')
    document['report'] = {'surface_scores': {'access_control': {
        'attempts': 0, 'label': 'No exploit attempts', 'score': 0,
    }}}
    control_event = {'status': 'sent', 'physical_requests': 1, 'method': 'ac_idor',
                     'visit_id': 'ac_idor:visit:1', 'control_id': 'control:ac_idor:high:method_probe:0',
                     'at': '2026-10-30T12:00:00+00:00', 'phase': 'method_probe'}
    document['control_events'] = [control_event]
    document['final_state']['control_events'] = [dict(control_event)]
    write_doc(tmp_path, 'sent.json', document)
    metric = build_ledger(tmp_path)['fidelity']['F6']
    assert metric['numerator'] == 0
    assert metric['codes'] == {}
    assert metric['disagreements'] == []


def test_measured_negative_wrong_reason_still_flags_independently(tmp_path):
    document = artifact('mn')
    document['measured_negative'] = {
        'complete': True, 'reason': 'every_required_precondition_measured_false',
        'surface': 'access_control', 'control_events_sent': 5,
    }
    document['security_outcome_reason'] = {'code': 'NO_CANDIDATE_CONFIRMATION'}
    document['report'] = {'surface_scores': {'access_control': {
        'attempts': 0, 'label': 'No exploit attempts', 'score': 0,
    }}}
    document['control_events'] = [{'status': 'sent', 'physical_requests': 1,
                                   'method': 'ac_idor', 'visit_id': 'ac_idor:visit:1',
                                   'control_id': 'control:ac_idor:high:method_probe:0',
                                   'at': '2026-10-30T12:00:00+00:00', 'phase': 'method_probe'}]
    write_doc(tmp_path, 'mn.json', document)
    metric = build_ledger(tmp_path)['fidelity']['F6']
    assert metric['numerator'] == 1
    assert metric['codes'] == {'measured_negative_described_as_missing_proof': 1}


def test_repeat_stability_is_per_cell_and_never_pools_conditions(tmp_path):
    for index, output_grade in enumerate((4, 4, 3)):
        document = artifact(
            f'linear-{index}', composite_score=2.9,
            composite_components={'Smethod': 3, 'Spayload': 2, 'Sexploit': 3,
                                  'Schain': 0, 'Soutput': output_grade},
        )
        document['config']['repeat_index'] = index
        write_doc(tmp_path, f'linear-{index}.json', document)
    for index in range(3):
        document = artifact(
            f'akg-{index}', composite_score=2.9,
            composite_components={'Smethod': 3, 'Spayload': 2, 'Sexploit': 3,
                                  'Schain': 0, 'Soutput': 4},
        )
        document['config'].update(experiment_condition='akg_guided_hybrid', repeat_index=index)
        write_doc(tmp_path, f'akg-{index}.json', document)
    excluded = artifact(
        'ac-high', composite_score=2.9,
        composite_components={'Smethod': 3, 'Spayload': 2, 'Sexploit': 3,
                              'Schain': 0, 'Soutput': 4},
    )
    excluded['config'].update(surface='access_control', security_level='high')
    write_doc(tmp_path, 'ac-high.json', excluded)

    metric = build_ledger(tmp_path)['fidelity']['F7']
    assert metric['n_cells'] == 2
    assert metric['value'] == 0.5
    cells = {(cell['experiment_condition'], cell['n_distinct_vectors']) for cell in metric['cells']}
    assert cells == {('linear_hybrid', 2), ('akg_guided_hybrid', 1)}
    assert metric['no_condition_pooling'].startswith('cell key includes')


def test_f7_partitions_mixed_modes_and_epochs(tmp_path):
    for index, mode in enumerate(('human', 'ai')):
        document = artifact(
            f'mode-{index}', composite_score=2.7,
            composite_components={'Smethod': 3, 'Spayload': 2, 'Sexploit': 3,
                                  'Schain': 0, 'Soutput': 4},
        )
        document['config']['scoring_mode'] = mode
        document['source_hashes_sha256'] = f'epoch-{mode}'
        write_doc(tmp_path, f'mode-{index}.json', document)
    metric = build_ledger(tmp_path)['fidelity']['F7']
    assert metric['n_cells'] == 2
    assert metric['n_comparable_cells'] == 0
    assert metric['value'] is None
    assert metric['unavailable_reason'] == 'no_cells_with_two_runtime_vectors'
    assert {(cell['scoring_mode'], cell['source_hashes_sha256'])
            for cell in metric['cells']} == {('human', 'epoch-human'), ('ai', 'epoch-ai')}
    assert metric['by_condition']['linear_hybrid'] == {
        'n_cells': 2, 'n_comparable_cells': 0, 'stable_cells': 0,
    }


def test_f7_duplicate_repeat_identity_is_not_stability(tmp_path):
    for index, (score, output_grade) in enumerate(((2.7, 4), (2.5, 3))):
        document = artifact(
            f'duplicate-{index}', composite_score=score,
            composite_components={'Smethod': 3, 'Spayload': 2, 'Sexploit': 3,
                                  'Schain': 0, 'Soutput': output_grade},
        )
        document['config']['repeat_index'] = 0
        write_doc(tmp_path, f'duplicate-{index}.json', document)
    metric = build_ledger(tmp_path)['fidelity']['F7']
    assert metric['n_cells'] == 1
    cell = metric['cells'][0]
    assert cell['repeat_identity_status'] == 'duplicate_repeat_index'
    assert cell['n_distinct_vectors'] == 2
    assert cell['repeat_stability_available'] is False
    assert metric['value'] is None
    assert metric['unavailable_reason'] == 'no_cells_with_two_runtime_vectors'


def test_all_selection_receipt_metadata_exposes_nonfinal_g16_exceptions(tmp_path):
    document = artifact('meta')
    document['final_state'].update({
        'selected_method': 'sqli_union',
        'scoring_decisions': [
            {'dimension': 'Smethod', 'method': 'sqli_union', 'surface': 'sqli',
             'observations': {'union_select_possible': True},
             'preconditions': ['union_select_possible'],
             'required_preconditions': ['union_select_possible'],
             'visit_id': 'sqli_union:visit:1'},
            {'dimension': 'Smethod', 'method': 'bf_dictionary', 'surface': 'brute_force',
             'observations': {'no_rate_limit': True},
             'preconditions': ['credentials_extracted'],
             'selection_source': 'akg_route',
             'visit_id': 'bf_dictionary:visit:2'},
        ],
    })
    write_doc(tmp_path, 'meta.json', document)
    ledger = build_ledger(tmp_path)
    metadata = ledger['selection_receipt_metadata']
    assert metadata['n_rows'] == 2
    assert metadata['n_mismatches'] == 1
    assert metadata['n_nonfinal_mismatches'] == 1
    assert metadata['n_final_selected_mismatches'] == 0
    row = metadata['mismatches'][0]
    assert row['method'] == 'bf_dictionary'
    assert row['visit_id'] == 'bf_dictionary:visit:2'
    assert row['origin'] == 'akg_route'
    assert row['pointer'] == '#/final_state/scoring_decisions/1'
    assert row['final_selected'] is False
    assert row['mismatch']['extra_in_recorded'] == ['credentials_extracted']
    assert row['mismatch']['missing_from_recorded'] == ['no_rate_limit']
    fd1 = ledger['fidelity']['FD1']
    assert fd1['denominator'] == 1
    assert fd1['value'] == 1.0
    assert fd1['selection_receipt_metadata']['n_nonfinal_mismatches'] == 1


def test_offline_fidelity_readiness_never_claims_full_convergence(tmp_path):
    write_doc(tmp_path, 'e.json', artifact('e'))
    convergence = build_ledger(tmp_path)['convergence']
    assert convergence['converged'] is False
    assert convergence['scope'] == 'offline_fidelity_only'
    assert convergence['fresh_epoch_acceptance'] == 'not_assessed'
    assert convergence['phase_b'] == 'not_assessed'
    assert convergence['frozen_invariants'] == 'not_assessed'
    assert 'fresh_epoch_acceptance_not_assessed' in convergence['blocking_reasons']
    assert 'phase_b_not_assessed' in convergence['blocking_reasons']
    assert 'frozen_invariants_not_assessed' in convergence['blocking_reasons']


def test_empty_population_cannot_close_phase_a_or_offline_readiness(tmp_path):
    empty = tmp_path / 'empty'
    empty.mkdir()
    ledger = build_ledger(empty)
    assert ledger['populations']['accepted_runs'] == 0
    assert ledger['phase_a']['complete'] is False
    assert 'no_graded_artifacts' in ledger['phase_a']['blocking_reasons']
    convergence = ledger['convergence']
    assert convergence['offline_fidelity_ready'] is False
    assert 'no_accepted_runs' in convergence['offline_blocking_reasons']
    assert 'fresh_epoch_acceptance_not_assessed' in convergence['blocking_reasons']


def test_unexpected_scoring_defect_is_not_silently_ungradeable(tmp_path, monkeypatch):
    write_doc(tmp_path, 'e.json', artifact('e'))

    def boom(path):
        raise RuntimeError('internal scoring defect')

    monkeypatch.setattr('evaluation.fidelity_ledger.review_queue', boom)
    with pytest.raises(RuntimeError, match='internal scoring defect'):
        build_ledger(tmp_path)


def test_superseded_and_duplicate_identity_are_excluded(tmp_path):
    write_doc(tmp_path, 'accepted.json', artifact('accepted'))
    write_doc(tmp_path, '_superseded_epoch/superseded.json', artifact('superseded'))
    write_doc(tmp_path, 'duplicate-a.json', artifact('duplicate', run_id='run-a'))
    write_doc(tmp_path, 'duplicate-b.json', artifact('duplicate', run_id='run-b'))
    write_doc(tmp_path, 'accepted.rich.json', artifact('sidecar'))
    ledger = build_ledger(tmp_path)
    assert ledger['populations']['accepted_runs'] == 1
    assert [run['run_ref'] for run in ledger['runs']] == ['accepted']
    assert 'superseded' not in {run['execution_id'] for run in ledger['runs']}
    assert 'sidecar' not in {run['execution_id'] for run in ledger['runs']}
    reasons = [item['reason'] for item in ledger['inputs']['excluded']]
    assert reasons.count('duplicate_execution_identity') == 2
    assert any(item['code'] == 'duplicate_execution_identity'
               for item in ledger['inputs']['diagnostics'])
    assert ledger['phase_a']['population_integrity_ok'] is False
    assert any(reason.startswith('dropped_duplicate_execution_identities=')
               for reason in ledger['phase_a']['blocking_reasons'])
    convergence = ledger['convergence']
    assert convergence['offline_fidelity_ready'] is False
    assert convergence['population_integrity_ok'] is False
    assert any(reason.startswith('dropped_duplicate_execution_identities=')
               for reason in convergence['offline_blocking_reasons'])


def test_writer_preserves_inputs_and_refuses_to_overwrite(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    path = write_doc(source, 'e.json', artifact('e'))
    original = sha256(path.read_bytes()).hexdigest()
    output = tmp_path / 'fidelity-ledger.json'
    ledger = build_ledger(source, output=output)
    assert output.is_file()
    assert sha256(path.read_bytes()).hexdigest() == original
    disk = json.loads(output.read_text())
    assert disk['ledger_version'] == ledger['ledger_version']
    with pytest.raises(ValueError, match='overwrite an input'):
        build_ledger(source, output=path)
    with pytest.raises(ValueError, match='overwrite an input'):
        write_ledger(ledger, path)


def test_prior_ledger_can_be_replaced_but_artifacts_cannot(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    write_doc(source, 'e.json', artifact('e'))
    output = source / 'fidelity-ledger.json'
    build_ledger(source, output=output)
    second = build_ledger(source, output=output)
    assert second['ledger_version'] == 'fidelity-ledger.v1'
    notes = source / 'notes.json'
    notes.write_text('{"not": "a ledger"}')
    with pytest.raises(ValueError, match='overwrite an input'):
        build_ledger(source, output=notes)


def test_fd1_uses_static_akg_preconditions_and_reports_g16(tmp_path):
    method = 'sqli_union'
    precondition = AttackKnowledgeGraph.METHOD_PRECONDITIONS[method][0]

    def with_decision(execution_id, observation):
        document = artifact(execution_id)
        document['final_state'].update({
            'selected_method': method,
            'scoring_decisions': [{
                'dimension': 'Smethod', 'method': method, 'surface': 'sqli',
                'observations': {precondition: observation},
                'preconditions': ['credentials_extracted'],
            }],
        })
        return document

    write_doc(tmp_path, 'good.json', with_decision('good', True))
    write_doc(tmp_path, 'false.json', with_decision('false', False))
    write_doc(tmp_path, 'unknown.json', with_decision('unknown', 'unknown'))
    missing = artifact('missing')
    missing['final_state']['selected_method'] = method
    write_doc(tmp_path, 'missing.json', missing)

    ledger = build_ledger(tmp_path)
    metric = ledger['fidelity']['FD1']
    assert metric['value'] == pytest.approx(1 / 3)
    assert metric['denominator'] == 3
    assert metric['diagnostic'] is True
    assert metric['excluded_from'] == ['Smethod', 'Srun']
    assert metric['a2_freeze_provenance_caveat'].startswith('A2:')
    assert metric['missing_snapshots'][0]['reason'] == 'missing_selected_method_snapshot'
    assert len(metric['inconsistent_runs']) == 2
    assert len(metric['g16_mismatches']) == 3
    assert metric['g16_mismatches'][0]['extra_in_recorded'] == ['credentials_extracted']
    good = next(run for run in ledger['runs'] if run['run_ref'] == 'good')
    assert good['selection_precondition']['consistent'] is True


def test_f1_and_f2_candidate_accounting(tmp_path):
    receipts = artifact('receipts', candidate_budget_receipts=[
        {'generated': ['static-1', 'sqli_llm_0'], 'executed': ['sqli_llm_0']},
        {'generated': ['static-2', 'sqli_llm_1'], 'executed': ['static-2']},
    ])
    write_doc(tmp_path, 'receipts.json', receipts)
    candidate = artifact('candidate', composite_score=3.2, composite_components={
        'Smethod': 3, 'Spayload': 3, 'Sexploit': 3, 'Schain': 3, 'Soutput': 4,
    })
    candidate['final_state'].update(candidate_state('sqli_llm_9', source='llm_generated'))
    write_doc(tmp_path, 'candidate.json', candidate)
    static = artifact('static', composite_score=2.4, composite_components={
        'Smethod': 3, 'Spayload': 2, 'Sexploit': 2, 'Schain': 2, 'Soutput': 3,
    })
    write_doc(tmp_path, 'static.json', static)
    ledger = build_ledger(tmp_path)
    assert ledger['fidelity']['F1']['value'] == 0.5
    assert ledger['fidelity']['F1']['numerator'] == 1
    assert ledger['fidelity']['F1']['denominator'] == 2
    assert ledger['fidelity']['F2']['value'] == 0.5
    assert ledger['fidelity']['F2']['numerator'] == 1
    assert ledger['fidelity']['F2']['denominator'] == 2


def test_ungraded_artifact_is_reported_and_blocks_phase_a(tmp_path):
    document = artifact('legacy')
    document['config']['scoring_rubric_version'] = 'scoring.v3'
    write_doc(tmp_path, 'legacy.json', document)
    ledger = build_ledger(tmp_path)
    run = ledger['runs'][0]
    assert run['graded']['available'] is False
    assert 'requires scoring.v4' in run['graded']['reason']
    assert run['dimensions']['Smethod']['state'] == 'ungraded'
    assert ledger['fidelity']['F8']['value'] == 0.0
    assert ledger['phase_a']['complete'] is False
    assert any('ungraded_artifacts' in reason for reason in ledger['phase_a']['blocking_reasons'])


def test_f8_null_reasons_stay_visible(tmp_path):
    write_doc(tmp_path, 'e.json', artifact('e'))
    metric = build_ledger(tmp_path)['fidelity']['F8']
    assert metric['value'] == 1.0
    assert metric['null_reason_discipline']['denominator'] == 5
    assert metric['null_reason_discipline']['value'] == 1.0


def test_p1_lexicographic_ranking_and_falsification_state():
    rows = [
        {'id': 'label', 'component': 'Soutput', 'benchmax_risk': 'none',
         'evidence_strength': 'artifact-only', 'runs_affected': 4,
         'prediction': 'Soutput labels only', 'control': 're-read saved receipts'},
        {'id': 'ordering', 'component': 'Sexploit', 'benchmax_risk': 'needs §4.2',
         'evidence_strength': 'artifact-only', 'runs_affected': 92,
         'prediction': 'candidate order changes execution', 'control': 'replay saved queue'},
        {'id': 'live', 'component': 'F1', 'benchmax_risk': 'none',
         'evidence_strength': 'needs-live', 'runs_affected': 60,
         'prediction': 'fresh epoch lifts execution', 'control': 'single coordinate'},
        {'id': 'dead', 'component': 'Schain', 'benchmax_risk': 'none',
         'evidence_strength': 'artifact-only', 'runs_affected': 10,
         'prediction': 'chain reach improves', 'control': 'route census',
         'falsification_attempts': 2, 'falsification_state': 'falsified'},
    ]
    ranked = rank_hypotheses(rows)
    assert [row['id'] for row in ranked['ordered']] == ['label', 'live', 'ordering']
    assert [row['id'] for row in ranked['falsified']] == ['dead']
    with pytest.raises(ValueError, match='two failures'):
        rank_hypotheses([{**rows[0], 'id': 'open-failure', 'falsification_attempts': 2}])
    with pytest.raises(ValueError, match='pre-change prediction'):
        rank_hypotheses([{**rows[0], 'id': 'no-prediction', 'prediction': ''}])
    with pytest.raises(ValueError, match='named discriminating control'):
        rank_hypotheses([{**rows[0], 'id': 'no-control', 'control': ''}])
