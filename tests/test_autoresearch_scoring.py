"""Offline scoring-integrity controls; no graph, target or provider execution."""
from hashlib import sha256
import json
from typing import Any

import pytest

from evaluation.scoring_evidence import (
    automatic_components, candidate_base, chain_grade, prerequisite_proof,
)
from evaluation.thesis_scoring import review_queue, finalize_reviews


def artifact() -> dict[str, Any]:
    return {
        'run_id': 'offline-run', 'execution_id': 'offline-execution',
        'validation_scope': 'offline_synthetic_fixture',
        'config': {'scoring_mode': 'human', 'scoring_rubric_version': 'scoring.v4',
                   'scoring_profile': {}, 'scoring_oracles': []},
        'score_epoch': {'thesis_final': 'scoring.v4',
                        'scoring_rule_sha256': 'recorded-source-policy'},
        'final_state': {},
    }


def export(tmp_path, document, name='execution.json'):
    path = tmp_path / name
    path.write_text(json.dumps(document))
    return path


@pytest.mark.parametrize('version', ['scoring.v2', 'scoring.v3', 'scoring.v5', None])
def test_artifact_cannot_choose_a_legacy_or_unknown_rubric(tmp_path, version):
    document = artifact()
    document['config']['scoring_rubric_version'] = version
    with pytest.raises(ValueError, match='requires scoring.v4'):
        review_queue(export(tmp_path, document))


@pytest.mark.parametrize('version', ['scoring.v3', 'scoring.v5', None])
def test_score_epoch_must_agree_with_pinned_rubric(tmp_path, version):
    document = artifact()
    document['score_epoch']['thesis_final'] = version
    with pytest.raises(ValueError, match='score_epoch.thesis_final'):
        review_queue(export(tmp_path, document))


def test_deleting_config_version_never_recovers_legacy_selection_credit(tmp_path):
    document = artifact()
    document['final_state']['selected_method'] = 'sqli_union'
    document['final_state']['scoring_decisions'] = [
        {'dimension': 'Smethod', 'method': 'sqli_union', 'surface': 'sqli', 'viable': True}
    ]
    path = export(tmp_path, document)
    original = review_queue(path)
    del document['config']['scoring_rubric_version']
    changed = review_queue(export(tmp_path, document))
    assert original['rubric_version'] == changed['rubric_version'] == 'scoring.v4'
    assert original['components']['Smethod'] is changed['components']['Smethod'] is None
    assert original['component_pending_reasons']['Smethod'] == changed['component_pending_reasons']['Smethod']


def test_review_hash_is_canonical_without_relabeling_source_epoch(tmp_path):
    from evaluation.research_metrics import scoring_rule_hash
    path = export(tmp_path, artifact())
    original = sha256(path.read_bytes()).hexdigest()
    queue = review_queue(path)
    assert queue['scoring_rule_sha256'] == queue['scoring_policy']['scoring_rule_sha256'] == scoring_rule_hash()
    assert queue['source_scoring_rule_sha256'] == 'recorded-source-policy'
    assert sha256(path.read_bytes()).hexdigest() == original


def candidate_artifact() -> dict[str, Any]:
    document = artifact()
    state = document['final_state']
    state.update(
        selected_method='sqli_union',
        payload_candidates={'sqli_union': [
            {'candidate_id': cid, 'stage': 'exploit', 'payload_or_logic': 'fixture'}
            for cid in ('candidate-a', 'candidate-b')]},
        payload_provenance={cid: {'method': 'sqli_union', 'source': 'static_seed'}
                            for cid in ('candidate-a', 'candidate-b')},
        payload_validation_results={'sqli_union': [
            {'candidate_id': cid, 'valid': True} for cid in ('candidate-a', 'candidate-b')]},
        response_evidence=[
            {'candidate_id': cid, 'agent_id': 'sqli_union', 'stage': 'exploit',
             'visit_id': 'visit-1', 'evidence_id': cid, 'status_code': 200,
             'response_sha256': sha256(cid.encode()).hexdigest(),
             'verification_reason': 'partial_union_data', 'signal_detected': True}
            for cid in ('candidate-a', 'candidate-b')],
        verifier_history=[{'agent_id': 'sqli_union', 'visit_id': 'visit-1',
                           'source': 'method_agent_evidence', 'decision': 'unverified',
                           'evidence_refs': [f'#/final_state/response_evidence/{i}' for i in range(2)]}],
    )
    return document


def test_reviewed_payload_mean_survives_missing_selection_profile(tmp_path):
    path = export(tmp_path, candidate_artifact())
    queue = review_queue(path)
    decisions = [
        {'decision_id': f'decision-{index}', 'candidate_id': row['candidate_id'],
         'scoring_mode': 'human', 'score': index + 1, 'reason': 'Synthetic partial evidence',
         'source_sha256': queue['source_sha256'], 'run_id': queue['run_id'],
         'rubric_version': queue['rubric_version'], 'reviewer_id': 'fixture-reviewer',
         'review_version': 'fixture.v1', 'timestamp': '2026-10-31T00:00:00+00:00',
         'evidence_refs': row['evidence_refs']}
        for index, row in enumerate(queue['candidates'])]
    result = finalize_reviews(path, decisions, output_dir=tmp_path / 'derived', isolated_output=True)
    workflow = result['workflows']['human']
    assert workflow['status'] == 'pending'
    assert workflow['components']['Smethod'] is None
    assert workflow['component_pending_reasons']['Smethod']
    assert workflow['numerator'] == 3
    assert workflow['denominator'] == 2
    assert workflow['components']['Spayload'] == workflow['Spayload_final'] == 1.5
    assert workflow['Srun_final'] is None
    assert result['receipts'] == {}
    from evaluation.observer_reviews import discover_reviews
    from tesis.artifact_catalog import ArtifactCatalog
    catalog = ArtifactCatalog({'source': path}, {'reviews': tmp_path / 'derived'}).scan()
    observed = discover_reviews(catalog, catalog.runs[0])['human']
    assert observed['status'] == 'pending'
    assert observed['components']['Spayload'] == observed['Spayload_final'] == 1.5
    assert observed['Srun_final'] is None


def test_missing_candidate_review_keeps_payload_pending(tmp_path):
    path = export(tmp_path, candidate_artifact())
    result = finalize_reviews(path, [], output_dir=tmp_path / 'derived', isolated_output=True)
    workflow = result['workflows']['human']
    assert workflow['components']['Spayload'] is None
    assert workflow['component_pending_reasons']['Spayload'] == 'pending_candidate_grades'
    assert workflow['denominator'] == 2
    assert workflow['Srun_final'] is None


def _candidate_row(candidate_id, method, visit_id, *, reason, signal, index):
    row = {
        'candidate_id': candidate_id, 'agent_id': method, 'visit_id': visit_id,
        'stage': 'exploit', 'status_code': 200, 'signal_detected': signal,
        'evidence_id': f'{candidate_id}:{index}',
        'response_sha256': sha256(f'{candidate_id}:{index}'.encode()).hexdigest(),
    }
    if reason is not None:
        row['verification_reason'] = reason
    return row


def chain_run_artifact() -> dict[str, Any]:
    """One completed hop whose source is a prior method, with no dependency proof."""
    document = artifact()
    state = document['final_state']
    method, candidate_id = 'sqli_union', 'chain-source'
    visit_id = f'{method}:visit:1'
    ref = '#/final_state/response_evidence/0'
    state.update(
        selected_method='sqli_time_blind',
        payload_candidates={method: [{'candidate_id': candidate_id, 'stage': 'exploit',
                                      'payload_or_logic': 'fixture'}]},
        payload_provenance={candidate_id: {'method': method, 'source': 'static_seed'}},
        payload_validation_results={method: [{'candidate_id': candidate_id, 'valid': True}]},
        response_evidence=[_candidate_row(candidate_id, method, visit_id,
                                          reason='verified_account_extraction', signal=True, index=0)],
        verifier_history=[{'visit_id': visit_id, 'agent_id': method,
                           'source': 'method_agent_evidence', 'decision': 'confirmed',
                           'verifier_id': 'verifier-source',
                           'confirmed_vulns': ['credentials_extracted'],
                           'evidence_refs': [ref]}],
        chain_history=[{'route_id': 'route:0', 'status': 'ready',
                        'source': 'credentials_extracted', 'target': 'bf_dictionary',
                        'target_agent': 'bf_dictionary',
                        'preconditions': ['credentials_extracted'],
                        'prerequisite_evidence_refs': {
                            'credentials_extracted': ['#/final_state/verifier_history/0']},
                        'source_evidence_refs': [ref]}],
        weak_chain_opportunities=[],
        chain_assessment={'assessed': True, 'status': 'assessed',
                          'reason': 'chain_opportunity_evaluated'},
    )
    return document


def chain_source_proof_artifact(source_ref: str) -> dict[str, Any]:
    """A proved route whose source material may be weaker than its prerequisites."""
    document = artifact()
    state = document['final_state']
    method, candidate_id = 'sqli_union', 'chain-source'
    visit_id = f'{method}:visit:1'
    strong_ref = '#/final_state/response_evidence/0'
    strong = _candidate_row(candidate_id, method, visit_id,
                            reason='verified_account_extraction', signal=True, index=0)
    weak = _candidate_row(candidate_id, method, visit_id,
                          reason='partial_union_data', signal=True, index=1)
    state.update(
        selected_method=method,
        payload_candidates={method: [{'candidate_id': candidate_id, 'stage': 'exploit',
                                      'payload_or_logic': 'fixture'}]},
        payload_provenance={candidate_id: {'method': method, 'source': 'static_seed'}},
        payload_validation_results={method: [{'candidate_id': candidate_id, 'valid': True}]},
        response_evidence=[strong, weak],
        verifier_history=[{'visit_id': visit_id, 'agent_id': method,
                           'source': 'method_agent_evidence', 'decision': 'confirmed',
                           'verifier_id': 'verifier-source',
                           'confirmed_vulns': ['credentials_extracted'],
                           'evidence_refs': [strong_ref, '#/final_state/response_evidence/1']}],
        chain_history=[{'route_id': 'route:0', 'status': 'ready',
                        'source': 'credentials_extracted', 'target': 'bf_dictionary',
                        'target_agent': 'bf_dictionary',
                        'preconditions': ['credentials_extracted'],
                        'prerequisite_evidence_refs': {
                            'credentials_extracted': ['#/final_state/verifier_history/0']},
                        'source_evidence_refs': [source_ref]}],
        weak_chain_opportunities=[],
        chain_assessment={'assessed': True, 'status': 'assessed',
                          'reason': 'chain_opportunity_evaluated'},
    )
    return document


def weak_chain_artifact() -> dict[str, Any]:
    """A completed method visit with partial chain material and an open edge."""
    document = artifact()
    state = document['final_state']
    method, candidate_id = 'bf_spray', 'weak-candidate'
    visit_id = f'{method}:visit:1'
    ref = '#/final_state/response_evidence/0'
    state.update(
        selected_method=method,
        payload_candidates={method: [{'candidate_id': candidate_id, 'stage': 'exploit',
                                      'payload_or_logic': 'fixture'}]},
        payload_provenance={candidate_id: {'method': method, 'source': 'static_seed'}},
        payload_validation_results={method: [{'candidate_id': candidate_id, 'valid': True}]},
        response_evidence=[_candidate_row(candidate_id, method, visit_id,
                                          reason='verified_login', signal=True, index=0)],
        verifier_history=[{'visit_id': visit_id, 'agent_id': method,
                           'source': 'method_agent_evidence', 'decision': 'confirmed',
                           'verifier_id': 'verifier-weak', 'evidence_refs': [ref]}],
        chain_history=[],
        weak_chain_opportunities=[{
            'evidence_id': 'weak:response:0:ac_force_browse', 'opportunity_class': 'weak',
            'method': method, 'candidate_id': candidate_id, 'visit_id': visit_id,
            'source': 'authenticated_session', 'target': 'ac_force_browse',
            'target_agent': 'ac_force_browse',
            'missing_material': ['fresh_authenticated_session'],
            'source_evidence_refs': [ref],
            'prerequisite_status': {'authenticated_session': 'unproved'}}],
        chain_assessment={'assessed': True, 'status': 'assessed',
                          'reason': 'chain_opportunity_evaluated'},
    )
    return document


def candidate_artifact_with(specs: list[dict[str, Any]]) -> dict[str, Any]:
    """Valid, executed payload candidates with configurable verification evidence."""
    document = artifact()
    state = document['final_state']
    method = 'sqli_union'
    rows = [_candidate_row(spec['candidate_id'], method, 'visit-1', reason=spec.get('reason'),
                           signal=spec.get('signal'), index=index)
            for index, spec in enumerate(specs)]
    state.update(
        selected_method=method,
        payload_candidates={method: [{'candidate_id': spec['candidate_id'], 'stage': 'exploit',
                                      'payload_or_logic': 'fixture'} for spec in specs]},
        payload_provenance={spec['candidate_id']: {'method': method, 'source': 'static_seed'}
                            for spec in specs},
        payload_validation_results={method: [{'candidate_id': spec['candidate_id'], 'valid': True}
                                             for spec in specs]},
        response_evidence=rows,
        verifier_history=[{'visit_id': 'visit-1', 'agent_id': method,
                           'source': 'method_agent_evidence', 'decision': 'confirmed',
                           'verifier_id': 'verifier-candidate',
                           'evidence_refs': [f'#/final_state/response_evidence/{i}'
                                             for i in range(len(rows))]}],
        chain_history=[], weak_chain_opportunities=[],
        chain_assessment={'assessed': True, 'status': 'assessed',
                          'reason': 'chain_opportunity_evaluated'},
    )
    return document


def test_chain_grade_is_run_scope_for_prior_method_and_selected_method():
    document = chain_run_artifact()
    route = document['final_state']['chain_history'][0]
    assert prerequisite_proof(document, route) is True
    assert chain_grade(document, 'sqli_time_blind', []) == 2
    assert chain_grade(document, 'sqli_union', []) == 2
    assert chain_grade(document, 'bf_dictionary', []) == 2
    source = document['final_state']['response_evidence'][0]
    destination = {'candidate_id': 'chain-destination', 'agent_id': 'bf_dictionary',
                   'visit_id': 'bf_dictionary:visit:1', 'stage': 'exploit',
                   'evidence_id': 'destination-evidence', 'status_code': 200,
                   'response_sha256': 'b' * 64}
    dependency = {'route': {'route_id': 'route:0'}, 'source': source,
                  'destination': destination, 'consumption': {}}
    assert chain_grade(document, 'sqli_time_blind', [dependency]) == 3
    second_destination = {'candidate_id': 'second-hop', 'agent_id': 'ac_idor',
                          'evidence_id': 'second-hop-evidence'}
    second = {'route': {'route_id': 'route:1'}, 'source': destination,
              'destination': second_destination, 'consumption': {}}
    assert chain_grade(document, 'sqli_time_blind', [dependency, second]) == 4


def test_chain_level_two_requires_proven_source_material_not_only_prerequisites():
    strong = chain_source_proof_artifact('#/final_state/response_evidence/0')
    weak = chain_source_proof_artifact('#/final_state/response_evidence/1')
    assert prerequisite_proof(strong, strong['final_state']['chain_history'][0]) is True
    assert prerequisite_proof(weak, weak['final_state']['chain_history'][0]) is True
    assert chain_grade(strong, 'sqli_union', []) == 2
    assert chain_grade(weak, 'sqli_union', []) == 0


def test_chain_level_one_uses_the_weak_row_not_the_candidate_maximum(monkeypatch):
    document = weak_chain_artifact()
    refs = ['#/final_state/response_evidence/0']
    monkeypatch.setattr('evaluation.scoring_evidence.oracle_confirmed', lambda *_: True)
    assert candidate_base(document, 'weak-candidate', 'bf_spray', refs) == 3
    assert chain_grade(document, 'bf_spray', []) == 1


def test_measured_negative_grades_zero_while_missing_evidence_stays_pending(tmp_path):
    negative = candidate_artifact_with([
        {'candidate_id': 'negative-candidate', 'reason': 'no_verified_exploit_signal', 'signal': False}])
    queue = review_queue(export(tmp_path, negative, 'negative.json'))
    assert queue['components']['Sexploit'] == 0
    assert 'Sexploit' not in queue['component_pending_reasons']
    assert queue['candidates'][0]['status'] == 'signal_absent'
    assert queue['candidates'][0]['base_proof'] == 0
    workflow = finalize_reviews(export(tmp_path, negative, 'negative.json'), [],
                                output_dir=tmp_path / 'derived-negative',
                                isolated_output=True)['workflows']['human']
    assert workflow['components']['Spayload'] == 0.0
    assert workflow['numerator'] == 0
    assert workflow['denominator'] == 1
    assert workflow['Srun_final'] is None

    missing = candidate_artifact_with([
        {'candidate_id': 'negative-candidate', 'reason': 'no_verified_exploit_signal', 'signal': False},
        {'candidate_id': 'pending-candidate', 'reason': None, 'signal': None}])
    path = export(tmp_path, missing, 'missing.json')
    queue = review_queue(path)
    assert queue['components']['Sexploit'] is None
    assert queue['component_pending_reasons']['Sexploit'] == 'missing_required_evidence'
    assert {row['candidate_id']: (row['status'], row['base_proof']) for row in queue['candidates']} == {
        'negative-candidate': ('signal_absent', 0), 'pending-candidate': ('not_assessable', None)}
    workflow = finalize_reviews(path, [], output_dir=tmp_path / 'derived-missing',
                                isolated_output=True)['workflows']['human']
    assert workflow['components']['Spayload'] is None
    assert workflow['component_pending_reasons']['Spayload'] == 'pending_candidate_grades'
    assert workflow['denominator'] == 2
    assert workflow['numerator'] is None
    assert workflow['Srun_final'] is None


def test_run_scope_chain_does_not_upgrade_unrelated_method_exploit(monkeypatch):
    document = chain_run_artifact()
    source = document['final_state']['response_evidence'][0]
    destination = {'candidate_id': 'chain-destination', 'agent_id': 'bf_dictionary',
                   'evidence_id': 'destination-evidence'}
    dependency = {'route': {'route_id': 'route:0'}, 'source': source,
                  'destination': destination, 'consumption': {}}
    monkeypatch.setattr('evaluation.scoring_evidence.verified_dependencies',
                        lambda *_: [dependency])
    components, _evidence, _reason = automatic_components(
        document, 'sqli_time_blind', [{'eligible': True, 'base_proof': 3}])
    assert components['Schain'] == 3
    assert components['Sexploit'] == 3
