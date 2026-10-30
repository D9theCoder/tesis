"""Offline scoring-integrity controls; no graph, target or provider execution."""
from hashlib import sha256
import json
from typing import Any

import pytest

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


def export(tmp_path, document):
    path = tmp_path / 'execution.json'
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
