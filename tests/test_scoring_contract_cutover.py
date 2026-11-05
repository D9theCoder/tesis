"""Offline identity/integrity controls, never target proof or new thesis scores."""
from copy import deepcopy
from hashlib import sha256
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.historical_contracts import HISTORICAL_LABELS, HISTORICAL_SCORING_SOURCE_FILES
from evaluation.observer_reviews import _source_bound_queue
from evaluation.research_metrics import SCORING_RULE_DIGEST_DEFINITION, compute_run_metrics
from evaluation.thesis_scoring import evaluate_queue, finalize_reviews, review_queue
from tests.test_execution_security_status import evidence_artifact


def historical_identity(tmp_path):
    """Synthetic original-policy controls; fake hashes are not research evidence."""
    artifact = evidence_artifact()
    artifact['validation_scope'] = 'offline_synthetic_fixture'
    rubric = next(iter(HISTORICAL_LABELS['thesis_rubric']))
    fields = {'rubric_version': rubric,
              'policy_version': next(iter(HISTORICAL_LABELS['scoring_policy'])),
              'metrics_epoch': next(iter(HISTORICAL_LABELS['research_metrics'])),
              'rate_definition_version': next(iter(HISTORICAL_LABELS['event_rates']))}
    hashes = {name: sha256(f'offline-control:{name}'.encode()).hexdigest()
              for name in HISTORICAL_SCORING_SOURCE_FILES}
    digest = sha256(''.join(hashes[name] for name in HISTORICAL_SCORING_SOURCE_FILES).encode()).hexdigest()
    identity_digest = sha256(json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    policy = {**fields, 'digest_definition': SCORING_RULE_DIGEST_DEFINITION,
              'source_files': list(HISTORICAL_SCORING_SOURCE_FILES),
              'source_hashes': hashes, 'scoring_rule_sha256': digest}
    artifact['config']['scoring_rubric_version'] = rubric
    artifact['scoring_policy'] = deepcopy(policy)
    artifact['source_identity'] = {'source_hashes': dict(hashes), 'source_hashes_sha256': identity_digest}
    artifact['source_hashes_sha256'] = identity_digest
    artifact['score_epoch'] = {'thesis_final': rubric, 'metrics_epoch': fields['metrics_epoch'],
                              'scoring_policy_version': fields['policy_version'], 'scoring_rule_sha256': digest}
    path = tmp_path / 'original-source.json'
    path.write_text(json.dumps(artifact))
    queue = review_queue(path)
    document = {'rubric_version': rubric, 'scoring_policy': deepcopy(policy),
                'metrics_epoch': fields['policy_version'], 'scoring_rule_sha256': digest}
    return path, artifact, queue, document


def test_historical_view_keeps_original_identity_but_cannot_write_or_call_evaluator(tmp_path):
    path, artifact, queue, document = historical_identity(tmp_path)
    original = path.read_bytes()
    anchored = _source_bound_queue(SimpleNamespace(record=artifact), document, queue)
    assert anchored['rubric_version'] == artifact['config']['scoring_rubric_version']
    assert anchored['scoring_rule_sha256'] == artifact['score_epoch']['scoring_rule_sha256']
    assert anchored['scoring_policy']['source_hashes'] == artifact['scoring_policy']['source_hashes']
    invoke = Mock(side_effect=AssertionError('no model may run'))
    with pytest.raises(ValueError, match='read-only'):
        evaluate_queue(queue, {}, invoke=invoke)
    out = tmp_path / 'must-not-write'
    with pytest.raises(ValueError, match='read-only'):
        finalize_reviews(path, [], output_dir=out, isolated_output=True)
    # Previously saved queues do not have the new flag. Their original rubric
    # still cannot enter a live evaluator merely by omitting that flag.
    serialized_original = dict(queue)
    serialized_original.pop('historical_read_only')
    with pytest.raises(ValueError, match='read-only'):
        evaluate_queue(serialized_original, {}, invoke=invoke)
    invoke.assert_not_called()
    assert not out.exists()
    assert path.read_bytes() == original


@pytest.mark.parametrize('tamper,expected', [
    ('source_files', 'scoring_rule_epoch_source_files_mismatch'),
    ('missing_source_hash', 'scoring_rule_epoch_source_hashes_missing'),
    ('forged_source_hash', 'source_identity_hash_mismatch'),
    ('identity_digest', 'source_identity_digest_mismatch'),
    ('epoch_digest', 'scoring_epoch_digest_mismatch'),
    ('policy_label', 'historical_policy_identity_mismatch'),
    ('unknown_policy_type', 'historical_policy_identity_mismatch'),
    ('original_policy', 'historical_policy_source_mismatch'),
    ('metrics_epoch', 'historical_policy_epoch_mismatch'),
    ('current_digest_shortcut', 'scoring_rule_epoch_anchor_digest_mismatch'),
])
def test_historical_names_never_replace_source_policy_and_epoch_proof(tmp_path, tamper, expected):
    _path, artifact, queue, document = historical_identity(tmp_path)
    policy = document['scoring_policy']
    if tamper == 'source_files':
        policy['source_files'] = list(reversed(policy['source_files']))
    elif tamper == 'missing_source_hash':
        policy['source_hashes'].pop(HISTORICAL_SCORING_SOURCE_FILES[0])
    elif tamper == 'forged_source_hash':
        policy['source_hashes'][HISTORICAL_SCORING_SOURCE_FILES[0]] = 'd' * 64
        digest = sha256(''.join(policy['source_hashes'][name] for name in HISTORICAL_SCORING_SOURCE_FILES).encode()).hexdigest()
        document['scoring_rule_sha256'] = policy['scoring_rule_sha256'] = digest
    elif tamper == 'identity_digest':
        artifact['source_identity']['source_hashes_sha256'] = 'd' * 64
    elif tamper == 'epoch_digest':
        artifact['score_epoch']['scoring_rule_sha256'] = 'd' * 64
    elif tamper == 'policy_label':
        policy['policy_version'] = 'unknown-policy'
    elif tamper == 'unknown_policy_type':
        policy['policy_version'] = {'not': 'a label'}
    elif tamper == 'original_policy':
        artifact['scoring_policy']['source_hashes'][HISTORICAL_SCORING_SOURCE_FILES[0]] = 'd' * 64
    elif tamper == 'metrics_epoch':
        document['metrics_epoch'] = 'unrecognized-metric-policy'
    elif tamper == 'current_digest_shortcut':
        document['scoring_rule_sha256'] = queue['scoring_rule_sha256']
    with pytest.raises(ValueError, match=f'^{expected}$'):
        _source_bound_queue(SimpleNamespace(record=artifact), document, queue)


@pytest.mark.parametrize('role', ['thesis_rubric', 'obsolete_thesis_rubric', 'runtime_rubric', 'unknown'])
def test_live_launches_refuse_historical_or_unknown_contracts_before_dispatch(tmp_path, monkeypatch, role):
    from evaluation import runner, multi_llm_runner
    from evaluation.scoring_evidence import validate_evidence_config
    value = next(iter(HISTORICAL_LABELS[role])) if role != 'unknown' else 'unsupported-rubric'
    graph = Mock(side_effect=AssertionError('no graph may run'))
    child = Mock(side_effect=AssertionError('no matrix child may run'))
    monkeypatch.setattr(runner, 'build_framework', graph)
    monkeypatch.setattr(multi_llm_runner, 'run_single_engagement', child)
    out = tmp_path / 'must-not-launch'
    with pytest.raises(ValueError, match='canonical thesis-scoring'):
        validate_evidence_config(value, {}, [])
    with pytest.raises(ValueError, match='canonical thesis-scoring'):
        runner.run_single_engagement(target_url='http://localhost/dvwa',
            security_level='low', llm_provider='openai_compatible',
            scoring_rubric_version=value, output_dir=str(out))
    with pytest.raises(ValueError, match='canonical thesis-scoring'):
        multi_llm_runner.run_provider_matrix(target_url='http://localhost/dvwa',
            scoring_rubric_version=value, output_dir=str(out))
    graph.assert_not_called()
    child.assert_not_called()
    assert not out.exists()


def test_obsolete_metrics_are_only_read_not_reconstructed_from_runtime_scores():
    obsolete = next(iter(HISTORICAL_LABELS['obsolete_thesis_rubric']))
    artifact = {'config': {'scoring_rubric_version': obsolete}, 'final_state': {},
                'composite_components': {'Sexploit': 4, 'Schain': 4}}
    absent = compute_run_metrics(artifact, components={'Sexploit': 4, 'Schain': 4})
    assert all(value is None for value in absent['values'].values())
    assert all(value is False for value in absent['availability'].values())
    stored = {'rubric_version': obsolete, 'values': {'full_exploit_rate': 1},
              'availability': {'full_exploit_rate': True}, 'denominators': {'executed_candidates': 2}}
    artifact['metrics'] = deepcopy(stored)
    before = json.dumps(artifact, sort_keys=True)
    assert compute_run_metrics(artifact) == stored
    assert json.dumps(artifact, sort_keys=True) == before


def test_shared_formula_source_changes_invalidate_the_rule_digest(tmp_path, monkeypatch):
    from evaluation import research_metrics
    root = tmp_path / 'checkout'
    for name in research_metrics.SCORING_SOURCE_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('offline source bytes')
    monkeypatch.setattr(research_metrics, '__file__', str(root / 'evaluation/research_metrics.py'))
    before = research_metrics.scoring_rule_hash()
    (root / 'core/scoring_contracts.py').write_text('changed offline formula bytes')
    assert research_metrics.scoring_rule_hash() != before
