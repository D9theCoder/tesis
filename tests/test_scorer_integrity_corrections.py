"""Focused controls for the 2026-11-07 scorer integrity corrections.

These are offline software controls.  The restored-epoch cases read preserved
execution artifacts and write only temporary copies; they do not regrade the
retained epoch, create a study result, or call DVWA/providers.
"""
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
RESTORED = ROOT / 'results/runs/restored-primary-2026-11-06'
PLAN_PATH = RESTORED / 'research-plan.json'
RUN_007 = RESTORED / 'selection/run-007'
RUN_009 = RESTORED / 'selection/run-009'
RUN_001 = RESTORED / 'selection/run-001'

requires_restored = pytest.mark.skipif(
    not (PLAN_PATH.is_file() and RUN_007.is_dir() and RUN_009.is_dir() and RUN_001.is_dir()),
    reason='restored primary epoch artifacts are not present in this checkout')

PLAN = json.loads(PLAN_PATH.read_text()) if PLAN_PATH.is_file() else {}


def _execution(run_dir, name):
    source = next(path for path in run_dir.glob('exec-*.json')
                  if not path.name.endswith('.rich.json'))
    artifact = json.loads(source.read_text())
    artifact = deepcopy(artifact)
    artifact['research_plan_identity'] = {
        'plan_sha256': PLAN['plan_sha256'],
        'epoch_id': PLAN['epoch_id'],
    }
    # Keep the copy outside the retained tree.
    path = Path(tempfile.mkdtemp()) / source.name
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True))
    return path, artifact


def _planless_copy(tmp_path, run_dir):
    source = next(path for path in run_dir.glob('exec-*.json')
                  if not path.name.endswith('.rich.json'))
    path = tmp_path / source.name
    path.write_text(source.read_text())
    return path


def _decisions(queue, mode='ai'):
    from evaluation.thesis_scoring import JUDGE_VERSION
    decisions = []
    for row in queue['candidates']:
        if row['status'] != 'pending_review':
            continue
        decisions.append({
            'decision_id': f"{mode}:{row['candidate_id']}",
            'run_id': queue['run_id'], 'source_sha256': queue['source_sha256'],
            'rubric_version': queue['rubric_version'], 'scoring_mode': mode,
            'candidate_id': row['candidate_id'], 'score': row['base_proof'],
            'reason': 'offline contract control', 'evidence_refs': row['evidence_refs'],
            'reviewer_id': (f"{queue['evaluator']['provider']}/{queue['evaluator']['model']}"
                            if mode == 'ai' else 'offline-reviewer'),
            'review_version': JUDGE_VERSION if mode == 'ai' else 'manual-assessment',
            'timestamp': '2026-11-07T00:00:00+00:00',
        })
    return decisions


def _finalize(tmp_path, source, mode='ai'):
    from evaluation.thesis_scoring import finalize_reviews, review_queue
    queue = review_queue(source)
    result = finalize_reviews(
        source, _decisions(queue, mode), output_dir=tmp_path / f'out-{mode}',
        isolated_output=True)
    assert result['receipts'], result['workflows']
    receipt = json.loads(Path(result['receipts'][mode]).read_text())
    return queue, result, receipt


@requires_restored
def test_epoch_projection_uses_population_identity_not_execution_observations():
    from evaluation.thesis_scoring import review_queue
    path_a, _ = _execution(RUN_007, 'repeat-a')
    path_b, _ = _execution(RUN_009, 'repeat-b')
    queue_a, queue_b = review_queue(path_a), review_queue(path_b)
    assert queue_a['prospective_study'] and queue_b['prospective_study']
    assert queue_a['epoch_binding_problems'] == []
    assert queue_b['epoch_binding_problems'] == []
    binding_a, binding_b = queue_a['epoch_binding'], queue_b['epoch_binding']
    assert binding_a['plan'] == {
        'status': 'bound', 'plan_sha256': PLAN['plan_sha256'],
        'epoch_id': PLAN['epoch_id'], 'source': 'research_plan_identity'}
    # Collected sources differ between these repeats, but they are per-execution
    # observations and must not split the frozen population key.
    assert binding_a['oracles']['collected_source_count'] != \
        binding_b['oracles']['collected_source_count']
    assert binding_a['epoch_sha256'] == queue_a['epoch_sha256'] == \
        binding_b['epoch_sha256'] == queue_b['epoch_sha256']
    # The source execution hash remains per receipt and is individually bound.
    assert queue_a['source_sha256'] != queue_b['source_sha256']
    assert binding_a['source_execution_sha256'] == queue_a['source_sha256']
    assert binding_b['source_execution_sha256'] == queue_b['source_sha256']
    assert binding_a['source_execution']['source_sha256'] == queue_a['source_sha256']
    assert binding_a['plan_sha256'] == PLAN['plan_sha256']
    assert binding_a['experiment_epoch_id'] == PLAN['epoch_id']


@requires_restored
def test_runtime_plan_identity_shape_is_accepted_by_scorer_and_plan_runner():
    from evaluation.research_plan import _validate_artifact_plan_identities
    from evaluation.runner import _validated_research_plan_identity
    from evaluation.thesis_scoring import build_epoch_binding
    source, artifact = _execution(RUN_007, 'runtime-shape')
    normalized = _validated_research_plan_identity(artifact['research_plan_identity'])
    assert normalized == {'plan_sha256': PLAN['plan_sha256'],
                          'epoch_id': PLAN['epoch_id']}
    assert _validate_artifact_plan_identities(
        {'plan_sha256': PLAN['plan_sha256'], 'epoch_id': PLAN['epoch_id']},
        [artifact]) == normalized
    binding = build_epoch_binding(
        artifact, source_sha256=sha256(source.read_bytes()).hexdigest())
    assert binding['plan'] == {
        'status': 'bound', 'plan_sha256': PLAN['plan_sha256'],
        'epoch_id': PLAN['epoch_id'], 'source': 'research_plan_identity'}


@requires_restored
def test_real_receipts_share_epoch_and_validate_their_own_execution(tmp_path):
    from evaluation.thesis_scoring import (
        compare_receipts, validate_epoch_binding,
    )
    source_a, _ = _execution(RUN_007, 'repeat-a')
    source_b, _ = _execution(RUN_009, 'repeat-b')
    queue_a, result_a, receipt_a = _finalize(tmp_path / 'a', source_a)
    queue_b, result_b, receipt_b = _finalize(tmp_path / 'b', source_b)
    assert receipt_a['epoch_sha256'] == receipt_b['epoch_sha256']
    assert receipt_a['epoch_binding']['source_execution_sha256'] != \
        receipt_b['epoch_binding']['source_execution_sha256']
    assert validate_epoch_binding(receipt_a, queue_a)['status'] == 'current'
    assert validate_epoch_binding(receipt_b, queue_b)['status'] == 'current'
    with pytest.raises(ValueError, match='source_execution_sha256'):
        validate_epoch_binding(receipt_a, queue_b)
    tampered = deepcopy(receipt_a)
    tampered['epoch_binding']['source_execution']['source_sha256'] = 'e' * 64
    from evaluation.thesis_scoring import seal_epoch_binding
    tampered['epoch_binding'] = seal_epoch_binding(tampered['epoch_binding'])
    tampered['epoch_sha256'] = tampered['epoch_binding']['epoch_sha256']
    with pytest.raises(ValueError, match='source_execution_binding_mismatch'):
        validate_epoch_binding(tampered, queue_a)
    compared = compare_receipts([result_a['receipts']['ai'], result_b['receipts']['ai']])
    assert len(compared['groups']) == 1
    assert compared['groups'][0]['n_final'] == 2
    # The observer reader validates the same receipt through the catalog path.
    from evaluation.observer_reviews import discover_reviews
    from tesis.artifact_catalog import ArtifactCatalog
    review_dir = tmp_path / 'a' / 'out-ai'
    catalog = ArtifactCatalog({'source': source_a}, {'reviews': review_dir})
    catalog.scan()
    entry = next(iter(catalog.runs))
    discovered = discover_reviews(catalog, entry)
    assert discovered['ai']['status'] == 'final'
    assert discovered['ai']['epoch_sha256'] == receipt_a['epoch_sha256']


@requires_restored
def test_prospective_final_receipt_requires_plan_identity(tmp_path):
    from evaluation.thesis_scoring import (
        evaluate_queue, finalize_reviews, review_queue, validate_epoch_binding,
    )
    source = _planless_copy(tmp_path, RUN_007)
    queue = review_queue(source)
    assert queue['prospective_study'] is True
    assert 'plan_unavailable' in queue['epoch_binding_problems']
    with pytest.raises(ValueError, match='prospective_epoch_binding_incomplete'):
        finalize_reviews(source, _decisions(queue), output_dir=tmp_path / 'out',
                         isolated_output=True)
    assert not (tmp_path / 'out').exists()
    called = []
    with pytest.raises(ValueError, match='prospective_epoch_binding_incomplete'):
        evaluate_queue(queue, queue['evaluator'],
                       invoke=lambda messages: called.append(messages))
    assert called == []
    # A pending read-only status remains available; only a final receipt is
    # refused without the frozen plan identity.
    pending = finalize_reviews(source, [], output_dir=tmp_path / 'pending',
                               isolated_output=True)
    assert pending['workflows']['ai']['status'] == 'pending'
    assert pending['receipts'] == {}
    status_path = next((tmp_path / 'pending').glob('*.review-status.json'))
    status = json.loads(status_path.read_text())
    assert validate_epoch_binding(status, queue)['status'] == 'current'
    # The planned copy is the supported prospective path.
    source_planned, _ = _execution(RUN_007, 'planned')
    _queue, _result, receipt = _finalize(tmp_path / 'planned', source_planned)
    assert receipt['epoch_binding']['plan']['status'] == 'bound'


@requires_restored
def test_plan_identity_must_be_well_formed_and_match_the_experiment_epoch(tmp_path):
    from evaluation.thesis_scoring import build_epoch_binding
    source, artifact = _execution(RUN_007, 'plan-shape')
    source_sha256 = sha256(source.read_bytes()).hexdigest()
    wrong_epoch = deepcopy(artifact)
    wrong_epoch['research_plan_identity']['epoch_id'] = 'different-epoch'
    with pytest.raises(ValueError, match='research_plan_epoch_mismatch'):
        build_epoch_binding(wrong_epoch, source_sha256=source_sha256)
    malformed = deepcopy(artifact)
    malformed['research_plan_identity'] = {'plan_sha256': 'a' * 64}
    with pytest.raises(ValueError, match='research_plan_identity_invalid'):
        build_epoch_binding(malformed, source_sha256=source_sha256)
    malformed_hash = deepcopy(artifact)
    malformed_hash['research_plan_identity']['plan_sha256'] = 'not-a-hash'
    with pytest.raises(ValueError, match='research_plan_identity_invalid'):
        build_epoch_binding(malformed_hash, source_sha256=source_sha256)


@requires_restored
def test_cross_epoch_and_cross_level_populations_are_refused(tmp_path):
    from evaluation.thesis_scoring import (
        compare_receipts, review_queue, seal_epoch_binding, validate_epoch_binding,
    )
    source_low, _ = _execution(RUN_007, 'low')
    source_high, _ = _execution(RUN_001, 'high')
    queue_low, result_low, receipt_low = _finalize(tmp_path / 'low', source_low)
    queue_high = review_queue(source_high)
    assert queue_low['epoch_sha256'] != queue_high['epoch_sha256']
    with pytest.raises(ValueError, match='receipt_epoch_binding_mismatch'):
        validate_epoch_binding(receipt_low, queue_high)
    # A resealed receipt whose frozen epoch identity differs is a different
    # population even when its per-run config is otherwise compatible.
    source_other, _ = _execution(RUN_009, 'other')
    _queue_other, _result_other, receipt_other = _finalize(
        tmp_path / 'other', source_other)
    changed = deepcopy(receipt_other)
    binding = changed['epoch_binding']
    binding['experiment_epoch_id'] = 'other-epoch'
    binding['plan_sha256'] = 'd' * 64
    binding['experiment_epoch']['epoch_id'] = 'other-epoch'
    binding['plan']['epoch_id'] = 'other-epoch'
    binding['plan']['plan_sha256'] = 'd' * 64
    binding['rules']['metrics_epoch'] = 'other-metrics'
    binding['scoring_epoch']['metrics_epoch'] = 'other-metrics'
    changed['epoch_binding'] = seal_epoch_binding(binding)
    changed['epoch_sha256'] = changed['epoch_binding']['epoch_sha256']
    other_receipt = tmp_path / 'other-epoch-receipt.json'
    other_receipt.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match='different scoring epochs'):
        compare_receipts([result_low['receipts']['ai'], other_receipt])


@requires_restored
def test_historical_unbound_receipt_remains_readable_without_relabeling():
    from evaluation.thesis_scoring import (
        load_review_decisions, review_queue, validate_epoch_binding,
    )
    reviews = sorted((ROOT / 'results/reviews/restored-primary-2026-11-06').glob('*.ai-verified.json'))
    target = next((path for path in reviews
                   if 'run-007' in json.loads(path.read_text()).get('source_path', '')), None)
    if target is None:
        pytest.skip('retained run-007 receipt is not present')
    before = target.read_bytes()
    receipt = json.loads(before)
    queue = review_queue(receipt['source_path'])
    assert queue['prospective_study'] is True
    assert validate_epoch_binding(receipt, queue)['status'] == 'historical_unbound'
    decisions = load_review_decisions(receipt['source_path'], queue=queue,
                                      receipt_path=target)
    assert decisions
    assert target.read_bytes() == before


def _set_config(artifact):
    artifact['config'].update(scoring_mode='human', scoring_evaluator={},
                              scoring_rubric_version='thesis-scoring',
                              payload_mode='static_only', surface='access_control')
    artifact['score_epoch'] = {'thesis_final': 'thesis-scoring'}


def _negative_ac_artifact(monkeypatch, *, with_oracle):
    from tests.test_permission_chain_e2e import FakeSession, TARGET, chain_artifact
    artifact, source_candidate, _dest_candidate, source_row, dest_row, _route = chain_artifact()
    dest_row.update(signal_detected=False, verified_grade=0, success=True,
                    verification_reason='no_verified_exploit_signal')
    artifact['final_state']['verifier_history'][1]['decision'] = 'not_confirmed'
    if with_oracle:
        class DeniedSession(FakeSession):
            def get(self, path, params=None):
                path = str(path)
                if path.endswith('get_user_data.php') and self.principal == 'gordonb':
                    self.calls.append(('GET', path, deepcopy(params or {})))
                    return SimpleNamespace(
                        text='{"result":"fail","error":"Access denied"}',
                        status_code=200, url=f"{TARGET}/{path.lstrip('/')}")
                return super().get(path, params)

        import evaluation.permission_oracle as permission_oracle
        import foundation.session_manager as session_manager
        FakeSession.instances = []
        monkeypatch.setattr(permission_oracle, 'DVWASession', DeniedSession)
        monkeypatch.setattr(session_manager, 'DVWASession', DeniedSession)
        artifact['final_state']['found_credentials'] = [{
            'username': 'gordonb', 'password': 'fixture-secret',
            'source_evidence_id': source_row['evidence_id'],
            'source_candidate_id': source_candidate['candidate_id'],
            'source_visit_id': source_row['visit_id'],
        }]
        artifact = permission_oracle.collect_permission_oracles(
            artifact, artifact['final_state'])
        from evaluation.scoring_evidence import attach_oracle_evidence
        attach_oracle_evidence(artifact)
    _set_config(artifact)
    return artifact


def test_ac_negative_without_permission_oracle_is_not_exploitation_zero(tmp_path, monkeypatch):
    from evaluation.thesis_scoring import finalize_reviews, review_queue
    artifact = _negative_ac_artifact(monkeypatch, with_oracle=False)
    path = tmp_path / 'ac-negative.json'
    path.write_text(json.dumps(artifact))
    queue = review_queue(path)
    assert queue['components']['Sexploit'] is None
    assert queue['component_pending_reasons']['Sexploit'] == 'negative_permission_oracle_unavailable'
    row = next(row for row in queue['candidates'] if row['candidate_id'].startswith('ac_idor'))
    # The payload signal gate is still a legitimate payload zero.
    assert (row['status'], row['base_proof'], row['exploit_base_proof']) == \
        ('signal_absent', 0, None)
    result = finalize_reviews(path, [], output_dir=tmp_path / 'out', isolated_output=True)
    workflow = result['workflows']['human']
    assert workflow['status'] == 'pending' and workflow['Srun_final'] is None
    assert workflow['components']['Spayload'] == 0.0
    assert result['receipts'] == {}


def test_ac_negative_with_permission_oracle_is_zero(tmp_path, monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = _negative_ac_artifact(monkeypatch, with_oracle=True)
    path = tmp_path / 'ac-negative-oracle.json'
    path.write_text(json.dumps(artifact))
    queue = review_queue(path)
    assert queue['components']['Sexploit'] == 0
    assert 'Sexploit' not in queue['component_pending_reasons']
    row = next(row for row in queue['candidates'] if row['candidate_id'].startswith('ac_idor'))
    assert (row['status'], row['base_proof'], row['exploit_base_proof']) == \
        ('signal_absent', 0, 0)


def test_derived_component_reader_keeps_ac_negative_unavailable_without_oracle(monkeypatch):
    from evaluation.research_metrics import _derive_component_evidence
    artifact = _negative_ac_artifact(monkeypatch, with_oracle=False)
    destination = artifact['final_state']['response_evidence'][1]
    view = [{'candidate_id': destination['candidate_id'], 'valid': True,
             'executed': True, 'stage': 'exploit', 'proof': 0}]
    assert _derive_component_evidence(artifact, 'ac_idor', None, view)['Sexploit'] is None
    with_oracle = _negative_ac_artifact(monkeypatch, with_oracle=True)
    destination = with_oracle['final_state']['response_evidence'][1]
    view = [{'candidate_id': destination['candidate_id'], 'valid': True,
             'executed': True, 'stage': 'exploit', 'proof': 0}]
    assert _derive_component_evidence(with_oracle, 'ac_idor', None, view)['Sexploit'] == 0


def test_sqli_negative_payload_semantics_are_unchanged():
    from tests.test_execution_security_status import evidence_artifact
    from evaluation.thesis_scoring import review_queue
    import tempfile
    path = Path(tempfile.mkdtemp()) / 'sqli.json'
    path.write_text(json.dumps(evidence_artifact(method='sqli_union')))
    queue = review_queue(path)
    assert queue['components']['Sexploit'] == 0
    assert queue['candidates'][0]['exploit_base_proof'] == 0


def test_bf_negative_without_session_oracle_keeps_exploit_unavailable():
    from tests.test_execution_security_status import evidence_artifact
    from evaluation.thesis_scoring import review_queue
    import tempfile
    path = Path(tempfile.mkdtemp()) / 'bf.json'
    path.write_text(json.dumps(evidence_artifact(method='bf_dictionary')))
    queue = review_queue(path)
    assert queue['components']['Sexploit'] is None
    assert queue['component_pending_reasons']['Sexploit'] == 'negative_session_oracle_unavailable'
    assert queue['candidates'][0]['exploit_base_proof'] is None


def _rejection_queue():
    return {
        'selection': 'ai',
        'evaluator': {'provider': 'offline', 'model': 'judge',
                      'max_attempts': 1, 'max_tokens': 256, 'timeout': 5},
        'run_id': 'run:test', 'execution_id': 'execution:test',
        'source_sha256': 'a' * 64, 'rubric_version': 'thesis-scoring',
        'scoring_rule_sha256': 'f' * 64, 'epoch_sha256': 'e' * 64,
        'candidates': [{
            'candidate_id': 'candidate-a', 'method': 'sqli_union',
            'stage': 'exploit', 'status': 'pending_review',
            'proof_ceiling': 3, 'base_proof': 3,
            'evidence_refs': ['#/final_state/response_evidence/0'],
        }],
    }


def _rejection_decision():
    return {
        'decision_id': 'decision-a', 'candidate_id': 'candidate-a',
        'scoring_mode': 'ai', 'score': 2, 'reason': 'below machine proof',
        'evidence_refs': ['#/final_state/response_evidence/0'],
        'source_sha256': 'a' * 64, 'run_id': 'run:test',
        'rubric_version': 'thesis-scoring', 'reviewer_id': 'offline/judge',
        'review_version': 'artifact-judge',
    }


def test_historical_bound_status_remains_readable_without_reprojection():
    from evaluation.observer_reviews import _validate_epoch_claims
    from evaluation.thesis_scoring import _binding_digest
    binding = {
        'binding_version': 'scoring-epoch-binding',
        'epoch_sha256': '0' * 64,
        'plan': {'status': 'unavailable'},
        'experiment_epoch': {'status': 'unavailable'},
        'fixture': {'status': 'bound', 'fixture_id': 'synthetic-dvwa',
                    'security_level': 'low'},
    }
    binding['binding_sha256'] = _binding_digest(binding)
    status = {'artifact_type': 'review_status',
              'receipt_contract': 'epoch-bound-receipt',
              'epoch_binding': binding}
    _validate_epoch_claims(status, {'prospective_study': False})
    tampered = deepcopy(status)
    tampered['epoch_binding']['fixture']['security_level'] = 'high'
    with pytest.raises(ValueError, match='receipt_binding_digest_mismatch'):
        _validate_epoch_claims(tampered, {'prospective_study': False})


def test_float_below_floor_is_recorded_as_rejected():
    from evaluation.thesis_scoring import rejected_decision_events
    decision = _rejection_decision()
    decision['score'] = 2.5
    events = rejected_decision_events([], [decision], queue=_rejection_queue())
    assert len(events) == 1
    assert events[0]['attempted_score'] == 2.5
    assert events[0]['floor'] == 3


def test_rejected_events_replay_idempotently_at_different_clocks(tmp_path):
    from evaluation.thesis_scoring import (
        _rejected_event_content_digest, append_rejected_decisions,
        rejected_decision_event, rejected_decisions_path,
    )
    queue = _rejection_queue()
    decision = _rejection_decision()
    first = rejected_decision_event(decision, 3, queue=queue)
    second = rejected_decision_event(decision, 3, queue=queue)
    assert first['event_id'] == second['event_id']
    assert first['content_sha256'] == second['content_sha256']
    second['recorded_at'] = '2026-11-08T00:00:00+00:00'
    source = tmp_path / 'execution.json'
    source.write_text('{}')
    path = rejected_decisions_path(source, output_dir=tmp_path, queue=queue)
    assert append_rejected_decisions(path, [first], source) == [first]
    saved = json.loads(path.read_text())
    assert len(saved) == 1 and saved[0]['recorded_at'] == first['recorded_at']
    assert append_rejected_decisions(path, [second], source) == saved
    conflicting = deepcopy(first)
    conflicting['reason'] = 'different reasoning'
    conflicting.pop('content_sha256', None)
    conflicting['content_sha256'] = _rejected_event_content_digest(conflicting)
    with pytest.raises(ValueError, match='Cannot change a saved rejected-decision event'):
        append_rejected_decisions(path, [conflicting], source)
    assert json.loads(path.read_text()) == saved


def test_direct_finalize_records_human_below_floor_submission(monkeypatch):
    from tests.test_thesis_scoring_e2e import source
    from evaluation.thesis_scoring import finalize_reviews, review_queue
    path = source(monkeypatch, 'human')
    queue = review_queue(path)
    row = next(row for row in queue['candidates'] if row['status'] == 'pending_review')
    decision = {
        'decision_id': 'human:below-floor', 'run_id': queue['run_id'],
        'source_sha256': queue['source_sha256'], 'rubric_version': queue['rubric_version'],
        'scoring_mode': 'human', 'candidate_id': row['candidate_id'],
        'score': row['base_proof'] - 1, 'reason': 'contradicts machine proof',
        'evidence_refs': row['evidence_refs'], 'reviewer_id': 'offline-reviewer',
        'review_version': 'manual-assessment',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }
    rejection_path = path.parent / 'reviews' / f'{path.stem}.rejected-decisions.json'
    with pytest.raises(ValueError, match='below the machine proof'):
        finalize_reviews(path, [decision])
    events = json.loads(rejection_path.read_text())
    assert len(events) == 1
    assert events[0]['candidate_id'] == row['candidate_id']
    assert events[0]['attempted_score'] == row['base_proof'] - 1
    assert events[0]['floor'] == row['base_proof']


def test_cli_external_decision_below_floor_records_rejection(monkeypatch, tmp_path):
    from tests.test_thesis_scoring_e2e import source
    from evaluation.thesis_scoring import main, review_queue
    path = source(monkeypatch, 'human')
    queue = review_queue(path)
    row = next(row for row in queue['candidates'] if row['status'] == 'pending_review')
    decision_file = tmp_path / 'decisions.json'
    decision_file.write_text(json.dumps([{
        'decision_id': 'human:cli-below-floor', 'run_id': queue['run_id'],
        'source_sha256': queue['source_sha256'], 'rubric_version': queue['rubric_version'],
        'scoring_mode': 'human', 'candidate_id': row['candidate_id'],
        'score': row['base_proof'] - 1, 'reason': 'contradicts machine proof',
        'evidence_refs': row['evidence_refs'], 'reviewer_id': 'offline-reviewer',
        'review_version': 'manual-assessment',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }]))
    rejection_path = path.parent / 'reviews' / f'{path.stem}.rejected-decisions.json'
    with pytest.raises(SystemExit):
        main([str(path), '--decisions', str(decision_file),
              '--output-dir', str(tmp_path / 'cli-out')])
    events = json.loads(rejection_path.read_text())
    assert events[0]['candidate_id'] == row['candidate_id']
    assert events[0]['attempted_score'] == row['base_proof'] - 1


def test_evaluator_telemetry_records_below_floor_rejection(monkeypatch, tmp_path):
    from tests.test_thesis_scoring_e2e import source
    from evaluation.thesis_scoring import (
        evaluate_queue, review_queue, save_evaluator_telemetry,
    )
    source_path = source(monkeypatch, 'ai')
    path = tmp_path / source_path.name
    path.write_text(source_path.read_text())
    queue = review_queue(path)
    row = next(row for row in queue['candidates'] if row['status'] == 'pending_review')
    response = SimpleNamespace(content=json.dumps({
        'score': row['base_proof'] - 1,
        'reason': 'contradicts the machine proof',
        'evidence_refs': row['evidence_refs'],
    }))
    evaluated = evaluate_queue(queue, queue['evaluator'], invoke=lambda messages: response)
    assert evaluated['status'] == 'pending'
    assert evaluated['decisions'] == []
    assert evaluated['rejected_decisions'][0]['candidate_id'] == row['candidate_id']
    save_evaluator_telemetry(path, evaluated, output_dir=tmp_path / 'reviews',
                             isolated_output=True)
    rejection_path = (tmp_path / 'reviews' /
                      f"{queue['execution_id']}.rejected-decisions.json")
    events = json.loads(rejection_path.read_text())
    assert events[0]['attempted_score'] == row['base_proof'] - 1
    assert events[0]['floor'] == row['base_proof']
    assert (tmp_path / 'reviews' / f"{queue['execution_id']}.evaluator.json").is_file()


def test_prospective_and_binding_guards_run_under_optimized_python():
    import subprocess
    import sys
    script = (
        'from evaluation.thesis_scoring import (\n'
        '    _require_prospective_epoch_binding, _validate_receipt_binding_integrity,\n'
        ')\n'
        'try:\n'
        '    _require_prospective_epoch_binding({"plan": {"status": "unavailable"}},\n'
        '        context="prospective_epoch_binding_incomplete")\n'
        'except ValueError as exc:\n'
        '    print(exc)\n'
        'else:\n'
        '    raise SystemExit("prospective guard disappeared")\n'
        'try:\n'
        '    _validate_receipt_binding_integrity({\n'
        '        "receipt_contract": "epoch-bound-receipt",\n'
        '        "epoch_binding": {"binding_version": "scoring-epoch-binding"},\n'
        '    })\n'
        'except ValueError as exc:\n'
        '    print(type(exc).__name__)\n'
        'else:\n'
        '    raise SystemExit("receipt integrity guard disappeared")\n'
    )
    completed = subprocess.run(
        [sys.executable, '-O', '-c', script], cwd=ROOT,
        capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert 'prospective_epoch_binding_incomplete' in completed.stdout
    assert 'ValueError' in completed.stdout


def test_tui_human_below_floor_submission_records_rejection(monkeypatch):
    import asyncio
    from textual.widgets import Input, Select
    from tesis.tui import TesisApp, ReviewDrawer
    from tests.test_thesis_scoring_e2e import source
    path = source(monkeypatch, 'human')

    async def scenario():
        app = TesisApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await app.push_screen(ReviewDrawer(path))
            drawer = app.screen
            for _ in range(100):
                await pilot.pause(.02)
                if drawer.queue:
                    break
            pending = [row for row in drawer.queue['candidates']
                       if row['status'] == 'pending_review']
            assert pending
            floor = max(row['base_proof'] for row in pending)
            drawer.query_one('#review-candidate', Select).value = pending[-1]['candidate_id']
            drawer.query_one('#review-score', Select).value = floor - 1
            drawer.query_one('#review-reason', Input).value = 'contradicts machine proof'
            drawer.query_one('#review-reviewer', Input).value = 'offline-reviewer'
            drawer.submit_grade()
            rejection_path = (path.parent / 'reviews' /
                              f'{path.stem}.rejected-decisions.json')
            for _ in range(200):
                await pilot.pause(.02)
                if rejection_path.exists() and not drawer._review_busy:
                    break
            assert rejection_path.exists()
            events = json.loads(rejection_path.read_text())
            assert events[0]['attempted_score'] == floor - 1
            assert events[0]['floor'] == floor
            assert not drawer.result or not drawer.result['receipts']
            await pilot.press('escape')
            app.exit()

    asyncio.run(asyncio.wait_for(scenario(), timeout=20))
