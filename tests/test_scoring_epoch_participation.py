"""Focused controls for epoch-bound receipts, rejected-decision audit and causal participation.

These are offline software controls. They do not create target/provider evidence,
new thesis scores, or a historical rescoring epoch.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from evaluation.thesis_scoring import EPOCH_BINDING_VERSION, RECEIPT_CONTRACT
from tests.test_thesis_scoring_e2e import grades, source


def _minimal_queue(**overrides):
    queue = {
        'selection': 'ai',
        'evaluator': {'provider': 'offline', 'model': 'judge',
                      'max_attempts': 1, 'max_tokens': 256, 'timeout': 5},
        'run_id': 'run:test', 'execution_id': 'execution:test',
        'source_sha256': 'a' * 64, 'rubric_version': 'thesis-scoring',
        'historical_read_only': False, 'epoch_sha256': 'e' * 64,
        'candidates': [{
            'candidate_id': 'candidate-a', 'method': 'sqli_union',
            'stage': 'exploit', 'candidate': {}, 'evidence': {},
            'status': 'pending_review', 'proof_ceiling': 3, 'base_proof': 3,
            'evidence_refs': ['#/final_state/response_evidence/0'],
        }],
    }
    queue.update(overrides)
    return queue


def _decision(score=2, **overrides):
    decision = {
        'decision_id': 'decision-a', 'candidate_id': 'candidate-a',
        'scoring_mode': 'ai', 'score': score,
        'reason': 'Judge saw weaker evidence than the machine proof',
        'evidence_refs': ['#/final_state/response_evidence/0'],
        'source_sha256': 'a' * 64, 'run_id': 'run:test',
        'rubric_version': 'thesis-scoring',
        'reviewer_id': 'offline/judge', 'review_version': 'artifact-judge',
        'timestamp': '2026-11-07T00:00:00+00:00',
    }
    decision.update(overrides)
    return decision


def test_below_floor_decision_is_audited_never_accepted(tmp_path):
    from evaluation.thesis_scoring import (
        REJECTED_DECISION_REASON, append_evaluator_decisions,
        append_rejected_decisions, rejected_decisions_path,
    )
    queue = _minimal_queue()
    rejected = []
    accepted = append_evaluator_decisions(
        [], [_decision(score=2)], queue=queue, rejected=rejected)
    assert accepted == []
    assert len(rejected) == 1
    event = rejected[0]
    assert event['event'] == 'below_machine_proof_floor'
    assert event['candidate_id'] == 'candidate-a'
    assert event['method'] == 'sqli_union'
    assert event['attempted_score'] == 2 and event['floor'] == 3
    assert event['rejection_reason'] == REJECTED_DECISION_REASON
    assert event['source_sha256'] == 'a' * 64
    assert event['rubric_version'] == 'thesis-scoring'
    assert event['reviewer_id'] == 'offline/judge'
    assert event['evaluator_provenance'] == {'provider': 'offline', 'model': 'judge'}
    legal = _decision(score=3, decision_id='decision-b')
    accepted = append_evaluator_decisions([], [legal], queue=queue, rejected=rejected)
    assert [row['decision_id'] for row in accepted] == ['decision-b']
    assert len(rejected) == 1

    source_path = tmp_path / 'execution.json'
    source_path.write_text('{}')
    path = rejected_decisions_path(source_path, output_dir=tmp_path, queue=queue)
    assert append_rejected_decisions(path, rejected, source_path) == rejected
    # Idempotent append retains the first event and never rewrites it.
    assert append_rejected_decisions(path, rejected, source_path) == rejected
    changed = deepcopy(rejected[0])
    changed['attempted_score'] = 1
    with pytest.raises(ValueError, match='Cannot change a saved rejected-decision event'):
        append_rejected_decisions(path, [changed], source_path)
    assert json.loads(path.read_text()) == rejected


def test_evaluator_below_floor_rejection_is_visible_in_telemetry():
    from evaluation.thesis_scoring import evaluate_queue
    queue = _minimal_queue()
    response = SimpleNamespace(content=json.dumps({
        'score': 2, 'reason': 'contradicts the machine proof',
        'evidence_refs': ['#/final_state/response_evidence/0'],
    }))
    result = evaluate_queue(queue, dict(queue['evaluator']), invoke=lambda messages: response)
    assert result['status'] == 'pending'
    assert result['decisions'] == []
    assert result['telemetry'][0]['status'] == 'rejected'
    assert result['telemetry'][0]['attempted_score'] == 2
    assert result['telemetry'][0]['floor'] == 3
    assert result['rejected_decisions'][0]['candidate_id'] == 'candidate-a'


def test_final_payload_integrity_guard_runs_under_optimized_python():
    from evaluation.thesis_scoring import _require_final_payload
    with pytest.raises(ValueError, match='no complete payload numerator'):
        _require_final_payload(None, None)
    script = (
        'from evaluation.thesis_scoring import _require_final_payload\n'
        'try:\n'
        '    _require_final_payload(None, None)\n'
        'except ValueError as exc:\n'
        '    print(str(exc))\n'
        'else:\n'
        '    raise SystemExit("optimized guard disappeared")\n'
    )
    completed = subprocess.run(
        [sys.executable, '-O', '-c', script], cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert 'no complete payload numerator' in completed.stdout


def test_new_receipt_binds_epoch_and_historical_receipt_reads_unbound(monkeypatch, tmp_path):
    from evaluation.thesis_scoring import (
        build_epoch_binding, finalize_reviews, load_review_decisions,
        review_queue, seal_epoch_binding, validate_epoch_binding,
    )
    path = source(monkeypatch)
    queue = review_queue(path)
    artifact = json.loads(path.read_text())
    result = finalize_reviews(
        path, grades(queue, 'human', 3), output_dir=tmp_path / 'bound')
    receipt = json.loads(Path(result['receipts']['human']).read_text())
    assert receipt['receipt_contract'] == RECEIPT_CONTRACT
    assert receipt['epoch_binding']['binding_version'] == EPOCH_BINDING_VERSION
    assert receipt['epoch_sha256'] == receipt['epoch_binding']['epoch_sha256']
    assert receipt['epoch_binding'] == build_epoch_binding(
        artifact, source_sha256=queue['source_sha256'])
    binding = receipt['epoch_binding']
    assert binding['experiment_epoch']['status'] == 'unavailable'
    assert binding['plan']['status'] == 'unavailable'
    assert binding['fixture']['status'] == 'bound'
    assert binding['rules']['scoring_rule_sha256'] == receipt['scoring_rule_sha256']
    assert binding['source_execution']['source_sha256'] == queue['source_sha256']
    assert binding['scoring_epoch_id'] == binding['scoring_epoch']['scoring_rule_sha256']
    assert binding['source_execution_sha256'] == queue['source_sha256']
    assert binding['config_sha256'] == queue['epoch_binding']['config']['source_config_sha256'] \
        or len(binding['config_sha256']) == 64
    assert binding['fixture_id'] == 'synthetic-dvwa'
    assert binding['protocol_version'] == 'offline-protocol'
    assert binding['oracle_sha256'] is None or len(binding['oracle_sha256']) == 64
    assert binding['plan_sha256'] is None
    assert validate_epoch_binding(receipt, queue)['status'] == 'current'

    tampered = deepcopy(receipt)
    tampered['epoch_binding']['rules']['metrics_epoch'] = 'different-metrics'
    tampered['epoch_binding'] = seal_epoch_binding(tampered['epoch_binding'])
    tampered['epoch_sha256'] = tampered['epoch_binding']['epoch_sha256']
    with pytest.raises(ValueError, match='receipt_epoch_binding_mismatch'):
        validate_epoch_binding(tampered, queue)

    digest_tampered = deepcopy(receipt)
    digest_tampered['epoch_binding']['rules']['source_hashes']['core/scoring_contracts.py'] = 'd' * 64
    with pytest.raises(ValueError, match='receipt_binding_digest_mismatch'):
        validate_epoch_binding(digest_tampered, queue)

    historical = deepcopy(receipt)
    for key in ('receipt_contract', 'epoch_binding', 'epoch_sha256'):
        historical.pop(key)
    assert validate_epoch_binding(historical, queue)['status'] == 'historical_unbound'
    historical_path = tmp_path / 'historical-receipt.json'
    historical_path.write_text(json.dumps(historical))
    loaded = load_review_decisions(path, queue=queue, receipt_path=historical_path)
    assert [row['candidate_id'] for row in loaded] == [
        row['candidate_id'] for row in receipt['review_history']]

    planned = deepcopy(artifact)
    planned['research_plan_identity'] = {
        'plan_sha256': 'c' * 64, 'epoch_id': 'declared-epoch'}
    planned_binding = build_epoch_binding(planned, source_sha256=queue['source_sha256'])
    assert planned_binding['plan'] == {
        'status': 'bound', 'plan_sha256': 'c' * 64,
        'epoch_id': 'declared-epoch', 'source': 'research_plan_identity'}
    conflict = deepcopy(artifact)
    conflict['config']['policy_epoch'] = {'epoch_id': 'experiment-epoch'}
    conflict['research_plan_identity'] = {
        'plan_sha256': 'c' * 64, 'epoch_id': 'other-epoch'}
    with pytest.raises(ValueError, match='research_plan_epoch_mismatch'):
        build_epoch_binding(conflict, source_sha256=queue['source_sha256'])


def test_receipt_comparison_refuses_mixed_epochs(monkeypatch, tmp_path):
    from evaluation.thesis_scoring import (
        compare_receipts, finalize_reviews, review_queue, seal_epoch_binding,
    )
    paths = []
    for index in range(2):
        path = source(monkeypatch)
        queue = review_queue(path)
        result = finalize_reviews(
            path, grades(queue, 'human', 3), output_dir=tmp_path / f'epoch-{index}')
        paths.append(Path(result['receipts']['human']))
    compared = compare_receipts(paths)
    assert len(compared['groups']) == 1 and compared['groups'][0]['n_final'] == 2

    other = json.loads(paths[1].read_text())
    other['epoch_binding']['rules']['metrics_epoch'] = 'different-metrics'
    other['epoch_binding']['scoring_epoch']['metrics_epoch'] = 'different-metrics'
    other['epoch_binding'] = seal_epoch_binding(other['epoch_binding'])
    other['epoch_sha256'] = other['epoch_binding']['epoch_sha256']
    cross_path = tmp_path / 'cross-epoch-receipt.json'
    cross_path.write_text(json.dumps(other))
    with pytest.raises(ValueError, match='different scoring epochs'):
        compare_receipts([paths[0], cross_path])

    unbound = json.loads(paths[1].read_text())
    for key in ('receipt_contract', 'epoch_binding', 'epoch_sha256'):
        unbound.pop(key)
    unbound_path = tmp_path / 'unbound-receipt.json'
    unbound_path.write_text(json.dumps(unbound))
    with pytest.raises(ValueError, match='different scoring epochs'):
        compare_receipts([paths[0], unbound_path])


@pytest.fixture
def causal_chain(monkeypatch):
    """Offline operator-controlled chain with a source and a consumer."""
    from tests.test_permission_chain_e2e import (
        TARGET, FakeSession, chain_artifact,
    )
    from evaluation import dependency_oracle, permission_oracle, session_oracle
    from evaluation.scoring_evidence import attach_oracle_evidence
    FakeSession.instances = []
    monkeypatch.setattr(permission_oracle, 'DVWASession', FakeSession)
    monkeypatch.setattr(session_oracle, 'DVWASession', FakeSession)
    monkeypatch.setattr(dependency_oracle, 'DVWASession', FakeSession)
    monkeypatch.setattr('foundation.session_manager.DVWASession', FakeSession)
    artifact, source_candidate, dest_candidate, source_row, dest_row, route = chain_artifact()
    raw = {
        'target_url': TARGET, 'security_level': 'low',
        'found_credentials': [{
            'username': 'gordonb', 'password': 'fixture-secret',
            'source_evidence_id': source_row['evidence_id'],
            'source_candidate_id': source_candidate['candidate_id'],
            'source_visit_id': source_row['visit_id'],
        }],
        'payload_candidates': artifact['final_state']['payload_candidates'],
        'payload_validation_results': artifact['final_state']['payload_validation_results'],
        'response_evidence': artifact['final_state']['response_evidence'],
        'chain_history': artifact['final_state']['chain_history'],
    }
    artifact = permission_oracle.collect_permission_oracles(artifact, raw)
    artifact = session_oracle.collect_session_oracles(artifact, raw)
    attach_oracle_evidence(artifact)
    artifact = dependency_oracle.collect_dependency_oracles(artifact, raw)
    return artifact, source_candidate, dest_candidate


def test_causal_participation_roles_and_level_four_controls(causal_chain):
    from evaluation.scoring_evidence import (
        automatic_components, causal_participation, evidence_hash,
        method_causal_participation, verified_dependencies,
    )
    artifact, source_candidate, dest_candidate = causal_chain
    dependencies = verified_dependencies(artifact)
    assert len(dependencies) == 1
    dependency = dependencies[0]
    assert dependency['lineage']['material_fingerprint']
    assert dependency['route_ref'] == '#/final_state/chain_history/0'
    assert len(dependency['control_refs']) == 2

    source_result = causal_participation(
        artifact, source_candidate['candidate_id'], 'bf_dictionary', 3, dependencies)
    assert (source_result['status'], source_result['role']) == ('verified', 'source')
    assert source_result['lineage'][0]['source_evidence_id'] == 'response:0'
    consumer_result = causal_participation(
        artifact, dest_candidate['candidate_id'], 'ac_idor', 3, dependencies)
    assert (consumer_result['status'], consumer_result['role']) == ('verified', 'consumer')
    assert consumer_result['control_refs'] == dependency['control_refs']

    source_rows = [{'candidate_id': source_candidate['candidate_id'],
                    'method': 'bf_dictionary', 'eligible': True, 'base_proof': 3}]
    consumer_rows = [{'candidate_id': dest_candidate['candidate_id'],
                      'method': 'ac_idor', 'eligible': True, 'base_proof': 3}]
    unrelated_rows = [{'candidate_id': 'other', 'method': 'sqli_union',
                       'eligible': True, 'base_proof': 3}]
    assert automatic_components(
        artifact, 'bf_dictionary', source_rows,
        dependencies=dependencies)[0]['Sexploit'] == 4
    assert automatic_components(
        artifact, 'ac_idor', consumer_rows,
        dependencies=dependencies)[0]['Sexploit'] == 4
    assert automatic_components(
        artifact, 'sqli_union', unrelated_rows,
        dependencies=dependencies)[0]['Sexploit'] == 3
    assert method_causal_participation(
        artifact, 'sqli_union', dependencies, unrelated_rows)['status'] == 'not_participating'

    # The same local proof below 3 cannot earn level 4.
    assert causal_participation(
        artifact, dest_candidate['candidate_id'], 'ac_idor', 2, dependencies
    )['status'] == 'local_proof_below_3'

    # A control that no longer matches its expected truth invalidates the join.
    tampered = deepcopy(artifact)
    bundle_index = int(dependency['dependency_ref'].split('/')[3])
    bundle = tampered['config']['scoring_oracles'][bundle_index]
    bundle['document']['dependency_controls'][0]['expected_source_available'] = False
    bundle['sha256'] = evidence_hash(bundle['document'])
    assert verified_dependencies(tampered) == []

    # Reused control sessions are not independent matched controls.
    reused = deepcopy(artifact)
    bundle = reused['config']['scoring_oracles'][bundle_index]
    controls = bundle['document']['dependency_controls']
    controls[0]['session_fingerprint'] = controls[1]['session_fingerprint']
    bundle['sha256'] = evidence_hash(bundle['document'])
    assert verified_dependencies(reused) == []

    # Summary controls must agree with the detailed rows.
    summary_mismatch = deepcopy(artifact)
    bundle = summary_mismatch['config']['scoring_oracles'][bundle_index]
    bundle['document']['dependencies'][0]['controls'][1]['response_sha256'] = '0' * 64
    bundle['sha256'] = evidence_hash(bundle['document'])
    assert verified_dependencies(summary_mismatch) == []


def test_final_receipt_records_selected_method_participation(monkeypatch, tmp_path):
    from evaluation import thesis_scoring
    from evaluation.thesis_scoring import build_epoch_binding
    source_path = tmp_path / 'execution.json'
    source_path.write_text('{}')
    source_sha = sha256(source_path.read_bytes()).hexdigest()
    binding = build_epoch_binding(
        {'config': {}, 'score_epoch': {}, 'execution_id': 'execution:test',
         'run_id': 'run:test'}, source_sha256=source_sha)
    participation = {
        'status': 'verified', 'role': 'source', 'roles': ['source'],
        'candidate_id': 'candidate-a', 'visit_id': 'bf_dictionary:visit:1',
        'local_proof': 3,
        'evidence_refs': ['#/final_state/response_evidence/0'],
        'dependency_refs': ['#/config/scoring_oracles/0/document/dependencies/0'],
        'control_refs': ['#/config/scoring_oracles/0/document/dependency_controls/0'],
        'chain_route_ids': ['route:0'], 'lineage': [],
        'reason': 'verified_source_participation', 'candidates': [],
    }
    queue = {
        'rubric_version': 'thesis-scoring', 'source_sha256': source_sha,
        'execution_id': 'execution:test', 'run_id': 'run:test',
        'source_path': str(source_path), 'selection': 'human', 'evaluator': {},
        'historical_read_only': False, 'method': 'bf_dictionary',
        'config': {}, 'components': {'Smethod': 3, 'Sexploit': 4, 'Schain': 3, 'Soutput': 4},
        'component_pending_reasons': {}, 'component_evidence_refs': {},
        'selection_evidence': {'status': 'assessed'}, 'stop_reason': None,
        'output_reason': None, 'causal_participation': participation,
        'epoch_binding': binding, 'epoch_sha256': binding['epoch_sha256'],
        'recorded_epoch_binding': None, 'scoring_rule_sha256': 'f' * 64,
        'scoring_policy': {}, 'prompt_identities': [],
        'metrics': {'metrics_epoch': 'research-metrics'},
        'execution_status': 'completed', 'execution_reason': None,
        'security_outcome': 'confirmed', 'security_outcome_reason': None,
        'candidates': [{
            'candidate_id': 'candidate-a', 'method': 'bf_dictionary',
            'status': 'pending_review', 'eligible': True, 'proof_ceiling': 4,
            'base_proof': 3, 'evidence_refs': ['#/final_state/response_evidence/0'],
            'provenance': {'source': 'static_seed'}, 'stage': 'exploit',
        }],
    }
    monkeypatch.setattr(thesis_scoring, 'review_queue', lambda path: deepcopy(queue))
    decision = {
        'decision_id': 'human:a', 'candidate_id': 'candidate-a',
        'scoring_mode': 'human', 'score': 4, 'reason': 'confirmed source participation',
        'evidence_refs': ['#/final_state/response_evidence/0'],
        'source_sha256': source_sha, 'run_id': 'run:test',
        'rubric_version': 'thesis-scoring', 'reviewer_id': 'offline-reviewer',
        'review_version': 'manual-assessment',
        'timestamp': '2026-11-07T00:00:00+00:00',
    }
    result = thesis_scoring.finalize_reviews(
        source_path, [decision], output_dir=tmp_path / 'out')
    receipt = json.loads(Path(result['receipts']['human']).read_text())
    assert receipt['exploit_participation'] == participation
    assert result['workflows']['human']['exploit_participation'] == participation
    assert receipt['components'] == {
        'Smethod': 3, 'Spayload': 4.0, 'Sexploit': 4, 'Schain': 3, 'Soutput': 4}
    assert receipt['Srun_final'] == 3.7
    assert receipt['epoch_sha256'] == binding['epoch_sha256']
    assert receipt['candidate_grades'][0]['score'] == 4
    assert result['rejected_decision_count'] == 0


def test_intermediate_conflicting_and_unavailable_participation():
    from evaluation.scoring_evidence import causal_participation
    middle = {'agent_id': 'bf_dictionary', 'candidate_id': 'middle',
              'visit_id': 'bf_dictionary:visit:1', 'evidence_id': 'response:1',
              'response_sha256': 'b' * 64}
    destination = {'agent_id': 'ac_idor', 'candidate_id': 'destination',
                   'visit_id': 'ac_idor:visit:2', 'evidence_id': 'response:2',
                   'response_sha256': 'c' * 64}
    origin = {'agent_id': 'sqli_union', 'candidate_id': 'origin',
              'visit_id': 'sqli_union:visit:0', 'evidence_id': 'response:0',
              'response_sha256': 'a' * 64}
    first_route = {'route_id': 'route:0', 'status': 'completed',
                   'source_evidence_refs': ['#/final_state/response_evidence/0'],
                   'destination_evidence_refs': ['#/final_state/response_evidence/1']}
    second_route = {'route_id': 'route:1', 'status': 'completed',
                    'source_evidence_refs': ['#/final_state/response_evidence/1'],
                    'destination_evidence_refs': ['#/final_state/response_evidence/2']}
    incoming = {'route': first_route, 'source': origin, 'destination': middle,
                'consumption': {}, 'control_refs': [], 'lineage': {
                    'route_id': 'route:0', 'route_ref': '#/final_state/chain_history/0',
                    'source_candidate_id': 'origin', 'source_visit_id': 'sqli_union:visit:0',
                    'source_evidence_id': 'response:0', 'source_response_sha256': 'a' * 64,
                    'destination_candidate_id': 'middle',
                    'destination_visit_id': 'bf_dictionary:visit:1',
                    'destination_evidence_id': 'response:1',
                    'destination_response_sha256': 'b' * 64,
                    'material_fingerprint': 'd' * 64},
                'dependency': {'source_at': '2026-11-07T00:00:00+00:00',
                               'consumed_at': '2026-11-07T00:00:01+00:00',
                               'verified_at': '2026-11-07T00:00:02+00:00'}}
    outgoing = {'route': second_route, 'source': middle, 'destination': destination,
                'consumption': {}, 'control_refs': [], 'lineage': {
                    'route_id': 'route:1', 'route_ref': '#/final_state/chain_history/1',
                    'source_candidate_id': 'middle',
                    'source_visit_id': 'bf_dictionary:visit:1',
                    'source_evidence_id': 'response:1', 'source_response_sha256': 'b' * 64,
                    'destination_candidate_id': 'destination',
                    'destination_visit_id': 'ac_idor:visit:2',
                    'destination_evidence_id': 'response:2',
                    'destination_response_sha256': 'c' * 64,
                    'material_fingerprint': 'e' * 64},
                'dependency': {'source_at': '2026-11-07T00:00:03+00:00',
                               'consumed_at': '2026-11-07T00:00:04+00:00',
                               'verified_at': '2026-11-07T00:00:05+00:00'}}
    artifact = {'final_state': {
        'response_evidence': [origin, middle, destination],
        'chain_history': [first_route, second_route],
    }}
    result = causal_participation(
        artifact, 'middle', 'bf_dictionary', 3, [incoming, outgoing])
    assert (result['status'], result['role']) == ('verified', 'intermediate')
    assert result['chain_route_ids'] == ['route:0', 'route:1']

    conflict_artifact = {'final_state': {
        'response_evidence': [middle],
        'chain_history': [{'route_id': 'route:9', 'status': 'completed',
                           'source_evidence_refs': ['#/final_state/response_evidence/0'],
                           'destination_evidence_refs': []}],
    }}
    conflict = causal_participation(
        conflict_artifact, 'middle', 'bf_dictionary', 3, [])
    assert conflict['status'] == 'conflicting_lineage'
    assert conflict['reason'] == 'completed_chain_participation_unverified'

    unavailable = causal_participation({'final_state': {}}, 'middle', 'bf_dictionary', 3, [])
    assert unavailable['status'] == 'unavailable'
    idle = causal_participation(
        {'final_state': {'chain_history': []}}, 'middle', 'bf_dictionary', 3, [])
    assert idle['status'] == 'not_participating'
