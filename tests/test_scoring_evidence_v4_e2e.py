"""Artifact E2E controls declared before v4 implementation.

Failure inventory: M1-M9 ranking/snapshots; P1-P5 candidate/use attribution;
A1-A3 permission oracles; B1-B3 fresh sessions; E1-E2 final-method boundary;
C1-C4 passive opportunities/dependencies; O1-O6 calls/refs/stability;
R1-R4 pending/independent receipts/precision/version; D1-D2 document agreement.
Synthetic attestation controls prove the offline contract, never live DVWA.

Review failure controls: malformed optional decision fields escape fallback;
native schemas omit chain bindings; synthetic dependency bundles contaminate
unlabeled scores; permission attestations reject unchanged sessions; one role's
fallback masks another role/visit's failure; oracle hashes split repeats;
DOCX controls depend on an untracked local source.
"""
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import pytest

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE
from evaluation.reporter import write_json_report
from tests.test_scoring_remediation_e2e import control

ROOT = Path('results/validation/scoring-evidence-v4')


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def profile(surface='sqli'):
    doc = {'kind': 'offline_reference_protocol', 'controls': 'synthetic equal-budget protocols'}
    methods = {m: {'preconditions': AttackKnowledgeGraph.METHOD_PRECONDITIONS[m],
        'fit_predicates': [{'key': AttackKnowledgeGraph.METHOD_PRECONDITIONS[m][0], 'equals': True}],
        'planned_request_count': 10, 'protocol_refs': ['protocol'],
        'allowed_plans': ['stop_after_target', 'stop_at_budget', 'continue_same_surface']}
        for m in METHODS_BY_SURFACE[surface]}
    p = {'profile_id': 'offline-ranking', 'version': 'ranking.v1',
        'fixture_id': 'synthetic-dvwa', 'protocol_version': 'offline.v1',
        'frozen_at': '2026-09-01T00:00:00+00:00', 'candidate_budget': 5,
        'sources': [{'source_id': 'protocol', 'origin': 'offline_control',
            'document': doc, 'sha256': digest(doc)}],
        'scenarios': {f'{surface}:low': methods}}
    p['sha256'] = digest(p)
    return p


def export(artifact, name):
    path = ROOT / 'controls' / f'{name}-{uuid4().hex}' / 'execution.json'
    write_json_report(path, artifact)
    return path


def artifact_v4(monkeypatch):
    artifact, _, _ = control(monkeypatch, 'mixed_candidates')
    artifact['execution_id'] = uuid4().hex
    artifact['config'].update(scoring_mode='both', scoring_rubric_version='scoring.v4',
        scoring_profile=profile(), scoring_oracles=[], fixture_id='synthetic-dvwa',
        protocol_version='offline.v1', scoring_evaluator={'provider': 'offline',
        'model': 'independent-judge', 'max_attempts': 2, 'max_tokens': 512, 'timeout': 5})
    artifact['validation_scope'] = 'offline_synthetic_fixture'
    state = artifact['final_state']
    selection = next(d for d in state['scoring_decisions'] if d['dimension'] == 'Smethod')
    selection.update(observations={key: True for keys in AttackKnowledgeGraph.METHOD_PRECONDITIONS.values()
        for key in keys}, reason_refs=['union_select_possible'], plan={'kind': 'stop_after_target'},
        selected_at='2026-10-01T00:00:00+00:00', profile_sha256=artifact['config']['scoring_profile']['sha256'])
    selection['precondition_status'] = {key: 'true' for key in selection['observations']}
    call_input = {'observations': selection['observations']}
    output = {'next_agent': 'sqli_union', 'reason_code': 'supported observation',
        'reason_refs': ['union_select_possible'], 'plan': {'kind': 'stop_after_target'}}
    generator_calls = [r for r in artifact.get('llm_performance', [])
                       if isinstance(r, dict) and r.get('role') == 'payload_generator']
    artifact['llm_performance'] = [{'call_id': 'call:1', 'role': 'orchestrator',
        'method': 'sqli_union', 'visit_id': selection['visit_id'], 'schema_version': 'orchestrator.v1',
        'input': call_input, 'output': output, 'input_sha256': digest(call_input),
        'output_sha256': digest(output), 'parse_status': 'ok', 'validation_status': 'valid',
        'attempt': 1, 'provider': 'offline', 'model': 'fixture',
        'started_at': '2026-10-01T00:00:00+00:00'},
        *generator_calls]
    return artifact


def test_real_runner_freezes_v4_configuration(monkeypatch):
    from evaluation.runner import run_single_engagement
    # Establish the existing contained HTTP/provider fixture and actual graph.
    control(monkeypatch, 'mixed_candidates')
    a = run_single_engagement(target_url='http://localhost/dvwa', security_level='low',
        llm_provider='openai_compatible', target_method='sqli_union', payload_mode='hybrid',
        scoring_rubric_version='scoring.v4', scoring_profile=profile(), fixture_id='synthetic-dvwa',
        protocol_version='offline.v1', execution_id='v4-runner', output_dir=str(ROOT / 'runner'))
    assert a['config']['scoring_rubric_version'] == 'scoring.v4'
    assert a['config']['scoring_profile']['sha256'] == profile()['sha256']
    assert all(r.get('input_sha256') and r.get('schema_version') and r.get('method')
        for r in a['llm_performance'])
    selection = next(d for d in a['final_state']['scoring_decisions'] if d['dimension'] == 'Smethod')
    assert selection['profile_sha256'] == profile()['sha256']
    assert 'weak_chain_opportunities' in a['final_state']


def oracle_artifact(monkeypatch, method):
    a = artifact_v4(monkeypatch)
    state = a['final_state']
    surface = 'access_control' if method.startswith('ac_') else 'brute_force'
    a['selected_method'] = state['selected_method'] = method
    for field in ('payload_candidates', 'payload_validation_results', 'tried_payloads'):
        state[field][method] = state[field].pop('sqli_union')
    for row in state['response_evidence']:
        row['agent_id'] = method
        row['verification_reason'] = 'visibility_without_permission_oracle' if method.startswith('ac_') else 'verified_login'
        row['signal_detected'] = True
    for d in state['verifier_history']:
        d['agent_id'] = method
        d['decision'] = 'confirmed'
    selection = next(d for d in state['scoring_decisions'] if d['dimension'] == 'Smethod')
    selection.update(method=method, surface=surface)
    a['config']['scoring_profile'] = profile(surface)
    selection['profile_sha256'] = a['config']['scoring_profile']['sha256']
    row = next(r for r in state['response_evidence'] if r['stage'] == 'exploit')
    att = {'kind': 'permission' if method.startswith('ac_') else 'session',
        'run_id': a['run_id'], 'execution_id': a['execution_id'],
        'method': method, 'visit_id': row['visit_id'], 'candidate_id': row['candidate_id'],
        'evidence_id': row['evidence_id'], 'response_sha256': row['response_sha256'],
        'fixture_id': 'synthetic-dvwa', 'protocol_version': 'offline.v1',
        'timestamp': '2026-10-01T00:00:01+00:00', 'principal_id': 'user-1',
        'session_fingerprint': '1'*64, 'initial_session_fingerprint': '2'*64,
        'object_id': 'account-2', 'action': 'read', 'expected_allowed': False,
        'observed_allowed': True, 'credentials_valid': True, 'new_session': True,
        'initial_authenticated': False, 'expected_principal_id': 'user-1'}
    if method.startswith('ac_'):
        controls = [{**att, 'expected_allowed': allowed, 'observed_allowed': allowed,
            'expected_confirmed': False} for allowed in (False, True)]
    else:
        controls = [{**att, **change, 'expected_confirmed': False} for change in (
            {'new_session': False}, {'credentials_valid': False},
            {'session_fingerprint': att['initial_session_fingerprint']}, {'principal_id': 'other'})]
    doc = {'fixture_id': 'synthetic-dvwa', 'protocol_version': 'offline.v1',
        'attestations': [att], 'controls': controls}
    a['config']['scoring_oracles'] = [{'source_id': 'oracle', 'origin': 'offline_control',
        'document': doc, 'sha256': digest(doc)}]
    row['oracle_ref'] = '#/config/scoring_oracles/0/document/attestations/0'
    row['timestamp'] = '2026-10-01T00:00:00+00:00'
    row.update({k: att[k] for k in ('principal_id', 'expected_principal_id', 'object_id', 'action',
        'session_fingerprint', 'initial_session_fingerprint')})
    return a, row, att


def test_offline_sources_cannot_grade_unmarked_execution(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    ranking = artifact_v4(monkeypatch)
    ranking.pop('validation_scope')
    assert review_queue(export(ranking, 'unmarked-ranking'))['components']['Smethod'] is None
    oracle, row, _ = oracle_artifact(monkeypatch, 'ac_idor')
    oracle.pop('validation_scope')
    queue = review_queue(export(oracle, 'unmarked-oracle'))
    assert next(r for r in queue['candidates'] if r['candidate_id'] == row['candidate_id'])['proof_ceiling'] == 2


def test_all_pending_repeats_remain_visible(monkeypatch):
    from evaluation.thesis_scoring import review_queue, finalize_reviews, compare_receipts
    files = []
    for i in range(2):
        path = export(artifact_v4(monkeypatch), f'all-pending-{i}')
        q = review_queue(path)
        finalize_reviews(path, [])
        files.append(str(path.parent / 'reviews' / f"{q['execution_id']}.review-status.json"))
    groups = compare_receipts(files, planned_repeats=3)['groups']
    assert len(groups) == 2
    assert {g['scoring_mode'] for g in groups} == {'human', 'ai'}
    assert all((g['n_final'], g['n_pending'], g['n_planned']) == (0, 2, 3) for g in groups)
    assert all(g['output_stability'] is None and g['mean'] is None for g in groups)


@pytest.mark.parametrize('method,ceiling', [('ac_idor', 3), ('bf_dictionary', 2)])
def test_same_session_proof_depends_on_attestation_kind(monkeypatch, method, ceiling):
    from evaluation.thesis_scoring import review_queue
    a, row, att = oracle_artifact(monkeypatch, method)
    row['session_fingerprint'] = att['session_fingerprint'] = att['initial_session_fingerprint']
    bundle = a['config']['scoring_oracles'][0]
    for c in bundle['document']['controls']:
        if method.startswith('ac_'):
            c['session_fingerprint'] = c['initial_session_fingerprint']
    bundle['sha256'] = digest(bundle['document'])
    q = review_queue(export(a, f'{method}-same-session'))
    assert next(r for r in q['candidates'] if r['candidate_id'] == row['candidate_id'])['proof_ceiling'] == ceiling
