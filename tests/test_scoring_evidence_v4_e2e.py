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
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import pytest

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE
from evaluation.reporter import write_json_report
from tests.test_scoring_remediation_e2e import control
from tests.test_thesis_scoring_e2e import grades

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


def rehash(p):
    p['sha256'] = digest({k: v for k, v in p.items() if k != 'sha256'})


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
    call_input = {'observations': selection['observations']}
    output = {'next_agent': 'sqli_union', 'reason_code': 'supported observation',
        'reason_refs': ['union_select_possible'], 'plan': {'kind': 'stop_after_target'}}
    artifact['llm_performance'] = [{'call_id': 'call:1', 'role': 'orchestrator',
        'method': 'sqli_union', 'visit_id': selection['visit_id'], 'schema_version': 'orchestrator.v1',
        'input': call_input, 'output': output, 'input_sha256': digest(call_input),
        'output_sha256': digest(output), 'parse_status': 'ok', 'validation_status': 'valid',
        'attempt': 1, 'provider': 'offline', 'model': 'fixture',
        'started_at': '2026-10-01T00:00:00+00:00'}]
    return artifact


@pytest.mark.parametrize('case,expected', [('outside', 0), ('prerequisite', 1), ('lower', 2),
    ('unreferenced', 3), ('complete', 4), ('tie', 4), ('future_observation', 3), ('missing_profile', None)])
def test_ranking_export_review(monkeypatch, case, expected):
    from evaluation.thesis_scoring import review_queue
    artifact = artifact_v4(monkeypatch)
    selection = next(d for d in artifact['final_state']['scoring_decisions'] if d['dimension'] == 'Smethod')
    if case == 'outside': selection['surface'] = 'brute_force'
    if case == 'prerequisite': selection['observations']['union_select_possible'] = False
    if case == 'lower':
        artifact['config']['scoring_profile']['scenarios']['sqli:low']['sqli_error']['planned_request_count'] = 1
        rehash(artifact['config']['scoring_profile'])
        selection['profile_sha256'] = artifact['config']['scoring_profile']['sha256']
    if case == 'unreferenced': selection['reason_refs'] = []
    if case == 'future_observation': selection['reason_refs'] = ['not_in_snapshot']
    if case == 'missing_profile': artifact['config']['scoring_profile'] = {}
    queue = review_queue(export(artifact, case))
    assert queue['rubric_version'] == 'scoring.v4'
    assert queue['components']['Smethod'] == expected
    assert queue['selection_evidence']['selection_source'] == 'forced'
    if case == 'tie': assert len(queue['selection_evidence']['top_methods']) == 4


@pytest.mark.parametrize('case', ['hash', 'boolean_count', 'unknown_predicate', 'missing_method'])
def test_bad_profile_never_finalizes(monkeypatch, case):
    from evaluation.thesis_scoring import review_queue
    artifact = artifact_v4(monkeypatch)
    p = artifact['config']['scoring_profile']
    entry = p['scenarios']['sqli:low']['sqli_union']
    if case == 'hash': p['profile_id'] = 'tampered'
    if case == 'boolean_count': entry['planned_request_count'] = True; rehash(p)
    if case == 'unknown_predicate': entry['fit_predicates'][0]['key'] = 'imaginary'; rehash(p)
    if case == 'missing_method': del p['scenarios']['sqli:low']['sqli_error']; rehash(p)
    with pytest.raises(ValueError): review_queue(export(artifact, case))


@pytest.mark.parametrize('case,expected', [('complete', 4), ('unreferenced', 3), ('fake_ref', 3),
    ('retry', 2), ('unrecovered', 0), ('fallback', 1), ('containment', 0), ('other_method', 4),
    ('evaluator', 4), ('no_calls', None), ('missing_calls', None)])
def test_output_call_evidence(monkeypatch, case, expected):
    from evaluation.thesis_scoring import review_queue
    a = artifact_v4(monkeypatch)
    call = a['llm_performance'][0]
    if case == 'unreferenced': call['output']['reason_refs'] = []
    if case == 'fake_ref': call['output']['reason_refs'] = ['future']
    if case in {'retry', 'unrecovered', 'fallback'}:
        a['llm_performance'].insert(0, {**deepcopy(call), 'call_id': 'failed:1',
            'parse_status': 'invalid', 'validation_status': 'invalid'})
        if case == 'retry': call['attempt'] = 2
        if case == 'unrecovered': call['parse_status'] = 'invalid'; call['validation_status'] = 'invalid'
        if case == 'fallback': a['final_state']['fallback_events'] = [{'method': 'sqli_union',
            'fallback': 'static_seed', 'valid': True}]
    if case == 'containment': a['final_state']['containment_events'].append({'kind': 'request'})
    if case in {'other_method', 'evaluator'}:
        a['llm_performance'].append({**deepcopy(call), 'call_id': 'excluded:1',
            'method': 'sqli_error', 'role': 'evaluator' if case == 'evaluator' else 'orchestrator',
            'parse_status': 'invalid', 'validation_status': 'invalid'})
    if case in {'no_calls', 'missing_calls'}:
        a['llm_performance'] = []
        if case == 'no_calls': a['llm_activity'] = {'started': 0, 'completed': 0}
    call['output_sha256'] = digest(call['output'])
    q = review_queue(export(a, case))
    assert q['components']['Soutput'] == expected


def test_independent_receipts_pending_precision_and_source_hash(monkeypatch):
    from evaluation.thesis_scoring import review_queue, finalize_reviews, compare_receipts
    a = artifact_v4(monkeypatch)
    path = export(a, 'both')
    original = path.read_bytes()
    q = review_queue(path)
    assert not finalize_reviews(path, [])['receipts']
    decisions = [{**d, 'rubric_version': q['rubric_version']} for mode, score in [('human', 3), ('ai', 2)]
        for d in grades(q, mode, score)]
    result = finalize_reviews(path, decisions)
    assert set(result['receipts']) == {'human', 'ai'}
    receipts = [json.loads(Path(p).read_bytes()) for p in result['receipts'].values()]
    assert receipts[0]['Srun_final'] != receipts[1]['Srun_final']
    for r in receipts:
        assert r['rubric_version'] == 'scoring.v4'
        assert r['Srun_final'] == round(sum(r['components'][k]*w for k,w in r['formula'].items()), 4)
        assert r['source_sha256'] == sha256(original).hexdigest()
    assert path.read_bytes() == original
    comparison = compare_receipts(list(result['receipts'].values()))
    assert all(g['output_stability'] is None for g in comparison['groups'])
    assert result['fresh_http_calls'] == result['fresh_provider_calls'] == 0


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


@pytest.mark.parametrize('method', ['ac_idor', 'bf_dictionary'])
@pytest.mark.parametrize('case,ceiling', [('complete', 3), ('label_only', 2), ('wrong_candidate', 2),
    ('wrong_visit', 2), ('missing_controls', 2), ('permitted', 2), ('old_session', 2),
    ('other_identity', 2)])
def test_oracle_contract_through_review(monkeypatch, method, case, ceiling):
    from evaluation.thesis_scoring import review_queue
    a, row, att = oracle_artifact(monkeypatch, method)
    if case == 'label_only': row.pop('oracle_ref'); row['verification_reason'] = 'oracle_confirmed'
    if case == 'wrong_candidate': att['candidate_id'] = 'other'
    if case == 'wrong_visit': att['visit_id'] = 'other'
    if case == 'missing_controls': a['config']['scoring_oracles'][0]['document']['controls'] = []
    if case == 'permitted':
        if method.startswith('ac_'): att['expected_allowed'] = True
        else: att['credentials_valid'] = False
    if case == 'old_session': att['session_fingerprint'] = att['initial_session_fingerprint']
    if case == 'other_identity': att['principal_id'] = 'other'
    source = a['config']['scoring_oracles'][0]
    source['sha256'] = digest(source['document'])
    q = review_queue(export(a, f'{method}-{case}'))
    candidate = next(r for r in q['candidates'] if r['candidate_id'] == row['candidate_id'])
    assert candidate['proof_ceiling'] == ceiling


def test_offline_sources_cannot_grade_unmarked_execution(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    ranking = artifact_v4(monkeypatch)
    ranking.pop('validation_scope')
    assert review_queue(export(ranking, 'unmarked-ranking'))['components']['Smethod'] is None
    oracle, row, _ = oracle_artifact(monkeypatch, 'ac_idor')
    oracle.pop('validation_scope')
    queue = review_queue(export(oracle, 'unmarked-oracle'))
    assert next(r for r in queue['candidates'] if r['candidate_id'] == row['candidate_id'])['proof_ceiling'] == 2


def test_saved_operator_source_is_bound_to_response(monkeypatch):
    from evaluation.scoring_evidence import attach_oracle_evidence
    from evaluation.thesis_scoring import review_queue
    artifact, row, _ = oracle_artifact(monkeypatch, 'ac_idor')
    row.pop('oracle_ref')
    attach_oracle_evidence(artifact)
    assert row['oracle_ref'] == '#/config/scoring_oracles/0/document/attestations/0'
    queue = review_queue(export(artifact, 'attached-oracle'))
    assert next(r for r in queue['candidates'] if r['candidate_id'] == row['candidate_id'])['proof_ceiling'] == 3


def test_malformed_oracle_attestations_fail_before_review(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact, _, _ = oracle_artifact(monkeypatch, 'ac_idor')
    source = artifact['config']['scoring_oracles'][0]
    source['document']['attestations'] = None
    source['sha256'] = digest(source['document'])
    with pytest.raises(ValueError, match='attestations'):
        review_queue(export(artifact, 'malformed-attestations'))


@pytest.mark.parametrize('case,expected', [('weak', 1), ('claim', 0), ('missing_log', None)])
def test_passive_chain_opportunity(monkeypatch, case, expected):
    from evaluation.thesis_scoring import review_queue
    a = artifact_v4(monkeypatch)
    state = a['final_state']
    state['weak_chain_opportunities'] = []
    if case == 'weak':
        row = next(r for r in state['response_evidence'] if r['stage'] == 'exploit')
        row['verification_reason'] = 'partial_union_data'
        state['weak_chain_opportunities'].append({'opportunity_class': 'weak',
            'method': 'sqli_union', 'source': 'credentials_extracted', 'target': 'bf_dictionary',
            'target_agent': 'bf_dictionary', 'source_evidence_refs': [f"#/final_state/response_evidence/{state['response_evidence'].index(row)}"],
            'missing_material': ['complete_credentials'],
            'prerequisite_status': {'credentials_extracted': 'unproved'}})
    if case == 'claim': state['weak_chain_opportunities'].append({'opportunity_class': 'weak', 'method': 'sqli_union'})
    if case == 'missing_log': state.pop('weak_chain_opportunities')
    q = review_queue(export(a, case))
    assert q['components']['Schain'] == expected


def dependency_artifact(monkeypatch):
    a = artifact_v4(monkeypatch)
    b, dest, att = oracle_artifact(monkeypatch, 'bf_dictionary')
    state = a['final_state']
    source = next(r for r in state['response_evidence'] if r.get('verification_reason') == 'verified_account_extraction')
    source['timestamp'] = '2026-10-01T00:00:00+00:00'
    old_cid = dest['candidate_id']
    dest = deepcopy(dest)
    dest.update(candidate_id='bf:destination', evidence_id='response:3', visit_id='bf:visit:2',
        consumed_source_evidence_id=source['evidence_id'])
    state['response_evidence'].append(dest)
    candidate = next(c for c in b['final_state']['payload_candidates']['bf_dictionary'] if c['candidate_id'] == old_cid)
    state['payload_candidates']['bf_dictionary'] = [{**candidate, 'candidate_id': dest['candidate_id']}]
    state['payload_validation_results']['bf_dictionary'] = [{'candidate_id': dest['candidate_id'], 'valid': True}]
    state['payload_provenance'][dest['candidate_id']] = {'source': 'static_seed'}
    att.update(run_id=a['run_id'], execution_id=a['execution_id'], candidate_id=dest['candidate_id'],
        evidence_id=dest['evidence_id'], visit_id=dest['visit_id'])
    state['verifier_history'].append({'agent_id': 'bf_dictionary', 'visit_id': dest['visit_id'],
        'verifier_id': 'verifier:destination', 'decision': 'confirmed', 'source': 'method_agent_evidence',
        'evidence_refs': ['#/final_state/response_evidence/3'],
        'confirmed_vulns': ['bf_dictionary_confirmed'], 'achieved_outcomes': ['authenticated_session']})
    source_ref = f"#/final_state/response_evidence/{state['response_evidence'].index(source)}"
    consumption = {'route_id': 'route:1', 'source_candidate_id': source['candidate_id'],
        'source_visit_id': source['visit_id'], 'source_evidence_id': source['evidence_id'],
        'candidate_id': dest['candidate_id'], 'visit_id': dest['visit_id'],
        'destination_evidence_id': dest['evidence_id'],
        'dependency_ref': '#/config/scoring_oracles/0/document/dependencies/0'}
    dependency = {**consumption, 'depends_on_source': True, 'fixture_id': 'synthetic-dvwa',
        'protocol_version': 'offline.v1', 'run_id': a['run_id'], 'execution_id': a['execution_id'],
        'source_response_sha256': source['response_sha256'], 'destination_response_sha256': dest['response_sha256'],
        'material_fingerprint': '3'*64, 'source_at': '2026-10-01T00:00:00+00:00',
        'consumed_at': '2026-10-01T00:00:01+00:00', 'verified_at': '2026-10-01T00:00:02+00:00'}
    document = b['config']['scoring_oracles'][0]['document']
    document['dependencies'] = [dependency]
    document['dependency_controls'] = [{'source_available': available, 'destination_confirmed': available}
        for available in (False, True)]
    source_bundle = b['config']['scoring_oracles'][0]
    source_bundle['sha256'] = digest(document)
    a['config']['scoring_oracles'] = [source_bundle]
    state['chain_history'] = [{'route_id': 'route:1', 'source': 'credentials_extracted',
        'target': 'bf_dictionary', 'target_agent': 'bf_dictionary', 'target_visit_id': dest['visit_id'],
        'preconditions': ['credentials_extracted'], 'prerequisites_proved': True,
        'prerequisite_evidence_refs': {'credentials_extracted': ['#/final_state/verifier_history/0']},
        'source_evidence_refs': [source_ref], 'destination_evidence_refs': ['#/final_state/response_evidence/3'],
        'source_evidence_ids': [source['evidence_id']], 'destination_verifier_id': 'verifier:destination',
        'credited_method': 'bf_dictionary', 'status': 'completed', 'consumption': [consumption]}]
    return a, source, dest


@pytest.mark.parametrize('case,ceiling,exploit', [('complete', 4, 4), ('ready', 3, 3),
    ('wrong_candidate', 3, 3), ('wrong_visit', 3, 3), ('negative_destination', 3, 3),
    ('missing_prerequisite', 3, 3), ('no_independent_use', 3, 3), ('no_control', 3, 3)])
def test_candidate_use_and_automatic_exploit_are_separate(monkeypatch, case, ceiling, exploit):
    from evaluation.thesis_scoring import review_queue
    a, source, dest = dependency_artifact(monkeypatch)
    route = a['final_state']['chain_history'][0]
    if case == 'ready': route['status'] = 'ready'; route['consumption'] = []
    if case == 'wrong_candidate': route['consumption'][0]['source_candidate_id'] = 'other'
    if case == 'wrong_visit': route['consumption'][0]['source_visit_id'] = 'other'
    if case == 'negative_destination': a['final_state']['verifier_history'][-1]['decision'] = 'not_confirmed'
    if case == 'missing_prerequisite': route['prerequisite_evidence_refs'] = {}
    if case == 'no_independent_use': route['consumption'][0].pop('dependency_ref')
    if case == 'no_control':
        a['config']['scoring_oracles'][0]['document']['dependency_controls'] = []
        a['config']['scoring_oracles'][0]['sha256'] = digest(a['config']['scoring_oracles'][0]['document'])
    q = review_queue(export(a, case))
    row = next(r for r in q['candidates'] if r['candidate_id'] == source['candidate_id'])
    assert row['proof_ceiling'] == ceiling
    assert row['base_proof'] == 3
    assert q['components']['Sexploit'] == exploit
    assert dest['candidate_id'] not in {r['candidate_id'] for r in q['candidates']}


def final_method(a, method, visit):
    surface = next(s for s, methods in METHODS_BY_SURFACE.items() if method in methods)
    a['selected_method'] = a['final_state']['selected_method'] = method
    a['final_state']['selected_visit_id'] = visit
    a['config']['target_method'] = None
    a['config']['experiment_condition'] = 'akg_guided_hybrid'
    a['config']['surface'] = surface
    a['config']['scoring_profile'] = profile(surface)
    selection = deepcopy(next(d for d in a['final_state']['scoring_decisions'] if d['dimension'] == 'Smethod'))
    selection.update(method=method, surface=surface, visit_id=visit,
        profile_sha256=a['config']['scoring_profile']['sha256'], selection_source='akg_route',
        reason_refs=AttackKnowledgeGraph.METHOD_PRECONDITIONS[method], plan={'kind': 'continue_same_surface'})
    a['final_state']['scoring_decisions'].append(selection)
    call = deepcopy(a['llm_performance'][0])
    call.update(method=method, visit_id=visit, call_id='final:1')
    call['output'].update(next_agent=method, reason_refs=selection['reason_refs'])
    call['output_sha256'] = digest(call['output'])
    a['llm_performance'].append(call)


@pytest.mark.parametrize('broken', [False, True])
def test_two_causal_hops_and_final_destination_boundary(monkeypatch, broken):
    from evaluation.thesis_scoring import review_queue
    a, sql, bf = dependency_artifact(monkeypatch)
    c, dest, att = oracle_artifact(monkeypatch, 'ac_idor')
    state = a['final_state']
    old_cid = dest['candidate_id']
    dest = deepcopy(dest)
    dest.update(candidate_id='ac:destination', evidence_id='response:4', visit_id='ac:visit:3',
        consumed_source_evidence_id=bf['evidence_id'], oracle_ref='#/config/scoring_oracles/1/document/attestations/0')
    state['response_evidence'].append(dest)
    candidate = next(c for c in c['final_state']['payload_candidates']['ac_idor'] if c['candidate_id'] == old_cid)
    state['payload_candidates']['ac_idor'] = [{**candidate, 'candidate_id': dest['candidate_id']}]
    state['payload_validation_results']['ac_idor'] = [{'candidate_id': dest['candidate_id'], 'valid': True}]
    state['payload_provenance'][dest['candidate_id']] = {'source': 'static_seed'}
    att.update(run_id=a['run_id'], execution_id=a['execution_id'], candidate_id=dest['candidate_id'],
        evidence_id=dest['evidence_id'], visit_id=dest['visit_id'])
    state['verifier_history'].append({'agent_id': 'ac_idor', 'visit_id': dest['visit_id'],
        'verifier_id': 'verifier:ac', 'decision': 'confirmed', 'source': 'method_agent_evidence',
        'evidence_refs': ['#/final_state/response_evidence/4'], 'confirmed_vulns': ['ac_idor_confirmed']})
    consumption = {'route_id': 'route:2', 'source_candidate_id': bf['candidate_id'],
        'source_visit_id': bf['visit_id'], 'source_evidence_id': bf['evidence_id'],
        'candidate_id': dest['candidate_id'], 'visit_id': dest['visit_id'],
        'destination_evidence_id': dest['evidence_id'],
        'dependency_ref': '#/config/scoring_oracles/1/document/dependencies/0'}
    bundle = c['config']['scoring_oracles'][0]
    bundle['source_id'] = 'oracle:ac'
    document = bundle['document']
    document['dependencies'] = [{**consumption, 'depends_on_source': not broken,
        'run_id': a['run_id'], 'execution_id': a['execution_id'], 'fixture_id': 'synthetic-dvwa',
        'protocol_version': 'offline.v1', 'material_fingerprint': bf['session_fingerprint'],
        'source_response_sha256': bf['response_sha256'], 'destination_response_sha256': dest['response_sha256'],
        'source_at': '2026-10-01T00:00:02+00:00', 'consumed_at': '2026-10-01T00:00:03+00:00',
        'verified_at': '2026-10-01T00:00:04+00:00'}]
    document['dependency_controls'] = [{'source_available': available, 'destination_confirmed': available}
        for available in (False, True)]
    bundle['sha256'] = digest(document)
    a['config']['scoring_oracles'].append(bundle)
    state['chain_history'].append({'route_id': 'route:2', 'source': 'authenticated_session',
        'target': 'ac_idor', 'target_agent': 'ac_idor', 'target_visit_id': dest['visit_id'],
        'preconditions': ['authenticated_session'], 'prerequisites_proved': True,
        'prerequisite_evidence_refs': {'authenticated_session': ['#/final_state/verifier_history/1']},
        'source_evidence_refs': ['#/final_state/response_evidence/3'],
        'destination_evidence_refs': ['#/final_state/response_evidence/4'],
        'source_evidence_ids': [bf['evidence_id']], 'destination_verifier_id': 'verifier:ac',
        'credited_method': 'ac_idor', 'status': 'completed', 'consumption': [consumption]})
    final_method(a, 'ac_idor', dest['visit_id'])
    q = review_queue(export(a, 'two-hop'))
    assert q['components']['Schain'] == (0 if broken else 4)
    assert q['components']['Sexploit'] == 3
    assert {r['candidate_id'] for r in q['candidates']} == {dest['candidate_id']}
    assert q['candidates'][0]['proof_ceiling'] == 3


def test_one_hop_destination_scores_and_invalid_prerequisite(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    a, source, dest = dependency_artifact(monkeypatch)
    final_method(a, 'bf_dictionary', dest['visit_id'])
    q = review_queue(export(a, 'one-hop'))
    assert q['components']['Schain'] == 3 and q['components']['Sexploit'] == 3
    a['final_state']['chain_history'][0]['prerequisite_evidence_refs'] = {}
    q = review_queue(export(a, 'missing-prerequisite'))
    assert q['components']['Schain'] == 0


def test_output_stability_counts_final_pending_and_planned(monkeypatch):
    from evaluation.thesis_scoring import review_queue, finalize_reviews, compare_receipts
    files = []
    for i in range(3):
        path = export(artifact_v4(monkeypatch), f'repeat-{i}')
        q = review_queue(path)
        ds = [{**d, 'rubric_version': q['rubric_version']} for d in grades(q, 'human', 3)] if i < 2 else []
        result = finalize_reviews(path, ds)
        files.append(result['receipts']['human'] if i < 2 else str(path.parent / 'reviews' / f"{q['execution_id']}.review-status.json"))
    compared = compare_receipts(files, planned_repeats=4)
    group = compared['groups'][0]
    assert (group['n_final'], group['n_pending'], group['n_planned']) == (2, 1, 4)
    assert group['output_stability'] == 1
    assert group['output_stability_numerator'] == group['output_stability_denominator'] == 2
    write_json_report(ROOT / 'repeat-comparison.json', compared)


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


def test_report_tables_examples_and_package_preservation(tmp_path):
    from evaluation.rubric_document import update_document
    source = Path('metrik_penilaian_tesis.docx')
    handoff = Path('docs/active/HANDOFF_SCORING_EVIDENCE_AND_RUBRIC_COMPLETION_2026-10-01.md')
    result = update_document(source, handoff, tmp_path / 'rubric.docx')
    assert result['tables'] == 7 and result['examples'] == 35
    assert result['math_preserved'] is True and result['other_package_parts_preserved'] is True
    assert result['visual_layout'] == 'unverified'
    write_json_report(ROOT / 'docx-control.json', result)


@pytest.mark.parametrize('mode', ['off', 'auto'])
@pytest.mark.parametrize('optional', [
    {'reason_refs': 7}, {'reason_refs': 'union_select_possible'}, {'reason_refs': [7]},
    {'reason_refs': None}, {'plan': 7}, {'plan': []}, {'plan': None},
    {'plan': {}}, {'plan': {'kind': 7}}, {'plan': {'kind': 'invented'}},
    {'plan': {'kind': 'chain', 'source': 'credentials_extracted'}},
    {'plan': {'kind': 'stop_at_budget', 'extra': True}},
])
def test_optional_decision_rejection_keeps_selection_alive(monkeypatch, mode, optional):
    from types import SimpleNamespace
    from agents.orchestrator import orchestrator
    from core.state import new_default_state
    from llm.runtime import LLMRuntime, RoleSettings

    class Client:
        def with_structured_output(self, schema, **kwargs):
            raise ValueError('structured output unsupported')

        def invoke(self, messages):
            return SimpleNamespace(content=json.dumps({'next_agent': 'sqli_union',
                'reason_code': 'best_viable', **optional}), usage_metadata={}, response_metadata={})

    monkeypatch.setattr('llm.runtime.get_llm', lambda *a, **k: Client())
    state = new_default_state()
    state.update(target_url='http://localhost/dvwa', current_surface='sqli',
        observations={'union_select_possible': True}, selected_method='sqli_union')
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(coordinate_id='optional-fields', default_provider='openai_compatible',
        role_settings={'orchestrator': RoleSettings(structured_output=mode)}) as context:
        update = orchestrator(state)
    assert update['selected_method'] == 'sqli_union'
    assert update['fallback_events']
    assert context.records[-1]['validation_status'] == 'invalid'
    selection = update['scoring_decisions'][-1]
    assert selection['reason_refs'] == [] and selection['plan'] == {}
    write_json_report(ROOT / 'optional-fields' / f'{mode}-{digest(optional)}.json',
        {'input': optional, 'selection': selection, 'calls': context.records,
         'fallback': update['fallback_events'], 'fresh_http_calls': 0, 'fresh_provider_calls': 0})


def test_native_chain_plan_reaches_selection_grade_four(monkeypatch):
    from types import SimpleNamespace
    from agents.orchestrator import orchestrator
    from core.state import new_default_state
    from llm.runtime import LLMRuntime, RoleSettings
    from evaluation.thesis_scoring import review_queue
    a = artifact_v4(monkeypatch)
    plan = {'kind': 'chain', 'source': 'credentials_extracted',
        'target': 'bf_dictionary', 'target_agent': 'bf_dictionary'}
    decision = {'next_agent': 'sqli_union', 'reason_code': 'best_viable',
        'reason_refs': ['union_select_possible'], 'plan': plan}

    class Client:
        def with_structured_output(self, schema, **kwargs):
            plan_schema = schema['properties']['plan']
            assert set(plan) <= set(plan_schema['properties'])
            chain_schema = next(s for s in plan_schema['anyOf']
                if 'chain' in s['properties']['kind']['enum'])
            assert set(chain_schema['required']) == {'source', 'target', 'target_agent'}
            return SimpleNamespace(invoke=lambda messages: {
                'raw': SimpleNamespace(content='', usage_metadata={}, response_metadata={}),
                'parsed': decision})

    monkeypatch.setattr('llm.runtime.get_llm', lambda *a, **k: Client())
    p = a['config']['scoring_profile']
    p['scenarios']['sqli:low']['sqli_union']['allowed_plans'].append('chain')
    rehash(p)
    a['config'].update(target_method=None, experiment_condition='akg_guided_hybrid')
    state = new_default_state()
    state.update(target_url='http://localhost/dvwa', current_surface='sqli',
        experiment_condition='akg_guided_hybrid', scoring_profile=p,
        observations=a['final_state']['scoring_decisions'][0]['observations'])
    runtime = LLMRuntime(max_concurrency=1)
    with runtime.coordinate(coordinate_id='native-chain', default_provider='openai_compatible',
        role_settings={'orchestrator': RoleSettings(structured_output='native')}) as context:
        update = orchestrator(state)
    assert not update['fallback_events']
    assert update['scoring_decisions'][-1]['plan'] == plan
    a['final_state']['scoring_decisions'] = update['scoring_decisions']
    a['llm_performance'] = context.records
    q = review_queue(export(a, 'native-chain'))
    assert q['components']['Smethod'] == 4


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


@pytest.mark.parametrize('scope,origin,expected', [
    (None, 'offline_control', 3), ('offline_synthetic_fixture', 'offline_control', 4),
    (None, 'operator_fixture', 4)])
def test_dependency_origin_is_checked_separately_from_destination(monkeypatch, scope, origin, expected):
    from evaluation.thesis_scoring import review_queue
    a, source, dest = dependency_artifact(monkeypatch)
    if scope is None:
        a.pop('validation_scope')
    oracle = a['config']['scoring_oracles'][0]
    dependency = deepcopy(oracle)
    dependency.update(source_id='dependency', origin=origin)
    dependency['document'].pop('attestations')
    dependency['sha256'] = digest(dependency['document'])
    oracle['origin'] = 'operator_fixture'
    oracle['document'].pop('dependencies')
    oracle['sha256'] = digest(oracle['document'])
    a['config']['scoring_oracles'].append(dependency)
    a['final_state']['chain_history'][0]['consumption'][0]['dependency_ref'] = '#/config/scoring_oracles/1/document/dependencies/0'
    q = review_queue(export(a, f'dependency-{scope}-{origin}'))
    assert next(r for r in q['candidates'] if r['candidate_id'] == source['candidate_id'])['proof_ceiling'] == expected
    assert q['components']['Sexploit'] == expected
    final_method(a, 'bf_dictionary', dest['visit_id'])
    q = review_queue(export(a, f'dependency-destination-{scope}-{origin}'))
    assert q['components']['Schain'] == (3 if expected == 4 else 0)


@pytest.mark.parametrize('other', ['valid', 'invalid_role', 'invalid_visit', 'unvalidated'])
def test_fallback_applies_only_to_its_role_and_visit(monkeypatch, other):
    from evaluation.thesis_scoring import review_queue
    a = artifact_v4(monkeypatch)
    call = a['llm_performance'][0]
    fallback_call = deepcopy(call)
    fallback_call.update(call_id='payload-fallback', role='payload_generator',
        parse_status='invalid', validation_status='invalid')
    a['llm_performance'].append(fallback_call)
    a['final_state']['fallback_events'] = [{'method': 'sqli_union', 'origin': 'payload_generator',
        'visit_id': call['visit_id'], 'event': 'payload_generation.static_seed_fallback'}]
    if other == 'invalid_role':
        call.update(parse_status='invalid', validation_status='invalid')
    if other == 'invalid_visit':
        a['llm_performance'].append({**deepcopy(fallback_call), 'call_id': 'later-failure', 'visit_id': 'later'})
    if other == 'unvalidated':
        a['final_state']['payload_validation_results']['sqli_union'] = []
    q = review_queue(export(a, f'fallback-{other}'))
    assert q['components']['Soutput'] == (1 if other == 'valid' else 0)


@pytest.mark.parametrize('change', [None, 'protocol', 'origin'])
def test_oracle_receipts_group_by_protocol_with_pending_repeats(monkeypatch, change):
    from evaluation.thesis_scoring import review_queue, finalize_reviews, compare_receipts
    files, bundles = [], []
    for i in range(3):
        a, row, _ = oracle_artifact(monkeypatch, 'ac_idor')
        final_method(a, 'ac_idor', row['visit_id'])
        bundle = a['config']['scoring_oracles'][0]
        bundle['document']['oracle_protocol'] = {'version': 'attestation.v1'}
        if i and change == 'protocol':
            bundle['document']['oracle_protocol']['version'] = 'attestation.v2'
        if i and change == 'origin':
            bundle['origin'] = 'operator_fixture'
        bundle['sha256'] = digest(bundle['document'])
        path = export(a, f'oracle-repeat-{change}-{i}')
        q = review_queue(path)
        decisions = [{**d, 'rubric_version': q['rubric_version']} for d in grades(q, 'human', 3)] if i < 2 else []
        result = finalize_reviews(path, decisions)
        if i < 2:
            receipt = result['receipts']['human']
            files.append(receipt)
            bundles.append(json.loads(Path(receipt).read_bytes())['config']['scoring_oracles'])
        else:
            files.append(str(path.parent / 'reviews' / f"{q['execution_id']}.review-status.json"))
    assert bundles[0] != bundles[1]  # Attestations remain execution-specific in receipts.
    compared = compare_receipts(files, planned_repeats=4)
    human = [g for g in compared['groups'] if g['scoring_mode'] == 'human']
    assert len(human) == (1 if change is None else 2)
    if change is None:
        assert (human[0]['n_final'], human[0]['n_pending'], human[0]['n_planned']) == (2, 1, 4)
        assert human[0]['output_stability'] == 1
    write_json_report(ROOT / f'oracle-repeat-comparison-{change}.json', compared)


@pytest.mark.parametrize('condition', ['linear_hybrid', 'akg_guided_hybrid'])
@pytest.mark.parametrize('level', ['low', 'medium', 'high'])
@pytest.mark.parametrize('surface,method', [(s,m) for s,methods in METHODS_BY_SURFACE.items() for m in methods])
def test_offline_ai_checking_matrix(monkeypatch, condition, level, surface, method):
    """All primary method/security/condition coordinates; fake external I/O only."""
    from evaluation.runner import run_single_engagement
    from evaluation.thesis_scoring import review_queue, evaluate_queue, finalize_reviews
    from tests.test_method_agents_e2e import Fixture
    import httpx
    fixture = Fixture(method, level, 'generated_valid')
    import importlib
    from types import SimpleNamespace
    if method == 'sqli_time_blind':
        monkeypatch.setattr(importlib.import_module('agents.sqli.sqli_time_blind_agent'), 'time', SimpleNamespace(monotonic=lambda: fixture.clock))
    if method.startswith('bf_'):
        monkeypatch.setattr(importlib.import_module(f'agents.brute_force.{method}_agent'), 'time_mod',
            SimpleNamespace(monotonic=lambda: fixture.clock, sleep=lambda _: None))
    monkeypatch.setattr(httpx.Client, 'request', lambda client,*a,**k: fixture.request(client,*a,**k))
    monkeypatch.setattr('llm.runtime.get_llm', lambda *a,**k: fixture)
    evaluator = {'provider': 'openai_compatible', 'model': 'offline-checker',
        'max_attempts': 1, 'max_tokens': 512, 'timeout': 5}
    a = run_single_engagement(target_url='http://localhost/dvwa', security_level=level,
        llm_provider='openai_compatible', surface=surface, payload_mode='hybrid',
        experiment_condition=condition, target_method=method, max_iterations=12,
        scoring_rubric_version='scoring.v4', scoring_mode='ai', scoring_evaluator=evaluator,
        execution_id=f'offline-{condition}-{method}-{level}',
        llm_role_configs={r: {'structured_output': 'off'} for r in ('orchestrator', 'payload_generator')})
    assert a.get('report') and (a.get('error') is None or str(a['error']).startswith('Experiment incomplete:'))
    a['validation_scope'] = 'offline_synthetic_fixture'
    path = export(a, f'matrix-{condition}-{method}-{level}')
    q = review_queue(path)
    calls = fixture.provider_calls
    def judge(messages):
        evidence = json.loads(messages[-1].content)
        return json.dumps({'score': evidence['proof_ceiling'], 'reason': 'Offline evidence ceiling control',
            'evidence_refs': evidence['evidence_refs']})
    evaluated = evaluate_queue(q, evaluator, invoke=judge)
    result = finalize_reviews(path, evaluated['decisions'])
    assert fixture.provider_calls == calls
    assert result['fresh_http_calls'] == result['fresh_provider_calls'] == 0
    assert set(result['workflows']) == {'ai'}
    assert all(r['proof_ceiling'] <= 2 for r in q['candidates'] if r['proof_ceiling'] is not None) if method.startswith(('ac_', 'bf_')) else True
    assert not result['receipts']  # No invented preregistered research profile.
    write_json_report(path.parent / 'matrix-control.json', {'validation_scope': 'offline_synthetic_fixture',
        'method': method, 'surface': surface, 'security_level': level, 'condition': condition,
        'source_sha256': q['source_sha256'], 'components': q['components'], 'ai_status': evaluated['status'],
        'ai_mock_calls': len(evaluated['telemetry']), 'attack_mock_calls': calls,
        'fresh_http_calls': 0, 'fresh_provider_calls': 0, 'result': result})
