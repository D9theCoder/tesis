"""Scoring failure controls declared before remediation; external I/O only is faked.

Inventory: results/validation/scoring-remediation-2026-09-29/failure-inventory.json.
Each control retains graph inputs, transport receipts, decisions and real exports.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from langgraph.types import Overwrite

from core.graph_builder import build_framework
from core.state import new_default_state
from evaluation.manual_scoring_sheet import manual_scoring_rows
from evaluation.reporter import write_json_report
from evaluation.runner import run_single_engagement
from foundation.http_client import ContainmentError, HTTPClient
from tests.test_method_agents_e2e import Fixture


ROOT = Path('results/validation/scoring-remediation-2026-09-29')


class ScoringFixture(Fixture):
    def __init__(self, method, control):
        super().__init__(method, 'low', 'positive')
        self.scoring_control = control
        if control == 'mixed_candidates':
            self.generation = 'generated_valid'
        self.union_exploits = []
        from foundation.payload_library import PayloadLibrary
        self.failed_union = next(c['payload_or_logic'] for c in PayloadLibrary().load_seed_candidates(method, 'low') if c['stage'] == 'exploit')

    def invoke(self, messages, **kwargs):
        if self.scoring_control == 'invalid_json':
            self.provider_calls += 1
            return SimpleNamespace(content='{', usage_metadata={}, response_metadata={})
        if self.scoring_control == 'provider_timeout':
            self.provider_calls += 1
            raise httpx.ReadTimeout('offline timeout')
        return super().invoke(messages, **kwargs)

    def body(self, session, verb, path, data):
        if 'brute/' in path:
            method = self.method
            self.method = 'bf_dictionary'
            try:
                if self.scoring_control == 'failed_chain':
                    self.control = 'negative'
                return super().body(session, verb, path, data)
            finally:
                self.method = method
                self.control = 'positive'
        result = super().body(session, verb, path, data)
        if path.endswith('index.php'):
            return (result[0] + '<a href="https://external.invalid/vulnerabilities/sqli/">External</a>', *result[1:])
        if self.scoring_control == 'discarded_form' and path.endswith('vulnerabilities/sqli/') and not data:
            return (result[0] + '<form action="https://external.invalid/submit"><input name="id"></form>', *result[1:])
        value = str(data.get('id', ''))
        if self.method == 'sqli_union' and value and value not in self.probes:
            self.union_exploits.append(value)
            if self.control == 'negative':
                return ('No extraction evidence', 200, .01)
            if self.scoring_control == 'mixed_candidates' and value == self.failed_union:
                return ('You have an error in your SQL syntax', 200, .01)
            if self.scoring_control == 'plaintext_chain':
                return ('First name: admin<br>Surname: password', 200, .01)
        return result


def control(monkeypatch, name, *, automatic=False, condition='linear_hybrid', method='sqli_union'):
    fixture = ScoringFixture(method, name)
    monkeypatch.setattr(httpx.Client, 'request', lambda client, *a, **k: fixture.request(client, *a, **k))
    monkeypatch.setattr('llm.runtime.get_llm', lambda *a, **k: fixture)
    monkeypatch.setattr('agents.orchestrator.get_llm', lambda *a, **k: fixture)
    monkeypatch.setattr('foundation.payload_generator.get_llm', lambda *a, **k: fixture)
    graph = build_framework()
    monkeypatch.setattr('evaluation.runner.build_framework', lambda **kwargs: graph)
    config = dict(target_url='http://localhost/dvwa', security_level='low',
        llm_provider='openai_compatible', surface='sqli', payload_mode='hybrid' if name == 'mixed_candidates' else 'static_only',
        target_method=None if automatic else method, experiment_condition=condition,
        max_iterations=12, execution_id=name, output_dir=str(ROOT / 'controls' / name),
        llm_role_configs={r: {'structured_output': 'off'} for r in ('orchestrator', 'payload_generator')})
    artifact = run_single_engagement(**config)
    write_json_report(ROOT / 'controls' / name / 'fixture.json', {
        'kind': 'offline_control', 'config': config, 'requests': fixture.requests,
        'fresh_http_calls': 0, 'fresh_provider_calls': 0, 'fake_provider_calls': fixture.provider_calls,
        'expected': name, 'code_sha256': {str(p): sha256(p.read_bytes()).hexdigest()
            for p in (Path('core/scorer.py'), Path('core/state.py'), Path('agents/state_utils.py'))}})
    assert artifact.get('report'), artifact.get('error')
    assert all(httpx.URL(r['url']).host == 'localhost' for r in fixture.requests)
    return artifact, fixture, graph


def save_graph(name, state, fixture):
    from tesis.runtime_events import redact_secrets
    state = redact_secrets({k: v for k, v in state.items() if k not in {'messages', 'model_config'}})
    artifact = {'kind': 'offline_graph_control', 'final_state': state,
        'config': {'provider': 'openai_compatible'},
        'response_evidence': state['response_evidence'], 'timing_evidence': state['timing_evidence'],
        'verifier_decision': state['verifier_decision'], 'scoring_decisions': state.get('scoring_decisions', []),
        'requests': fixture.requests, 'fresh_http_calls': 0, 'fresh_provider_calls': 0}
    artifact['manual_scoring_evidence'] = manual_scoring_rows(artifact)
    write_json_report(ROOT / 'controls' / name / 'graph.json', artifact)
    return artifact


def assert_vector(state):
    method = state['selected_method']
    ids = {c['candidate_id'] for c in state['payload_candidates'][method]}
    vector = [state['method_scores'].get(method, 0),
        max((v for cid, v in state['payload_scores'].items() if cid in ids), default=0),
        state['exploitation_scores'].get(method, 0), state['chain_scores'].get(method, 0),
        state['output_scores'][method]]
    assert state['composite_scores'][method] == round(sum(w*v for w, v in zip([.2, .2, .3, .1, .2], vector)), 4)


def test_scoring_navigation_and_complete_export(monkeypatch):
    artifact, fixture, _ = control(monkeypatch, 'navigation')
    state = artifact['final_state']
    assert state['output_scores']['sqli_union'] == 4
    assert state['containment_events'][0]['classification'] == 'discarded_navigation'
    for field in ('chain_history', 'current_chain', 'found_credentials', 'attempted_agents',
                  'tried_payloads', 'verifier_history', 'scoring_decisions', 'selected_visit_id'):
        assert field in state
    assert state['found_credentials'][0]['password'] == '[REDACTED]'
    assert {d['dimension'] for d in state['scoring_decisions']} == {'Smethod', 'Spayload', 'Sexploit', 'Schain', 'Soutput', 'Srun'}
    assert all(d['rubric_version'] and d['method'] and d['visit_id'] and d['aggregation'] for d in state['scoring_decisions'])
    assert fixture.provider_calls == 0
    assert_vector(state)
    assert manual_scoring_rows(artifact) == artifact['manual_scoring_evidence']


def test_scoring_discarded_page_form_is_only_a_recon_observation(monkeypatch):
    artifact, fixture, _ = control(monkeypatch, 'discarded_form')
    assert artifact['output_score'] == 4
    assert any(e['kind'] == 'form' and e['classification'] == 'discarded_page_reference'
        for e in artifact['containment_events'])
    assert not any('external.invalid' in r['url'] for r in fixture.requests)


@pytest.mark.parametrize('kind', ['request', 'redirect'])
def test_scoring_real_scope_penalty_survives_graph_reducers(monkeypatch, kind):
    artifact, fixture, graph = control(monkeypatch, f'penalty-{kind}')
    threads = list(graph.checkpointer.storage)
    config = {'configurable': {'thread_id': threads[0]}}
    client = HTTPClient('http://localhost/dvwa')
    before = len(fixture.requests)
    try:
        with pytest.raises(ContainmentError):
            if kind == 'request':
                client.get('https://external.invalid/escape')
            else:
                def redirect(session, verb, url, **kwargs):
                    fixture.requests.append({'url': str(url), 'verb': verb, 'data': {}})
                    return httpx.Response(302, headers={'Location': 'https://external.invalid/escape'}, request=httpx.Request(verb, url))
                monkeypatch.setattr(httpx.Client, 'request', redirect)
                client.get('vulnerabilities/sqli/')
        violation = deepcopy(client.containment_events)
    finally:
        client.close()
    assert len(fixture.requests) == before + (kind == 'redirect')
    graph.update_state(config, {'containment_events': violation}, as_node='chaining_router')
    final = graph.invoke(None, config=config)
    save_graph(f'penalty-{kind}', final, fixture)
    assert artifact['output_score'] == 4
    assert final['output_scores']['sqli_union'] == 0
    assert final['exploitation_scores']['sqli_union'] == 3
    assert_vector(final)
    outputs = [d['score'] for d in final['scoring_decisions'] if d['dimension'] == 'Soutput']
    assert outputs[0] == 4 and outputs[-1] == 0


def test_scoring_candidate_evidence_and_revisit(monkeypatch):
    artifact, fixture, graph = control(monkeypatch, 'mixed_candidates')
    state = artifact['final_state']
    exploit = [r for r in artifact['response_evidence'] if r['stage'] == 'exploit']
    failed, success = exploit[:2]
    assert state['payload_scores'][failed['candidate_id']] == 0
    assert state['payload_scores'][success['candidate_id']] == 3
    assert state['payload_provenance'][failed['candidate_id']]['source'] == 'static_seed'
    assert state['payload_provenance'][success['candidate_id']]['source'] == 'llm_generated'
    probes = [r for r in artifact['response_evidence'] if r['stage'] == 'probe']
    assert all(state['payload_scores'][r['candidate_id']] <= 1 for r in probes)
    unused = {c['candidate_id'] for c in state['payload_candidates']['sqli_union']} - {r['candidate_id'] for r in artifact['response_evidence'] if r.get('candidate_id')}
    assert unused and all(cid not in state['payload_scores'] for cid in unused)
    fixture.control = 'negative'
    config = {'configurable': {'thread_id': next(iter(graph.checkpointer.storage))}}
    graph.update_state(config, {'tried_payloads': Overwrite({})}, as_node='recon')
    final = graph.invoke(None, config=config)
    exported = save_graph('candidate-revisit', final, fixture)
    decisions = [d for d in final['scoring_decisions'] if d['dimension'] == 'Spayload' and d.get('candidate_id') == success['candidate_id']]
    assert [d['score'] for d in decisions] == [3, 0]
    assert final['payload_scores'][success['candidate_id']] == 3
    row = next(r for r in exported['manual_scoring_evidence'] if r['candidate_id'] == success['candidate_id'])
    assert row['scoring_decision']['decision_id'] == decisions[0]['decision_id']
    assert row['verifier_decision']['decision'] == 'confirmed'
    assert row['later_verifier_decisions'][-1]['decision'] == 'not_confirmed'
    assert_vector(final)


@pytest.mark.parametrize('name,credit,status', [
    ('plaintext_chain', 4, 'completed'), ('hash_chain', 0, 'unverified'),
    ('failed_chain', 0, 'failed'),
])
def test_scoring_chain_dependency_and_routed_selection(monkeypatch, name, credit, status):
    artifact, _, graph = control(monkeypatch, name, automatic=True, condition='akg_guided_hybrid')
    state = artifact['final_state']
    assert state['chain_scores']['bf_dictionary'] == credit
    routes = [h for h in state['chain_history'] if h.get('target_agent') == 'bf_dictionary']
    assert [h['status'] for h in routes] == ['ready', 'routed', 'executed', status]
    destination = [d for d in state['scoring_decisions'] if d['dimension'] == 'Smethod' and d['method'] == 'bf_dictionary']
    assert destination[0]['selection_source'] == 'akg_route'
    assert destination[0]['surface'] == 'brute_force'
    assert destination[0]['score'] == (3 if destination[0]['viable'] else 1)
    events = [e for e in artifact['execution_log'] if e['event_type'] == 'akg.route.selected']
    assert any(e['data'].get('source') and e['data'].get('preconditions') for e in events)
    if credit:
        receipt = routes[-1]
        assert receipt['consumption'] and receipt['source_evidence_refs'] and receipt['destination_evidence_refs']
        assert receipt['credited_method'] == 'bf_dictionary'
        config = {'configurable': {'thread_id': next(iter(graph.checkpointer.storage))}}
        graph.update_state(config, {}, as_node='bf_dictionary')
        again = graph.invoke(None, config=config)
        assert len([h for h in again['chain_history'] if h['status'] == 'completed']) == 1
    assert_vector(state)


def test_scoring_linear_forced_and_authorization_zeros(monkeypatch):
    forced, _, _ = control(monkeypatch, 'plaintext_chain', condition='akg_guided_hybrid')
    assert forced['chain_score'] == 0 and not forced['final_state']['chain_history']
    linear, _, _ = control(monkeypatch, 'plaintext_chain', automatic=True)
    assert not linear['final_state']['chain_history'] and linear['chain_score'] == 0
    chained, _, _ = control(monkeypatch, 'hash_chain', automatic=True, condition='akg_guided_hybrid')
    state = chained['final_state']
    assert state['exploitation_scores'].get('ac_idor', 0) < 3
    assert state['chain_scores'].get('ac_idor', 0) == 0
    assert 'sqli_confirmed' not in state['confirmed_vulns']
    assert 'credentials_extracted' not in state['confirmed_vulns']


def test_scoring_ready_route_does_not_earn_completion(monkeypatch):
    artifact, fixture, _ = control(monkeypatch, 'plaintext_chain')
    graph = build_framework()
    config = {'configurable': {'thread_id': 'ready-route'}}
    state = new_default_state()
    state.update(target_url='http://localhost/dvwa', current_surface='sqli',
        experiment_condition='akg_guided_hybrid', max_iterations=12)
    fixture.provider_calls = 0
    list(graph.stream(state, config=config, interrupt_after=['chaining_router']))
    paused = graph.get_state(config).values
    save_graph('ready-route', paused, fixture)
    assert paused['chain_history'][-1]['status'] == 'routed'
    assert not any(paused['chain_scores'].values())
    assert not any(d['dimension'] == 'Schain' and d['score'] == 4 for d in paused['scoring_decisions'])


@pytest.mark.parametrize('name,grade,invalid', [('invalid_json', 2, True), ('provider_timeout', 3, False)])
def test_scoring_provider_failure_is_distinct_from_returned_invalid_json(monkeypatch, name, grade, invalid):
    artifact, _, _ = control(monkeypatch, name, automatic=True)
    assert bool(artifact['invalid_json_events']) is invalid
    assert artifact['output_score'] == grade
    assert_vector(artifact['final_state'])


def test_scoring_saved_data_repair_uses_no_transport_or_provider(monkeypatch):
    from evaluation.scoring_repair import rescore_saved_artifact
    # Failure control: a missing terminal chain log must stay missing after
    # hash-pinned rescoring; setup cannot depend on a local historical archive.
    artifact, _, _ = control(monkeypatch, 'saved_data')
    artifact['validation_scope'] = 'offline_synthetic_fixture'
    artifact['final_state'].pop('chain_history')
    source = ROOT / 'controls' / 'saved-data' / 'source.json'
    write_json_report(source, artifact)
    before = source.read_bytes()
    def forbidden(*args, **kwargs):
        pytest.fail('Pure rescoring attempted external I/O')
    monkeypatch.setattr(httpx.Client, 'request', forbidden)
    monkeypatch.setattr('llm.runtime.LLMRuntime.invoke', forbidden)
    repaired = rescore_saved_artifact(source, expected_sha256=sha256(before).hexdigest())
    write_json_report(ROOT / 'controls' / 'saved-data' / 'rescored.json', repaired)
    assert source.read_bytes() == before
    assert repaired['source_sha256'] == sha256(before).hexdigest()
    assert repaired['fresh_http_calls'] == repaired['fresh_provider_calls'] == 0
    assert repaired['corrected_score_vector']['Soutput'] == 4
    assert repaired['corrected_score_vector']['Schain'] == 0
    assert 'chain_history' in repaired['legacy_evidence_gaps']
    assert 'chain_history' not in repaired['final_state']
    assert {d['dimension'] for d in repaired['component_comparison']} == {'Smethod', 'Spayload', 'Sexploit', 'Schain', 'Soutput', 'Srun'}
    assert_vector(repaired['final_state'])
    with pytest.raises(ValueError, match='hash'):
        rescore_saved_artifact(source, expected_sha256='wrong')


@pytest.mark.parametrize('method,name', [('sqli_time_blind', 'negative'),
    ('sqli_boolean_blind', 'negative'), ('ac_idor', 'negative'), ('bf_dictionary', 'throttle')])
def test_scoring_probe_candidates_require_the_declared_signal(monkeypatch, method, name):
    from tests import test_method_agents_e2e as existing
    monkeypatch.setattr(existing, 'EVIDENCE', ROOT / 'controls' / 'probe-signals')
    artifact, _ = existing.run_control(monkeypatch, method, 'low', name)
    probes = [r for r in artifact['response_evidence'] if r['stage'] == 'probe']
    assert probes
    assert all(artifact['final_state']['payload_scores'][r['candidate_id']] == 0 for r in probes)


def test_scoring_candidate_receipts_retain_the_response_that_earned_the_grade(monkeypatch):
    artifact, _, _ = control(monkeypatch, 'mixed_candidates')
    failed, success = [r for r in artifact['response_evidence'] if r['stage'] == 'exploit'][:2]
    assert failed['response_sha256'] == sha256(b'You have an error in your SQL syntax').hexdigest()
    assert 'SQL syntax' in failed['response_excerpt']
    assert 'First name: admin' in success['response_excerpt']
    assert success['credentials'] == '[REDACTED]'
    assert artifact['final_state']['found_credentials'][0]['password'] == '[REDACTED]'
    assert '5f4dcc3b5aa765d61d8327deb882cf99' not in success['response_excerpt']
    assert len(success['response_sha256']) == 64


def test_scoring_sanitized_frozen_chain_input_replays_source_binding(monkeypatch):
    from evaluation.payload_replay import replay_method_inputs
    artifact, fixture, _ = control(monkeypatch, 'plaintext_chain', automatic=True, condition='akg_guided_hybrid')
    frozen = next(item for item in artifact['method_execution_inputs'] if item['method'] == 'bf_dictionary')
    recovered = frozen['state']['found_credentials'][0]
    assert recovered['password'] == '[REDACTED]'
    bindings = frozen['state']['active_chain_route']['source_bindings']
    assert bindings and bindings[0]['source_evidence_id'] == recovered['source_evidence_id']
    assert bindings[0]['candidate_id'] in {c['candidate_id'] for c in frozen['state']['payload_candidates']['bf_dictionary']}
    source = ROOT / 'controls' / 'plaintext_chain' / 'plaintext_chain.json'
    calls = fixture.provider_calls
    replay = replay_method_inputs(source, output_path=ROOT / 'controls' / 'plaintext_chain' / f'dictionary-replay-{uuid4().hex}.json',
        input_index=artifact['method_execution_inputs'].index(frozen))
    assert fixture.provider_calls == calls and replay['fresh_provider_calls'] == 0
    assert replay['final_state']['chain_consumption']
    assert replay['final_state']['chain_consumption'][-1]['source_evidence_id'] == recovered['source_evidence_id']
