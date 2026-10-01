"""Artifact-backed graph controls; only external transport/provider are faked.

Failure inventory: docs/completed/METHOD_AGENTS_FAILURE_CONTROLS_2026-09-29.md.
Fixture ground truth is literal data/status, independent of agent verifiers.
"""
from copy import deepcopy
from datetime import timedelta
import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from uuid import uuid4

from agents.agent_telemetry import exploit_event
from agents.state_utils import make_update
from core.state import METHODS_BY_SURFACE, new_default_state
from evaluation.manual_scoring_sheet import manual_scoring_rows
from evaluation.runner import run_single_engagement

EVIDENCE = Path('results/validation/method-agents-2026-09-29/offline')
CASES = [(surface, method) for surface, methods in METHODS_BY_SURFACE.items() for method in methods]
HASH = '5f4dcc3b5aa765d61d8327deb882cf99'
REVIEW_EVIDENCE = Path('results/validation/review-fixes-2026-09-29')


class Fixture:
    def __init__(self, method, level, control):
        self.method, self.level, self.control = method, level, control
        self.generation = control
        if control.startswith("generated_"):
            self.control = "positive"
        if control.startswith('generated_false'):
            self.control = 'mixed_predicates'
        self.clock = 100.0
        self.requests = []
        self.stored = {}
        self.baselines = 0
        self.provider_calls = 0
        self.boolean_attempts = {}
        self.payload_generations = 0
        self.decisions = 0
        if control == "repeat_method":
            self.control = "positive"
        seeds = __import__('foundation.payload_library', fromlist=['PayloadLibrary']).PayloadLibrary().load_seed_candidates(method, level)
        self.probes = {s['payload_or_logic'] for s in seeds if s['stage'] == 'probe'}

    def request(self, client, verb, url, **kwargs):
        data = dict(kwargs.get('params') or kwargs.get('data') or {})
        cookie_id = __import__('urllib.parse', fromlist=['unquote']).unquote(client.cookies.get('id') or '') if self.level == 'high' else None
        if cookie_id:
            data['id'] = cookie_id
        url = str(url)
        path = httpx.URL(url).path
        self.requests.append({'session': id(client), 'verb': verb, 'url': url, 'data': data, 'cookie_id': cookie_id})
        body, status, delay = self.body(id(client), verb, path, data)
        self.clock += delay
        result = httpx.Response(status, text=body, request=httpx.Request(verb, url), headers={})
        result.elapsed = timedelta(seconds=delay)
        return result

    def body(self, session, verb, path, data):
        if path.endswith('login.php'):
            return ('<a href="logout.php">Logout</a>' if verb == 'POST' else '<input name="user_token" value="fixture-token">', 200, .01)
        if path.endswith('security.php'):
            return (f'DVWA Security Level: {self.level}<form><input name="user_token" value="fixture-token"></form>Database Setup', 200, .01)
        if path.endswith('index.php'):
            return ('<a href="vulnerabilities/sqli/">SQLi</a><a href="vulnerabilities/sqli_blind/">Blind</a><a href="vulnerabilities/authbypass/">AC</a><a href="vulnerabilities/brute/">Brute</a>', 200, .01)
        if path.endswith('setup.php') or path.endswith('phpinfo.php') or path.endswith('view_source.php'):
            return ('Database Setup View Source phpinfo()', 403 if self.control == 'negative' else 200, .01)
        if path.endswith('session-input.php'):
            self.stored[session] = data.get('id', '')
            return ('Stored', 503 if self.control == 'failed_submit' else 200, .01)
        if not data and not (self.level == 'high' and session in self.stored):
            field = 'username' if 'brute/' in path else ('userId' if 'authbypass/' in path else 'id')
            return (f'<form action="{path}"><input name="{field}"><input name="user_token" value="fixture-token"></form>', 200, .01)
        value = str(data.get('id', self.stored.get(session, '')))
        probe = value in self.probes
        if self.method.startswith('bf_'):
            username = data.get('username')
            if username in {'rate_test', 'probe'}:
                if self.control == 'failed_probe':
                    raise httpx.ConnectError('fixture unavailable')
                if self.control == 'rejected_probe':
                    return ('CSRF token is incorrect', 200, .01)
                if self.control == 'probe_jitter':
                    return ('Username and/or password incorrect', 200, .005 if username == 'rate_test' else .04)
                if self.control == 'error_probe':
                    return ('Service unavailable', 503, .01)
                if self.control == 'throttle':
                    return ('Too many requests', 429, .01)
                return ('Username and/or password incorrect', 200, .01)
            if self.control == 'captcha':
                return ('<form><input name="captcha"></form>', 200, .01)
            if self.control == 'token_error':
                return ('CSRF token is incorrect; password protected area', 403, .01)
            if self.control == 'http_error':
                return ('Welcome to the password protected area', 503, .01)
            if self.control in {'positive', 'probe_jitter'} and (username, data.get('password')) == ('admin', 'password'):
                return ('Welcome to the password protected area', 200, .01)
            return ('Username and/or password incorrect', 200, .01)
        if self.method == 'sqli_time_blind':
            if value == '1':
                self.baselines += 1
                if self.control == 'failed_baseline' and self.baselines > 3:
                    raise httpx.ConnectError('fixture baseline unavailable')
                return ('Harmless control', 200, 3.01 if self.control == 'uniform_slow' else .01)
            error = self.control in {'http_error', 'http_forbidden'} and not probe
            status = (403 if self.control == 'http_forbidden' else 503) if error else 200
            delay = 3.01 if self.control != 'negative' else .01
            if self.control == 'mixed_timing' and '>100' in value:
                delay = .01
            if self.control == 'jitter' and not probe:
                delay = 8.01
            if self.control == 'missing_delay':
                return ('User ID is missing from the database', 404, delay)
            if self.control == 'generic_404':
                return ('Gateway page unavailable', 404, delay)
            return ('User ID exists in the database', status, delay)
        if self.method == 'sqli_error':
            if probe:
                return ('You have an error in your SQL syntax', 200, .01)
            if self.generation.startswith('generated_duplicate_') and 'FLOOR(RAND(0)*2)' in value:
                control = self.generation.removeprefix('generated_duplicate_')
                bodies = {'zero': "<pre>Duplicate entry 'dvwa0' for key 'group_key'</pre>",
                    'one': "<pre>Duplicate entry 'dvwa1' for key 'group_key'</pre>",
                    'unrelated': "<pre>Duplicate entry 'admin1' for key 'group_key'</pre>",
                    'wrong_key': "<pre>Duplicate entry 'dvwa1' for key 'users.PRIMARY'</pre>",
                    'prose': "Tutorial: Duplicate entry 'dvwa1' for key 'group_key'",
                    'http_error': "<pre>Duplicate entry 'dvwa1' for key 'group_key'</pre>"}
                return (bodies[control], 503 if control == 'http_error' else 200, .01)
            bodies = {'positive': "XPATH syntax error: '~dvwa'", 'truncated': "XPATH syntax error: '~admin", 'negative': 'Normal page', 'tilde': 'Approximate value ~ 10; no extracted database data', 'xpath': 'Read the xpath tutorial', 'credentials': f'Unrelated admin:{HASH}'}
            return (bodies.get(self.control, 'Normal page'), 503 if self.control == 'http_error' else 200, .01)
        if self.method == 'sqli_union':
            if probe:
                return ('First name: NULL<br>Surname: NULL', 200, .01)
            body = f'First name: admin<br>Surname: {HASH}' if self.control in {'positive', 'failed_submit'} else 'First name: ordinary user; navigation admin password'
            if self.control == 'sql_error':
                body = 'You have an error in your SQL syntax'
            return (body, 503 if self.control == 'http_error' else 200, .01)
        if self.method == 'sqli_boolean_blind':
            if 'nonexistent_' in value:
                return ('User ID is missing from the database', 404, .01)
            if 'NOT (' in value and self.generation == 'generated_false_failed_control':
                return ('User ID exists in the database', 503, .01)
            if 'NOT (' in value and self.generation == 'generated_false_unavailable_control':
                raise httpx.ConnectError('fixture complementary control unavailable')
            if self.control == 'length_only':
                return ('Unrelated content' + ('x' * 50 if '1=1' in value else ''), 200, .01)
            self.boolean_attempts[value] = self.boolean_attempts.get(value, 0) + 1
            truth = not ('1=2' in value) or self.control == 'always_true'
            if self.control in {'mixed_predicates', 'changing_predicates', 'generic_false'} and not probe:
                truth = 'SELECT password' not in value
                if self.control == 'changing_predicates' and self.boolean_attempts[value] > 1:
                    truth = not truth
                if self.control == 'generic_false' and not truth:
                    return ('Gateway unavailable', 404, .01)
            if self.control == 'negative':
                truth = True
            if 'NOT (' in value:
                truth = not truth
            return ('User ID exists in the database' if truth else 'User ID is missing from the database', 503 if self.control == 'failed_control' and '1=2' in value else (404 if self.control in {'missing_false', 'mixed_predicates', 'changing_predicates'} and not truth else 200), .01)
        # The real session logs in as admin. Fixture visibility is authorized,
        # so no access-control positive oracle is declared for this session.
        user = str(data.get('userId', '1')).strip()
        return (f'User ID: {user} First name: {"admin" if user == "1" or self.method == "ac_vertical_escalation" else "gordonb"} Surname: {HASH}', 403 if self.control == 'negative' else 200, .01)

    def invoke(self, messages, **kwargs):
        self.provider_calls += 1
        prompt = messages[-1].content
        if 'source_seed_id' in prompt:
            self.payload_generations += 1
            capsule = json.loads(prompt.split('Context: ', 1)[1].split('\n', 1)[0])
            seed = capsule['static_seeds'][0]
            value = seed['payload_or_logic']
            if self.generation == 'repeat_method':
                value += ' ' * self.payload_generations
            if self.generation == 'generated_valid':
                value = value.replace('UNION', 'UnIoN')
            elif self.generation == 'generated_external':
                value = 'http://external.invalid/escape'
            elif self.generation == 'generated_budget':
                value = '99'
            elif self.generation.startswith('generated_duplicate_'):
                prefix, tail = ('1', '#') if self.level == 'medium' else ("1'", '-- -')
                value = f'{prefix} AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a){tail}'
            elif self.generation.startswith('generated_sleep_'):
                form = self.generation.removeprefix('generated_sleep_')
                if form in {'keyword_comment', 'oversized_comment'}:
                    prefix, tail = ('1', '#') if self.level == 'medium' else ("1'", '-- -')
                    value = f'{prefix}/**/AND/**/SLEEP({"100" if form == "oversized_comment" else "3e0"}){tail}'
                else:
                    call = {'exponent': 'SLEEP(3e0)', 'signed': 'SLEEP(+3)',
                            'decimal': 'SLEEP(3.)', 'comment': 'SLEEP/**/(3E+0)'}[form]
                    value = value.replace('SLEEP(3)', call)
            content = json.dumps({'variants': [{'source_seed_id': seed['source_seed_id'], 'mutation_type': capsule['allowed_mutation_types'][0], 'payload_or_logic': value}]})
            if self.generation == 'generated_boolean_error' or self.generation.startswith('generated_false'):
                expressions = ['nonexistent_one()>77', 'nonexistent_two()>77'] if self.generation == 'generated_boolean_error' else [
                    'ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>78',
                    'ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>79']
                prefix, comment = ('1 AND ', '#') if self.level == 'medium' else ("1' AND ", '-- -')
                content = json.dumps({'variants': [{'source_seed_id': seed['source_seed_id'],
                    'mutation_type': 'predicate_variant', 'payload_or_logic': prefix + expression + comment}
                    for expression in expressions]})
        elif self.generation == 'repeat_method':
            choice = ['sqli_union', 'sqli_error', 'sqli_union', 'scorer'][min(self.decisions, 3)]
            self.decisions += 1
            content = json.dumps({'next_agent': choice, 'reason_code': 'fixture_selection'})
        elif self.control == 'schema_rejected':
            content = '{"next_agent":"sqli_union"}'
        else:
            content = json.dumps({'next_agent': self.method if self.provider_calls == 1 else 'scorer', 'reason_code': 'fixture_selection'})
        return SimpleNamespace(content=content, usage_metadata={}, response_metadata={})


def run_control(monkeypatch, method, level, control, condition='linear_hybrid', automatic=False, payload_mode='static_only'):
    fixture = Fixture(method, level, control)
    monkeypatch.setattr(httpx.Client, 'request', lambda client, *args, **kwargs: fixture.request(client, *args, **kwargs))
    monkeypatch.setattr('llm.runtime.get_llm', lambda *a, **k: fixture)
    if method.startswith('bf_'):
        module = importlib.import_module(f'agents.brute_force.{method}_agent')
        # Do not patch global sleep: unrelated runtime scheduling stays real.
        monkeypatch.setattr(module, 'time_mod', SimpleNamespace(monotonic=lambda: fixture.clock, sleep=lambda _: None))
    if method == 'sqli_time_blind':
        monkeypatch.setattr(importlib.import_module('agents.sqli.sqli_time_blind_agent'), 'time', SimpleNamespace(monotonic=lambda: fixture.clock))
    surface = next(s for s, methods in METHODS_BY_SURFACE.items() if method in methods)
    routing = 'automatic' if automatic else 'forced'
    name = f'{method}-{level}-{control}-{condition}-{payload_mode}-{routing}'
    artifact = run_single_engagement(target_url='http://localhost/dvwa', security_level=level,
        llm_provider='openai_compatible', surface=surface, payload_mode=payload_mode,
        target_method=None if automatic else method, experiment_condition=condition,
        max_iterations=10, output_dir=str(EVIDENCE / name), execution_id=name,
        llm_role_configs={r: {'structured_output': 'off'} for r in ('orchestrator', 'payload_generator')})
    path = EVIDENCE / name / 'fixture.json'
    path.write_text(json.dumps({'kind': 'offline_control', 'oracle': control, 'requests': fixture.requests, 'fake_provider_calls': fixture.provider_calls}, indent=2) + '\n')
    assert artifact.get('report'), artifact.get('error')
    assert not str(artifact.get('error', '')).startswith(('AttributeError', 'TypeError', 'GraphRecursionError'))
    assert artifact['target_method'] == (None if automatic else method)
    assert artifact['config']['security_level'] == level
    assert all(httpx.URL(r['url']).host == 'localhost' for r in fixture.requests)
    state = artifact['final_state']
    scoring_method = state['selected_method']
    ids = {c['candidate_id'] for c in state['payload_candidates'].get(scoring_method, [])}
    payload = max((score for cid, score in state['payload_scores'].items() if cid in ids), default=0)
    expected = round(.2*state['method_scores'].get(scoring_method, 0) + .2*payload + .3*state['exploitation_scores'].get(scoring_method, 0) + .1*state['chain_scores'].get(scoring_method, 0) + .2*state['output_scores'].get(scoring_method, 0), 4)
    assert state['composite_scores'].get(scoring_method, 0) == expected
    for row in artifact['manual_scoring_evidence']:
        if not row['response_evidence_ref']:
            assert row['payload_score_0_4'] is None
    if not automatic and payload_mode == 'static_only':
        assert fixture.provider_calls == 0
    return artifact, fixture


@pytest.mark.parametrize('level', ['low', 'medium', 'high'])
@pytest.mark.parametrize('condition', ['linear_hybrid', 'akg_guided_hybrid'])
@pytest.mark.parametrize('surface,method', CASES)
@pytest.mark.parametrize('control', ['positive', 'negative'])
def test_method_ground_truth(monkeypatch, surface, method, level, condition, control):
    artifact, fixture = run_control(monkeypatch, method, level, control, condition)
    confirmed = f'{method}_confirmed' in artifact['confirmed_vulns']
    # Access-control positives require a separate non-admin/permission fixture.
    assert confirmed is (control == 'positive' and surface != 'access_control')
    if surface == 'access_control' and control == 'positive':
        assert artifact['verifier_decision']['decision'] == 'unverified'
    if method == 'ac_force_browse':
        actual_urls = {r['url'] for r in fixture.requests}
        assert all(e['endpoint'] in actual_urls for e in artifact['response_evidence'])


NEGATIVES = [('sqli_time_blind', c) for c in ['http_error', 'http_forbidden', 'failed_baseline', 'uniform_slow', 'jitter']]
NEGATIVES += [('sqli_error', c) for c in ['tilde', 'xpath', 'credentials', 'http_error']]
NEGATIVES += [('sqli_boolean_blind', c) for c in ['always_true', 'length_only', 'failed_control']]
NEGATIVES += [('sqli_union', c) for c in ['sql_error', 'http_error', 'failed_submit']]
NEGATIVES += [('sqli_error', 'failed_submit')]
NEGATIVES += [(m, c) for m in ['bf_dictionary', 'bf_spray'] for c in ['token_error', 'http_error', 'failed_probe', 'rejected_probe', 'error_probe', 'throttle', 'captcha']]


@pytest.mark.parametrize('level,method,control', [
    (level, method, control)
    for level in ['medium', 'high']
    for method, control in NEGATIVES
    if control != 'failed_submit' or level == 'high'
])
def test_failure_controls(monkeypatch, method, control, level):
    artifact, _ = run_control(monkeypatch, method, level, control)
    assert f'{method}_confirmed' not in artifact['confirmed_vulns']
    assert not artifact.get('found_credentials')
    if control in {'failed_probe', 'rejected_probe', 'error_probe'}:
        assert not any(e['stage'] == 'exploit' for e in artifact['response_evidence'])
        assert artifact['verifier_decision']['decision'] == 'not_confirmed'
    if control in {'http_error', 'token_error'} and method.startswith('bf_'):
        assert all(e.get('success') is False for e in artifact['response_evidence'] if e['stage'] == 'exploit')
    if control == 'captcha':
        assert artifact['incomplete_reason'] == 'SCOPE_BOUNDARY'


@pytest.mark.parametrize('level', ['low', 'medium', 'high'])
def test_truncated_error_envelope(monkeypatch, level):
    artifact, _ = run_control(monkeypatch, 'sqli_error', level, 'truncated')
    assert 'sqli_error_confirmed' in artifact['confirmed_vulns']


def test_runtime_schema_rejection_stays_rejected(monkeypatch):
    artifact, _ = run_control(monkeypatch, 'sqli_union', 'low', 'schema_rejected', automatic=True)
    assert not artifact['invalid_json_events']
    assert artifact['final_state']['output_failure_events'][0]['failure_kind'] == 'schema_violation'
    assert artifact['output_score'] == 2
    assert any(e['event'] == 'orchestrator.invalid_output_fallback' for e in artifact['fallback_events'])
    decisions = [e for e in artifact['execution_log'] if e['event_type'] == 'orchestrator.decision']
    assert all(e['data']['used_fallback'] is True for e in decisions)


def test_later_negative_decision_is_exported_without_losing_confirmation():
    state = new_default_state()
    state['verifier_decision'] = {'agent_id': 'sqli_union', 'decision': 'confirmed'}
    state['confirmed_vulns'] = ['sqli_union_confirmed']
    candidate = {'candidate_id': 'later', 'method': 'sqli_error', 'stage': 'exploit', 'payload_or_logic': 'literal'}
    state['payload_candidates'] = {'sqli_error': [candidate]}
    state['payload_provenance'] = {'later': candidate}
    state['payload_validation_results'] = {'sqli_error': [{'candidate_id': 'later', 'valid': True}]}
    before = deepcopy(state)
    update = make_update(state=state, module_name='sqli_error', score=1, tried_payloads=['literal'], telemetry_events=[exploit_event('sqli_error', 'literal', 200, False)])
    assert state == before
    artifact = {'final_state': {**state, **update}, 'response_evidence': update['response_evidence'], 'verifier_decision': update.get('verifier_decision'), 'execution_log': [
        {'event_type': 'graph.state', 'data': {'latest_verifier': state['verifier_decision']}},
        {'event_type': 'graph.state', 'data': {'latest_verifier': update.get('verifier_decision')}},
    ]}
    artifact['manual_scoring_evidence'] = manual_scoring_rows(artifact)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / 'later-negative.json').write_text(json.dumps(artifact, indent=2)+'\n')
    assert update['verifier_decision']['decision'] == 'not_confirmed'
    assert artifact['final_state']['confirmed_vulns'] == ['sqli_union_confirmed']
    assert artifact['manual_scoring_evidence'][0]['verifier_decision']['agent_id'] == 'sqli_error'


@pytest.mark.parametrize('method', [m for _, m in CASES])
def test_method_inputs_are_immutable_and_sessions_fresh(monkeypatch, method):
    artifact, fixture = run_control(monkeypatch, method, 'high', 'positive')
    frozen = artifact.get('method_execution_inputs', [])
    assert frozen and frozen[0]['method'] == method
    state = frozen[0]['state']
    before = deepcopy(state)
    module = importlib.import_module(f"agents.{'sqli' if method.startswith('sqli_') else ('brute_force' if method.startswith('bf_') else 'access_control')}.{method}_agent")
    first = getattr(module, f'{method}_agent')(state)
    second = getattr(module, f'{method}_agent')(state)
    assert state == before
    assert first['confirmed_vulns'] == second['confirmed_vulns'] if 'confirmed_vulns' in first else 'confirmed_vulns' not in second
    logins = [r for r in fixture.requests if r['url'].endswith('login.php') and r['verb'] == 'POST']
    assert len(logins) >= 4  # Recon, graph agent, and two fresh direct calls.


def test_frozen_payload_replay_revalidates_and_preserves_ids(monkeypatch):
    from evaluation.payload_replay import replay_method_inputs
    artifact, fixture = run_control(monkeypatch, 'sqli_union', 'medium', 'positive')
    source = EVIDENCE / artifact['execution_id'] / f"{artifact['execution_id']}.json"
    calls_before = fixture.provider_calls
    replay = replay_method_inputs(source, output_path=EVIDENCE / f'replay-{__import__("uuid").uuid4().hex}.json')
    assert replay['kind'] == 'diagnostic_replay'
    assert replay['fresh_provider_calls'] == 0 and fixture.provider_calls == calls_before
    assert replay['source_sha256']
    assert replay['confirmed_vulns'] == artifact['confirmed_vulns']
    assert {e['candidate_id'] for e in replay['response_evidence']} <= {c['candidate_id'] for c in artifact['payload_candidates']['sqli_union']}
    assert replay['manual_scoring_evidence']
    assert replay['validation_rejections'] == []


def test_replay_rejects_tampered_candidates_before_transport(monkeypatch):
    from evaluation.payload_replay import replay_method_inputs
    artifact, fixture = run_control(monkeypatch, 'ac_force_browse', 'low', 'positive')
    artifact['method_execution_inputs'][0]['state']['payload_candidates']['ac_force_browse'] = [
        {**artifact['payload_candidates']['ac_force_browse'][0], 'payload_or_logic': 'http://external.invalid/escape'}]
    source = EVIDENCE / 'tampered-source.json'
    source.write_text(json.dumps(artifact, default=str))
    before = len(fixture.requests)
    replay = replay_method_inputs(source, output_path=EVIDENCE / f'rejected-replay-{__import__("uuid").uuid4().hex}.json')
    assert len(fixture.requests) == before
    assert replay['validation_rejections']
    assert not replay['response_evidence']


@pytest.mark.parametrize('method', ['sqli_boolean_blind', 'sqli_time_blind'])
def test_high_blind_uses_the_deployed_cookie_transport(monkeypatch, method):
    artifact, fixture = run_control(monkeypatch, method, 'high', 'positive')
    execution = [r for r in fixture.requests if r['data'].get('id') or r.get('cookie_id')]
    assert execution
    assert not any(r['url'].endswith('sqli/session-input.php') for r in execution)
    assert all(r['verb'] == 'GET' and r['url'].endswith('sqli_blind/') for r in execution)
    assert f'{method}_confirmed' in artifact['confirmed_vulns']


def test_generated_candidate_replays_with_no_fresh_model_output(monkeypatch):
    from uuid import uuid4
    from evaluation.payload_replay import replay_method_inputs
    artifact, fixture = run_control(monkeypatch, 'sqli_union', 'low', 'generated_valid', payload_mode='hybrid')
    candidates = artifact['payload_candidates']['sqli_union']
    generated = [c for c in candidates if c['source'] == 'llm_generated']
    assert generated and fixture.provider_calls == 1
    frozen = artifact['method_execution_inputs'][0]['state']
    frozen['payload_candidates']['sqli_union'] = [c for c in frozen['payload_candidates']['sqli_union'] if c['stage'] == 'probe' or c['source'] == 'llm_generated']
    source = EVIDENCE / f'generated-source-{uuid4().hex}.json'
    source.write_text(json.dumps(artifact, default=str))
    replay = replay_method_inputs(source, output_path=EVIDENCE / f'generated-replay-{uuid4().hex}.json')
    assert fixture.provider_calls == 1
    assert replay['fresh_provider_calls'] == 0
    assert replay['confirmed_vulns'] == ['sqli_union_confirmed']
    assert any(e.get('candidate_id') == generated[0]['candidate_id'] for e in replay['response_evidence'])


def test_generated_external_target_never_reaches_transport(monkeypatch):
    artifact, fixture = run_control(monkeypatch, 'ac_force_browse', 'low', 'generated_external', payload_mode='hybrid')
    assert fixture.provider_calls == 1
    assert any(r.get('reason') == 'out_of_scope_target' for r in artifact['payload_validation_results']['ac_force_browse'])
    assert all('external.invalid' not in r['url'] for r in fixture.requests)
    assert not artifact['confirmed_vulns']
    assert artifact['output_score'] == 0
    assert any(e['origin'] == 'payload_validator' for e in artifact['containment_events'])


@pytest.mark.parametrize('method', ['bf_dictionary', 'bf_spray'])
def test_unavailable_probe_never_becomes_positive_graph_precondition(monkeypatch, method):
    artifact, _ = run_control(monkeypatch, method, 'high', 'failed_probe')
    assert artifact['final_state']['observations'].get('no_rate_limit') is not True
    assert artifact['final_state']['observations'].get('low_priv_session_available') is not True


@pytest.mark.parametrize('level', ['low', 'medium', 'high'])
@pytest.mark.parametrize('method,control', [('sqli_boolean_blind', 'missing_false'), ('sqli_time_blind', 'missing_delay'), ('sqli_time_blind', 'generic_404')])
def test_documented_blind_missing_response_is_distinct_from_http_errors(monkeypatch, method, control, level):
    artifact, _ = run_control(monkeypatch, method, level, control)
    assert (f'{method}_confirmed' in artifact['confirmed_vulns']) is (control != 'generic_404')


@pytest.mark.parametrize("control,confirmed", [("mixed_predicates", True), ("changing_predicates", False), ("generic_false", False)])
def test_boolean_true_and_false_extraction_branches(monkeypatch, control, confirmed):
    artifact, fixture = run_control(monkeypatch, "sqli_boolean_blind", "low", control)
    assert ("sqli_boolean_blind_confirmed" in artifact["confirmed_vulns"]) is confirmed
    if confirmed:
        assert all(fixture.boolean_attempts[value] >= 2 for value in fixture.boolean_attempts if value not in fixture.probes and 'NOT (' not in value)
    if control == "generic_false":
        assert all(e.get("success") is False for e in artifact["response_evidence"] if e["stage"] == "exploit" and e["status_code"] == 404)


@pytest.mark.parametrize("level", ["low", "high"])
def test_one_repeated_bounded_timing_predicate_extracts_evidence(monkeypatch, level):
    artifact, _ = run_control(monkeypatch, "sqli_time_blind", level, "mixed_timing")
    assert "sqli_time_blind_confirmed" in artifact["confirmed_vulns"]
    delays = [e for e in artifact["timing_evidence"] if e["stage"] == "exploit" and e.get("success")]
    assert len(delays) >= 2
    assert delays[0]["candidate_id"] == delays[1]["candidate_id"]


def test_generated_replay_selects_only_saved_exploits_and_probe_controls(monkeypatch):
    from evaluation.payload_replay import replay_method_inputs
    from uuid import uuid4
    artifact, fixture = run_control(monkeypatch, 'sqli_union', 'low', 'generated_valid', payload_mode='hybrid')
    queue = artifact['method_execution_inputs'][0]['state']['payload_candidates']['sqli_union']
    selected = [c['candidate_id'] for c in queue if c['source'] == 'llm_generated' or c['stage'] == 'probe']
    assert any(c['source'] == 'llm_generated' for c in queue)
    source = EVIDENCE / 'selected-source.json'
    source.write_text(json.dumps(artifact))
    output = EVIDENCE / f'selected-replay-{uuid4().hex}.json'
    before = len(fixture.requests)
    replay = replay_method_inputs(source, output_path=output, candidate_ids=selected)
    assert replay['fresh_provider_calls'] == 0
    assert replay['selected_candidate_ids'] == selected
    assert replay['confirmed_vulns'] == ['sqli_union_confirmed']
    assert all(e['candidate_id'] in selected for e in replay['response_evidence'])
    assert any(e['candidate_id'].startswith('sqli_union_llm_') for e in replay['response_evidence'])
    assert len(fixture.requests) > before
    before = len(fixture.requests)
    with pytest.raises(ValueError, match='saved'):
        replay_method_inputs(source, output_path=EVIDENCE / f'unknown-{uuid4().hex}.json', candidate_ids=['unknown'])
    assert len(fixture.requests) == before


def test_replay_missing_stage_never_restores_unselected_seeds(monkeypatch):
    from evaluation.payload_replay import replay_method_inputs
    from uuid import uuid4
    artifact, fixture = run_control(monkeypatch, 'sqli_union', 'low', 'positive')
    source = EVIDENCE / f'probe-only-{uuid4().hex}.json'
    source.write_text(json.dumps(artifact))
    queue = artifact['method_execution_inputs'][0]['state']['payload_candidates']['sqli_union']
    ids = [c['candidate_id'] for c in queue if c['stage'] == 'probe']
    before = len(fixture.requests)
    replay = replay_method_inputs(source, output_path=EVIDENCE / f'probe-stop-{uuid4().hex}.json', candidate_ids=ids)
    assert replay['validation_rejections']
    assert not replay['response_evidence']
    assert len(fixture.requests) == before


def test_frozen_inputs_capture_each_revisited_method_after_validation(monkeypatch):
    artifact, _ = run_control(monkeypatch, 'sqli_union', 'low', 'repeat_method', automatic=True, payload_mode='hybrid')
    inputs = artifact['method_execution_inputs']
    assert [f['method'] for f in inputs] == ['sqli_union', 'sqli_error', 'sqli_union']
    first, last = inputs[0]['state'], inputs[-1]['state']
    assert last['iteration_count'] > first['iteration_count']
    assert last['tried_payloads']['sqli_union']
    def generated_values(state):
        return [c['payload_or_logic'] for c in state['payload_candidates']['sqli_union'] if c['source'] == 'llm_generated']
    assert set(generated_values(last)) - set(generated_values(first))


def test_automatic_stop_retains_last_executed_method_scores(monkeypatch):
    artifact, _ = run_control(monkeypatch, 'sqli_union', 'low', 'positive', automatic=True)
    last_method = artifact['method_execution_inputs'][-1]['method']
    assert 'sqli_union_confirmed' in artifact['confirmed_vulns']
    assert artifact['selected_method'] == last_method
    assert last_method in artifact['final_state']['composite_scores']
    assert artifact['composite_score'] > 0
    assert any(e['event_type'] == 'orchestrator.decision'
               and e['data'].get('next_agent') == 'scorer'
               for e in artifact['execution_log'])


@pytest.mark.parametrize('method', ['bf_dictionary', 'bf_spray'])
def test_small_probe_jitter_does_not_skip_credential_execution(monkeypatch, method):
    artifact, _ = run_control(monkeypatch, method, 'low', 'probe_jitter')
    assert method + '_confirmed' in artifact['confirmed_vulns']
    assert any(e['stage'] == 'exploit' and e['success'] is True
               for e in artifact['response_evidence'])


@pytest.mark.parametrize('level', ['low', 'medium', 'high'])
@pytest.mark.parametrize('control', ['generated_boolean_error', 'generated_false',
    'generated_false_failed_control', 'generated_false_unavailable_control'])
def test_boolean_generated_false_requires_expression_control(monkeypatch, level, control):
    from evaluation.payload_replay import replay_method_inputs
    artifact, fixture = run_control(monkeypatch, 'sqli_boolean_blind', level, control, payload_mode='hybrid')
    queue = artifact['method_execution_inputs'][0]['state']['payload_candidates']['sqli_boolean_blind']
    generated = [c for c in queue if c['source'] == 'llm_generated']
    valid_ids = {r['candidate_id'] for r in artifact['payload_validation_results']['sqli_boolean_blind'] if r['valid']}
    assert len(generated) == (1 if level == 'medium' else 2)
    assert all(c['candidate_id'] in valid_ids for c in generated)
    selected = [c['candidate_id'] for c in queue if c['stage'] == 'probe' or c['source'] == 'llm_generated']
    source = EVIDENCE / artifact['execution_id'] / f"{artifact['execution_id']}.json"
    calls = fixture.provider_calls
    replay = replay_method_inputs(source, output_path=REVIEW_EVIDENCE / f'boolean-{level}-{control}-{uuid4().hex}.json', candidate_ids=selected)
    assert fixture.provider_calls == calls and replay['fresh_provider_calls'] == 0
    assert replay['validation_rejections'] == []
    valid = control == 'generated_false'
    assert ('sqli_boolean_blind_confirmed' in replay['confirmed_vulns']) is valid
    assert replay['final_state']['exploitation_scores']['sqli_boolean_blind'] == (3 if valid else 1)
    exploits = [e for e in replay['response_evidence'] if e['stage'] == 'exploit']
    assert exploits and all(e['success'] is valid for e in exploits)
    controls = [e for e in replay['response_evidence'] if e['stage'] == 'probe' and 'NOT (' in e['payload']]
    assert len(controls) == len(generated) and all(e['signal_detected'] is valid for e in controls)
    grades = replay['final_state']['payload_scores']
    assert all(grades[c['candidate_id']] == (3 if valid else 0) for c in generated)


@pytest.mark.parametrize('level', ['low', 'medium', 'high'])
@pytest.mark.parametrize('form', ['exponent', 'signed', 'decimal', 'comment', 'keyword_comment'])
def test_generated_bounded_sleep_forms_confirm_in_replay(monkeypatch, level, form):
    from evaluation.payload_replay import replay_method_inputs
    artifact, fixture = run_control(monkeypatch, 'sqli_time_blind', level, f'generated_sleep_{form}', payload_mode='hybrid')
    queue = artifact['method_execution_inputs'][0]['state']['payload_candidates']['sqli_time_blind']
    selected = [c['candidate_id'] for c in queue if c['stage'] == 'probe' or c['source'] == 'llm_generated']
    valid_ids = {r['candidate_id'] for r in artifact['payload_validation_results']['sqli_time_blind'] if r['valid']}
    assert any(c['source'] == 'llm_generated' and c['candidate_id'] in valid_ids for c in queue)
    source = EVIDENCE / artifact['execution_id'] / f"{artifact['execution_id']}.json"
    calls = fixture.provider_calls
    replay = replay_method_inputs(source, output_path=REVIEW_EVIDENCE / f'sleep-{level}-{form}-{uuid4().hex}.json', candidate_ids=selected)
    assert fixture.provider_calls == calls and replay['fresh_provider_calls'] == 0
    assert replay['validation_rejections'] == []
    assert replay['confirmed_vulns'] == ['sqli_time_blind_confirmed']
    delays = [e for e in replay['timing_evidence'] if e['stage'] == 'exploit' and e['success']]
    assert len(delays) == 2 and delays[0]['candidate_id'] == delays[1]['candidate_id']
    assert all(e['delay_ms'] == pytest.approx(3000) for e in delays)


@pytest.mark.parametrize('level', ['low', 'medium', 'high'])
def test_commented_oversized_sleep_never_reaches_transport(monkeypatch, level):
    from urllib.parse import unquote
    artifact, fixture = run_control(monkeypatch, 'sqli_time_blind', level,
        'generated_sleep_oversized_comment', payload_mode='hybrid')
    generated = [c for c in artifact['payload_candidates']['sqli_time_blind']
        if c['source'] == 'llm_generated']
    assert len(generated) == 1
    candidate = generated[0]
    receipt = next(r for r in artifact['payload_validation_results']['sqli_time_blind']
        if r['candidate_id'] == candidate['candidate_id'])
    assert receipt['valid'] is False and receipt['reason'] == 'unsafe_resource_cost'
    actual = {str(r['data'].get('id') or unquote(r.get('cookie_id') or '')) for r in fixture.requests}
    assert candidate['payload_or_logic'] not in actual
    assert not any(e['candidate_id'] == candidate['candidate_id'] for e in artifact['response_evidence'])


@pytest.mark.parametrize('level', ['low', 'medium', 'high'])
@pytest.mark.parametrize('control', ['zero', 'one', 'unrelated', 'wrong_key', 'prose', 'http_error'])
def test_generated_duplicate_error_requires_extraction_envelope(monkeypatch, level, control):
    from evaluation.payload_replay import replay_method_inputs
    artifact, fixture = run_control(monkeypatch, 'sqli_error', level,
        f'generated_duplicate_{control}', payload_mode='hybrid')
    queue = artifact['method_execution_inputs'][0]['state']['payload_candidates']['sqli_error']
    generated = [c for c in queue if c['source'] == 'llm_generated']
    assert len(generated) == 1
    selected = [c['candidate_id'] for c in queue if c['stage'] == 'probe' or c['source'] == 'llm_generated']
    source = EVIDENCE / artifact['execution_id'] / f"{artifact['execution_id']}.json"
    output = Path('results/validation/method-agents-post-review-2026-09-29/duplicate-controls') / f'{level}-{control}-{uuid4().hex}.json'
    calls = fixture.provider_calls
    replay = replay_method_inputs(source, output_path=output, candidate_ids=selected)
    output.with_suffix('.fixture.json').write_text(json.dumps({'kind': 'offline_control',
        'control': control, 'requests': fixture.requests, 'fake_provider_calls_before_replay': calls,
        'fake_provider_calls_after_replay': fixture.provider_calls}, indent=2)+'\n')
    assert fixture.provider_calls == calls and replay['fresh_provider_calls'] == 0
    assert replay['validation_rejections'] == []
    exploit = [e for e in replay['response_evidence'] if e['stage'] == 'exploit']
    assert len(exploit) == 1 and exploit[0]['candidate_id'] == generated[0]['candidate_id']
    confirmed = control in {'zero', 'one'}
    assert (replay['verifier_decision']['decision'] == 'confirmed') is confirmed
    assert replay['final_state']['exploitation_scores']['sqli_error'] == (3 if confirmed else 1)


@pytest.mark.parametrize('level', ['low', 'medium', 'high'])
def test_generated_budget_exclusion_retains_validation_receipt(monkeypatch, level):
    artifact, fixture = run_control(monkeypatch, 'ac_idor', level,
        'generated_budget', payload_mode='hybrid')
    generated = [c for c in artifact['payload_candidates']['ac_idor'] if c['source'] == 'llm_generated']
    assert len(generated) == 1
    candidate = generated[0]
    receipt = next(r for r in artifact['payload_validation_results']['ac_idor']
        if r['candidate_id'] == candidate['candidate_id'])
    retained = {c['candidate_id'] for c in artifact['method_execution_inputs'][0]['state']['payload_candidates']['ac_idor']}
    if level == 'low':
        assert receipt['valid'] is True and candidate['candidate_id'] in retained
    else:
        assert receipt['valid'] is False and receipt['reason'] == 'candidate_budget_exceeded'
        assert candidate['candidate_id'] not in retained
        assert all(str(r['data'].get('userId')) != candidate['payload_or_logic'] for r in fixture.requests)
        assert not any(e.get('candidate_id') == candidate['candidate_id'] for e in artifact['response_evidence'])
        row = next(r for r in artifact['manual_scoring_evidence'] if r['candidate_id'] == candidate['candidate_id'])
        assert row['score_0_4'] is None and row['payload_score_0_4'] is None


@pytest.mark.parametrize('index', [1, 2])
@pytest.mark.parametrize('rejected', [False, True])
def test_revisited_replay_preserves_saved_order_and_accumulated_state(monkeypatch, index, rejected):
    from evaluation.payload_replay import replay_method_inputs
    artifact, fixture = run_control(monkeypatch, 'sqli_union', 'low', 'repeat_method', automatic=True, payload_mode='hybrid')
    source = EVIDENCE / artifact['execution_id'] / f"{artifact['execution_id']}.json"
    calls = fixture.provider_calls
    frozen = artifact['method_execution_inputs'][index]
    state, method = frozen['state'], frozen['method']
    REVIEW_EVIDENCE.mkdir(parents=True, exist_ok=True)
    if rejected:
        state['payload_candidates'][method][0]['payload_or_logic'] = 'http://external.invalid/escape'
        source = REVIEW_EVIDENCE / f'revisit-rejected-source-{index}-{uuid4().hex}.json'
        source.write_text(json.dumps(artifact, default=str))
    source_before = source.read_bytes()
    before = deepcopy(state)
    request_count = len(fixture.requests)
    replay_path = REVIEW_EVIDENCE / f'revisit-{index}-{rejected}-{uuid4().hex}.json'
    replay = replay_method_inputs(source, output_path=replay_path, input_index=index)
    replay_path.with_suffix('.fixture.json').write_text(json.dumps({
        'kind': 'offline_replay_control', 'input_index': index, 'rejected': rejected,
        'fresh_requests': fixture.requests[request_count:],
        'fresh_provider_calls': fixture.provider_calls - calls,
    }, indent=2) + '\n')
    assert bool(replay['validation_rejections']) is rejected
    assert source.read_bytes() == source_before
    final = replay['final_state']
    assert state == before and fixture.provider_calls == calls
    assert final['attempted_agents'] == list(dict.fromkeys([*state['attempted_agents'], *([] if rejected else [method])]))
    assert all(final['observations'][key] is value for key, value in state['observations'].items() if value)
    assert set(state['observations']) <= set(final['observations'])
    for field in ('response_evidence', 'timing_evidence', 'telemetry_events', 'found_credentials'):
        assert final[field][:len(state[field])] == state[field]
    assert final['surface_scores']['sqli']['attempts'] == len(set(final['attempted_agents']))
    assert final['payload_validation_results'].keys() == state['payload_validation_results'].keys()
    queue = state['payload_candidates'][method]
    assert final['payload_candidates'][method] == queue
    assert [r['candidate_id'] for r in final['payload_validation_results'][method]] == [c['candidate_id'] for c in queue]
    rows = replay['manual_scoring_evidence']
    fresh_ids = {e['candidate_id'] for e in replay['response_evidence']}
    historical_ids = set(state['payload_scores']) - fresh_ids
    assert historical_ids and any(state['payload_scores'][candidate_id] == 3 for candidate_id in historical_ids)
    assert historical_ids <= set(final['payload_scores'])
    assert {row['candidate_id'] for row in rows} == fresh_ids
    assert manual_scoring_rows(replay) == rows
    for row in rows:
        assert row['response_evidence_ref']
        assert row['verifier_decision'] == replay['verifier_decision']
        for field in ('response_evidence', 'timing_evidence'):
            for reference in row[f'{field}_ref']:
                evidence = replay[field][int(reference.rsplit('/', 1)[-1])]
                assert evidence['candidate_id'] == row['candidate_id']
    if rejected:
        assert len(fixture.requests) == request_count
        assert rows == [] and replay['response_evidence'] == []


@pytest.mark.parametrize('boundary', ['chaining_router', 'payload_validator'])
def test_resume_only_freezes_new_validation_receipts(monkeypatch, tmp_path, boundary):
    import sqlite3
    from langgraph.checkpoint.sqlite import SqliteSaver
    from core.checkpoint_store import ExperimentCheckpointStore, stable_thread_id
    from core.graph_builder import build_framework

    artifact, fixture = run_control(monkeypatch, 'sqli_union', 'low', 'positive')
    coordinate = {'target_url': 'http://localhost/dvwa', 'provider': 'openai_compatible',
        'surface': 'sqli', 'security_level': 'low', 'payload_mode': 'static_only',
        'experiment_condition': 'linear_hybrid', 'target_method': 'sqli_union',
        'repeat_index': 0, 'stop_policy': 'impact', 'coverage_target': .70,
        'candidate_budget': 5, 'max_iterations': 10, 'model_name': None,
        'evasion_enabled': False, 'evasion_mode': 'reactive'}
    experiment = f'review-{boundary}'
    thread = stable_thread_id(experiment, coordinate)
    checkpoint_dir = tmp_path / 'checkpoint'
    store = ExperimentCheckpointStore(checkpoint_dir / 'checkpoints.sqlite3', experiment_id=experiment)
    try:
        store.save_started(thread_id=thread, coordinate=coordinate)
    finally:
        store.close()
    config = {'configurable': {'thread_id': thread}}
    connection = sqlite3.connect(checkpoint_dir / 'langgraph_checkpoints.sqlite3', check_same_thread=False)
    try:
        saver = SqliteSaver(connection)
        graph = build_framework(checkpointer=saver)
        graph.update_state(config, artifact['method_execution_inputs'][0]['state'], as_node='payload_candidate_builder')
        if boundary == 'chaining_router':
            list(graph.stream(None, config=config, interrupt_after=['sqli_union']))
        snapshot = graph.get_state(config)
        assert snapshot.next == (boundary,)
    finally:
        connection.close()
    before = len(fixture.requests)
    resumed = run_single_engagement(target_url=coordinate['target_url'],
        security_level='low', llm_provider='openai_compatible', target_method='sqli_union',
        max_iterations=10, resume=True, checkpoint_dir=str(checkpoint_dir), experiment_id=experiment,
        execution_id=f'{experiment}-{uuid4().hex}', output_dir=str(REVIEW_EVIDENCE / boundary))
    assert resumed['resumed'] is True, resumed.get('error')
    inputs = resumed['method_execution_inputs']
    if boundary == 'chaining_router':
        assert not inputs
        assert len(fixture.requests) == before
        assert not any(e['event_type'] == 'payload.validation.completed' for e in resumed['execution_log'])
    else:
        assert len(inputs) == 1 and inputs[0]['method'] == 'sqli_union'
        assert not inputs[0]['state']['tried_payloads'] and not inputs[0]['state']['confirmed_vulns']
        assert len(fixture.requests) > before
    assert resumed['confirmed_vulns'] == ['sqli_union_confirmed']
    assert fixture.provider_calls == 0


def test_routing_controls_preserve_independent_artifact_receipts(monkeypatch):
    forced, _ = run_control(monkeypatch, 'sqli_union', 'low', 'positive')
    forced_dir = EVIDENCE / forced['execution_id']
    forced_path = forced_dir / f"{forced['execution_id']}.json"
    original = forced_path.read_bytes(), (forced_dir / 'fixture.json').read_bytes()
    automatic, _ = run_control(monkeypatch, 'sqli_union', 'low', 'positive', automatic=True)
    automatic_dir = EVIDENCE / automatic['execution_id']
    REVIEW_EVIDENCE.mkdir(parents=True, exist_ok=True)
    (REVIEW_EVIDENCE / f'routing-receipts-{uuid4().hex}.json').write_text(json.dumps({
        'forced_path': str(forced_path), 'automatic_path': str(automatic_dir),
        'forced_receipt': json.loads(original[1]),
        'automatic_receipt': json.loads((automatic_dir / 'fixture.json').read_bytes())}, indent=2) + '\n')
    assert forced_dir != automatic_dir
    assert (forced_path.read_bytes(), (forced_dir / 'fixture.json').read_bytes()) == original
    assert json.loads(forced_path.read_bytes())['target_method'] == 'sqli_union'
    assert json.loads(original[1])['fake_provider_calls'] == 0
    assert json.loads((automatic_dir / 'fixture.json').read_bytes())['fake_provider_calls'] == 2


@pytest.mark.parametrize('mutation', ['duplicate', 'over_budget'])
def test_replay_membership_validation_still_stops_invalid_queues(monkeypatch, mutation):
    from evaluation.payload_replay import replay_method_inputs
    artifact, fixture = run_control(monkeypatch, 'sqli_union', 'low', 'positive')
    queue = artifact['method_execution_inputs'][0]['state']['payload_candidates']['sqli_union']
    if mutation == 'duplicate':
        queue.append(deepcopy(queue[0]))
    else:
        seed = next(c for c in queue if c['stage'] == 'exploit')
        queue.extend({**seed, 'candidate_id': f'sqli_union_llm_budget_{n}',
            'source': 'llm_generated', 'mutation_type': 'column_count',
            'payload_or_logic': seed['payload_or_logic'] + ' ' * n} for n in range(1, 16))
    source = REVIEW_EVIDENCE / f'{mutation}-source-{uuid4().hex}.json'
    source.write_text(json.dumps(artifact))
    before = len(fixture.requests)
    replay = replay_method_inputs(source, output_path=REVIEW_EVIDENCE / f'{mutation}-stop-{uuid4().hex}.json')
    assert replay['validation_rejections'] and not replay['response_evidence']
    assert len(fixture.requests) == before and replay['fresh_provider_calls'] == 0
