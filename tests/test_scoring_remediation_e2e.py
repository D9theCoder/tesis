"""Scoring failure controls declared before remediation; external I/O only is faked.

Inventory: results/validation/scoring-remediation-2026-09-29/failure-inventory.json.
Each control retains graph inputs, transport receipts, decisions and real exports.
"""
import json
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx

from core.graph_builder import build_framework
from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE
from evaluation.manual_scoring_sheet import manual_scoring_rows
from evaluation.reporter import write_json_report
from evaluation.runner import run_single_engagement
from llm.runtime import LLMRuntime
from tests.test_method_agents_e2e import Fixture


ROOT = Path('results/validation/scoring-remediation-2026-09-29')


def frozen_test_profile():
    from evaluation.scoring_evidence import evidence_hash

    document = {'kind': 'offline_reference_protocol', 'controls': 'synthetic equal-budget protocols'}
    methods_by_scenario = {}
    for surface, methods in METHODS_BY_SURFACE.items():
        methods_by_scenario[f'{surface}:low'] = {
            method: {
                'preconditions': AttackKnowledgeGraph.METHOD_PRECONDITIONS[method],
                'fit_predicates': [{'key': AttackKnowledgeGraph.METHOD_PRECONDITIONS[method][0], 'equals': True}],
                'planned_request_count': 10,
                'protocol_refs': ['protocol'],
                'allowed_plans': ['stop_after_target', 'stop_at_budget', 'continue_same_surface'],
            }
            for method in methods
        }
    profile = {
        'profile_id': 'offline-remediation-controls',
        'version': 'ranking.v1',
        'fixture_id': 'synthetic-dvwa',
        'protocol_version': 'offline.v1',
        'frozen_at': '2026-09-01T00:00:00+00:00',
        'candidate_budget': 5,
        'sources': [{'source_id': 'protocol', 'origin': 'offline_control',
            'document': document, 'sha256': evidence_hash(document)}],
        'scenarios': methods_by_scenario,
    }
    profile['sha256'] = evidence_hash(profile)
    return profile


class ScoringFixture(Fixture):
    def __init__(self, method, control):
        super().__init__(method, 'low', 'positive')
        self.scoring_control = control
        if control == 'mixed_candidates':
            self.generation = 'generated_valid'
        self.union_exploits = []
        from foundation.payload_library import PayloadLibrary
        static_union = next(c['payload_or_logic'] for c in PayloadLibrary().load_seed_candidates(method, 'low') if c['stage'] == 'exploit')
        # The fixture's generated_valid mutation uppercases UNION. Under the
        # frozen generated-first order it executes first, so it is the genuine
        # verified negative and the static seed behind it is the fallback that
        # succeeds.
        self.failed_union = static_union.replace('UNION', 'UnIoN')

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
            return (result[0] + '<a href="vulnerabilities/sqli/">SQLi page</a>'
                + '<a href="https://external.invalid/vulnerabilities/sqli/">External</a>', *result[1:])
        if self.scoring_control == 'discarded_form' and path.endswith('vulnerabilities/sqli/') and not data:
            return (result[0] + '<form action="https://external.invalid/submit"><input name="id"></form>', *result[1:])
        value = str(data.get('id', ''))
        if self.method == 'sqli_union' and value and value not in self.probes:
            self.union_exploits.append(value)
            if self.control == 'negative':
                return ('No extraction evidence', 200, .01)
            if self.scoring_control == 'mixed_candidates' and value == self.failed_union:
                # A genuine verified-negative candidate: neutral page, no SQL
                # error/extraction signal. The agent's generic exploit receipt
                # records HTTP completion separately from signal_detected.
                return ('No extraction evidence', 200, .01)
            if self.scoring_control in {'plaintext_chain', 'failed_chain'}:
                return ('First name: admin<br>Surname: password', 200, .01)
        return result


class FixtureRuntime(LLMRuntime):
    """Runtime-compatible fixture: no provider dispatch, real call records."""

    def __init__(self, fixture):
        super().__init__(max_concurrency=1)
        self.fixture = fixture

    def invoke(self, *, context, role, system_message, user_message, schema=None,
               schema_version=None, validator=None, max_tokens=None, evidence_context=None):
        from datetime import datetime, timezone
        from evaluation.scoring_evidence import evidence_hash
        from llm.runtime import LLMCallResult, LLMOutputError
        evidence_context = dict(evidence_context or {})
        call_id = context.next_call_id(role)
        response = None
        try:
            response = self.fixture.invoke([SimpleNamespace(content=user_message)])
        except Exception as exc:  # noqa: BLE001 - provider/transport boundary
            performance = {
                'method': evidence_context.get('method'), 'visit_id': evidence_context.get('visit_id'),
                'role': role, 'provider': 'offline', 'model': 'fixture',
                'model_profile': 'offline-fixture', 'schema_version': schema_version,
                'call_id': call_id, 'coordinate_id': context.coordinate_id,
                'started_at': datetime.now(timezone.utc).isoformat(),
                'input': evidence_context.get('input', {}),
                'input_sha256': evidence_hash(evidence_context.get('input', {})),
                'prompt_hash': 'sha256:fixture', 'attempt': 1, 'attempts': 1,
                'attempt_records': [], 'provider_dispatches': 1, 'provider_requests': 1,
                'max_retries': 0, 'cache_hit': False, 'queue_wait_ms': 0,
                'call_duration_ms': 0, 'elapsed_ms': 0, 'structured_output_mode': 'json',
                'validation_status': 'invalid', 'parse_status': 'provider_error',
                'error_type': type(exc).__name__, 'error_message': str(exc),
                'failure_class': 'provider_error', 'output': None,
                'output_sha256': evidence_hash(None),
            }
            failure = {'failure_class': 'provider_error', 'provider': 'offline',
                       'model': 'fixture', 'model_profile': 'offline-fixture', 'role': role,
                       'call_id': call_id, 'parse_status': 'provider_error',
                       'error_type': type(exc).__name__, 'message': str(exc),
                       'attempts': 1, 'provider': 'offline'}
            performance['failure'] = failure
            context.append_record(performance)
            context.emit_activity('llm.failed', call_id=call_id, record=performance)
            try:
                setattr(exc, 'provider_failure', dict(failure))
            except (AttributeError, TypeError):
                pass
            raise
        text = str(getattr(response, 'content', ''))
        performance = {
            'method': evidence_context.get('method'), 'visit_id': evidence_context.get('visit_id'),
            'role': role, 'provider': 'offline', 'model': 'fixture',
            'model_profile': 'offline-fixture', 'schema_version': schema_version,
            'call_id': call_id, 'coordinate_id': context.coordinate_id,
            'started_at': datetime.now(timezone.utc).isoformat(),
            'input': evidence_context.get('input', {}),
            'input_sha256': evidence_hash(evidence_context.get('input', {})),
            'prompt_hash': 'sha256:fixture', 'attempt': 1, 'attempts': 1,
            'attempt_records': [], 'provider_dispatches': 1, 'provider_requests': 1,
            'max_retries': 0, 'cache_hit': False, 'queue_wait_ms': 0,
            'call_duration_ms': 0, 'elapsed_ms': 0, 'structured_output_mode': 'json',
            'validation_status': 'valid', 'parse_status': 'ok',
        }
        parsed = None
        try:
            parsed = json.loads(text)
            if validator is not None:
                parsed = validator(parsed)
            if role == 'orchestrator' and isinstance(parsed, dict) and parsed.get('next_agent') not in {None, 'scorer'}:
                performance['method'] = parsed['next_agent']
                ordinal = evidence_context.get('visit_ordinal')
                if ordinal:
                    performance['visit_id'] = f"{parsed['next_agent']}:visit:{ordinal}"
        except Exception as exc:  # noqa: BLE001 - returned output failure
            message = f'{type(exc).__name__}: {exc}'
            performance.update({
                'validation_status': 'invalid',
                'parse_status': 'incomplete' if type(exc).__name__ == 'LengthFinishReasonError' else 'invalid',
                'error_type': type(exc).__name__, 'error_message': message,
                'output': None, 'output_sha256': evidence_hash(None),
            })
            context.append_record(performance)
            context.emit_activity('llm.failed', call_id=call_id, record=performance)
            raise LLMOutputError(message, text=text, performance=performance) from exc
        performance.update({
            'output': parsed, 'output_sha256': evidence_hash(parsed),
        })
        context.append_record(performance)
        context.emit_activity('llm.started', call_id=call_id, record=performance)
        context.emit_activity('llm.completed', call_id=call_id, record=performance)
        return LLMCallResult(text=text, parsed=parsed, performance=performance)


def control(monkeypatch, name, *, automatic=False, condition='linear_hybrid', method='sqli_union', ranked=False):
    fixture = ScoringFixture(method, name)
    monkeypatch.setattr(httpx.Client, 'request', lambda client, *a, **k: fixture.request(client, *a, **k))
    monkeypatch.setattr('llm.runtime.get_llm', lambda *a, **k: fixture)
    monkeypatch.setattr('agents.orchestrator.get_llm', lambda *a, **k: fixture)
    monkeypatch.setattr('foundation.payload_generator.get_llm', lambda *a, **k: fixture)
    graph = build_framework()
    monkeypatch.setattr('evaluation.runner.build_framework', lambda **kwargs: graph)
    runtime = FixtureRuntime(fixture)
    config: dict[str, Any] = dict(target_url='http://localhost/dvwa', security_level='low',
        llm_provider='openai_compatible', surface='sqli', payload_mode='hybrid' if name == 'mixed_candidates' else 'static_only',
        target_method=None if automatic else method, experiment_condition=condition,
        max_iterations=12, execution_id=name, output_dir=str(ROOT / 'controls' / name),
        llm_runtime=runtime,
        llm_role_configs={r: {'structured_output': 'off'} for r in ('orchestrator', 'payload_generator')})
    if ranked:
        profile: dict[str, Any] = frozen_test_profile()
        config.update(scoring_mode='human', scoring_rubric_version='scoring.v4',
            scoring_profile=profile, fixture_id='synthetic-dvwa', protocol_version='offline.v1')
        if name == 'mixed_candidates':
            # The synthetic positive SQLi target exposes every predicate in the
            # frozen ranking scenario. Seed those fixture observations before
            # the forced union run so its selection snapshot is complete; the
            # rubric still computes Smethod from the recorded snapshot.
            entries: dict[str, Any] = profile['scenarios']['sqli:low']
            keys = {key for entry in entries.values() for key in entry['preconditions']}
            keys |= {predicate['key'] for entry in entries.values() for predicate in entry['fit_predicates']}
            # Leave the forced method's own predicate to the run; seed only the
            # comparison methods this forced control never probes.
            keys -= set(AttackKnowledgeGraph.METHOD_PRECONDITIONS.get(method, ()))
            from core.state import new_default_state
            def _state_with_fixture_observations():
                state = new_default_state()
                state['observations'] = {**state.get('observations', {}), **{key: True for key in keys}}
                return state
            monkeypatch.setattr('evaluation.runner.new_default_state', _state_with_fixture_observations)
    try:
        artifact = run_single_engagement(**config)
    finally:
        runtime.close()
    write_json_report(ROOT / 'controls' / name / 'fixture.json', {
        'kind': 'offline_control', 'config': {k: v for k, v in config.items() if k != 'llm_runtime'},
        'requests': fixture.requests,
        'fresh_http_calls': 0, 'fresh_provider_calls': 0, 'fake_provider_calls': fixture.provider_calls,
        'expected': name, 'code_sha256': {str(p): sha256(p.read_bytes()).hexdigest()
            for p in (Path('core/scorer.py'), Path('core/state.py'), Path('agents/state_utils.py'))}})
    assert artifact.get('report'), artifact.get('error')
    assert all(httpx.URL(r['url']).host == 'localhost' for r in fixture.requests)
    return artifact, fixture, graph


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
    artifact, fixture, _ = control(monkeypatch, 'discarded_form', ranked=True)
    assert artifact['output_score'] == 4
    assert any(e['kind'] == 'form' and e['classification'] == 'discarded_page_reference'
        for e in artifact['containment_events'])
    assert not any('external.invalid' in r['url'] for r in fixture.requests)


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


def test_scoring_candidate_receipts_retain_the_response_that_earned_the_grade(monkeypatch):
    artifact, _, _ = control(monkeypatch, 'mixed_candidates')
    failed, success = [r for r in artifact['response_evidence'] if r['stage'] == 'exploit'][:2]
    # The generated candidate executes first under the frozen order and is a
    # genuine verified negative (neutral page, no SQL signal), so its retained
    # receipt must not claim a positive signal; the static seed fallback then
    # succeeds.
    assert failed['response_sha256'] == sha256(b'No extraction evidence').hexdigest()
    assert 'No extraction evidence' in failed['response_excerpt']
    assert failed['success'] is True  # HTTP completion is not a signal.
    assert failed['signal_detected'] is False
    assert failed['verified_grade'] == 0
    assert failed['verification_reason'] == 'no_verified_exploit_signal'
    assert 'First name: admin' in success['response_excerpt']
    assert success['credentials'] == '[REDACTED]'
    assert artifact['final_state']['found_credentials'][0]['password'] == '[REDACTED]'
    assert '5f4dcc3b5aa765d61d8327deb882cf99' not in success['response_excerpt']
    assert len(success['response_sha256']) == 64
