"""Status review controls using metadata and setup-only session stubs.

No graph or request execution, provider calls, or framework E2E.
"""
from copy import deepcopy
import importlib
import json

import pytest

from agents.state_utils import make_update
from core.run_status import STATUS_FIELDS, reason, terminal_status
from core.state import ALL_METHOD_AGENTS, new_default_state
from evaluation.runner import run_single_engagement
from evaluation.thesis_scoring import review_queue
from foundation.http_client import RequestTimeoutError, TransportError
from tesis.runtime_events import RunEvent
from tesis.tui_state import TuiRunState, apply_run_event
from tests.test_execution_security_status import evidence_artifact
from tests.support import ready_state


def method_module(method):
    surface = 'sqli' if method.startswith('sqli_') else 'access_control' if method.startswith('ac_') else 'brute_force'
    return importlib.import_module(f'agents.{surface}.{method}_agent')


@pytest.mark.parametrize('method', ALL_METHOD_AGENTS)
@pytest.mark.parametrize('stage,error_type,code', [
    ('login', TransportError, 'TARGET_TRANSPORT_FAILURE'),
    ('security_level', RequestTimeoutError, 'TARGET_TRANSPORT_FAILURE'),
    ('login', RuntimeError, 'METHOD_EXECUTION_FAILURE'),
])
def test_caught_method_setup_error_preserves_explicit_failure(monkeypatch, method, stage, error_type, code):
    module = method_module(method)
    state = ready_state(method)
    state.update(target_url='http://localhost/dvwa', selected_method=method)
    before = deepcopy(state)
    closed = []
    calls = []
    class SetupSession:
        def login(self):
            calls.append('login')
            if stage == 'login':
                raise error_type('setup-only unit error')
            return True
        def set_security_level(self, level):
            calls.append('security_level')
            if stage == 'security_level':
                raise error_type('setup-only unit error')
        def close(self):
            closed.append(True)
        def get(self, *args, **kwargs):
            raise AssertionError('setup failure must not reach HTTP')
        post = get
    if method.startswith('ac_'):
        def setup(*args):
            session = SetupSession()
            # The AC setup function owns its session until it returns it.
            try:
                session.login()
                session.set_security_level('low')
            finally:
                session.close()
            raise AssertionError('expected setup error')
        monkeypatch.setattr(module, 'open_access_control_session', setup)
    else:
        monkeypatch.setattr(module, 'DVWASession', lambda *args: SetupSession())
    update = getattr(module, method + '_agent')(state)
    assert update['execution_status'] == 'failed'
    assert update['execution_reason']['code'] == code
    assert update['execution_reason']['detail'] == f'{method}: {error_type.__name__}'
    assert not update.get('response_evidence')
    assert closed == [True]
    assert calls == (['login'] if stage == 'login' else ['login', 'security_level'])
    assert state == before


@pytest.mark.parametrize('method', [m for m in ALL_METHOD_AGENTS if not m.startswith('ac_')])
def test_explicit_session_login_rejection_is_a_setup_failure(monkeypatch, method):
    from types import SimpleNamespace
    module = method_module(method)
    monkeypatch.setattr(module, 'DVWASession', lambda *args: SimpleNamespace(login=lambda: False, close=lambda: None))
    state = dict(ready_state(method), target_url='http://localhost/dvwa')
    update = getattr(module, method + '_agent')(state)
    assert update['execution_status'] == 'failed'
    assert update['execution_reason']['code'] == 'SESSION_LOGIN_FAILED'


def test_controlled_failure_agent_marker_is_not_an_execution_failure():
    update = make_update(state=new_default_state(), module_name='bf_dictionary', score=0,
        tried_payloads=[], failure_agents=['bf_dictionary'], blocked_agents=['bf_dictionary'],
        task_result='INCOMPLETE', incomplete_reason='SCOPE_BOUNDARY')
    assert update['failure_agents'] == ['bf_dictionary']
    assert update.get('execution_status') is None
    assert update.get('execution_reason') is None


def test_runner_retains_caught_setup_failure_without_response_evidence(monkeypatch, tmp_path):
    state = new_default_state()
    failure = make_update(state=state, module_name='sqli_union', score=0, tried_payloads=[],
        failure_agents=['sqli_union'], execution_error=TransportError('setup-only error'))
    class SnapshotApp:
        def stream(self, initial, **kwargs):
            yield dict(initial, **failure, task_result='INCOMPLETE', incomplete_reason='ALL_METHODS_FAILED')
    monkeypatch.setattr('evaluation.runner.build_framework', lambda **kwargs: SnapshotApp())
    artifact = run_single_engagement(target_url='http://localhost/dvwa', security_level='low',
        llm_provider='openai_compatible', target_method='sqli_union', output_dir=str(tmp_path))
    assert artifact['status'] == 'error'
    assert artifact['execution_status'] == 'failed'
    assert artifact['execution_reason'] == failure['execution_reason']
    assert artifact['security_outcome'] == 'unconfirmed'
    assert not artifact['response_evidence']
    saved = json.loads((tmp_path / f"{artifact['execution_id']}.failure.json").read_text())
    assert saved['execution_reason'] == failure['execution_reason']


@pytest.mark.parametrize('control_case,expected', [
    ('linked', 'confirmed'), ('other_candidate', 'unconfirmed'),
    ('other_visit', 'unconfirmed'), ('unlinked_verifier', 'unconfirmed')])
def test_boolean_outcome_includes_only_candidate_linked_complementary_evidence(tmp_path, control_case, expected):
    artifact = evidence_artifact('sqli_boolean_blind', 'confirmed', 'verified_repeatable_boolean_extraction')
    state = artifact['final_state']
    first = dict(state['response_evidence'][0], payload='offline-example', control_payload='offline-complement')
    second = dict(first, evidence_id='repeat', response_sha256='b' * 64)
    control = dict(agent_id='sqli_boolean_blind', stage='probe', visit_id='visit',
        source_candidate_id='candidate', identity_kind='derived_control',
        payload='offline-complement', evidence_id='control', response_sha256='c' * 64,
        status_code=200, signal_detected=True, verification_reason='evaluated_boolean_branch')
    if control_case == 'other_candidate': control['source_candidate_id'] = 'another-candidate'
    if control_case == 'other_visit': control['visit_id'] = 'another-visit'
    state['response_evidence'] = artifact['response_evidence'] = [first, second, control]
    state['verifier_history'][0]['evidence_refs'] = [f'#/final_state/response_evidence/{i}' for i in range(3 if control_case != 'unlinked_verifier' else 2)]
    state['scoring_decisions'] = [dict(dimension='Spayload', method='sqli_boolean_blind',
        candidate_id='candidate', score=3, evidence_refs=state['verifier_history'][0]['evidence_refs'])]
    before = deepcopy(artifact)
    fields = terminal_status(artifact, classify=True)
    assert fields['security_outcome'] == expected
    assert artifact == before
    if control_case == 'linked':
        source = tmp_path / 'boolean-evidence.json'
        source.write_text(json.dumps(artifact))
        assert review_queue(source)['candidates'][0]['proof_ceiling'] == 3


@pytest.mark.parametrize('executed', [True, False])
def test_missing_response_for_a_tried_candidate_blocks_no_finding(executed):
    artifact = evidence_artifact()
    state = artifact['final_state']
    method = 'sqli_union'
    missing = dict(state['payload_candidates'][method][0], candidate_id='missing', payload_or_logic='offline-missing')
    state['payload_candidates'][method].append(missing)
    state['payload_validation_results'][method].append(dict(candidate_id='missing', valid=True))
    state['payload_provenance']['missing'] = dict(method=method, source='static_seed')
    state['tried_payloads'] = {method: ['offline-example', *(['offline-missing'] if executed else [])]}
    before = deepcopy(artifact)
    fields = terminal_status(artifact, classify=True)
    assert fields['security_outcome'] == ('unconfirmed' if executed else 'no_finding')
    assert artifact == before


@pytest.mark.parametrize('event_type', ['run.cancelled', 'matrix.cancelled', 'run.cancellation'])
@pytest.mark.parametrize('outcome', ['confirmed', 'fixture_limited', 'unconfirmed'])
def test_cancellation_applies_terminal_fields_and_refreshes_evidence(event_type, outcome):
    state = TuiRunState(status='running', security_outcome='unconfirmed')
    if event_type == 'matrix.cancelled': state.run_mode = 'matrix'
    fields = terminal_status(dict(execution_status='interrupted', execution_reason=reason('CANCELLED', 'operator request'),
        security_outcome=outcome, security_outcome_reason=None if outcome == 'confirmed' else reason('UNIT_EVIDENCE')))
    dirty = apply_run_event(state, RunEvent(event_type, data=dict(status='cancelled', **fields)))
    assert state.status == 'cancelled'
    assert {key: getattr(state, key) for key in STATUS_FIELDS} == fields
    assert 'evidence' in dirty


def test_early_cancellation_preserves_confirmed_evidence_and_uses_interruption_reason():
    state = TuiRunState(status='failed', execution_status='failed', execution_reason=reason('LLM_RUNTIME_FAILURE'),
        security_outcome='confirmed')
    dirty = apply_run_event(state, RunEvent('run.cancelled', message='operator request'))
    assert state.execution_status == 'interrupted'
    assert state.execution_reason['code'] == 'CANCELLED'
    assert state.security_outcome == 'confirmed' and state.security_outcome_reason is None
    assert 'evidence' in dirty


def test_child_cancellation_does_not_terminalize_the_matrix_parent():
    state = TuiRunState(status='running', run_mode='matrix')
    dirty = apply_run_event(state, RunEvent('run.cancelled', execution_id='child', data=dict(execution_status='interrupted')))
    assert state.status == 'running' and state.execution_status is None
    assert not dirty
