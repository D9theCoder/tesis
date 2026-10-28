"""Unit controls for terminal metadata; no graph, HTTP, or provider execution."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from core.run_status import (EXECUTION_STATUSES, SECURITY_OUTCOMES, STATUS_FIELDS,
    terminal_status, matrix_terminal_status, lifecycle_alias, reason)
from core.scorer import scorer
from core.state import new_default_state
from evaluation.metrics import aggregate_runs
from evaluation.multi_llm_runner import _build_matrix_aggregate
from evaluation.reporter import build_markdown_summary
from evaluation.thesis_scoring import review_queue, finalize_reviews
from tesis.artifact_repository import ArtifactRepository
from tesis.runtime_events import RunEvent
from tesis.tui_state import TuiRunState, apply_run_event
from tesis.headless import _terminal_status_for_result


def evidence_artifact(method='sqli_union', decision='not_confirmed', signal='no_verified_exploit_signal'):
    row = dict(candidate_id='candidate', agent_id=method, stage='exploit', visit_id='visit',
        evidence_id='response', response_sha256='a' * 64, status_code=200,
        verification_reason=signal, signal_detected=decision == 'confirmed')
    state = new_default_state()
    state.update(selected_method=method, target_method=method,
        payload_candidates={method: [dict(candidate_id='candidate', method=method,
            stage='exploit', payload_or_logic='offline-example', source='static_seed')]},
        payload_validation_results={method: [dict(candidate_id='candidate', valid=True)]},
        payload_provenance={'candidate': dict(method=method, source='static_seed')},
        response_evidence=[row], verifier_history=[dict(agent_id=method, visit_id='visit',
            decision=decision, source='method_agent_evidence',
            evidence_refs=['#/final_state/response_evidence/0'])])
    return dict(status='success', run_id='unit', execution_id='unit-execution',
        selected_method=method, target_method=method, final_state=state, response_evidence=[row],
        config=dict(provider='offline', surface='sqli', security_level='low', payload_mode='static_only',
            scoring_rubric_version='scoring.v4', scoring_profile={}, scoring_oracles=[],
            scoring_mode='human', scoring_evaluator={}))


@pytest.mark.parametrize('execution', EXECUTION_STATUSES)
@pytest.mark.parametrize('outcome', SECURITY_OUTCOMES)
def test_independent_fields_round_trip_and_tui(execution, outcome, tmp_path):
    fields = terminal_status(dict(execution_status=execution, security_outcome=outcome,
        execution_reason=reason('UNIT_FAILURE') if execution == 'failed' else reason('CANCELLED') if execution == 'interrupted' else None,
        security_outcome_reason=None if outcome == 'confirmed' else reason('UNIT_EVIDENCE')))
    artifact = dict(run_id='unit', execution_id='unit-execution', status=lifecycle_alias(execution),
        **fields, final_state=dict(fields))
    path = tmp_path / 'execution.json'
    path.write_text(json.dumps(artifact))
    before = path.read_bytes()
    item = ArtifactRepository(tmp_path).scan()[0]
    assert item.execution_status == execution and item.security_outcome == outcome
    assert terminal_status(json.loads(path.read_text())) == fields
    state = TuiRunState()
    apply_run_event(state, RunEvent('matrix.run.finished', data=dict(artifact, coordinate_index=0)))
    row = state.coordinates[0]
    assert row.execution_status == execution and row.security_outcome == outcome
    assert row.status == {'completed': 'succeeded', 'failed': 'failed', 'interrupted': 'cancelled'}[execution]
    assert _terminal_status_for_result(artifact) == {'completed': 'finished', 'failed': 'failed', 'interrupted': 'cancelled'}[execution]
    assert path.read_bytes() == before


@pytest.mark.parametrize('case,outcome,code', [
    ('negative', 'no_finding', 'VERIFIED_NEGATIVE'),
    ('missing_response', 'unconfirmed', 'NO_CANDIDATE_CONFIRMATION'),
    ('missing_hash', 'unconfirmed', 'NO_CANDIDATE_CONFIRMATION'),
    ('missing_link', 'unconfirmed', 'NO_CANDIDATE_CONFIRMATION'),
    ('unverified', 'unconfirmed', 'NO_CANDIDATE_CONFIRMATION'),
    ('partial', 'unconfirmed', 'PARTIAL_SIGNAL'),
    ('permission', 'fixture_limited', 'PERMISSION_ORACLE_UNAVAILABLE'),
    ('session', 'fixture_limited', 'SESSION_ORACLE_UNAVAILABLE'),
])
def test_evidence_classification_never_imputes_a_negative(case, outcome, code):
    artifact = evidence_artifact()
    state = artifact['final_state']
    if case == 'missing_response': state['response_evidence'] = []
    if case == 'missing_hash': state['response_evidence'][0].pop('response_sha256')
    if case == 'missing_link': state['verifier_history'][0]['evidence_refs'] = []
    if case == 'unverified': state['verifier_history'][0]['decision'] = 'unverified'
    if case == 'partial': state['response_evidence'][0]['verification_reason'] = 'partial_union_data'
    if case in {'permission', 'session'}:
        artifact = evidence_artifact('ac_force_browse' if case == 'permission' else 'bf_dictionary',
            'unverified', 'visibility_without_permission_oracle' if case == 'permission' else 'verified_login')
    before = deepcopy(artifact)
    fields = terminal_status(artifact, execution_status='completed', classify=True)
    assert fields['security_outcome'] == outcome
    assert fields['security_outcome_reason']['code'] == code
    assert fields['execution_status'] == 'completed'
    assert artifact == before


def test_confirmed_requires_method_proof_and_legacy_marker_alone_is_insufficient():
    artifact = evidence_artifact(decision='confirmed', signal='verified_account_extraction')
    assert terminal_status(artifact, classify=True)['security_outcome'] == 'confirmed'
    assert terminal_status({'status': 'success', 'task_result': 'SUCCESS', 'confirmed_vulns': ['old-label']})['security_outcome'] == 'unconfirmed'


def test_scorer_normal_completion_and_provider_failure_are_independent():
    state = evidence_artifact()['final_state']
    update = scorer(state)
    assert update['execution_status'] == 'completed'
    assert update['security_outcome'] == 'no_finding'
    state.update(execution_status='failed', execution_reason=reason('LLM_RUNTIME_FAILURE'))
    update = scorer(state)
    assert update['execution_status'] == 'failed'
    assert update['security_outcome'] == 'no_finding'


def test_matrix_counts_completed_outcomes_separately_from_exploit_rate():
    artifacts = [dict(status='success', execution_status='completed', security_outcome=outcome,
        security_outcome_reason=None if outcome == 'confirmed' else reason('UNIT_EVIDENCE'),
        config=dict(provider='offline', surface='sqli', security_level='low', payload_mode='static_only'))
        for outcome in SECURITY_OUTCOMES]
    totals = aggregate_runs(artifacts)
    assert totals['completed_runs'] == 4 and totals['error_runs'] == 0
    assert totals['confirmed_runs'] == 1
    assert totals['security_outcome_counts'] == dict.fromkeys(SECURITY_OUTCOMES, 1)
    aggregate = _build_matrix_aggregate(artifacts)
    assert aggregate['totals']['completed_runs'] == 4
    assert aggregate['by_provider']['offline']['execution_status_counts']['completed'] == 4
    text = build_markdown_summary(aggregate)
    assert 'Completed executions: 4' in text and 'Security outcome confirmed: 1' in text
    assert matrix_terminal_status(artifacts)['execution_status'] == 'completed'
    failed = dict(status='error', execution_status='failed', execution_reason=reason('LLM_RUNTIME_FAILURE'), security_outcome='unconfirmed')
    assert matrix_terminal_status([failed])['execution_status'] == 'failed'
    assert matrix_terminal_status([failed], interrupted=True)['execution_status'] == 'interrupted'


def test_historical_incomplete_requires_execution_evidence_and_preserves_source(tmp_path):
    artifact = dict(status='error', task_result='INCOMPLETE', incomplete_reason='ALL_METHODS_FAILED',
        llm_required=True, llm_activity=dict(started=1, completed=1, failed=0),
        execution_log=[dict(event_type='run.finished')], response_evidence=[dict(status_code=200)])
    path = tmp_path / 'historical.json'
    path.write_text(json.dumps(artifact))
    before = sha256(path.read_bytes()).hexdigest()
    assert ArtifactRepository(tmp_path).scan()[0].execution_status == 'completed'
    artifact.pop('execution_log')
    assert terminal_status(artifact)['execution_status'] is None
    artifact['llm_activity']['failed'] = 1
    assert terminal_status(artifact)['execution_status'] == 'failed'
    assert sha256(path.read_bytes()).hexdigest() == before


@pytest.mark.parametrize('missing', [False, True])
def test_v4_negative_zero_and_missing_proof_pending_are_preserved(missing, tmp_path):
    artifact = evidence_artifact()
    if missing:
        artifact['final_state']['response_evidence'][0].pop('verification_reason')
    path = tmp_path / 'source.json'
    path.write_text(json.dumps(artifact))
    queue = review_queue(path)
    assert queue['components']['Sexploit'] == (None if missing else 0)
    assert queue['candidates'][0]['proof_ceiling'] == (None if missing else 0)
    result = finalize_reviews(path, [])
    assert not result['receipts']
    assert result['workflows']['human']['Srun_final'] is None


@pytest.mark.parametrize('missing_component', [False, True])
def test_final_score_requires_all_components_and_zero_does_not_zero_the_sum(monkeypatch, tmp_path, missing_component):
    # Isolate finalization: ranking/output proofs are supplied by its queue contract.
    artifact = evidence_artifact()
    path = tmp_path / 'source.json'
    path.write_text(json.dumps(artifact))
    before = path.read_bytes()
    queue = review_queue(path)
    queue['components'].update(Smethod=3, Sexploit=0, Schain=0, Soutput=None if missing_component else 3)
    queue['component_pending_reasons'] = {'Soutput': 'missing_required_evidence'} if missing_component else {}
    monkeypatch.setattr('evaluation.thesis_scoring.review_queue', lambda source: deepcopy(queue))
    result = finalize_reviews(path, [])
    if missing_component:
        assert not result['receipts'] and result['workflows']['human']['Srun_final'] is None
    else:
        receipt = json.loads(Path(result['receipts']['human']).read_text())
        assert receipt['components']['Sexploit'] == receipt['Spayload_final'] == 0
        assert receipt['Srun_final'] == 1.2
        assert receipt['security_outcome'] == 'no_finding'
    assert path.read_bytes() == before


@pytest.mark.parametrize('field,value', [('execution_status', 'success'), ('security_outcome', 'negative')])
def test_invalid_canonical_status_is_rejected(field, value):
    with pytest.raises(ValueError): terminal_status({field: value})


@pytest.mark.parametrize('execution,outcome', [
    ('completed', 'no_finding'), ('completed', 'unconfirmed'), ('completed', 'fixture_limited'),
    ('failed', 'unconfirmed'), ('interrupted', 'unconfirmed')])
def test_headless_adapter_persists_canonical_fields_to_journal_descriptor_and_manifest(monkeypatch, tmp_path, execution, outcome):
    from tesis.headless import run_headless
    config = tmp_path / 'config.yaml'
    config.write_text(f'target_url: http://localhost/dvwa\nprovider: gemini\noutput_dir: {tmp_path / "results"}\n')
    fields = terminal_status(dict(execution_status=execution, security_outcome=outcome,
        security_outcome_reason=reason('UNIT_EVIDENCE')))
    def stub_runner(**kwargs):
        return dict(execution_id=kwargs['execution_id'], run_id='adapter-unit',
            status=lifecycle_alias(execution), **fields)
    monkeypatch.setattr('tesis.headless.run_single_engagement', stub_runner)
    code, result, root = run_headless(config_path=str(config), cli_args={})
    assert code == (1 if execution == 'failed' else 0)
    descriptor = json.loads((root / 'runtime.json').read_text())
    manifest = json.loads((root / 'experiment.manifest.json').read_text())
    journal = [json.loads(line) for line in (root / 'runtime.events.jsonl').read_text().splitlines()]
    for saved in (descriptor, manifest, manifest['runs'][0], journal[-1]['data']):
        for key in STATUS_FIELDS:
            assert saved[key] == result[key]


def test_result_table_renders_execution_and_outcome_as_separate_cells():
    from types import SimpleNamespace
    from tesis.tui_drawers import ResultsDrawer
    rows = []
    table = SimpleNamespace(clear=lambda: None, add_row=lambda *cells, **kwargs: rows.append(cells),
        row_count=0, cursor_row=0, scroll_y=0, rows=[], move_cursor=lambda **kw: None, scroll_to=lambda **kw: None)
    summary = SimpleNamespace(update=lambda text: None)
    item = SimpleNamespace(run_id='unit', execution_id='unit-execution', status='success',
        execution_status='completed', security_outcome='fixture_limited', provider='offline',
        security_level='low', path='unit.json')
    drawer = SimpleNamespace(_visible_items=lambda: [item], _cell=ResultsDrawer._cell, _items=[item], _row_items={},
        _filters={}, query_one=lambda selector, kind: table if selector == '#results-table' else summary)
    ResultsDrawer._render_table(drawer)
    assert rows == [('unit', 'completed', 'fixture_limited', 'offline', 'low')]


def test_repository_retains_unknown_lifecycle_for_invalid_or_unattributed_records(tmp_path):
    (tmp_path / 'unknown.json').write_text(json.dumps(dict(run_id='old', status='error', task_result='INCOMPLETE')))
    (tmp_path / 'invalid.json').write_text(json.dumps(dict(run_id='invalid', execution_status='bad', final_state=None)))
    items = ArtifactRepository(tmp_path).scan()
    assert len(items) == 2
    assert all(item.status == 'unknown' and item.execution_status is None for item in items)


def test_historical_incomplete_events_remain_unattributed_without_evidence():
    state = TuiRunState()
    data = dict(status='error', task_result='INCOMPLETE', reason='ALL_METHODS_FAILED')
    apply_run_event(state, RunEvent('run.failed', data=data))
    assert state.status == 'unknown'
    apply_run_event(state, RunEvent('run.finished', data=data))
    assert state.status == 'unknown' and state.execution_status is None
    apply_run_event(state, RunEvent('matrix.run.finished', data=dict(data, coordinate_index=0)))
    assert state.coordinates[0].status == 'unknown'


def test_terminal_fields_survive_checkpoint_sanitization():
    from core.state import checkpoint_safe_state
    fields = terminal_status(dict(execution_status='completed', security_outcome='fixture_limited',
        security_outcome_reason=reason('PERMISSION_ORACLE_UNAVAILABLE', refs=['#/final_state/response_evidence/0'])))
    snapshot = checkpoint_safe_state(dict(new_default_state(), **fields))
    assert {key: snapshot[key] for key in STATUS_FIELDS} == fields


def test_canonical_completion_controls_lifecycle_even_with_a_diagnostic_failure_class():
    state = TuiRunState()
    data = dict(status='error', execution_status='completed', security_outcome='unconfirmed',
        security_outcome_reason=reason('NO_CANDIDATE_CONFIRMATION'), failure_class='historical-diagnostic', coordinate_index=0)
    apply_run_event(state, RunEvent('matrix.run.finished', data=data))
    assert state.coordinates[0].status == 'succeeded'


def test_child_interruption_remains_a_matrix_interruption():
    fields = terminal_status(dict(execution_status='interrupted', security_outcome='unconfirmed'))
    child = dict(status='cancelled', **fields)
    assert matrix_terminal_status([child])['execution_status'] == 'interrupted'


def test_absent_permission_oracle_preserves_partial_proof_and_pending_final_score(tmp_path):
    artifact = evidence_artifact('ac_force_browse', 'unverified', 'visibility_without_permission_oracle')
    path = tmp_path / 'source.json'
    path.write_text(json.dumps(artifact))
    queue = review_queue(path)
    assert queue['security_outcome'] == 'fixture_limited'
    assert queue['components']['Sexploit'] == 2  # independently supported visibility evidence
    assert queue['candidates'][0]['status'] == 'pending_review'
    result = finalize_reviews(path, [])
    assert not result['receipts']
    assert result['workflows']['human']['Srun_final'] is None
