"""Graph/export/replay controls declared before the probe snapshot repair.

Failures: mutation-only probes escape validation and candidate attribution;
replay restores today's seeds; probe controls enter the exploit denominator;
changed value, provenance, stage, method, visit, or order reaches HTTP;
missing historical stages are silently repaired; a replay invokes a provider.
External HTTP and model responses are offline fixtures, never live acceptance.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
from uuid import uuid4


from evaluation.payload_replay import replay_method_inputs
from evaluation.reporter import write_json_report
from tests.test_method_agents_e2e import run_control


ROOT = Path(os.environ.get(
    'TESIS_SCORING_V4_PROBE_REPLAY_EVIDENCE',
    'results/validation/scoring-v4-probe-replay-2026-10-11/offline',
))


def resolve_pointer(document, pointer):
    value = document
    for part in pointer.removeprefix('#/').split('/'):
        part = part.replace('~1', '/').replace('~0', '~')
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def test_replay_execution_log_redacts_confirmed_credentials(monkeypatch, tmp_path):
    artifact, _ = run_control(monkeypatch, 'bf_dictionary', 'low', 'positive')
    source = tmp_path / 'execution.json'
    write_json_report(source, artifact)
    before = source.read_bytes()
    output = tmp_path / 'replay.json'

    replay = replay_method_inputs(source, output_path=output)

    assert replay['validation_rejections'] == []
    credentials = [event['data']['credentials'] for event in replay['execution_log']
        if 'credentials' in event['data']]
    assert credentials
    assert all(credential == '[REDACTED]' for credential in credentials)
    assert json.loads(output.read_text())['execution_log'] == replay['execution_log']
    assert source.read_bytes() == before
    assert replay['fresh_provider_calls'] == 0


def test_revisited_visits_keep_distinct_queues_probe_and_request_links(monkeypatch):
    """Exercise per-visit capture/export twice with no provider or HTTP client."""
    import httpx

    from agents.agent_telemetry import exploit_event, probe_event
    from agents.state_utils import make_update
    from evaluation.runner import run_single_engagement
    from foundation.payload_generator import _stamp_static_candidates
    from foundation.payload_library import PayloadLibrary
    from foundation.payload_validator import payload_validator_node

    method = 'sqli_union'
    level = 'medium'
    seeds = PayloadLibrary().load_seed_candidates(method, level)
    visit_candidates = [
        next(candidate for candidate in seeds if candidate.get('stage') == 'exploit'),
        next(candidate for candidate in seeds if candidate.get('stage') == 'bypass'),
    ]
    execution_id = f'capture-revisit-{uuid4().hex}'
    evidence_dir = ROOT / 'revisit-control'

    class RevisitGraph:
        def stream(self, initial_state, stream_mode=None, config=None):
            del stream_mode, config
            previous = None
            for visit_number, candidate in enumerate(visit_candidates, start=1):
                state = deepcopy(previous if previous is not None else initial_state)
                visit_id = f'{method}:fixture-visit:{visit_number}'
                state.update({
                    'selected_method': method,
                    'selected_visit_id': visit_id,
                    'current_surface': 'sqli',
                    'target_method': method,
                    'security_level': level,
                    'payload_mode': 'static_only',
                })
                historical = list(state.get('payload_candidates', {}).get(method, []))
                prior_validation = list(state.get('payload_validation_results', {}).get(method, []))
                current = _stamp_static_candidates(
                    method, level, visit_id, visit_candidates[:visit_number])
                state['payload_candidates'] = {method: [*historical, *current]}
                state['active_payload_candidates'] = {method: {
                    'visit_id': visit_id, 'status': 'pending',
                    'candidate_ids': [row['candidate_id'] for row in current],
                }}
                validation = payload_validator_node(state)
                queue = validation['payload_candidates'][method]
                assert queue and all(row['valid'] for row in
                                     validation['payload_validation_results'][method])
                state['payload_candidates'] = {method: [*historical, *queue]}
                state['payload_validation_results'] = {method: [
                    *prior_validation, *validation['payload_validation_results'][method]]}
                state['payload_provenance'] = {
                    **state.get('payload_provenance', {}), **validation['payload_provenance'],
                }
                state['active_payload_candidates'] = validation['active_payload_candidates']
                state['probe_controls'] = validation['probe_controls']
                controls = state['probe_controls'][method]
                probe = controls['candidates'][visit_number - 1]
                probe_payload = probe['payload_or_logic']
                selected = next(row for row in current
                                if row['source_seed_id'] == candidate['candidate_id'])
                exploit_payload = selected['payload_or_logic']
                endpoint = 'http://localhost/dvwa/vulnerabilities/sqli/'
                probe_response = httpx.Response(200, text='offline probe response', request=
                    httpx.Request('GET', endpoint, params={'id': probe_payload}))
                exploit_response = httpx.Response(200, text='offline exploit response', request=
                    httpx.Request('GET', endpoint, params={'id': exploit_payload}))
                events = [
                    {'node': 'payload_validator', 'event': 'payload.validation.completed',
                     'status': 'ok', 'payload': {'method': method, 'visit_id': visit_id}},
                    probe_event(method, probe_payload, 200, False, endpoint=endpoint,
                                response=probe_response, control_id=probe['control_id']),
                    exploit_event(method, exploit_payload, 200, False, endpoint=endpoint,
                                  response=exploit_response, candidate_id=selected['candidate_id']),
                ]
                updates = make_update(
                    state=state, module_name=method, score=0,
                    tried_payloads=[exploit_payload], telemetry_events=events,
                )
                snapshot = {**state, **updates}
                snapshot['telemetry_events'] = [
                    *state.get('telemetry_events', []), *updates.get('telemetry_events', []),
                ]
                snapshot['response_evidence'] = [
                    *state.get('response_evidence', []), *updates.get('response_evidence', []),
                ]
                snapshot['iteration_count'] = state.get('iteration_count', 0) + 1
                snapshot['task_result'] = 'SUCCESS' if visit_number == len(visit_candidates) else None
                snapshot['next_agent'] = 'scorer'
                previous = snapshot
                yield snapshot

    monkeypatch.setattr('evaluation.runner.build_framework', lambda **_kwargs: RevisitGraph())
    artifact = run_single_engagement(
        target_url='http://localhost/dvwa', security_level=level,
        llm_provider='openai_compatible', surface='sqli', payload_mode='static_only',
        target_method=method, max_iterations=10, output_dir=str(evidence_dir),
        execution_id=execution_id,
    )

    inputs = artifact['method_execution_inputs']
    assert len(inputs) == 2
    assert [row['state']['selected_visit_id'] for row in inputs] == [
        f'{method}:fixture-visit:1', f'{method}:fixture-visit:2',
    ]
    first_queue = inputs[0]['state']['payload_candidates'][method]
    second_queue = inputs[1]['state']['payload_candidates'][method]
    assert [row['source_seed_id'] for row in first_queue] == [visit_candidates[0]['candidate_id']]
    assert {row['source_seed_id'] for row in second_queue} == {
        candidate['candidate_id'] for candidate in visit_candidates
    }
    assert not {row['candidate_id'] for row in first_queue} & {
        row['candidate_id'] for row in second_queue}
    assert all(row['valid'] for visit in inputs for row in
        visit['state']['payload_validation_results'][method])
    assert all(visit['state']['probe_controls'][method]['visit_id'] ==
        visit['state']['selected_visit_id'] for visit in inputs)
    assert artifact['llm_activity'] == {'started': 0, 'completed': 0, 'failed': 0, 'tokens': 0}
    assert artifact['llm_performance'] == []

    response_rows = artifact['response_evidence']
    assert len(response_rows) == 4
    assert len({row['request_id'] for row in response_rows}) == len(response_rows)
    dispositions = artifact['candidate_dispositions']
    disposition_by_visit_candidate = {
        (row['method'], row['visit_id'], row['candidate_id']): row
        for row in dispositions
    }
    first_visit_id, second_visit_id = [row['state']['selected_visit_id'] for row in inputs]
    first_candidate_id = first_queue[0]['candidate_id']
    second_ids = {row['source_seed_id']: row['candidate_id'] for row in second_queue}
    second_first_id = second_ids[visit_candidates[0]['candidate_id']]
    second_candidate_id = second_ids[visit_candidates[1]['candidate_id']]
    assert disposition_by_visit_candidate[(method, first_visit_id, first_candidate_id)]['disposition'] == 'selected_executed'
    revisited_unexecuted = disposition_by_visit_candidate[(method, second_visit_id, second_first_id)]
    assert revisited_unexecuted['disposition'] == 'already_tried'
    assert revisited_unexecuted['selection_status'] == 'selected'
    assert revisited_unexecuted['stop_reason'] == 'already_tried_before_visit'
    assert disposition_by_visit_candidate[(method, second_visit_id, second_candidate_id)]['disposition'] == 'selected_executed'
    for disposition in dispositions:
        assert disposition['method'] == method
        assert disposition['validation']['candidate_id'] == disposition['candidate_id']
        validation = resolve_pointer(artifact, disposition['validation_ref'])
        assert validation['candidate_id'] == disposition['candidate_id']
        for evidence_ref in disposition['response_refs']:
            evidence = resolve_pointer(artifact, evidence_ref)
            assert evidence['candidate_id'] == disposition['candidate_id']
        for request_ref in disposition['request_refs']:
            assert resolve_pointer(artifact, request_ref)
    for input_index, visit in enumerate(inputs):
        visit_id = visit['state']['selected_visit_id']
        rows = [row for row in response_rows if row['visit_id'] == visit_id]
        assert len(rows) == 2
        assert {row['stage'] for row in rows} == {'probe', 'exploit'}
        for row in rows:
            assert row['method'] == method
            assert row['validation']['visit_id'] == visit_id
            assert row['validation']['method'] == method
            assert row['validation_link_status'] == 'linked'
            if row['identity_kind'] == 'independent_control':
                expected_prefix = (
                    f"#/method_execution_inputs/{input_index}/state/probe_controls/{method}/validation_results/"
                )
            else:
                expected_prefix = (
                    f"#/method_execution_inputs/{input_index}/state/payload_validation_results/{method}/"
                )
            assert row['validation_ref'].startswith(expected_prefix)
            assert resolve_pointer(artifact, row['request_ref']) == row['request_structure']
            validation = resolve_pointer(artifact, row['validation_ref'])
            assert validation['candidate_id'] == (
                row['control_id'] if row['identity_kind'] == 'independent_control'
                else row.get('candidate_id', row.get('source_candidate_id')))
            assert validation['valid'] is True

    artifact_path = evidence_dir / f'{execution_id}.json'
    assert artifact_path.exists()
    write_json_report(evidence_dir / 'revisit-control.json', {
        'validation_scope': 'offline_mocked_graph_no_http_or_provider',
        'artifact_path': artifact_path.as_posix(),
        'execution_id': execution_id,
        'visit_ids': [row['state']['selected_visit_id'] for row in inputs],
        'candidate_queues': [[c['candidate_id'] for c in row['state']['payload_candidates'][method]]
                             for row in inputs],
        'response_count': len(response_rows),
        'unique_request_ids': len({row['request_id'] for row in response_rows}),
        'request_links_resolved': sum(
            resolve_pointer(artifact, row['request_ref']) == row['request_structure']
            for row in response_rows),
        'provider_calls': len(artifact['llm_performance']),
    })
