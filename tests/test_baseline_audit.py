"""Offline baseline-audit controls; no target, provider, graph or review execution."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from evaluation.baseline_audit import audit_baseline, classify_dimension


def measured_negative_artifact(**overrides):
    document = {
        'run_id': 'run-mn',
        'execution_id': 'mn-1',
        'validation_scope': 'offline_synthetic_fixture',
        'config': {
            'scoring_mode': 'human', 'scoring_rubric_version': 'scoring.v4',
            'scoring_profile': {}, 'scoring_oracles': [],
            'experiment_condition': 'linear_hybrid', 'model': 'model-a',
            'provider': 'provider-a', 'surface': 'access_control',
            'security_level': 'high', 'repeat_index': 0,
        },
        'score_epoch': {'thesis_final': 'scoring.v4', 'scoring_rule_sha256': 'recorded'},
        'final_state': {
            'weak_chain_opportunities': [],
            'model_call_requirements': [{
                'role': 'orchestrator', 'required': False, 'status': 'not_run',
                'reason': 'NO_VIABLE_METHODS', 'method': None, 'visit_id': None,
                'call_id': None,
            }],
            'scoring_decisions': [], 'payload_candidates': {},
        },
        'measured_negative': {
            'complete': True,
            'reason': 'every_required_precondition_measured_false',
            'surface': 'access_control',
        },
        'method_verdicts': {
            'ac_idor': {'verdict': 'not_vulnerable', 'signal_detected': False,
                        'required_preconditions': ['object_ids_enumerable']},
        },
        'control_events': [{
            'status': 'sent', 'physical_requests': 1, 'method': 'ac_idor',
            'visit_id': 'ac_idor:visit:1', 'control_id': 'c1',
            'at': '2026-10-30T12:00:00+00:00', 'phase': 'method_probe',
        }],
    }
    document.update(overrides)
    return document


def write_artifact(root, document, name='mn.json'):
    path = Path(root) / 'runs' / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document))
    return path


def test_audit_accounts_for_measured_negative_fixture(tmp_path):
    source = tmp_path / 'source'
    path = write_artifact(source, measured_negative_artifact())
    before = sha256(path.read_bytes()).hexdigest()
    output = tmp_path / 'out' / 'audit.json'
    document = audit_baseline(source, output=output)

    assert document['population']['accepted_runs'] == 1
    assert document['accounting']['total_deductions_and_nulls'] == 5
    assert document['accounting']['closed_total'] == 5
    assert document['accounting']['unresolved_total'] == 0
    assert document['fidelity']['F3']['value'] == 1.0
    assert document['accounting']['by_cause'] == {'fixture_infeasible': 5}
    assert document['inputs']['artifacts_unchanged'] is True
    assert document['inputs']['run_sources'][0]['sha256'] == before
    assert sha256(path.read_bytes()).hexdigest() == before
    assert output.exists()
    assert json.loads(output.read_text())['audit_version'] == document['audit_version']


def test_audit_refuses_output_inside_source_root(tmp_path):
    source = tmp_path / 'source'
    write_artifact(source, measured_negative_artifact())
    with pytest.raises(ValueError, match='inside the source root'):
        audit_baseline(source, output=source / 'audit.json')


def test_missing_selected_authority_receipt_is_an_explicit_gap():
    record = measured_negative_artifact()
    record['final_state']['payload_candidates'] = {'ac_idor': [{'candidate_id': 'c1'}]}
    row = {'state': 'null', 'component': None,
           'pending_reason': 'pending_candidate_grades'}
    decision, gap = classify_dimension(
        record, {'method': 'ac_idor', 'candidates': [{'eligible': True}]},
        'Spayload', row, 'mn-1')
    assert decision is None
    assert gap['gap'] == 'missing_selected_authority_receipt'
    assert gap['run_ref'] == 'mn-1'


def test_rejected_selection_without_decision_is_a_scoring_gap():
    record = measured_negative_artifact()
    record['final_state']['model_call_requirements'] = [{
        'role': 'orchestrator', 'required': True, 'status': 'completed',
        'reason': 'selection_rejected_precondition_false',
        'method': 'ac_force_browse', 'visit_id': 'ac_force_browse:visit:1',
        'call_id': 'mn-1:orchestrator:1',
    }]
    record['final_state']['precondition_status'] = {
        'force_browse_endpoints_visible': 'false',
    }
    record['llm_performance'] = [{
        'call_id': 'mn-1:orchestrator:1', 'role': 'orchestrator',
        'method': 'ac_force_browse', 'visit_id': 'ac_force_browse:visit:1',
        'parse_status': 'ok', 'validation_status': 'valid',
        'input': {'observations': {'force_browse_endpoints_visible': False}},
        'output': {'next_agent': 'ac_force_browse', 'reason_code': 'best_viable'},
    }]
    row = {'state': 'null', 'component': None,
           'pending_reason': 'ranking_unavailable:missing_selection_snapshot'}
    decision, gap = classify_dimension(
        record, {'method': None, 'candidates': []}, 'Smethod', row, 'mn-1')
    assert gap is None
    assert decision['cause'] == 'harness_scoring'
    assert '#/llm_performance/0' in decision['evidence_refs']
    assert 'precondition' in decision['note']


def test_chain_ready_route_without_dependency_ref_is_an_evidence_gap():
    record = measured_negative_artifact()
    record['final_state']['chain_history'] = [{
        'status': 'completed', 'route_id': 'route:0',
        'source_evidence_refs': ['#/final_state/response_evidence/0'],
        'consumption': [{'source_evidence_id': 'response:1',
                         'destination_evidence_id': 'response:2'}],
    }]
    record['final_state']['response_evidence'] = [
        {'evidence_id': 'response:1', 'candidate_id': 'c1', 'agent_id': 'sqli_union',
         'visit_id': 'sqli_union:visit:1', 'stage': 'exploit'},
    ]
    row = {'state': 'deduction', 'component': 2, 'pending_reason': None}
    decision, gap = classify_dimension(
        record, {'method': 'sqli_time_blind', 'candidates': []},
        'Schain', row, 'mn-1')
    assert decision is None
    assert gap['gap'] == 'missing_dependency_attestation'
    assert '#/final_state/chain_history/0' in gap['evidence_refs']


def destination_unproved_edge():
    return {
        'status': 'infeasible', 'edge_supported': True,
        'decisive_stage': 'destination',
        'reason': 'destination_preconditions_not_proved',
        'destination_rejection': {
            'code': 'destination_preconditions_not_proved',
            'detail': 'unproved destination preconditions: no_rate_limit',
        },
        'source_rejection': None,
        'source': 'credentials_extracted', 'target': 'bf_dictionary',
        'target_agent': 'bf_dictionary',
    }


def test_destination_precondition_unproved_is_not_fixture_infeasible():
    record = measured_negative_artifact()
    record['final_state']['chain_assessment'] = {'edges': [destination_unproved_edge()]}
    record['final_state']['chain_history'] = []
    row = {'state': 'deduction', 'component': 3, 'pending_reason': None}
    decision, gap = classify_dimension(
        record, {'method': 'sqli_time_blind', 'candidates': []},
        'Sexploit', row, 'mn-1')
    assert decision is None
    assert gap['gap'] == 'destination_precondition_unproved'
    assert '#/final_state/chain_assessment/edges/0' in gap['evidence_refs']
    assert 'Missing proof' in gap['detail']


def test_destination_precondition_unproved_is_not_fixture_for_chain():
    record = measured_negative_artifact()
    record['final_state']['chain_assessment'] = {'edges': [destination_unproved_edge()]}
    record['final_state']['chain_history'] = []
    row = {'state': 'deduction', 'component': 0, 'pending_reason': None}
    decision, gap = classify_dimension(
        record, {'method': 'sqli_time_blind', 'candidates': []},
        'Schain', row, 'mn-1')
    assert decision is None
    assert gap['gap'] == 'destination_precondition_unproved'
    assert '#/final_state/chain_assessment/edges/0' in gap['evidence_refs']


def test_completed_route_without_dependency_is_not_ordering():
    record = measured_negative_artifact()
    record['final_state']['chain_history'] = [{
        'status': 'completed', 'route_id': 'route:0',
        'consumption': [{'source_evidence_id': 'response:1',
                         'destination_evidence_id': 'response:2'}],
    }]
    row = {'state': 'deduction', 'component': 3, 'pending_reason': None}
    decision, gap = classify_dimension(
        record, {'method': 'sqli_time_blind', 'candidates': []},
        'Sexploit', row, 'mn-1')
    assert decision is None
    assert gap['gap'] == 'missing_dependency_attestation'
    assert 'ordering alone is not sufficient' in gap['detail']


def test_gap_refs_are_filtered_to_resolving_pointers():
    record = measured_negative_artifact()
    record['final_state']['payload_candidates'] = {}
    # payload_validation_results is deliberately absent; the classifier must drop
    # that pointer instead of publishing it.
    queue = {
        'method': 'ac_idor',
        'candidates': [{'eligible': True}],
        'components': {'Smethod': None, 'Sexploit': 3, 'Schain': 0, 'Soutput': 3},
        'component_pending_reasons': {},
    }
    row = {'state': 'null', 'component': None,
           'pending_reason': 'pending_candidate_grades'}
    decision, gap = classify_dimension(record, queue, 'Spayload', row, 'mn-1')
    assert decision is None
    assert gap['gap'] == 'missing_selected_authority_receipt'
    assert 'queue:#/component_pending_reasons/Spayload' not in gap['evidence_refs']
    assert '#/final_state/payload_validation_results' not in gap['evidence_refs']
    assert 'queue:#/candidates' in gap['evidence_refs']
    assert '#/final_state/payload_candidates' in gap['evidence_refs']
    assert all(ref.startswith(('#/', 'queue:#/')) for ref in gap['evidence_refs'])
