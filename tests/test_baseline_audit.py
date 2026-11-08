"""Offline baseline-audit controls; no target, provider, graph or review execution."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

import evaluation.baseline_audit as baseline_audit
from evaluation.baseline_audit import (
    _ceilings,
    _decision,
    _dependency_census,
    audit_baseline,
    classify_dimension,
)


def measured_negative_artifact(**overrides):
    document = {
        'run_id': 'run-mn',
        'execution_id': 'mn-1',
        'validation_scope': 'offline_synthetic_fixture',
        'config': {
            'scoring_mode': 'human', 'scoring_rubric_version': 'thesis-scoring',
            'scoring_profile': {}, 'scoring_oracles': [],
            'experiment_condition': 'linear_hybrid', 'model': 'model-a',
            'provider': 'provider-a', 'surface': 'access_control',
            'security_level': 'high', 'repeat_index': 0,
        },
        'score_epoch': {'thesis_final': 'thesis-scoring', 'scoring_rule_sha256': 'recorded'},
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


def test_bare_denial_does_not_become_a_fixture_cause():
    record = measured_negative_artifact()
    record["measured_negative"] = {"complete": False}
    record["method_verdicts"] = {}
    record["control_events"] = [{"decision": "denied", "method": "ac_idor"}]
    row = {"state": "null", "component": None,
           "pending_reason": "no_eligible_candidate"}
    queue = {"method": "ac_idor", "components": {"Sexploit": None}, "candidates": []}
    decision, gap = classify_dimension(record, queue, "Sexploit", row, "mn-1")
    assert decision is None
    assert gap["gap"] == "unresolved_sexploit_no_eligible_candidate"

    record["control_events"] = [{
        "decision": "denied", "method": "ac_idor",
        "principal": "gordonb", "object": "admin_user_manager",
        "policy": "admin_only_user_record", "expected_allowed": False,
        "positive_control": {"principal": "admin", "allowed": True},
        "http_status": 403, "response_sha256": "b" * 64,
    }]
    # The audit decision builder admits the matched denial; the null-component
    # classifier still requires a complete measured negative before assigning a
    # fixture cause to an unavailable component.
    decision = _decision(
        "mn-1", "Sexploit", "fixture_infeasible", record, queue,
        ["#/control_events/0"], "matched denial",
    )
    assert decision is not None
    assert decision.get("admission") != "rejected"
    assert decision["cause"] == "fixture_infeasible"
    _decision_result, gap = classify_dimension(
        record, queue, "Sexploit", row, "mn-1")
    assert gap["gap"] == "unresolved_sexploit_no_eligible_candidate"


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


def payload_artifact(origin):
    record = measured_negative_artifact()
    record['final_state']['payload_candidates'] = {'ac_idor': [{
        'candidate_id': 'c1', 'method': 'ac_idor', 'stage': 'exploit',
        'origin_kind': origin, 'source': origin, 'visit_id': 'ac_idor:visit:1',
    }]}
    record['final_state']['payload_provenance'] = {'c1': {
        'origin_kind': origin, 'source': origin, 'visit_id': 'ac_idor:visit:1',
        'model_call_id': None,
    }}
    record['final_state']['payload_validation_results'] = {'ac_idor': [{
        'candidate_id': 'c1', 'valid': True, 'reason': 'ok',
        'visit_id': 'ac_idor:visit:1',
    }]}
    record['final_state']['response_evidence'] = [{
        'evidence_id': 'response:1', 'candidate_id': 'c1', 'agent_id': 'ac_idor',
        'visit_id': 'ac_idor:visit:1', 'stage': 'exploit', 'status_code': 200,
        'response_sha256': 'a' * 64,
        'verification_reason': 'no_verified_exploit_signal',
    }]
    return record


def payload_queue(origin, ceiling, status='pending_review'):
    return {'method': 'ac_idor', 'candidates': [{
        'candidate_id': 'c1', 'method': 'ac_idor', 'stage': 'exploit',
        'eligible': True, 'status': status, 'proof_ceiling': ceiling,
        'base_proof': ceiling, 'executed': True,
        'provenance': {'origin_kind': origin, 'source': origin,
                       'visit_id': 'ac_idor:visit:1'},
        'evidence_refs': ['#/final_state/response_evidence/0'],
        'execution_evidence_refs': ['#/final_state/response_evidence/0'],
    }]}


def test_static_seed_payload_deduction_is_not_model_quality():
    row = {'state': 'deduction', 'component': 3, 'pending_reason': None}
    decision, gap = classify_dimension(
        payload_artifact('static_seed'), payload_queue('static_seed', 3),
        'Spayload', row, 'mn-1')
    assert decision is None
    assert gap['gap'] == 'static_seed_payload_deduction'
    assert '#/final_state/payload_provenance/c1' in gap['evidence_refs']


def test_model_payload_deduction_without_cause_evidence_is_a_gap():
    row = {'state': 'deduction', 'component': 2, 'pending_reason': None}
    decision, gap = classify_dimension(
        payload_artifact('seed_mutation'), payload_queue('seed_mutation', 2),
        'Spayload', row, 'mn-1')
    assert decision is None
    assert gap['gap'] == 'payload_grade_limited_by_candidate_evidence'
    assert '#/final_state/response_evidence/0' in gap['evidence_refs']


def test_model_payload_missing_downstream_proof_is_not_model_quality():
    row = {'state': 'deduction', 'component': 3, 'pending_reason': None}
    decision, gap = classify_dimension(
        payload_artifact('seed_mutation'), payload_queue('seed_mutation', 3),
        'Spayload', row, 'mn-1')
    assert decision is None
    assert gap['gap'] == 'payload_downstream_use_unproved'


def test_verified_negative_payload_signal_is_a_gap_not_model_quality():
    row = {'state': 'deduction', 'component': 0, 'pending_reason': None}
    decision, gap = classify_dimension(
        payload_artifact('seed_mutation'),
        payload_queue('seed_mutation', 0, status='signal_absent'),
        'Spayload', row, 'mn-1')
    assert decision is None
    assert gap['gap'] == 'payload_negative_outcome_without_cause_evidence'
    assert '#/final_state/response_evidence/0' in gap['evidence_refs']


def test_recorded_negative_candidate_reviews_are_a_gap_not_model_quality():
    record = payload_artifact('seed_mutation')
    record['final_state']['scoring_decisions'] = [{
        'dimension': 'Spayload', 'method': 'ac_idor', 'candidate_id': 'c1',
        'score': 0, 'reason': 'own_exploit_events_all_negative',
        'evidence_refs': ['#/final_state/response_evidence/0'],
    }]
    row = {'state': 'deduction', 'component': 0, 'pending_reason': None}
    decision, gap = classify_dimension(
        record, payload_queue('seed_mutation', 2), 'Spayload', row, 'mn-1')
    assert decision is None
    assert gap['gap'] == 'payload_negative_outcome_without_cause_evidence'
    assert '#/final_state/scoring_decisions/0' in gap['evidence_refs']


def ceiling_ledger():
    runs = []
    for index in range(108):
        dimensions = {
            'Smethod': {'state': 'null', 'component': None},
            'Spayload': {'state': 'null', 'component': None},
            'Sexploit': {'state': 'deduction', 'component': 3},
            'Schain': {'state': 'deduction', 'component': 2},
            'Soutput': {'state': 'deduction', 'component': 3},
        }
        if index == 0:
            dimensions['Smethod'] = {'state': 'deduction', 'component': 3}
            dimensions['Spayload'] = {'state': 'deduction', 'component': 2.5}
        elif index == 1:
            dimensions['Schain'] = {'state': 'deduction', 'component': 3}
        elif index == 2:
            dimensions['Sexploit'] = {'state': 'cap', 'component': 4}
        runs.append({'dimensions': dimensions})
    counted = {}
    for run in runs:
        vector = tuple(
            run['dimensions'][dimension].get('component')
            if run['dimensions'][dimension].get('state') in {'cap', 'deduction'} else None
            for dimension in ('Smethod', 'Spayload', 'Sexploit', 'Schain', 'Soutput'))
        counted[vector] = counted.get(vector, 0) + 1
    graded_vectors = [
        {'vector': dict(zip(('Smethod', 'Spayload', 'Sexploit', 'Schain', 'Soutput'), vector)),
         'n_runs': count}
        for vector, count in sorted(counted.items(), key=lambda item: str(item[0]))
    ]
    return {'resolution': {'graded_vectors': graded_vectors, 'runtime_vectors': []},
            'runs': runs}


def test_ceilings_notes_follow_heterogeneous_population():
    result = _ceilings(ceiling_ledger())
    assert result['observed_counts']['Smethod'] == [{'component': 3, 'n_runs': 1}]
    assert result['observed_counts']['Spayload'] == [{'component': 2.5, 'n_runs': 1}]
    assert result['observed_counts']['Schain'] == [
        {'component': 2, 'n_runs': 107}, {'component': 3, 'n_runs': 1}]
    assert result['observed_counts']['Sexploit'] == [
        {'component': 3, 'n_runs': 107}, {'component': 4, 'n_runs': 1}]
    assert result['unavailable_counts'] == {'Smethod': 107, 'Spayload': 107}
    assert result['derived'] == {
        'graded_runs': 108,
        'complete_graded_runs': 1,
        'sexploit_level_4_observed': True,
        'schain_connected_level_observed': True,
    }


def test_dependency_census_reports_mixed_route_evidence(monkeypatch):
    missing = measured_negative_artifact()
    missing['execution_id'] = 'dep-missing'
    missing['final_state']['chain_history'] = [{
        'status': 'completed', 'route_id': 'route:missing',
        'consumption': [{'source_evidence_id': 's1', 'destination_evidence_id': 'd1'}],
    }]
    verified = measured_negative_artifact()
    verified['execution_id'] = 'dep-verified'
    verified['final_state']['chain_history'] = [{
        'status': 'completed', 'route_id': 'route:verified',
        'consumption': [{
            'source_evidence_id': 's2', 'destination_evidence_id': 'd2',
            'dependency_ref': '#/config/scoring_oracles/0/document/dependencies/0',
        }],
    }]
    empty = measured_negative_artifact()
    empty['execution_id'] = 'dep-empty'
    monkeypatch.setattr(
        baseline_audit, 'verified_dependencies',
        lambda record: [{'source': {'candidate_id': 'c1', 'agent_id': 'ac_idor'}}]
        if record is verified else [])
    census = _dependency_census([missing, verified, empty])
    assert census['completed_chain_routes'] == 2
    assert census['completed_routes_without_dependency_ref'] == 1
    assert census['verified_dependencies'] == 1
