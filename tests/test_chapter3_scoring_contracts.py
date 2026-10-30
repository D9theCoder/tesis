"""Chapter 3 v4 scoring and research-metric contract controls.

These are deterministic offline controls: no live DVWA, provider, or matrix run.
They cover required role/visit receipts, operational failure versus refusal,
visit-bound fallback, candidate-bound execution and level-1 signals, chain
assessment availability, ranking/prerequisite verdicts, metric denominators,
price schedules, epoch fields, and pending-final non-substitution.
"""
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE
from evaluation.reporter import write_json_report
from evaluation.scoring_evidence import evidence_hash
from tests.test_scoring_remediation_e2e import control

ROOT = Path('results/validation/chapter3-scoring-contracts')


def profile(surface='sqli'):
    document = {'kind': 'offline_reference_protocol', 'controls': 'synthetic equal-budget protocols'}
    methods = {m: {'preconditions': AttackKnowledgeGraph.METHOD_PRECONDITIONS[m],
        'fit_predicates': [{'key': AttackKnowledgeGraph.METHOD_PRECONDITIONS[m][0], 'equals': True}],
        'planned_request_count': 10, 'protocol_refs': ['protocol'],
        'allowed_plans': ['stop_after_target', 'stop_at_budget', 'continue_same_surface']}
        for m in METHODS_BY_SURFACE[surface]}
    result = {'profile_id': 'offline-ranking', 'version': 'ranking.v1',
        'fixture_id': 'synthetic-dwva', 'protocol_version': 'offline.v1',
        'frozen_at': '2026-09-01T00:00:00+00:00', 'candidate_budget': 5,
        'sources': [{'source_id': 'protocol', 'origin': 'offline_control',
            'document': document, 'sha256': evidence_hash(document)}],
        'scenarios': {f'{surface}:low': methods}}
    result['sha256'] = evidence_hash(result)
    return result


def export(artifact, name):
    path = ROOT / 'controls' / f'{name}-{uuid4().hex}' / 'execution.json'
    write_json_report(path, artifact)
    return path


def v4_artifact(monkeypatch):
    artifact, _, _ = control(monkeypatch, 'mixed_candidates')
    artifact['execution_id'] = uuid4().hex
    artifact['config'].update(scoring_mode='both', scoring_rubric_version='scoring.v4',
        scoring_profile=profile(), scoring_oracles=[], fixture_id='synthetic-dwva',
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
    generator_calls = [r for r in artifact.get('llm_performance', [])
                       if isinstance(r, dict) and r.get('role') == 'payload_generator']
    artifact['llm_performance'] = [{'call_id': 'call:1', 'role': 'orchestrator',
        'method': 'sqli_union', 'visit_id': selection['visit_id'], 'schema_version': 'orchestrator.v1',
        'input': call_input, 'output': output, 'input_sha256': evidence_hash(call_input),
        'output_sha256': evidence_hash(output), 'parse_status': 'ok', 'validation_status': 'valid',
        'attempt': 1, 'provider': 'offline', 'model': 'fixture',
        'started_at': '2026-10-01T00:00:00+00:00', 'call_duration_ms': 10,
        'provider_usage': {'input_tokens': 100, 'output_tokens': 20, 'total_tokens': 120}},
        *generator_calls]
    return artifact


def test_provider_failure_is_operational_not_a_model_refusal(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    call = artifact['llm_performance'][0]
    artifact['llm_performance'].append({**deepcopy(call), 'call_id': 'gen:provider',
        'role': 'payload_generator', 'parse_status': 'provider_error',
        'validation_status': 'invalid', 'failure_class': 'provider_error'})
    queue = review_queue(export(artifact, 'provider-failure'))
    assert queue['components']['Soutput'] is None
    assert queue['output_reason'].startswith('operational_failure:payload_generator@')


def test_chain_assessment_controls_zero_versus_unavailable(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    state = artifact['final_state']
    state['weak_chain_opportunities'] = []
    state['chain_assessment'] = {'assessed': False, 'status': 'not_run',
        'reason': 'stop_before_chain_opportunity', 'edges': [], 'routes_evaluated': 0,
        'policy_version': 'chain-assessment.v1'}
    queue = review_queue(export(artifact, 'chain-not-run'))
    assert queue['components']['Schain'] is None
    assert queue['component_pending_reasons']['Schain'] == 'stop_before_chain_opportunity'
    state['chain_assessment'] = {'assessed': True, 'status': 'assessed', 'reason': 'no_opportunity',
        'edges': [], 'routes_evaluated': 0, 'policy_version': 'chain-assessment.v1'}
    queue = review_queue(export(artifact, 'chain-assessed-absence'))
    assert queue['components']['Schain'] == 0


def test_cost_requires_usage_schedule_and_confirmed_success(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    queue = review_queue(export(artifact, 'cost-without-schedule'))
    assert queue['metrics']['values']['token_cost'] is None
    assert queue['metrics']['unavailable_reason']['token_cost'] == 'token_price_schedule_missing'
    schedule = {'schedule_id': 'offline-price', 'version': 'prices.v1',
        'currency': 'USD', 'effective_at': '2026-09-01T00:00:00+00:00',
        'prices': {'offline/fixture': {'input_per_million': 1.0, 'output_per_million': 2.0}}}
    artifact['config']['token_price_schedule'] = schedule
    queue = review_queue(export(artifact, 'cost-with-schedule'))
    assert queue['metrics']['values']['token_cost'] is None  # Generator usage is not yet known.
    for call in artifact['llm_performance']:
        if call.get('role') == 'payload_generator':
            call['provider_usage'] = {'input_tokens': 5, 'output_tokens': 1, 'total_tokens': 6}
        call['provider_usage']['input_token_details'] = {'cache_read': 0, 'cache_write': 0}
    queue = review_queue(export(artifact, 'cost-with-complete-usage'))
    assert queue['metrics']['values']['token_cost'] == pytest.approx((105 * 1.0 + 21 * 2.0) / 1_000_000)
    per_success = queue['metrics']['values']['token_cost_per_success']
    if queue['metrics']['denominators']['token_cost_per_success']['denominator'] == 0:
        assert per_success is None
        assert queue['metrics']['unavailable_reason']['token_cost_per_success'] == 'no_confirmed_success'


def test_metrics_cover_every_family_and_never_zero_fill(monkeypatch):
    from evaluation.research_metrics import RESEARCH_METRIC_NAMES
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    queue = review_queue(export(artifact, 'metric-coverage'))
    metrics = queue['metrics']
    assert metrics['schema_version'] == 'research-metrics.v2'
    for name in RESEARCH_METRIC_NAMES:
        assert name in metrics['values'], name
        assert name in metrics['availability'], name
        assert name in metrics['denominators'], name
        if metrics['values'][name] is None:
            assert metrics['unavailable_reason'][name], name
    assert metrics['values']['methods_attempted'] >= 1
    assert metrics['denominators']['methods_attempted']['denominator'] == len(
        __import__('core.state', fromlist=['ALL_METHOD_AGENTS']).ALL_METHOD_AGENTS)
    assert metrics['values']['methods_attempted'] + metrics['values']['methods_unattempted'] == len(
        __import__('core.state', fromlist=['ALL_METHOD_AGENTS']).ALL_METHOD_AGENTS)
    limited = review_queue(export(artifact, 'metric-limited'))['metrics']
    assert limited['values']['first_choice_accuracy'] is None
    assert limited['unavailable_reason']['first_choice_accuracy'] in {
        'forced_or_deterministic_selection', 'ranking_unavailable'}
    assert limited['values']['wall_time_ms'] is not None or limited['unavailable_reason']['wall_time_ms']


def test_pending_component_never_produces_a_final_receipt(monkeypatch):
    from evaluation.thesis_scoring import review_queue, finalize_reviews
    artifact = v4_artifact(monkeypatch)
    state = artifact['final_state']
    state['chain_assessment'] = {'assessed': False, 'status': 'not_run', 'reason': 'no_chain_opportunity',
        'edges': [], 'routes_evaluated': 0, 'policy_version': 'chain-assessment.v1'}
    path = export(artifact, 'pending-chain')
    queue = review_queue(path)
    assert queue['components']['Schain'] is None
    result = finalize_reviews(path, [])
    assert result['receipts'] == {}
    assert result['workflows']['human']['status'] == 'pending'
    assert result['workflows']['human']['Srun_final'] is None
    assert result['workflows']['human']['component_pending_reasons']['Schain'] == 'no_chain_opportunity'
    assert result['scoring_policy']['policy_version']


def test_smethod_uses_tri_state_not_known_nodes(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    for value, expected in (('true', 4), ('false', 1), ('unknown', None)):
        artifact = v4_artifact(monkeypatch)
        selection = next(d for d in artifact['final_state']['scoring_decisions']
                         if d['dimension'] == 'Smethod')
        selection.update(preconditions=['union_select_possible'], known_nodes=[],
                         precondition_status={'union_select_possible': value})
        queue = review_queue(export(artifact, f'tri-state-{value}'))
        assert queue['components']['Smethod'] == expected, value


def test_strict_validation_rejection_grades_zero(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    selection = next(d for d in artifact['final_state']['scoring_decisions']
                     if d['dimension'] == 'Smethod')
    call = artifact['llm_performance'][0]
    artifact['llm_performance'].append({**deepcopy(call), 'call_id': 'gen:rejected',
        'role': 'payload_generator', 'parse_status': 'ok', 'validation_status': 'valid'})
    artifact['final_state']['fallback_events'] = [{'event': 'payload_validation.strict_no_candidate',
        'origin': 'payload_validator', 'role': 'payload_generator', 'method': 'sqli_union',
        'visit_id': selection['visit_id'], 'reason': 'no_valid_generated_candidates',
        'call_id': 'gen:rejected'}]
    queue = review_queue(export(artifact, 'strict-rejected'))
    assert queue['components']['Soutput'] == 0


def test_output_references_require_prompt_visible_seeds(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    selection = next(d for d in artifact['final_state']['scoring_decisions']
                     if d['dimension'] == 'Smethod')
    visible = {'source_seed_id': 'seed-visible', 'candidate_id': 'seed-visible',
               'stage': 'exploit', 'payload_or_logic': '1', 'target_param': 'id'}
    hidden = {'source_seed_id': 'seed-probe', 'candidate_id': 'seed-probe',
              'stage': 'probe', 'payload_or_logic': '2', 'target_param': 'id'}
    base_input = {'seeds': [visible, hidden],
        'prompt_visible_seed_ids': ['seed-visible'],
        'prompt_visible_seeds': [visible],
        'prompt_visible_seeds_sha256': evidence_hash([visible]),
        'profile': {'allowed_mutation_types': ['variant'], 'target_params': ['id']}}
    generation_call_id = next(
        row['call_id'] for row in artifact['llm_performance']
        if row.get('role') == 'payload_generator')
    def call_for(seed_id):
        output = {'variants': [{'source_seed_id': seed_id, 'mutation_type': 'variant',
                                'payload_or_logic': "1' AND 3=3-- -"}]}
        return {'call_id': generation_call_id, 'role': 'payload_generator',
            'method': 'sqli_union', 'visit_id': selection['visit_id'],
            'schema_version': 'payload-variants.v3', 'provider': 'offline',
            'model': 'fixture', 'started_at': '2026-10-01T00:00:00+00:00',
            'input': base_input, 'input_sha256': evidence_hash(base_input),
            'output': output, 'output_sha256': evidence_hash(output),
            'parse_status': 'ok', 'validation_status': 'valid', 'attempt': 1}
    artifact['llm_performance'] = [artifact['llm_performance'][0], call_for('seed-probe')]
    assert review_queue(export(artifact, 'hidden-seed'))['components']['Soutput'] == 3
    artifact['llm_performance'] = [artifact['llm_performance'][0], call_for('seed-visible')]
    assert review_queue(export(artifact, 'visible-seed'))['components']['Soutput'] == 4
