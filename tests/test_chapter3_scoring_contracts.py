"""Chapter 3 v4 scoring and research-metric contract controls.

These are deterministic offline controls: no live DVWA, provider, or matrix run.
They cover required role/visit receipts, operational failure versus refusal,
visit-bound fallback, candidate-bound execution and level-1 signals, chain
assessment availability, ranking/prerequisite verdicts, metric denominators,
price schedules, epoch fields, and pending-final non-substitution.
"""
from copy import deepcopy
from hashlib import sha256
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


def static_candidate(state, method='sqli_union'):
    provenance = state.get('payload_provenance', {})
    return next((cid for cid, details in provenance.items()
                 if isinstance(details, dict) and details.get('source') == 'static_seed'), None)


def test_required_role_receipt_is_never_hidden(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    selection = next(d for d in artifact['final_state']['scoring_decisions'] if d['dimension'] == 'Smethod')
    artifact['final_state']['model_call_requirements'] = [
        {'opportunity_id': 'sel:1', 'role': 'orchestrator', 'method': 'sqli_union',
         'visit_id': selection['visit_id'], 'required': True, 'status': 'completed',
         'reason': 'model_selected', 'call_id': 'call:1'},
        {'opportunity_id': 'gen:1', 'role': 'payload_generator', 'method': 'sqli_union',
         'visit_id': selection['visit_id'], 'required': True, 'status': 'completed',
         'reason': 'model_selected', 'call_id': 'call:missing'},
    ]
    queue = review_queue(export(artifact, 'missing-generator-receipt'))
    assert queue['components']['Soutput'] is None
    assert queue['output_reason'] == f"required_role_receipt_missing:payload_generator@{selection['visit_id']}"


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


def test_previous_visit_seed_cannot_earn_fallback(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    state = artifact['final_state']
    method = 'sqli_union'
    seed = static_candidate(state)
    assert seed is not None
    for row in state.get('payload_validation_results', {}).get(method, []):
        row['visit_id'] = 'sqli_union:visit:1'
    for details in state.get('payload_provenance', {}).values():
        details['visit_id'] = 'sqli_union:visit:1'
    call = artifact['llm_performance'][0]
    artifact['llm_performance'].append({**deepcopy(call), 'call_id': 'gen:visit-2',
        'role': 'payload_generator', 'method': method, 'visit_id': 'sqli_union:visit:2',
        'parse_status': 'invalid', 'validation_status': 'invalid'})
    state['fallback_events'] = [{'event': 'payload_generation.static_seed_fallback',
        'origin': 'payload_generator', 'method': method, 'visit_id': 'sqli_union:visit:2'}]
    queue = review_queue(export(artifact, 'cross-visit-fallback'))
    # The visit-2 generator call is unusable and no visit-2 seed exists: grade 0.
    assert queue['components']['Soutput'] == 0


def test_probe_collision_without_own_request_is_not_executed(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    state = artifact['final_state']
    method = 'sqli_union'
    row = next(r for r in state['response_evidence'] if r.get('stage') in {'exploit', 'bypass'}
               and r.get('candidate_id'))
    candidate_id = row['candidate_id']
    payload = row.get('payload')
    state['response_evidence'] = [r for r in state['response_evidence']
                                  if not (r.get('candidate_id') == candidate_id
                                          and r.get('stage') in {'exploit', 'bypass'})]
    state.setdefault('tried_payloads', {}).setdefault(method, []).append(payload)
    queue = review_queue(export(artifact, 'probe-collision'))
    candidate = next(c for c in queue['candidates'] if c['candidate_id'] == candidate_id)
    assert candidate['eligible'] is False
    assert candidate['executed'] is False
    assert candidate['status'] == 'not_executed'


def test_candidate_level_one_signal_requires_its_baseline(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    state = artifact['final_state']
    method = 'sqli_union'
    row = next(r for r in state['response_evidence'] if r.get('stage') in {'exploit', 'bypass'}
               and r.get('candidate_id'))
    row.update(verified_grade=1, verification_reason='candidate_error_signal', signal_detected=True)
    for decision in state['verifier_history']:
        if decision.get('visit_id') == row.get('visit_id'):
            decision['decision'] = 'confirmed'
    queue = review_queue(export(artifact, 'level1-no-baseline'))
    candidate = next(c for c in queue['candidates'] if c['candidate_id'] == row['candidate_id'])
    assert candidate['proof_ceiling'] is None  # unavailable, not zero and not credited
    control_row = {'evidence_id': f"control:{row['candidate_id']}", 'agent_id': method,
        'method': method, 'stage': 'probe', 'visit_id': row['visit_id'],
        'identity_kind': 'derived_control', 'source_candidate_id': row['candidate_id'],
        'validation_relation': 'candidate_baseline', 'control_id': 'baseline:1',
        'response_sha256': 'f' * 64, 'status_code': 200}
    state['response_evidence'].append(control_row)
    queue = review_queue(export(artifact, 'level1-with-baseline'))
    candidate = next(c for c in queue['candidates'] if c['candidate_id'] == row['candidate_id'])
    assert candidate['proof_ceiling'] == 1 and candidate['status'] == 'pending_review'


def test_one_negative_plus_unassessable_is_not_a_verified_run_negative(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    state = artifact['final_state']
    method = 'sqli_union'
    for row in state['response_evidence']:
        if row.get('stage') in {'exploit', 'bypass'} and row.get('candidate_id'):
            row.update(verified_grade=0, verification_reason='no_verified_exploit_signal',
                       signal_detected=False, success=False)
    for decision in state['verifier_history']:
        decision['decision'] = 'not_confirmed'
    # Drop one candidate's request rows: it is executed/unknown only if a row exists.
    unassessable = next(c['candidate_id'] for c in state['payload_candidates'][method]
                        if c.get('stage') in {'exploit', 'bypass'}
                        and any(r.get('candidate_id') == c['candidate_id'] and r.get('stage') in {'exploit', 'bypass'}
                                for r in state['response_evidence']))
    for row in state['response_evidence']:
        if row.get('candidate_id') == unassessable and row.get('stage') in {'exploit', 'bypass'}:
            row['verification_reason'] = None
    queue = review_queue(export(artifact, 'negative-plus-unassessable'))
    assert queue['components']['Sexploit'] is None  # not a run-level verified negative


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


def test_prerequisite_and_scope_decisions_do_not_need_a_ranking_profile(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    artifact['config']['scoring_profile'] = {}
    selection = next(d for d in artifact['final_state']['scoring_decisions'] if d['dimension'] == 'Smethod')
    selection['observations']['union_select_possible'] = False
    selection['precondition_status']['union_select_possible'] = 'false'
    queue = review_queue(export(artifact, 'prerequisite-without-profile'))
    assert queue['components']['Smethod'] == 1
    assert queue['selection_evidence']['reason'] == 'prerequisites_not_proved_at_selection'
    selection['observations'].pop('union_select_possible')
    selection['precondition_status'].pop('union_select_possible')
    queue = review_queue(export(artifact, 'unknown-prerequisite-without-profile'))
    assert queue['components']['Smethod'] is None
    assert queue['selection_evidence']['reason'] == 'prerequisite_observation_unknown'
    selection['surface'] = 'brute_force'
    queue = review_queue(export(artifact, 'out-of-surface-without-profile'))
    assert queue['components']['Smethod'] == 0


def test_rates_use_unique_calls_and_keep_unbound_events(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    state = artifact['final_state']
    state['invalid_json_events'] = [{'event': 'orchestrator.invalid_json', 'call_id': 'call:1'},
                                    {'event': 'orchestrator.invalid_json', 'call_id': 'call:1'}]
    state['fallback_events'] = [{'event': 'payload_generation.static_seed_fallback', 'method': None}]
    queue = review_queue(export(artifact, 'event-rates'))
    metrics = queue['metrics']['values']
    assert metrics['invalid_json_rate'] == 0.5
    assert queue['metrics']['denominators']['invalid_json_rate']['raw_events'] == 2
    assert queue['metrics']['denominators']['fallback_rate']['unbound_events'] == 1
    assert metrics['fallback_rate'] == 0.0  # Unbound events cannot choose between two calls.
    assert queue['metrics']['denominators']['fallback_rate']['denominator'] == 2


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


def test_repeat_identity_is_a_dimension_not_a_grouping_boundary(monkeypatch):
    from evaluation.thesis_scoring import review_queue, finalize_reviews, compare_receipts
    from tests.test_thesis_scoring_e2e import grades
    receipts = []
    for repeat in (0, 1):
        artifact = v4_artifact(monkeypatch)
        artifact['config']['repeat_index'] = repeat
        artifact['final_state']['repeat_index'] = repeat
        path = export(artifact, f'repeat-{repeat}')
        queue = review_queue(path)
        decisions = [{**d, 'rubric_version': queue['rubric_version']} for d in grades(queue, 'human', 3)]
        receipts.append(finalize_reviews(path, decisions)['receipts']['human'])
    groups = compare_receipts(receipts, planned_repeats=2)['groups']
    human = [g for g in groups if g['scoring_mode'] == 'human']
    assert len(human) == 1
    assert human[0]['n_final'] == 2
    assert human[0]['repeat_indices'] == [0, 1]


def test_scoring_policy_and_source_hashes_are_recorded(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    queue = review_queue(export(artifact, 'policy-epoch'))
    policy = queue['scoring_policy']
    assert policy['policy_version'] == 'scoring-policy.v4.2'
    assert policy['metrics_epoch'] == 'research-metrics.v2'
    assert len(policy['scoring_rule_sha256']) == 64
    for path, digest in policy['source_hashes'].items():
        assert path.endswith('.py') and len(digest) == 64
    assert queue['source_sha256'] == sha256(Path(queue['source_path']).read_bytes()).hexdigest()


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


def test_provider_failure_event_never_earns_fallback_credit(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    selection = next(d for d in artifact['final_state']['scoring_decisions']
                     if d['dimension'] == 'Smethod')
    call = artifact['llm_performance'][0]
    artifact['llm_performance'].append({**deepcopy(call), 'call_id': 'gen:provider',
        'role': 'payload_generator', 'parse_status': 'provider_error',
        'validation_status': 'invalid', 'failure_class': 'provider_error'})
    artifact['final_state']['fallback_events'] = [{'event': 'payload_generation.provider_failure',
        'origin': 'payload_generator', 'method': 'sqli_union', 'visit_id': selection['visit_id'],
        'reason': 'provider_error', 'call_id': 'gen:provider'}]
    queue = review_queue(export(artifact, 'provider-no-credit'))
    assert queue['components']['Soutput'] is None
    assert queue['output_reason'].startswith('operational_failure:')


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


def test_opportunity_population_deduped_and_cost_numerator(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    selection = next(d for d in artifact['final_state']['scoring_decisions']
                     if d['dimension'] == 'Smethod')
    artifact['final_state']['model_call_requirements'] = [
        {'opportunity_id': 'gen:one', 'receipt_stage': 'generation', 'role': 'payload_generator',
         'method': 'sqli_union', 'visit_id': selection['visit_id'], 'required': True,
         'status': 'completed', 'reason': None, 'call_id': 'call:1',
         'parsed_candidate_ids': ['c1']},
        {'opportunity_id': 'gen:one', 'receipt_stage': 'validation', 'role': 'payload_generator',
         'method': 'sqli_union', 'visit_id': selection['visit_id'], 'required': True,
         'status': 'completed', 'reason': None, 'call_id': 'call:1',
         'valid_candidate_ids': ['c1']}]
    schedule = {'schedule_id': 'offline-price', 'version': 'prices.v1', 'currency': 'USD',
        'effective_at': '2026-09-01T00:00:00+00:00',
        'prices': {'offline/fixture': {'input_per_million': 1.0, 'output_per_million': 2.0}}}
    artifact['config']['token_price_schedule'] = schedule
    artifact['payload_generation_opportunities'] = [
        artifact['final_state']['model_call_requirements'][0]]
    artifact['payload_validation_opportunities'] = [
        artifact['final_state']['model_call_requirements'][1]]
    queue = review_queue(export(artifact, 'dedupe-cost'))
    assert queue['metrics']['values']['generation_opportunities'] == 1
    assert queue['metrics']['denominators']['generation_opportunities']['denominator'] in (None, 1)
    cost = queue['metrics']['values']['token_cost']
    per_success = queue['metrics']['denominators']['token_cost_per_success']
    if cost is not None and per_success.get('denominator'):
        assert queue['metrics']['denominators']['token_cost_per_success']['numerator'] == cost


def test_http_counters_are_not_evidence_rows(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    artifact['http_request_counters'] = {
        'policy_version': 'http-accounting.v1', 'complete': True, 'capture_status': 'complete',
        'total_requests': 7, 'retries': 2, 'redirect_hops': 1, 'failed_requests': 3,
        'by_role': {'detection_control': 4, 'candidate_verification': 1}}
    queue = review_queue(export(artifact, 'http-counters'))
    values = queue['metrics']['values']
    assert values['physical_requests_total'] == 7
    assert values['request_retries'] == 2
    assert values['redirect_hops'] == 1
    assert values['failed_requests'] == 3
    assert values['evidence_requests_total'] == sum(
        1 for row in artifact['final_state'].get('response_evidence', [])
        if isinstance(row, dict) and (row.get('agent_id') or row.get('method')) in (None, 'sqli_union'))
    artifact['http_request_counters'] = {'policy_version': 'http-accounting.v1',
        'complete': False, 'capture_status': 'unavailable', 'total_requests': 0,
        'retries': 0, 'redirect_hops': 0, 'failed_requests': 0}
    unavailable = review_queue(export(artifact, 'http-counters-unavailable'))
    assert unavailable['metrics']['values']['physical_requests_total'] is None
    assert unavailable['metrics']['unavailable_reason']['physical_requests_total'] == \
        'http_request_capture_unavailable'
    assert unavailable['metrics']['values']['request_retries'] is None


def test_rejected_first_model_choice_is_not_replaced(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    artifact = v4_artifact(monkeypatch)
    state = artifact['final_state']
    state['selection_rejections'] = [{'decision_origin': 'model', 'source': 'model_orchestrator',
        'method': 'sqli_error', 'visit_id': 'sqli_error:visit:1', 'reason_code': 'precondition_false',
        'required_preconditions': ['error_messages_enabled'],
        'precondition_status': {'error_messages_enabled': 'false'},
        'first_choice': True, 'rejected_at': '2026-10-01T00:00:01+00:00'}]
    queue = review_queue(export(artifact, 'rejected-first'))
    assert queue['metrics']['values']['first_choice_accuracy'] is None
    assert queue['metrics']['unavailable_reason']['first_choice_accuracy'] == \
        'rejected_choice_ranking_snapshot_unavailable'
    assert queue['metrics']['values']['rejected_model_selections'] == 1


def test_template_output_references_accept_the_actual_candidates_schema():
    from core.payload_policy import PAYLOAD_TEMPLATE_SCHEMA_VERSION
    from evaluation.scoring_evidence import output_references_valid
    inputs = {'template': {
        'template_id': 'template.sqli_union.low', 'template_version': 'v1',
        'template_sha256': 'a' * 64, 'target_param': 'id',
        'allowed_parameters': ['id'], 'expected_signal': 'union rows'}}
    output = {'candidates': [{'payload_or_logic': "1' UNION SELECT 1-- -",
                              'target_param': 'id', 'expected_signal': 'union rows'}]}
    record = {'role': 'payload_generator', 'call_id': 'call:template', 'method': 'sqli_union',
        'visit_id': 'sqli_union:visit:1', 'schema_version': PAYLOAD_TEMPLATE_SCHEMA_VERSION,
        'provider': 'offline', 'model': 'fixture', 'started_at': '2026-10-01T00:00:00+00:00',
        'input': inputs, 'output': output, 'input_sha256': evidence_hash(inputs),
        'output_sha256': evidence_hash(output)}
    # The real schema is candidates; template ids stay runtime provenance and
    # the Template input deliberately has no seed/profile payload.
    assert output_references_valid(record)
    leak = deepcopy(record)
    leak['output']['candidates'][0]['source_seed_id'] = 'seed'
    leak['output_sha256'] = evidence_hash(leak['output'])
    assert not output_references_valid(leak)
    wrong = deepcopy(record)
    wrong['output']['candidates'][0]['expected_signal'] = 'other'
    wrong['output_sha256'] = evidence_hash(wrong['output'])
    assert not output_references_valid(wrong)


def test_pair_compatibility_excludes_condition_and_choice_only():
    from evaluation.thesis_scoring import (pair_compatibility_key,
        pair_compatibility_mismatches)
    base = {'rubric_version': 'scoring.v4', 'scoring_mode': 'human',
        'scoring_rule_sha256': 'rule', 'metrics_epoch': 'research-metrics.v2',
        'scoring_policy': {'policy_version': 'scoring-policy.v4.2',
                           'metrics_epoch': 'research-metrics.v2',
                           'rate_definition_version': 'event-rates.v2',
                           'source_hashes': {'a': 'b'}},
        'prompt_identities': {'payload_generator': ['p:schema']},
        'config': {'provider': 'offline', 'model': 'fixture', 'surface': 'sqli',
            'security_level': 'low', 'payload_mode': 'hybrid', 'experiment_condition': 'linear_hybrid',
            'experiment_block': 'selection', 'target_method': None, 'candidate_budget': 5,
            'fixture_id': 'fixture', 'protocol_version': 'p1', 'evasion_enabled': False,
            'evasion_mode': 'reactive', 'repeat_index': 0,
            'token_price_schedule': {'schedule_id': 'price'}, 'scoring_profile': {'sha256': 'p'},
            'payload_policy_version': 'payload-policy.v2', 'control_policy_version': 'detection-controls.v2',
            'budget_policy_version': 'candidate-budget.v2', 'experiment_policy_version': 'chapter3-flow.v2'}}
    akg = deepcopy(base)
    akg['config']['experiment_condition'] = 'akg_guided_hybrid'
    akg['method'] = 'sqli_error'
    base['method'] = 'sqli_union'
    assert pair_compatibility_key(base) == pair_compatibility_key(akg)
    drift = deepcopy(akg)
    drift['config']['fixture_id'] = 'other-fixture'
    assert pair_compatibility_mismatches(base, drift) == ['config']
    assert pair_compatibility_key(base) != pair_compatibility_key(drift)


def test_validation_only_generation_coverage_is_unavailable():
    from evaluation.research_metrics import MetricSet, _generation_requirements, _model_payload_metrics
    artifact = {'payload_generation_opportunities': [],
        'payload_validation_opportunities': [{'role': 'payload_generator',
            'method': 'sqli_union', 'opportunity_id': 'o1', 'receipt_stage': 'validation'}],
        'final_state': {}}
    rows, validation, coverage_reason = _generation_requirements(artifact, 'sqli_union')
    assert rows is None and validation
    assert coverage_reason == 'generation_receipt_missing'
    metrics = MetricSet()
    _model_payload_metrics(metrics, artifact, 'sqli_union', [], [])
    assert metrics.values['generation_opportunities'] is None
    assert metrics.reasons['generation_opportunities'] == 'generation_receipt_missing'


def test_replay_legacy_controls_use_the_complete_canonical_set():
    from evaluation.payload_replay import _legacy_probe_controls_valid
    from foundation.payload_library import PayloadLibrary
    state = {'selected_method': 'sqli_union', 'security_level': 'low',
             'selected_visit_id': 'sqli_union:visit:1'}
    canonical = [c for c in PayloadLibrary().load_seed_candidates('sqli_union', 'low')
                 if c['stage'] == 'probe']
    controls = {'method': 'sqli_union', 'visit_id': state['selected_visit_id'],
                'sha256': evidence_hash(canonical), 'candidates': canonical}
    assert all(row['valid'] for row in _legacy_probe_controls_valid(state, controls))
    controls['candidates'] = list(reversed(canonical))
    assert not all(row['valid'] for row in _legacy_probe_controls_valid(state, controls))


def test_recorded_controls_survive_live_catalog_upgrade_and_reject_tampering(monkeypatch):
    from evaluation.payload_replay import _validated_probe_controls
    import foundation.control_catalog as catalog

    state = {'selected_method': 'sqli_union', 'selected_visit_id': 'sqli_union:visit:1',
             'security_level': 'low'}
    controls = catalog.freeze_detection_controls(state, 'sqli_union')
    monkeypatch.setattr(catalog, 'CATALOG_VERSION', 'future-catalog-version')
    assert all(row['valid'] for row in _validated_probe_controls(state, controls))
    controls['candidates'][0]['payload_or_logic'] += ' tampered'
    assert any(not row['valid'] for row in _validated_probe_controls(state, controls))


def test_template_output_grade_four_from_real_candidates_receipt():
    from core.payload_policy import PAYLOAD_TEMPLATE_SCHEMA_VERSION
    from evaluation.scoring_evidence import output_grade
    inputs = {'template': {
        'template_id': 'template.sqli_union.low', 'template_version': 'v1',
        'template_sha256': 'a' * 64, 'target_param': 'id',
        'allowed_parameters': ['id'], 'expected_signal': 'union rows'}}
    output = {'candidates': [{'payload_or_logic': "1' UNION SELECT 1-- -",
                              'target_param': 'id', 'expected_signal': 'union rows'}]}
    record = {'role': 'payload_generator', 'call_id': 'call:template', 'method': 'sqli_union',
        'visit_id': 'sqli_union:visit:1', 'schema_version': PAYLOAD_TEMPLATE_SCHEMA_VERSION,
        'provider': 'offline', 'model': 'fixture', 'started_at': '2026-10-01T00:00:00+00:00',
        'input': inputs, 'output': output, 'input_sha256': evidence_hash(inputs),
        'output_sha256': evidence_hash(output), 'parse_status': 'ok',
        'validation_status': 'valid', 'attempt': 1}
    artifact = {'final_state': {}, 'llm_performance': [record], 'config': {}}
    grade, reason = output_grade(artifact, 'sqli_union')
    assert (grade, reason) == (4, 'context_call_evidence')


def test_required_call_cannot_be_replaced_by_another_call_in_same_visit():
    from evaluation.scoring_evidence import output_grade

    artifact = {
        'final_state': {'model_call_requirements': [{
            'role': 'payload_generator', 'method': 'sqli_union', 'visit_id': 'v1',
            'required': True, 'status': 'completed', 'call_id': 'required-call',
        }]},
        'llm_performance': [{
            'role': 'payload_generator', 'method': 'sqli_union', 'visit_id': 'v1',
            'call_id': 'unrelated-call', 'parse_status': 'ok', 'validation_status': 'valid',
        }],
    }
    grade, reason = output_grade(artifact, 'sqli_union')
    assert grade is None
    assert reason == 'required_role_receipt_missing:payload_generator@v1'


def test_unscoped_selection_receipt_requires_an_exact_unique_call():
    from evaluation.scoring_evidence import output_grade

    requirement = {'role': 'orchestrator', 'method': 'sqli_union', 'visit_id': None,
                   'required': True, 'status': 'completed', 'call_id': 'selection-call'}
    call = {'role': 'orchestrator', 'method': 'sqli_union', 'visit_id': 'v1',
            'call_id': 'selection-call', 'parse_status': 'ok', 'validation_status': 'valid'}
    calls = [call]
    artifact = {'final_state': {'model_call_requirements': [requirement]},
                'llm_performance': calls}
    assert output_grade(artifact, 'sqli_union')[0] == 3
    requirement['call_id'] = 'different-call'
    assert output_grade(artifact, 'sqli_union')[0] is None
    requirement['call_id'] = 'selection-call'
    calls.append({**call, 'visit_id': 'v2'})
    assert output_grade(artifact, 'sqli_union')[0] is None
    calls.pop()
    requirement['visit_id'] = 'v2'
    assert output_grade(artifact, 'sqli_union')[0] is None


def test_tampered_payload_snapshot_blocks_replay_before_http(tmp_path, monkeypatch):
    import httpx
    from evaluation.payload_replay import replay_method_inputs
    from foundation.payload_snapshot import payload_policy_snapshot

    snapshot = payload_policy_snapshot()
    snapshot['policy_version'] = 'tampered'
    state = {'selected_method': 'sqli_union', 'target_url': 'http://localhost/dvwa',
             'payload_candidates': {'sqli_union': []}}
    path = tmp_path / 'source.json'
    write_json_report(path, {
        'config': {'target_url': state['target_url']},
        'payload_policy_snapshot': snapshot,
        'method_execution_inputs': [{'method': 'sqli_union', 'state': state}],
    })
    monkeypatch.setattr(httpx.Client, 'request',
                        lambda *args, **kwargs: pytest.fail('tampered replay dispatched HTTP'))
    with pytest.raises(ValueError, match='integrity failed'):
        replay_method_inputs(path, output_path=tmp_path / 'replay.json')


def test_selection_consistency_does_not_group_away_different_choices_or_count_graders_twice():
    from evaluation.thesis_scoring import _selection_repeat_summaries

    def receipt(source, method, repeat):
        return {
            'source_sha256': source, 'method': method, 'scoring_mode': 'human',
            'config': {'target_method': None, 'experiment_block': 'selection',
                       'experiment_condition': 'linear_hybrid', 'fixture_id': 'fixture',
                       'repeat_index': repeat},
            'metrics': {'denominators': {'first_choice_accuracy': {
                'origin': 'model', 'chosen_method': method}}},
        }

    first = receipt('source-a', 'sqli_union', 1)
    second = receipt('source-b', 'sqli_error', 2)
    ai = {**deepcopy(first), 'scoring_mode': 'ai'}
    groups = _selection_repeat_summaries([first, second, ai])
    assert len(groups) == 1
    assert groups[0]['first_choice_consistency'] == 0.5
    assert groups[0]['n_first_choice_available'] == 2
    assert groups[0]['first_choice_methods'] == {'sqli_union': 1, 'sqli_error': 1}
    second['config']['repeat_index'] = 1
    unavailable = _selection_repeat_summaries([first, second])[0]
    assert unavailable['first_choice_consistency'] is None
    assert unavailable['unavailable_reason'] == 'duplicate_repeat_identity'


def test_method_alignment_needs_an_independent_candidate_bound_verdict():
    from evaluation.research_metrics import MetricSet, _alignment_metric

    method = 'sqli_union'
    artifact = {'final_state': {'response_evidence': [
        {'candidate_id': cid, 'agent_id': method, 'visit_id': 'v1',
         'stage': 'exploit', 'response_sha256': 'response-digest'}
        for cid in ('one', 'two')
    ]}}
    candidates = [{'candidate_id': cid, 'assessed': True, 'valid': True}
                  for cid in ('one', 'two')]
    missing = MetricSet()
    _alignment_metric(missing, artifact, method, candidates)
    assert missing.values['method_alignment_rate'] is None
    artifact['method_alignment_verdicts'] = [
        {'definition_version': 'method-alignment.v1', 'candidate_id': cid,
         'method': method, 'visit_id': 'v1', 'aligned': aligned,
         'source': 'human_review', 'reviewer_id': 'reviewer', 'reason': 'technique inspected',
         'evidence_refs': [f'#/final_state/response_evidence/{index}']}
        for index, (cid, aligned) in enumerate((('one', True), ('two', False)))
    ]
    assessed = MetricSet()
    _alignment_metric(assessed, artifact, method, candidates)
    assert assessed.values['method_alignment_rate'] == 0.5
    artifact['method_alignment_verdicts'][0]['evidence_refs'] = ['#/final_state/response_evidence/1']
    wrong_candidate = MetricSet()
    _alignment_metric(wrong_candidate, artifact, method, candidates)
    assert wrong_candidate.values['method_alignment_rate'] == 0
    assert wrong_candidate.denominators['method_alignment_rate']['coverage'] == 0.5
