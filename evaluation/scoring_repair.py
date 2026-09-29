"""Pure, hash-pinned rescoring of legacy exports using the runtime scorer.

Missing terminal inputs are reported, never synthesized from earlier snapshots.
Only producer semantics established by the archived method code are recoverable.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from core.knowledge_graph import AttackKnowledgeGraph
from core.scorer import scorer
from core.state import METHODS_BY_SURFACE, SCORING_RUBRIC_VERSION, score_decision
from evaluation.manual_scoring_sheet import manual_scoring_rows
from evaluation.payload_replay import _apply_state_update


def _vector(state: dict) -> dict:
    method = state.get('selected_method')
    ids = {c['candidate_id'] for c in state.get('payload_candidates', {}).get(method, [])}
    return dict(zip(('Smethod', 'Spayload', 'Sexploit', 'Schain', 'Soutput', 'Srun'), (
        state.get('method_scores', {}).get(method, 0),
        max((s for cid, s in state.get('payload_scores', {}).items() if cid in ids), default=0),
        state.get('exploitation_scores', {}).get(method, 0),
        state.get('chain_scores', {}).get(method, 0),
        state.get('output_scores', {}).get(method, 0),
        state.get('composite_scores', {}).get(method, 0))))


def rescore_saved_artifact(source_path: str | Path, *, expected_sha256: str) -> dict:
    """Return a derived result; no target/provider access and no source writes."""
    source = Path(source_path)
    raw = source.read_bytes()
    digest = sha256(raw).hexdigest()
    if digest != expected_sha256:
        raise ValueError('Source hash does not match the frozen manifest')
    original = json.loads(raw)
    state = deepcopy(original['final_state'])
    before = _vector(state)
    gaps = [field for field in ('chain_history', 'current_chain', 'found_credentials',
        'attempted_agents', 'tried_payloads', 'verifier_history', 'scoring_decisions') if field not in state]
    decisions = []
    # The original receipt pins these exact recon-produced navigation records.
    navigation = []
    for i, event in enumerate(state.get('containment_events', [])):
        if (event.get('kind') == 'navigation'
                and event.get('reason') == 'navigation link outside allowed DVWA scope'
                and event.get('blocked_url') and event.get('allowed_host')):
            navigation.append(i)
            event.update(classification='discarded_navigation', origin='recon', scope='run')

    selection_repairs = []
    for i, frozen in enumerate(original.get('method_execution_inputs', [])):
        method, inputs = frozen['method'], frozen['state']
        surface = next(s for s, methods in METHODS_BY_SURFACE.items() if method in methods)
        # Frozen pre-execution state is contemporaneous selection evidence,
        # never a substitute for omitted terminal chain/credential fields.
        if method not in inputs.get('method_scores', {}):
            viable = method in AttackKnowledgeGraph().get_viable_methods(surface, inputs.get('observations', {}))
            grade = 3 if viable else 1
            state.setdefault('method_scores', {})[method] = max(state.get('method_scores', {}).get(method, 0), grade)
            receipt = score_decision(state, 'Smethod', method, grade,
                'legacy_routed_selection_graded_from_frozen_destination_preconditions',
                visit_id=f'{method}:saved:{i}', surface=surface, viable=viable,
                selection_source='akg_route' if inputs.get('chain_history') else 'deterministic_fallback',
                evidence_refs=[f'source:#/method_execution_inputs/{i}/state/observations'],
                source_sha256=digest, confidence='supported')
            decisions.append(receipt)
            selection_repairs.append(receipt)

    candidate_comparison = []
    pending = []
    visits = []
    for i, event in enumerate(original.get('execution_log', [])):
        if event.get('event_type') in {'agent.probe.sent', 'agent.exploit.sent'}:
            pending.append((i, event))
        elif pending and event.get('event_type') == 'graph.state':
            verifier = event.get('data', {}).get('latest_verifier')
            if isinstance(verifier, dict) and all(e.get('data', {}).get('agent_id') == verifier.get('agent_id') for _, e in pending):
                visits.append((i, pending, verifier))
                pending = []
    for candidate_id, old in state.get('payload_scores', {}).items():
        candidate = next((c for rows in state.get('payload_candidates', {}).values() for c in rows
                          if c.get('candidate_id') == candidate_id), None)
        if candidate is None:
            candidate_comparison.append({'candidate_id': candidate_id, 'original': old, 'corrected': None,
                'status': 'unresolved_missing_candidate', 'next_control': 'recover_original_validated_candidate_and_response'})
            continue
        method, stage = candidate.get('method'), candidate.get('stage')
        proved = []
        for graph_index, events, verifier in visits:
            linked = [(i, e) for i, e in events if e['data'].get('candidate_id') == candidate_id]
            if not linked:
                continue
            grade = None
            reason = 'legacy_candidate_verifier_detail_missing'
            if stage != 'probe':
                exploits = [(i, e) for i, e in events if e['event_type'] == 'agent.exploit.sent']
                own = [e['data'] for _, e in linked if e['event_type'] == 'agent.exploit.sent']
                if own and all(e.get('success') is False for e in own):
                    # Archived Boolean/time/BF producers emit semantic failure;
                    # UNION/error False occurs only on a failed transaction.
                    grade, reason = 0, 'own_exploit_events_all_negative'
                elif verifier.get('decision') == 'confirmed' and exploits:
                    if method == 'sqli_boolean_blind':
                        if len(own) >= 2 and all(e.get('success') is True for e in own):
                            grade, reason = 3, 'archived_repeatable_boolean_verification'
                    elif exploits[-1][1]['data'].get('candidate_id') == candidate_id:
                        grade, reason = 3, 'archived_executor_stopped_on_this_candidate_confirmation'
            if grade is not None:
                receipt = score_decision(state, 'Spayload', method, grade, reason,
                    visit_id=f'{method}:saved:{graph_index}', candidate_id=candidate_id,
                    stage=stage, provenance=state.get('payload_provenance', {}).get(candidate_id, {}),
                    evidence_refs=[f'source:#/execution_log/{i}' for i, _ in linked] + [f'source:#/execution_log/{graph_index}/data/latest_verifier'],
                    source_sha256=digest, confidence='supported')
                decisions.append(receipt)
                proved.append(receipt)
        if proved:
            corrected = max(d['score'] for d in proved)
            state['payload_scores'][candidate_id] = corrected
            candidate_comparison.append({'candidate_id': candidate_id, 'original': old, 'corrected': corrected,
                'status': 'supported', 'decision_ids': [d['decision_id'] for d in proved]})
        else:
            candidate_comparison.append({'candidate_id': candidate_id, 'original': old, 'corrected': None,
                'retained_legacy_grade': old, 'status': 'unresolved_legacy_candidate_verification',
                'next_control': 'fresh_saved_input_replay_with_candidate_verifier_receipts'})

    # Re-evaluate output rather than seeding the old zero into the minimum reducer.
    state['output_scores'] = {}
    state['composite_scores'] = {}
    state['scoring_decisions'] = decisions
    state['scores'] = {m: r['score'] for m, r in original.get('report', {}).get('module_scores', {}).items()}
    state['selected_visit_id'] = f"{state.get('selected_method')}:legacy_terminal"
    update = scorer(state)
    # Only exported terminal inputs and changed scoring fields are projected.
    for field in ('output_scores', 'composite_scores', 'scoring_decisions'):
        state[field] = _apply_state_update(state, {field: update[field]})[field]
    after = _vector(state)
    output = next((d for d in state['scoring_decisions'] if d['dimension'] == 'Soutput' and d['method'] == state.get('selected_method')), None)
    if output and navigation:
        output['evidence_refs'].extend(f'source:#/final_state/containment_events/{i}' for i in navigation)
        output['reason'] += ':classified_archived_recon_navigation'
        output['source_sha256'] = digest
    result = {'kind': 'diagnostic_rescoring', 'rubric_version': SCORING_RUBRIC_VERSION,
        'source_path': str(source), 'source_sha256': digest, 'coordinate': {
            k: original.get(k, original.get('config', {}).get(k)) for k in
            ('experiment_condition', 'target_method', 'provider', 'surface', 'security_level', 'payload_mode', 'repeat_index')},
        'fresh_http_calls': 0, 'fresh_provider_calls': 0,
        'original_score_vector': before, 'corrected_score_vector': after,
        'component_comparison': [{'dimension': k, 'original': before[k], 'corrected': after[k],
            'changed': before[k] != after[k],
            'status': 'unresolved_legacy_dependency' if k == 'Schain' else (
                'partially_recoverable_candidate_evidence' if k == 'Spayload' else 'supported_stored_input'),
            'decision_ids': [d['decision_id'] for d in state['scoring_decisions'] if d['dimension'] == k],
            'evidence_refs': [f"source:#/final_state/{dict(Smethod='method_scores', Spayload='payload_scores', Sexploit='exploitation_scores', Schain='chain_scores')[k]}"] if k not in {'Soutput', 'Srun'} else
                [ref for d in state['scoring_decisions'] if d['dimension'] == k for ref in d.get('evidence_refs', [])]}
            for k in before],
        'candidate_comparison': candidate_comparison, 'selection_repairs': selection_repairs,
        'legacy_evidence_gaps': gaps, 'next_chain_control': 'independent_source_consumption_and_destination_permission_oracle',
        'terminal_inputs_complete': not gaps,
        'authoritative_full_rescore': False if gaps else True,
        'interpretation': 'Derived scoring correction; retained unresolved legacy grades are not revalidated. Historical chains remain zero without consumption receipts.',
        'config': original['config'], 'final_state': state,
        'scoring_decisions': state['scoring_decisions'],
        'response_evidence': original.get('response_evidence', []),
        'timing_evidence': original.get('timing_evidence', []), 'execution_log': original.get('execution_log', []),
        'verifier_decision': original.get('verifier_decision'),
        'code_sha256': {str(p): sha256(p.read_bytes()).hexdigest() for p in
            (Path(__file__), Path('core/scorer.py'), Path('core/state.py'),
             Path('core/chaining_coordinator.py'), Path('core/knowledge_graph.py'),
             Path('agents/state_utils.py'), Path('foundation/recon.py'),
             Path('foundation/payload_validator.py'), Path('evaluation/manual_scoring_sheet.py'))}}
    result['manual_scoring_evidence'] = manual_scoring_rows(result)
    return result
