"""scoring.v4 evidence checks. No target or provider I/O and no routing input."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE

RUBRIC_VERSION = 'scoring.v4'


def evidence_hash(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def timestamp(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError('Evidence timestamps require a timezone')
    return parsed


def validate_sources(sources):
    from tesis.runtime_events import redact_secrets
    if not isinstance(sources, list):
        raise ValueError('Evidence sources must be a list')
    ids = set()
    for source in sources:
        if not isinstance(source, dict) or not source.get('source_id') or source['source_id'] in ids:
            raise ValueError('Evidence sources require distinct source IDs')
        if source.get('origin') not in {'operator_fixture', 'offline_control'}:
            raise ValueError('Oracle/protocol sources must come from the operator or labeled offline controls')
        if not isinstance(source.get('document'), dict) or source.get('sha256') != evidence_hash(source['document']):
            raise ValueError('Evidence source hash mismatch')
        if redact_secrets(source) != source:
            raise ValueError('Evidence sources must contain safe fingerprints, not authentication secrets')
        ids.add(source['source_id'])
    return ids


def validate_profile(profile):
    """Absent profiles are unavailable; malformed/tampered profiles are errors."""
    if not profile:
        return
    if not isinstance(profile, dict) or profile.get('sha256') != evidence_hash({k: v for k, v in profile.items() if k != 'sha256'}):
        raise ValueError('Ranking profile hash mismatch')
    for field in ('profile_id', 'version', 'fixture_id', 'protocol_version', 'frozen_at'):
        if not isinstance(profile.get(field), str) or not profile[field].strip():
            raise ValueError(f'Ranking profile missing {field}')
    timestamp(profile['frozen_at'])
    if type(profile.get('candidate_budget')) is not int or profile['candidate_budget'] <= 0:
        raise ValueError('Ranking profile candidate budget must be a positive integer')
    sources = validate_sources(profile.get('sources'))
    scenarios = profile.get('scenarios')
    if not isinstance(scenarios, dict) or not scenarios:
        raise ValueError('Ranking profile has no scenarios')
    predicates = {p for required in AttackKnowledgeGraph.METHOD_PRECONDITIONS.values() for p in required}
    for coordinate, entries in scenarios.items():
        parts = coordinate.split(':')
        if len(parts) != 2 or parts[0] not in METHODS_BY_SURFACE or parts[1] not in {'low', 'medium', 'high'}:
            raise ValueError('Ranking profile scenario is outside the registry')
        if not isinstance(entries, dict) or set(entries) != set(METHODS_BY_SURFACE[parts[0]]):
            raise ValueError('Ranking scenario must include every comparison method')
        for method, entry in entries.items():
            if not isinstance(entry, dict) or entry.get('preconditions') != AttackKnowledgeGraph.METHOD_PRECONDITIONS[method]:
                raise ValueError('Ranking prerequisites differ from the static AKG')
            count = entry.get('planned_request_count')
            if type(count) is not int or count <= 0:
                raise ValueError('planned_request_count must be a positive integer, never a boolean')
            refs = entry.get('protocol_refs')
            if not isinstance(refs, list) or not refs or not set(refs) <= sources:
                raise ValueError('Ranking protocol references do not resolve')
            tests = entry.get('fit_predicates')
            if not isinstance(tests, list) or not tests or any(not isinstance(p, dict) or p.get('key') not in predicates
                or type(p.get('equals')) is not bool for p in tests):
                raise ValueError('Unknown or invalid ranking observation predicate')
            plans = entry.get('allowed_plans')
            if not isinstance(plans, list) or not plans or not set(plans) <= {
                'stop_after_target', 'stop_at_budget', 'continue_same_surface', 'chain'}:
                raise ValueError('Ranking requires explicit valid stop/continuation plans')


def validate_evidence_config(version, profile, oracles):
    if version not in {'scoring.v3', RUBRIC_VERSION}:
        raise ValueError('Supported final rubrics are scoring.v3 and scoring.v4')
    validate_profile(profile)
    validate_sources(oracles)
    for source in oracles:
        attestations = source['document'].get('attestations', [])
        if not isinstance(attestations, list) or any(not isinstance(att, dict) for att in attestations):
            raise ValueError('Oracle attestations must be a list of records')


def selection_grade(artifact, method):
    config, state = artifact['config'], artifact['final_state']
    decisions = [d for d in state.get('scoring_decisions', []) if d.get('dimension') == 'Smethod' and d.get('method') == method]
    selection = decisions[-1] if decisions else {}
    result = {'selection_source': selection.get('selection_source'), 'top_methods': [],
        'status': 'unavailable', 'reason': 'missing_selection_snapshot'}
    if not selection:
        return None, result
    surface = selection.get('surface')
    if method not in METHODS_BY_SURFACE.get(surface, []):
        return 0, {**result, 'status': 'assessed', 'reason': 'outside_selected_surface'}
    observations = selection.get('observations')
    if not isinstance(observations, dict):
        return None, result
    if any(observations.get(p) is not True for p in AttackKnowledgeGraph.METHOD_PRECONDITIONS[method]) or any(
        p not in selection.get('known_nodes', []) for p in selection.get('preconditions', [])):
        return 1, {**result, 'status': 'assessed', 'reason': 'prerequisites_not_proved_at_selection'}
    profile = config.get('scoring_profile') or {}
    validate_profile(profile)
    result.update(profile_sha256=profile.get('sha256'), profile_id=profile.get('profile_id'))
    if not profile:
        return None, {**result, 'reason': 'ranking_unavailable'}
    if artifact.get('validation_scope') != 'offline_synthetic_fixture' and any(
        source['origin'] != 'operator_fixture' for source in profile['sources']):
        return None, {**result, 'reason': 'ranking_source_is_offline_control'}
    if selection.get('profile_sha256') != profile['sha256']:
        raise ValueError('Selection ranking profile hash mismatch')
    if any(config.get(k) != profile[k] for k in ('fixture_id', 'protocol_version', 'candidate_budget')):
        return None, {**result, 'reason': 'ranking_coordinate_mismatch'}
    try:
        if timestamp(profile['frozen_at']) > timestamp(selection['selected_at']):
            return None, {**result, 'reason': 'profile_not_frozen_before_selection'}
    except (ValueError, KeyError, TypeError):
        return None, {**result, 'reason': 'selection_time_unavailable'}
    entries = profile['scenarios'].get(f"{surface}:{config.get('security_level')}")
    if not entries:
        return None, {**result, 'reason': 'ranking_scenario_unavailable'}
    ranking = {}
    for name, entry in entries.items():
        # Unknown comparison predicates cannot silently remove a competitor.
        keys = [*entry['preconditions'], *[p['key'] for p in entry['fit_predicates']]]
        if any(type(observations.get(k)) is not bool for k in keys):
            return None, {**result, 'reason': 'ranking_observation_unknown'}
        eligible = all(observations[k] is True for k in entry['preconditions'])
        fit = 2 if all(observations[p['key']] == p['equals'] for p in entry['fit_predicates']) else 1
        ranking[name] = {'eligible': eligible, 'fit_level': fit,
            'planned_request_count': entry['planned_request_count']}
    pairs = {name: (-r['fit_level'], r['planned_request_count']) for name,r in ranking.items() if r['eligible']}
    best = min(pairs.values())
    top = [name for name, pair in pairs.items() if pair == best]
    result.update(status='assessed', comparison=ranking, top_methods=top,
        reason='higher_ranked_comparison_exists' if method not in top else 'top_ranked')
    if method not in top:
        return 2, result
    refs = selection.get('reason_refs')
    reason_ok = isinstance(refs, list) and bool(refs) and all(isinstance(k, str) and observations.get(k) is True for k in refs)
    plan = selection.get('plan') or {}
    kind = plan.get('kind')
    plan_ok = kind in entries[method]['allowed_plans']
    if kind == 'stop_after_target': plan_ok = plan_ok and config.get('target_method') == method
    if kind == 'continue_same_surface': plan_ok = plan_ok and not config.get('target_method')
    if kind == 'chain':
        plan_ok = plan_ok and config.get('experiment_condition') == 'akg_guided_hybrid' and not config.get('target_method') and bool(edge_for(plan))
    result.update(reason_refs_valid=bool(reason_ok), plan_valid=bool(plan_ok))
    return (4 if reason_ok and plan_ok else 3), result


def edge_for(record):
    source, target, agent = (record.get(k) for k in ('source', 'target', 'target_agent'))
    if not all(isinstance(k, str) and k for k in (source, target, agent)):
        return None
    return next((e for e in AttackKnowledgeGraph().get_next_actions(source)
        if e.get('is_chain') and e.get('target') == target and e.get('target_agent') == agent), None)


def oracle_confirmed(artifact, row):
    from evaluation.thesis_scoring import _resolve
    from foundation.verifier import fixture_attestation_valid
    ref = row.get('oracle_ref')
    if not isinstance(ref, str) or not ref.startswith('#/config/scoring_oracles/'):
        return False
    try:
        index = int(ref.split('/')[3])
        source = artifact['config']['scoring_oracles'][index]
    except (KeyError, ValueError, IndexError, TypeError):
        return False
    validate_sources([source])
    if source['origin'] != 'operator_fixture' and artifact.get('validation_scope') != 'offline_synthetic_fixture':
        return False
    attestation = _resolve(artifact, ref)
    return isinstance(attestation, dict) and attestation in source['document'].get('attestations', []) and fixture_attestation_valid(
        attestation, row, source['document'], artifact)


def candidate_base(artifact, cid, method, refs):
    from evaluation.thesis_scoring import _resolve, _candidate_proof
    state = artifact['final_state']
    if not state.get('payload_provenance', {}).get(cid) or not any(v.get('candidate_id') == cid and v.get('valid') is True
        for v in state.get('payload_validation_results', {}).get(method, [])) or not any(c.get('candidate_id') == cid
        and c.get('stage') in {'exploit', 'bypass'} for c in state.get('payload_candidates', {}).get(method, [])):
        return None
    linked = []
    valid_refs = []
    for ref in refs:
        row = _resolve(artifact, ref)
        if isinstance(row, dict) and any(d.get('visit_id') == row.get('visit_id') and d.get('agent_id') == method
            and d.get('source') == 'method_agent_evidence' and any(isinstance(original := _resolve(artifact, r), dict)
                and original.get('evidence_id') == row.get('evidence_id') and original.get('response_sha256') == row.get('response_sha256')
                for r in d.get('evidence_refs', []))
            for d in state.get('verifier_history', [])):
            valid_refs.append(ref)
    for ref in refs:
        row = _resolve(artifact, ref)
        if not isinstance(row, dict) or row.get('candidate_id') != cid or row.get('agent_id') != method:
            continue
        verifier = next((d for d in artifact['final_state'].get('verifier_history', [])
            if d.get('visit_id') == row.get('visit_id') and d.get('agent_id') == method
            and d.get('source') == 'method_agent_evidence' and ref in valid_refs), None)
        if not verifier or row.get('stage') not in {'exploit', 'bypass'} or row.get('status_code') not in (200, 404) or not row.get('response_sha256'):
            continue
        visit_refs = [r for r in valid_refs if _resolve(artifact, r).get('visit_id') == row.get('visit_id')]
        tier = _candidate_proof(artifact, cid, method, visit_refs)
        oracle = False
        if method.startswith(('ac_', 'bf_')):
            oracle = oracle_confirmed(artifact, row)
            if oracle:
                tier = 3
            elif tier is None and row.get('signal_detected') is True:
                tier = 2  # A renamed oracle label cannot establish independent proof.
        if tier is not None:
            if verifier.get('decision') == 'not_confirmed' and tier >= 3 or verifier.get('decision') == 'unverified' and tier >= 3 and not oracle:
                tier = 2
            linked.append(tier)
    if not linked:
        return None
    negatives = any(d.get('decision') == 'not_confirmed' and any(isinstance(r := _resolve(artifact, ref), dict)
        and r.get('candidate_id') == cid and r.get('visit_id') == d.get('visit_id') for ref in refs)
        for d in state.get('verifier_history', []) if d.get('agent_id') == method)
    return min(max(linked), 2) if (negatives or 0 in linked) and max(linked) > 0 else max(linked)


def prerequisite_proof(artifact, route):
    from evaluation.thesis_scoring import _resolve
    edge = edge_for(route)
    if not edge or set(route.get('preconditions', [])) != set(edge.get('preconditions', [])):
        return False
    mapping = route.get('prerequisite_evidence_refs')
    if not isinstance(mapping, dict) or set(mapping) != set(edge['preconditions']):
        return False
    for node, refs in mapping.items():
        if not isinstance(refs, list) or not refs:
            return False
        proved = False
        for ref in refs:
            decision = _resolve(artifact, ref)
            if not isinstance(decision, dict) or decision.get('decision') != 'confirmed' or not decision.get('verifier_id'):
                continue
            nodes = set(decision.get('confirmed_vulns', [])) | set(decision.get('achieved_outcomes', []))
            for surface, methods in METHODS_BY_SURFACE.items():
                if any(f'{m}_confirmed' in nodes for m in methods): nodes.add(f'{surface}_confirmed')
            if node in nodes and any(isinstance(row := _resolve(artifact, r), dict)
                and row.get('visit_id') == decision.get('visit_id')
                and candidate_base(artifact, row.get('candidate_id'), row.get('agent_id'), decision.get('evidence_refs', [])) == 3
                for r in decision.get('evidence_refs', [])):
                proved = True
        if not proved:
            return False
    return True


def verified_dependencies(artifact):
    from evaluation.thesis_scoring import _resolve
    accepted = []
    history = artifact['final_state'].get('verifier_history', [])
    for route in artifact['final_state'].get('chain_history', []):
        if route.get('status') != 'completed' or not prerequisite_proof(artifact, route):
            continue
        sources = [_resolve(artifact, r) for r in route.get('source_evidence_refs', [])]
        destinations = [_resolve(artifact, r) for r in route.get('destination_evidence_refs', [])]
        for consumption in route.get('consumption', []):
            source = next((r for r in sources if isinstance(r, dict) and r.get('evidence_id') == consumption.get('source_evidence_id')), None)
            dest = next((r for r in destinations if isinstance(r, dict) and r.get('evidence_id') == consumption.get('destination_evidence_id')), None)
            if not source or not dest or source.get('agent_id') == dest.get('agent_id'):
                continue
            bindings = {'source_candidate_id': source.get('candidate_id'), 'source_visit_id': source.get('visit_id'),
                'candidate_id': dest.get('candidate_id'), 'visit_id': dest.get('visit_id'), 'route_id': route.get('route_id')}
            if any(not v or consumption.get(k) != v for k,v in bindings.items()):
                continue
            if dest.get('visit_id') != route.get('target_visit_id') or dest.get('agent_id') != route.get('target_agent'):
                continue
            if candidate_base(artifact, source['candidate_id'], source['agent_id'], route['source_evidence_refs']) != 3 or candidate_base(
                artifact, dest['candidate_id'], dest['agent_id'], route['destination_evidence_refs']) != 3:
                continue
            verifier = next((d for d in history if d.get('verifier_id') == route.get('destination_verifier_id')
                and d.get('visit_id') == dest['visit_id'] and d.get('agent_id') == dest['agent_id'] and d.get('decision') == 'confirmed'), None)
            if not verifier or dest.get('consumed_source_evidence_id') != source['evidence_id'] or not any(
                _resolve(artifact, ref) == dest for ref in verifier.get('evidence_refs', [])):
                continue
            # Independence is operator evidence, never the response's consumption label.
            dependency_ref = consumption.get('dependency_ref')
            if not isinstance(dependency_ref, str) or not dependency_ref.startswith('#/config/scoring_oracles/'):
                continue
            att = _resolve(artifact, dependency_ref)
            if not isinstance(att, dict) or any(att.get(k) != v for k,v in bindings.items()):
                continue
            try:
                bundle = artifact['config']['scoring_oracles'][int(dependency_ref.split('/')[3])]
                validate_sources([bundle])
            except (KeyError, IndexError, ValueError, TypeError):
                continue
            if bundle['origin'] != 'operator_fixture' and artifact.get('validation_scope') != 'offline_synthetic_fixture':
                continue
            if att not in bundle['document'].get('dependencies', []) or att.get('depends_on_source') is not True:
                continue
            if any(att.get(k) != artifact.get(k) for k in ('run_id', 'execution_id')) or any(
                att.get(k) != artifact['config'].get(k) for k in ('fixture_id', 'protocol_version')):
                continue
            if att.get('source_evidence_id') != source['evidence_id'] or att.get('destination_evidence_id') != dest['evidence_id']:
                continue
            if att.get('source_response_sha256') != source.get('response_sha256') or att.get('destination_response_sha256') != dest.get('response_sha256'):
                continue
            material = att.get('material_fingerprint')
            if not isinstance(material, str) or len(material) != 64:
                continue
            try:
                if not timestamp(att['source_at']) <= timestamp(att['consumed_at']) <= timestamp(att['verified_at']):
                    continue
                if not source.get('timestamp') or not dest.get('timestamp') or timestamp(att['source_at']) < timestamp(source['timestamp']) or timestamp(att['verified_at']) < timestamp(dest['timestamp']):
                    continue
            except (KeyError, TypeError, ValueError):
                continue
            controls = bundle['document'].get('dependency_controls', [])
            if not all(any(c.get('source_available') is available and c.get('destination_confirmed') is available
                for c in controls if isinstance(c, dict)) for available in (True, False)):
                continue
            accepted.append({'route': route, 'source': source, 'destination': dest, 'consumption': consumption})
    return accepted


def chain_grade(artifact, method, dependencies):
    state = artifact['final_state']
    credited = [d for d in dependencies if d['destination']['agent_id'] == method]
    if credited:
        for second in credited:
            for first in dependencies:
                if first['route']['route_id'] != second['route']['route_id'] and first['destination']['evidence_id'] == second['source']['evidence_id']:
                    return 4
        return 3
    from evaluation.thesis_scoring import _resolve
    for route in state.get('chain_history', []):
        if prerequisite_proof(artifact, route) and any(isinstance(row := _resolve(artifact, ref), dict)
            and row.get('agent_id') == method for ref in route.get('source_evidence_refs', [])):
            return 2
    if 'weak_chain_opportunities' not in state:
        return None
    for weak in state['weak_chain_opportunities']:
        edge = edge_for(weak)
        if weak.get('method') != method or weak.get('opportunity_class') != 'weak' or not edge or not weak.get('missing_material'):
            continue
        statuses = weak.get('prerequisite_status') or {}
        if set(statuses) != set(edge['preconditions']) or not all(v in {'proved', 'unproved'} for v in statuses.values()) or 'unproved' not in statuses.values():
            continue
        if any(isinstance(row := _resolve(artifact, ref), dict) and row.get('agent_id') == method and
            candidate_base(artifact, row.get('candidate_id'), method, weak.get('source_evidence_refs', [])) in (1, 2)
            for ref in weak.get('source_evidence_refs', [])):
            return 1
    return 0


def output_references_valid(record):
    inputs, output = record.get('input'), record.get('output')
    if not isinstance(inputs, dict) or not isinstance(output, dict):
        return False
    if record.get('input_sha256') != evidence_hash(inputs) or record.get('output_sha256') != evidence_hash(output):
        return False
    if not all(record.get(k) for k in ('call_id', 'method', 'visit_id', 'schema_version', 'provider', 'model', 'started_at')):
        return False
    if record['role'] == 'orchestrator':
        refs = output.get('reason_refs')
        observations = inputs.get('observations', {})
        return bool(refs) and isinstance(refs, list) and all(isinstance(ref, str) and observations.get(ref) is True for ref in refs)
    if record['role'] == 'payload_generator':
        seeds = {s.get('source_seed_id') or s.get('candidate_id'): s for s in inputs.get('seeds', [])}
        variants = output.get('variants')
        profile = inputs.get('profile') or {}
        return isinstance(variants, list) and bool(variants) and all(isinstance(c, dict) and
            c.get('source_seed_id') in seeds and c.get('mutation_type') in profile.get('allowed_mutation_types', [])
            and c.get('target_param', seeds[c['source_seed_id']].get('target_param')) in profile.get('target_params', []) for c in variants)
    return False


def output_grade(artifact, method):
    state = artifact['final_state']
    from core.scorer import output_grade as historical_output
    if historical_output(state, method)[0] == 0:
        return 0, 'containment_violation'
    calls = [r for r in artifact.get('llm_performance', []) if r.get('role') in {'orchestrator', 'payload_generator'}
        and (r.get('method') == method or r.get('scope') == 'run')]
    if not calls:
        return None, 'call_evidence_unavailable' if artifact.get('llm_activity', {}).get('started') else 'not_applicable'
    relevant = lambda e: e.get('scope') == 'run' or (e.get('method') or e.get('selected_method')) == method
    fallback = [e for e in state.get('fallback_events', []) if relevant(e)]
    groups = {}
    for call in calls:
        groups.setdefault((call.get('role'), call.get('visit_id')), []).append(call)
    # Credit recovery only in the event's role/visit, never across other calls.
    recovered = set()
    for event in fallback:
        role = event.get('role') or event.get('origin')
        if role == 'payload_validator':
            role = 'payload_generator'
        contexts = [key for key in groups if (not role or key[0] == role)
            and (not event.get('visit_id') or key[1] == event['visit_id'])]
        if len(contexts) == 1:
            recovered.add(contexts[0])
    ids = {cid for cid, p in state.get('payload_provenance', {}).items() if p.get('source') == 'static_seed'}
    validated = any(v.get('candidate_id') in ids and v.get('valid') is True
        for v in state.get('payload_validation_results', {}).get(method, []))
    grades = []
    for key, group in groups.items():
        last = group[-1]
        valid = last.get('parse_status') == 'ok' and last.get('validation_status') == 'valid'
        if key in recovered:
            grades.append(1 if validated else 0)
        elif not valid:
            grades.append(0)
        elif any(c.get('parse_status') != 'ok' or c.get('validation_status') != 'valid' or c.get('attempt', 1) != 1
            or c.get('structured_output_fallback') for c in group):
            grades.append(2)
        else:
            grades.append(4 if all(output_references_valid(c) for c in group) else 3)
    failures = any(relevant(e) for field in ('invalid_json_events', 'output_failure_events', 'guardrail_activations')
        for e in state.get(field, []))
    grade = min(grades)
    if failures and grade > 2:
        grade = 2
    return grade, 'context_call_evidence'


def automatic_components(artifact, method, rows):
    selection, evidence = selection_grade(artifact, method)
    dependencies = verified_dependencies(artifact)
    tiers = [r['base_proof'] for r in rows if r['eligible'] and r['base_proof'] is not None]
    exploit = max(tiers) if tiers else None
    if exploit == 3 and any(d['source']['agent_id'] == method for d in dependencies):
        exploit = 4
    output, output_reason = output_grade(artifact, method)
    return {'Smethod': selection, 'Sexploit': exploit, 'Schain': chain_grade(artifact, method, dependencies),
        'Soutput': output}, evidence, output_reason


def attach_oracle_evidence(artifact):
    """Materialize trusted operator references on an explicitly derived artifact."""
    from foundation.verifier import fixture_attestation_valid
    sources = artifact['config'].get('scoring_oracles', [])
    validate_sources(sources)
    for row in artifact['final_state'].get('response_evidence', []):
        if not isinstance(row, dict) or not isinstance(row.get('agent_id'), str):
            continue
        matches = []
        for i, source in enumerate(sources):
            if source['origin'] != 'operator_fixture' and artifact.get('validation_scope') != 'offline_synthetic_fixture':
                continue
            for j, att in enumerate(source['document'].get('attestations', [])):
                if fixture_attestation_valid(att, row, source['document'], artifact):
                    matches.append(f'#/config/scoring_oracles/{i}/document/attestations/{j}')
        if len(matches) == 1:
            row['oracle_ref'] = matches[0]
        elif len(matches) > 1:
            row['oracle_conflict'] = 'ambiguous_operator_attestations'
            row.pop('oracle_ref', None)


def weak_opportunity_update(state):
    """Passive partial evidence; never changes nodes, eligibility or route priority."""
    from evaluation.thesis_scoring import PROOF_TIERS
    result = []
    history = state.get('weak_chain_opportunities', [])
    kg = AttackKnowledgeGraph()
    for i, row in enumerate(state.get('response_evidence', [])):
        if row.get('stage') not in {'exploit', 'bypass'} or not row.get('candidate_id') or not row.get('response_sha256') or row.get('status_code') != 200:
            continue
        if PROOF_TIERS.get(row.get('verification_reason')) not in (1, 2):
            continue
        # Only method evidence of incomplete material matches these source nodes.
        source = 'credentials_extracted' if row.get('verification_reason') == 'partial_union_data' else None
        if source is None:
            continue
        for edge in kg.get_next_actions(source):
            if not edge.get('is_chain'):
                continue
            identifier = f"weak:{row['evidence_id']}:{edge['target']}"
            if any(h.get('evidence_id') == identifier for h in history):
                continue
            result.append({'evidence_id': identifier, 'opportunity_class': 'weak',
                'method': row['agent_id'], 'candidate_id': row['candidate_id'], 'visit_id': row['visit_id'],
                'source': source, 'target': edge['target'], 'target_agent': edge['target_agent'],
                'missing_material': ['complete_credentials'], 'source_evidence_refs': [f'#/final_state/response_evidence/{i}'],
                'prerequisite_status': {p: 'unproved' for p in edge['preconditions']},
                'timestamp': datetime.now(timezone.utc).isoformat()})
    return {'weak_chain_opportunities': result} if result else {}
