"""scoring.v4 evidence checks. No target or provider I/O and no routing input."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re

from core.knowledge_graph import AttackKnowledgeGraph, get_attack_knowledge_graph
from core.payload_policy import (
    EVENT_MODEL_BUDGET_EXCLUDED,
    EVENT_PROVIDER_FAILURE,
    EVENT_STATIC_FALLBACK,
    EVENT_STRICT_NO_CANDIDATE,
    EVENT_TARGET_NO_VALID_PAYLOADS,
    EVENT_TEMPLATE_UNAVAILABLE,
    EVENT_VALIDATION_NO_USABLE,
    EVENT_VALIDATION_STRICT_NO_CANDIDATE,
    is_provider_failure_reason,
)
from core.state import METHODS_BY_SURFACE

RUBRIC_VERSION = 'scoring.v4'
STATIC_ORIGIN_KINDS = frozenset({'static_seed'})
CONTROL_IDENTITY_KINDS = frozenset({
    'probe_candidate', 'derived_control', 'independent_control', 'unresolved',
})
EXPERIMENT_ROLES = frozenset({'orchestrator', 'payload_generator'})
CANDIDATE_STAGES = frozenset({'exploit', 'bypass'})


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
            if any(k in entry for k in ('reference_status', 'reference_fit', 'reference_reason')):
                status, fit = entry.get('reference_status'), entry.get('reference_fit')
                if status not in {'confirmed', 'pending'} or not isinstance(entry.get('reference_reason'), str) or not entry['reference_reason'].strip():
                    raise ValueError('Calibration requires a status and evidence reason')
                if status == 'confirmed' and (type(fit) is not int or not 1 <= fit <= 3) or status == 'pending' and fit is not None:
                    raise ValueError('Confirmed reference fit must be 1..3; pending fit must be null')


def validate_evidence_config(version, profile, oracles):
    if version not in {'scoring.v3', RUBRIC_VERSION}:
        raise ValueError('Supported final rubrics are scoring.v3 and scoring.v4')
    validate_profile(profile)
    validate_sources(oracles)
    for source in oracles:
        for field in ('attestations', 'negative_attestations'):
            attestations = source['document'].get(field, [])
            if not isinstance(attestations, list) or any(not isinstance(att, dict) for att in attestations):
                raise ValueError('Oracle attestations must be a list of records')


def evidence_rows(artifact):
    """Return the artifact's evidence rows without copying or rewriting them."""
    state = artifact.get('final_state') if isinstance(artifact, dict) else None
    rows = state.get('response_evidence') if isinstance(state, dict) else None
    if isinstance(rows, list):
        return rows
    rows = artifact.get('response_evidence') if isinstance(artifact, dict) else None
    return rows if isinstance(rows, list) else []


def candidate_execution_rows(artifact, candidate_id, method=None):
    """Rows that are this candidate's own exploit/bypass request.

    A matching probe string, a derived verification control or an independent
    control never establishes candidate execution. Historical rows without the
    explicit denominator flag fall back to the identity/stage/response fields;
    contradictory control identities remain unexecuted.
    """
    if candidate_id is None:
        return []
    rows = []
    for index, row in enumerate(evidence_rows(artifact)):
        if not isinstance(row, dict) or row.get('candidate_id') is None:
            continue
        if str(row.get('candidate_id')) != str(candidate_id):
            continue
        if method is not None and (row.get('agent_id') or row.get('method')) not in (None, method):
            continue
        if row.get('control_id') or row.get('source_candidate_id'):
            continue
        kind = row.get('identity_kind')
        if kind in CONTROL_IDENTITY_KINDS or kind not in (None, 'candidate'):
            continue
        if (row.get('stage') or '') not in CANDIDATE_STAGES:
            continue
        if row.get('eligible_for_exploit_denominator') is False:
            continue
        if not row.get('response_sha256'):
            continue
        rows.append((index, row))
    return rows


def candidate_lifecycle_status(artifact, candidate_id, method=None):
    """Latest append-only lifecycle status, with contradictions left explicit."""
    state = artifact.get('final_state') if isinstance(artifact, dict) else None
    rows = state.get('candidate_lifecycle') if isinstance(state, dict) else None
    if not isinstance(rows, list):
        return None
    statuses = [row.get('status') for row in rows if isinstance(row, dict)
                and str(row.get('candidate_id')) == str(candidate_id)
                and (method is None or row.get('method') == method)]
    if not statuses:
        return None
    if 'executed' in statuses:
        executed_rows = [row for row in rows if isinstance(row, dict)
                         and str(row.get('candidate_id')) == str(candidate_id)
                         and (method is None or row.get('method') == method)
                         and row.get('status') == 'executed']
        evidenced = [row for row in executed_rows if str(row.get('reason') or '') != 'request_failed']
        if evidenced:
            return 'executed' if set(statuses) <= {'executed', 'queued', 'valid', 'generated'} else 'conflicting'
        return 'request_failed'
    for status in ('stopped_before_execution', 'budget_excluded', 'rejected'):
        if status in statuses:
            return status
    return statuses[-1]


def candidate_execution_evidence(artifact, candidate_id, method=None):
    """Candidate-bound execution rows, including the recorded visit binding.

    A request in another visit, or an ambiguous provenance/visit mismatch, is not
    execution evidence. Historical rows without any visit identity remain usable;
    contradictions stay unavailable rather than being rewritten.
    """
    rows = candidate_execution_rows(artifact, candidate_id, method)
    if not rows:
        return []
    state = artifact.get('final_state') if isinstance(artifact, dict) else None
    provenance = state.get('payload_provenance', {}) if isinstance(state, dict) else {}
    provenance = provenance if isinstance(provenance, dict) else {}
    details = provenance.get(candidate_id) if isinstance(provenance.get(candidate_id), dict) else {}
    visits = {str(row.get('visit_id')) for _index, row in rows if row.get('visit_id')}
    lifecycle = state.get('candidate_lifecycle') if isinstance(state, dict) else None
    lifecycle_visits = {str(row.get('visit_id')) for row in (lifecycle or [])
                        if isinstance(row, dict) and str(row.get('candidate_id')) == str(candidate_id)
                        and (method is None or row.get('method') == method)
                        and row.get('status') == 'executed' and row.get('visit_id')}
    expected = details.get('visit_id')
    if expected:
        matched = [(index, row) for index, row in rows if str(row.get('visit_id')) == str(expected)]
        if matched:
            return matched
        matched = [(index, row) for index, row in rows if str(row.get('visit_id')) in lifecycle_visits]
        return matched
    if lifecycle_visits:
        return [(index, row) for index, row in rows if str(row.get('visit_id')) in lifecycle_visits]
    row_visits = {str(row.get('visit_id')) for _index, row in rows if row.get('visit_id')}
    if len(row_visits) > 1:
        # Multiple visits and no provenance/lifecycle binding: ambiguous history
        # cannot establish which execution belongs to the assessed candidate.
        return []
    return rows


def candidate_is_executed(artifact, candidate_id, method=None):
    status = candidate_lifecycle_status(artifact, candidate_id, method)
    if status in {'stopped_before_execution', 'budget_excluded', 'rejected', 'conflicting'}:
        return False
    return bool(candidate_execution_evidence(artifact, candidate_id, method))


def candidate_baseline_evidence(artifact, candidate_id, method=None, row=None):
    """Method-appropriate baseline bound to this candidate and visit.

    Accepts a recorded candidate-derived control, inline baseline measurement
    fields, or a frozen control event naming the candidate. A probe string or an
    unrelated control never satisfies it.
    """
    visit_id = row.get('visit_id') if isinstance(row, dict) else None
    for other in evidence_rows(artifact):
        if not isinstance(other, dict):
            continue
        if str(other.get('source_candidate_id') or '') != str(candidate_id):
            continue
        if method is not None and (other.get('agent_id') or other.get('method')) not in (None, method):
            continue
        if other.get('identity_kind') not in {'derived_control', 'independent_control'}:
            continue
        if visit_id and other.get('visit_id') != visit_id:
            continue
        if other.get('validation_relation') in {'candidate_baseline', 'complementary_boolean', 'candidate_repeat'} \
                or other.get('control_id'):
            return other
    if isinstance(row, dict) and (row.get('baseline_elapsed_ms') is not None
                                  or row.get('baseline_response_sha256') is not None):
        return row
    state = artifact.get('final_state') if isinstance(artifact, dict) else None
    controls = (state.get('probe_controls') or {}).get(method) if isinstance(state, dict) else None
    lifecycle_visits = {str(item.get('visit_id')) for item in (state or {}).get('candidate_lifecycle', []) or []
                        if isinstance(item, dict) and str(item.get('candidate_id')) == str(candidate_id)
                        and (method is None or item.get('method') == method) and item.get('visit_id')}
    for event in (controls or {}).get('control_events', []) or []:
        if not isinstance(event, dict):
            continue
        if str(event.get('candidate_id')) != str(candidate_id):
            continue
        if event.get('status') not in {'sent', 'failed'}:
            continue
        if event.get('control_class') != 'candidate_verification':
            # Detection/oracle controls are not candidate verification baselines.
            continue
        event_visit = event.get('visit_id')
        if visit_id and event_visit != visit_id:
            continue
        if not visit_id and event_visit:
            if lifecycle_visits != {str(event_visit)}:
                continue
        if not visit_id and not event_visit and len(lifecycle_visits) > 1:
            continue
        return event
    return None


def ranking_comparison(artifact, selection):
    """Return (top_methods|None, reason|None, detail) for one frozen snapshot.

    Shared by the final-selection grade and the first-choice research metric so
    the ranking rule is defined exactly once.
    """
    config = artifact.get('config') or {}
    detail = {'selection_source': selection.get('selection_source') or selection.get('decision_origin'),
              'top_methods': [], 'status': 'unavailable'}
    if not selection:
        return None, 'missing_selection_snapshot', detail
    surface = selection.get('surface')
    profile = config.get('scoring_profile') or {}
    if not profile:
        return None, 'ranking_unavailable', detail
    validate_profile(profile)
    detail.update(profile_sha256=profile.get('sha256'), profile_id=profile.get('profile_id'))
    observations = selection.get('observations')
    if not isinstance(observations, dict):
        return None, 'missing_selection_snapshot', detail
    if artifact.get('validation_scope') != 'offline_synthetic_fixture' and any(
        source['origin'] != 'operator_fixture' for source in profile['sources']):
        return None, 'ranking_source_is_offline_control', detail
    recorded_profile = selection.get('profile_sha256')
    if recorded_profile is None:
        return None, 'selection_profile_identity_unavailable', detail
    if recorded_profile != profile['sha256']:
        raise ValueError('Selection ranking profile hash mismatch')
    coordinate_keys = ('fixture_id', 'protocol_version', 'candidate_budget')
    if any(config.get(k) != profile.get(k) for k in coordinate_keys):
        return None, 'ranking_coordinate_mismatch', detail
    expected_policy = profile.get('payload_policy_version')
    if expected_policy is not None and config.get('payload_policy_version') not in (None, expected_policy):
        return None, 'ranking_policy_epoch_mismatch', detail
    try:
        if timestamp(profile['frozen_at']) > timestamp(selection['selected_at']):
            return None, 'profile_not_frozen_before_selection', detail
    except (ValueError, KeyError, TypeError):
        return None, 'selection_time_unavailable', detail
    entries = profile['scenarios'].get(f"{surface}:{config.get('security_level')}")
    if not entries:
        return None, 'ranking_scenario_unavailable', detail
    ranking = {}
    for name, entry in entries.items():
        # Unknown comparison predicates cannot silently remove a competitor.
        keys = [*entry['preconditions'], *[p['key'] for p in entry['fit_predicates']]]
        if any(type(observations.get(k)) is not bool for k in keys):
            return None, 'ranking_observation_unknown', detail
        eligible = all(observations[k] is True for k in entry['preconditions'])
        if eligible and entry.get('reference_status') == 'pending':
            return None, 'ranking_reference_pending', {
                **detail, 'pending_method': name, 'reference_reason': entry['reference_reason']}
        fit = entry.get('reference_fit', 2) if all(observations[p['key']] == p['equals'] for p in entry['fit_predicates']) else 1
        ranking[name] = {'eligible': eligible, 'fit_level': fit,
            'planned_request_count': entry['planned_request_count']}
    pairs = {name: (-r['fit_level'], r['planned_request_count']) for name, r in ranking.items() if r['eligible']}
    if not pairs:
        return None, 'ranking_no_eligible_method', detail
    best = min(pairs.values())
    top = [name for name, pair in pairs.items() if pair == best]
    detail.update(status='assessed', comparison=ranking, top_methods=top)
    return top, None, detail


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
    statuses = selection.get('precondition_status')
    required = AttackKnowledgeGraph.METHOD_PRECONDITIONS[method]
    # Observation-key prerequisites are assessed against the recorded tri-state
    # snapshot, never against AKG confirmed/outcome nodes (known_nodes).
    if isinstance(statuses, dict) and statuses:
        if any(statuses.get(p) == 'false' for p in required):
            return 1, {**result, 'status': 'assessed', 'reason': 'prerequisites_not_proved_at_selection'}
        if any(statuses.get(p) != 'true' for p in required):
            return None, {**result, 'reason': 'prerequisite_observation_unknown'}
    elif isinstance(observations, dict):
        if any(observations.get(p) is False for p in required):
            return 1, {**result, 'status': 'assessed', 'reason': 'prerequisites_not_proved_at_selection'}
        if any(observations.get(p) is not True for p in required):
            return None, {**result, 'reason': 'prerequisite_observation_unknown'}
    else:
        return None, {**result, 'reason': 'missing_selection_snapshot'}
    top, reason, detail = ranking_comparison(artifact, selection)
    result.update({k: detail.get(k) for k in ('profile_sha256', 'profile_id') if detail.get(k) is not None})
    if top is None:
        return None, {**result, 'reason': reason, **{k: v for k, v in detail.items()
            if k in ('pending_method', 'reference_reason')}}
    entries = config['scoring_profile']['scenarios'][f"{surface}:{config.get('security_level')}"]
    result.update(status='assessed', comparison=detail.get('comparison'), top_methods=top,
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
    return next((e for e in get_attack_knowledge_graph().get_next_actions(source)
        if e.get('is_chain') and e.get('target') == target and e.get('target_agent') == agent), None)


def _collected_protocol_valid(artifact, source):
    parent_hash = source['document'].get('protocol_source_sha256')
    if parent_hash is None:
        return True
    parents = [parent for parent in artifact['config']['scoring_oracles']
        if parent.get('sha256') == parent_hash and 'status' not in parent['document']
        and parent.get('origin') == source['origin']
        and parent['document'].get('oracle_protocol') == source['document'].get('oracle_protocol')
        and (parent['document'].get('oracle_protocol') or {}).get('enabled') is True]
    if len(parents) != 1:
        return False
    validate_sources(parents)
    return True


def _oracle_verdict(artifact, row, *, negative=False):
    from evaluation.thesis_scoring import _resolve
    from foundation.verifier import fixture_attestation_valid
    if row.get('oracle_conflict'):
        return False
    field = 'negative_attestations' if negative else 'attestations'
    ref = row.get('negative_oracle_ref' if negative else 'oracle_ref')
    if not isinstance(ref, str) or not re.fullmatch(r'#/config/scoring_oracles/[0-9]+/document/' + field + r'/[0-9]+', ref):
        return False
    try:
        index = int(ref.split('/')[3])
        source = artifact['config']['scoring_oracles'][index]
    except (KeyError, ValueError, IndexError, TypeError):
        return False
    validate_sources([source])
    if source['origin'] != 'operator_fixture' and artifact.get('validation_scope') != 'offline_synthetic_fixture':
        return False
    if not _collected_protocol_valid(artifact, source):
        return False
    attestation = _resolve(artifact, ref)
    return isinstance(attestation, dict) and attestation in source['document'].get(field, []) and fixture_attestation_valid(
        attestation, row, source['document'], artifact, outcome='not_confirmed' if negative else 'confirmed')


def oracle_confirmed(artifact, row):
    return _oracle_verdict(artifact, row)


def oracle_negative_confirmed(artifact, row):
    return _oracle_verdict(artifact, row, negative=True)


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
        negative_oracle = method.startswith(('ac_', 'bf_')) and oracle_negative_confirmed(artifact, row)
        if not verifier or row.get('stage') not in {'exploit', 'bypass'} or (
                row.get('status_code') not in (200, 404) and not negative_oracle) or not row.get('response_sha256'):
            continue
        visit_refs = [r for r in valid_refs if _resolve(artifact, r).get('visit_id') == row.get('visit_id')]
        tier = _candidate_proof(artifact, cid, method, visit_refs)
        oracle = False
        if method.startswith(('ac_', 'bf_')):
            oracle = oracle_confirmed(artifact, row)
            if negative_oracle:
                tier = 0
            elif oracle:
                tier = 3
            elif tier is not None or row.get('signal_detected') is True:
                tier = min(2 if tier is None else tier, 2)  # Session/permission labels cannot replace an independent oracle.
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
                if not _collected_protocol_valid(artifact, bundle):
                    continue
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


def chain_availability(artifact):
    """Whether a chain-opportunity assessment actually ran with enough evidence."""
    state = artifact.get('final_state') or {}
    assessment = state.get('chain_assessment')
    if isinstance(assessment, dict):
        if assessment.get('assessed') is True:
            return True, None
        return False, assessment.get('reason') or assessment.get('status') or 'chain_assessment_unavailable'
    if 'weak_chain_opportunities' not in state:
        return False, 'chain_opportunity_log_unavailable'
    return True, None


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
    available, _reason = chain_availability(artifact)
    if not available:
        return None
    for weak in state.get('weak_chain_opportunities', []) or []:
        if not isinstance(weak, dict):
            continue
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


def origin_kind(provenance):
    """Trusted candidate origin class, tolerant of historical source labels."""
    if isinstance(provenance, dict) and isinstance(provenance.get('origin_kind'), str):
        return provenance['origin_kind']
    source = provenance.get('source') if isinstance(provenance, dict) else None
    if source == 'chain_derived':
        return 'chain_derived'
    if source == 'static_seed':
        return 'static_seed'
    if isinstance(source, str) and source.startswith('template'):
        return 'template_generation'
    if isinstance(source, str) and ('llm' in source or 'generated' in source or 'mutation' in source):
        return 'seed_mutation'
    return source if isinstance(source, str) else None


def _template_output_references_valid(record, _inputs, template):
    """Validate the ACTUAL Template schema against the exact neutral template.

    The template prompt requests ``output.candidates`` with only the value and
    the fixed parameter/signal. Template ids and seed references are runtime
    provenance, never model-owned fields, and the Template input intentionally
    carries no ranking profile or seed-backed profile. A matching extra id is
    tolerated; a fabricated/mismatched id, seed reference, or profile field is
    not accepted as a clean output.
    """
    from core.payload_policy import PAYLOAD_TEMPLATE_SCHEMA_VERSION
    if str(record.get('schema_version') or '') != PAYLOAD_TEMPLATE_SCHEMA_VERSION:
        return False
    # A Template prompt/schema never carries a seed-backed profile or seed rows.
    if isinstance(_inputs, dict) and any(
            _inputs.get(key) for key in ('profile', 'seeds', 'prompt_visible_seed_ids')):
        return False
    template_id = template.get('template_id')
    version = template.get('template_version')
    digest = template.get('template_sha256')
    target = template.get('target_param')
    expected = template.get('expected_signal')
    allowed = template.get('allowed_parameters')
    allowed = [target] if not isinstance(allowed, list) else allowed
    if not all(isinstance(value, str) and value for value in (template_id, version, digest, target, expected)):
        return False
    output = record.get('output')
    candidates = output.get('candidates') if isinstance(output, dict) else None
    if not isinstance(candidates, list) or not candidates:
        return False
    for candidate in candidates:
        if not isinstance(candidate, dict):
            return False
        value = candidate.get('payload_or_logic')
        if not isinstance(value, str) or not value.strip():
            return False
        if candidate.get('target_param') != target or target not in allowed:
            return False
        if candidate.get('expected_signal') != expected:
            return False
        if candidate.get('source_seed_id') or candidate.get('seed_id'):
            return False
        ref = candidate.get('origin_ref') if isinstance(candidate.get('origin_ref'), dict) else {}
        observed_id = ref.get('template_id') or candidate.get('template_id')
        observed_version = ref.get('template_version') or candidate.get('template_version')
        observed_digest = ref.get('template_sha256') or candidate.get('template_sha256')
        if any(value is not None for value in (observed_id, observed_version, observed_digest)):
            if (observed_id, observed_version, observed_digest) != (template_id, version, digest):
                return False
        if 'profile' in candidate or 'scoring_profile' in candidate:
            return False
    return True


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
        statuses = inputs.get('precondition_status', {})
        if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) for ref in refs):
            return False
        return all(observations.get(ref) is True or statuses.get(ref) == 'true' for ref in refs)
    if record['role'] == 'payload_generator':
        template = inputs.get('template')
        if isinstance(template, dict):
            return _template_output_references_valid(record, inputs, template)
        variants = output.get('variants')
        profile = inputs.get('profile') or {}
        if not isinstance(variants, list) or not variants:
            return False
        all_seeds = [s for s in inputs.get('seeds', []) if isinstance(s, dict)]
        visible_ids = inputs.get('prompt_visible_seed_ids')
        if visible_ids is not None:
            if not isinstance(visible_ids, list):
                return False
            visible_ids = [str(value) for value in visible_ids]
            visible_rows = inputs.get('prompt_visible_seeds')
            digest = inputs.get('prompt_visible_seeds_sha256')
            if isinstance(visible_rows, list):
                rows = [row for row in visible_rows if isinstance(row, dict)]
                if len(rows) != len(visible_rows):
                    return False
                if digest is not None and digest != evidence_hash(visible_rows):
                    return False
                if [str(row.get('source_seed_id') or row.get('candidate_id')) for row in rows] != visible_ids:
                    return False
                seeds = {str(row.get('source_seed_id') or row.get('candidate_id')): row for row in rows}
            else:
                seeds = {str(row.get('source_seed_id') or row.get('candidate_id')): row
                         for row in all_seeds
                         if str(row.get('source_seed_id') or row.get('candidate_id')) in visible_ids}
            if any(str(c.get('source_seed_id')) not in seeds
                   or str(seeds[str(c.get('source_seed_id'))].get('stage', '')).lower() not in {'exploit', 'bypass'}
                   for c in variants if isinstance(c, dict)):
                return False
        else:
            # Historical artifacts mirror the old builder's visible rule exactly:
            # execution-ready seeds, else the single first seed.
            execution = [row for row in all_seeds if str(row.get('stage', '')).lower() in {'exploit', 'bypass'}]
            seed_pool = execution or all_seeds[:1]
            seeds = {str(row.get('source_seed_id') or row.get('candidate_id')): row for row in seed_pool}
        return all(isinstance(c, dict) and
            c.get('source_seed_id') in seeds and c.get('mutation_type') in profile.get('allowed_mutation_types', [])
            and c.get('target_param', seeds[c['source_seed_id']].get('target_param')) in profile.get('target_params', []) for c in variants)
    return False


def _event_role(event):
    role = event.get('role')
    if role in EXPERIMENT_ROLES:
        return role
    origin = event.get('origin')
    return {'orchestrator': 'orchestrator',
            'payload_generator': 'payload_generator',
            'payload_validator': 'payload_generator'}.get(str(origin))


FALLBACK_NON_USE_EVENTS = frozenset({
    EVENT_MODEL_BUDGET_EXCLUDED,
    EVENT_PROVIDER_FAILURE, EVENT_STRICT_NO_CANDIDATE, EVENT_TEMPLATE_UNAVAILABLE,
    EVENT_VALIDATION_STRICT_NO_CANDIDATE, EVENT_VALIDATION_NO_USABLE,
    EVENT_TARGET_NO_VALID_PAYLOADS,
})
# Reasons that describe absence/infeasibility, not a usable fallback.
FALLBACK_ABSENCE_REASONS = frozenset({
    'no_supplied_seed', 'candidate_budget_zero', 'template_unavailable',
    'no_candidates_generated', 'probe_seed_for_exploit',
})


def _is_fallback_use_event(event):
    """A fallback credit requires explicit, evidenced fallback use."""
    name = str(event.get('event') or event.get('event_type') or '')
    if name in FALLBACK_NON_USE_EVENTS:
        return False
    reason = str(event.get('reason') or '')
    if is_provider_failure_reason(reason) or reason in FALLBACK_ABSENCE_REASONS:
        return False
    if name == EVENT_STATIC_FALLBACK:
        return True
    if 'static_seed_fallback' in name:
        return True
    if any(marker in name for marker in ('provider_failure', 'strict_no_candidate', 'template_unavailable')):
        return False
    return bool(event.get('fallback') or event.get('valid') is True or event.get('candidate_ids'))


def _relevant_event(event, method):
    return event.get('scope') == 'run' or not (event.get('method') or event.get('selected_method')) or \
        (event.get('method') or event.get('selected_method')) == method


def _fallback_contexts(groups, event):
    """Return the call group(s) an event can bind to; ambiguity earns nothing."""
    role, visit_id = _event_role(event), event.get('visit_id')
    keys = list(groups)
    if role:
        keys = [key for key in keys if key[0] == role]
    if visit_id:
        keys = [key for key in keys if key[1] == visit_id]
    return keys


def _static_fallback_valid(artifact, method, visit_id, event=None):
    """Validated static fallback in this role/visit, never another visit."""
    state = artifact['final_state']
    provenance = state.get('payload_provenance', {}) or {}
    rows = state.get('payload_validation_results', {}).get(method, []) or []
    static_visits = {details.get('visit_id') for cid, details in provenance.items()
                     if isinstance(details, dict) and origin_kind(details) in STATIC_ORIGIN_KINDS
                     and details.get('visit_id')}
    event_ids = {str(cid) for cid in (event or {}).get('candidate_ids') or []}
    for row in rows:
        if not isinstance(row, dict) or row.get('valid') is not True:
            continue
        details = provenance.get(str(row.get('candidate_id'))) or {}
        if origin_kind(details) not in STATIC_ORIGIN_KINDS:
            continue
        if event_ids and str(row.get('candidate_id')) not in event_ids:
            continue
        row_visit = row.get('visit_id') or details.get('visit_id')
        if visit_id and row_visit and str(row_visit) != str(visit_id):
            continue
        if visit_id and not row_visit and len(static_visits) > 1:
            continue
        return True
    return False


def _orchestrator_fallback_valid(artifact, method, visit_id):
    decisions = [d for d in artifact['final_state'].get('scoring_decisions', [])
                 if isinstance(d, dict) and d.get('dimension') == 'Smethod' and d.get('method') == method]
    if visit_id:
        decisions = [d for d in decisions if d.get('visit_id') == visit_id]
    for decision in decisions:
        origin = decision.get('decision_origin') or decision.get('selection_source')
        if origin not in {'deterministic_fallback', 'forced'}:
            continue
        surface = decision.get('surface')
        if decision.get('method') in METHODS_BY_SURFACE.get(surface, []):
            return True
    return False


def _fallback_credit(artifact, method, key, event, trusted_role):
    role, visit_id = key
    if not _is_fallback_use_event(event):
        return False
    if trusted_role is None:
        # Historical events predate explicit role binding. They are accepted only
        # when they bind to one call context and the same role/visit validates.
        return _static_fallback_valid(artifact, method, visit_id, event) or \
            _orchestrator_fallback_valid(artifact, method, visit_id)
    if trusted_role == 'orchestrator':
        return _orchestrator_fallback_valid(artifact, method, visit_id)
    if trusted_role == 'payload_generator':
        return _static_fallback_valid(artifact, method, visit_id, event)
    return False


def _validation_failure_override(artifact, method, key, events):
    """Strict validator rejection is unusable returned output; provider is null."""
    for event in events:
        name = str(event.get('event') or event.get('event_type') or '')
        if name not in {EVENT_VALIDATION_STRICT_NO_CANDIDATE, EVENT_VALIDATION_NO_USABLE}:
            continue
        reason = str(event.get('reason') or '')
        if reason in FALLBACK_ABSENCE_REASONS:
            continue
        if is_provider_failure_reason(reason):
            return 'operational'
        return 'unusable_output'
    return None


def _call_operational_failure(record):
    if str(record.get('parse_status')) == 'provider_error':
        return True
    for field in ('failure_class', 'failure_kind'):
        value = record.get(field)
        if isinstance(value, str) and is_provider_failure_reason(value):
            return True
    failure = record.get('failure')
    if isinstance(failure, dict):
        return is_provider_failure_reason(str(failure.get('kind') or failure.get('type') or failure.get('failure_class') or ''))
    return False


def _requirement_plan(artifact, method):
    state = artifact['final_state']
    requirements = state.get('model_call_requirements')
    if not isinstance(requirements, list) or not requirements:
        return None
    return [row for row in requirements if isinstance(row, dict)
            and row.get('role') in EXPERIMENT_ROLES
            and (method is None or row.get('method') in (None, method) or row.get('scope') == 'run')]


def output_grade(artifact, method):
    state = artifact['final_state']
    from core.scorer import output_grade as historical_output
    if historical_output(state, method)[0] == 0:
        return 0, 'containment_violation'
    calls = [r for r in artifact.get('llm_performance', []) if isinstance(r, dict)
             and r.get('role') in EXPERIMENT_ROLES
             and (r.get('method') == method or r.get('scope') == 'run')]
    activity = artifact.get('llm_activity', {}) if isinstance(artifact.get('llm_activity'), dict) else {}
    requirements = _requirement_plan(artifact, method)
    groups = {}
    for call in calls:
        groups.setdefault((call.get('role'), call.get('visit_id')), []).append(call)
    # Required-role coverage: one valid role cannot hide another missing receipt.
    fallback_only = []
    if requirements is not None:
        for row in requirements:
            if row.get('required') is not True or row.get('status') == 'not_required':
                continue
            key = (row.get('role'), row.get('visit_id'))
            if row.get('status') == 'not_run':
                return None, f"required_role_not_run:{row.get('role')}@{row.get('visit_id')}"
            if row.get('status') == 'blocked':
                return None, f"required_role_blocked:{row.get('role')}@{row.get('visit_id')}:{row.get('reason')}"
            matching_calls = groups.get(key, [])
            required_call_id = row.get('call_id')
            if row.get('role') == 'orchestrator' and row.get('visit_id') is None and required_call_id:
                # Older selection receipts predate visit attribution; an exact,
                # unique call ID still binds the call to this method's records.
                unscoped = [call for call in artifact.get('llm_performance', [])
                            if isinstance(call, dict) and call.get('role') == 'orchestrator'
                            and call.get('call_id') == required_call_id]
                if len(unscoped) == 1 and unscoped[0] in calls:
                    continue
                if len(unscoped) > 1:
                    return None, 'ambiguous_required_orchestrator_call_id'
            if matching_calls and (
                any(call.get('call_id') == required_call_id for call in matching_calls)
                if required_call_id else len({call.get('call_id') for call in matching_calls}) == 1
            ):
                continue
            fallback = [
                e for e in state.get('fallback_events', [])
                if isinstance(e, dict)
                and _relevant_event(e, method) and _is_fallback_use_event(e)
                and (_event_role(e) in (None, row.get('role')))
                and (not e.get('visit_id') or not row.get('visit_id')
                     or e.get('visit_id') == row.get('visit_id'))
                and (not required_call_id or e.get('call_id') == required_call_id)
            ]
            if any(_fallback_credit(artifact, method, key, event, _event_role(event))
                   for event in fallback):
                # Recovery is evidenced for this role/visit even without a call
                # receipt; the fallback grade is 1, never a clean 4.
                fallback_only.append(key)
                continue
            if row.get('status') == 'failed' and is_provider_failure_reason(str(row.get('reason') or '')):
                return None, f"operational_failure:{row.get('role')}@{row.get('visit_id')}:no_receipt"
            return None, f"required_role_receipt_missing:{row.get('role')}@{row.get('visit_id')}"
    if not groups:
        if fallback_only:
            return 1, 'fallback_credit_without_call_receipt'
        if requirements is not None and any(row.get('required') is True and row.get('status') in {'completed', 'failed'}
                                            for row in requirements):
            return None, 'required_role_receipt_missing'
        if activity.get('started'):
            return None, 'call_receipts_missing'
        return None, 'not_applicable'
    fallbacks = [e for e in state.get('fallback_events', []) if isinstance(e, dict)
                 and _relevant_event(e, method) and _is_fallback_use_event(e)]
    validation_events = [e for e in state.get('fallback_events', []) if isinstance(e, dict)
                         and _relevant_event(e, method)
                         and str(e.get('event') or '') in {EVENT_VALIDATION_STRICT_NO_CANDIDATE, EVENT_VALIDATION_NO_USABLE}]
    operational = []
    grades = [1] * len(fallback_only)
    for key, group in groups.items():
        last = group[-1]
        valid = last.get('parse_status') == 'ok' and last.get('validation_status') == 'valid'
        bound = [event for event in fallbacks if key in _fallback_contexts(groups, event)]
        credit = None
        for event in bound:
            result = _fallback_credit(artifact, method, key, event, _event_role(event))
            credit = bool(result) if credit is None else (credit or bool(result))
        if credit:
            grades.append(1)
            continue
        bound_validation = [event for event in validation_events
                            if key in _fallback_contexts(groups, event)]
        override = _validation_failure_override(artifact, method, key, bound_validation)
        if override == 'operational':
            operational.append(f"{key[0]}@{key[1]}:validation_provider_failure")
            continue
        if override == 'unusable_output':
            # Schema-valid but rejected/unusable returned output after validation.
            grades.append(0)
            continue
        if _call_operational_failure(last):
            operational.append(f"{key[0]}@{key[1]}:{last.get('parse_status')}")
            continue
        if not valid:
            grades.append(0)
            continue
        if any(c.get('parse_status') != 'ok' or c.get('validation_status') != 'valid'
               or c.get('attempt', 1) != 1 or c.get('structured_output_fallback') for c in group):
            grades.append(2)
        else:
            grades.append(4 if all(output_references_valid(c) for c in group) else 3)
    failures = any(_relevant_event(e, method) for field in ('invalid_json_events', 'output_failure_events', 'guardrail_activations')
        for e in state.get(field, []) if isinstance(e, dict))
    grade = min(grades) if grades else None
    if failures and grade is not None and grade > 2:
        grade = 2
    if operational:
        # A provider/transport failure is an operational outcome, never a model
        # refusal or a clean/invalid model output. One valid role cannot hide it.
        return None, 'operational_failure:' + ';'.join(sorted(operational))
    return grade, 'context_call_evidence'


def component_pending_reasons(artifact, method, rows, components, selection_evidence, output_reason):
    """Precise reason per unavailable component; pending is never a grade."""
    reasons = {}
    if components.get('Smethod') is None:
        reasons['Smethod'] = 'ranking_unavailable:' + str((selection_evidence or {}).get('reason'))
    if components.get('Sexploit') is None:
        executed = [row for row in rows if row.get('eligible')]
        reasons['Sexploit'] = ('missing_required_evidence' if executed else 'no_eligible_candidate')
    if components.get('Schain') is None:
        available, reason = chain_availability(artifact)
        reasons['Schain'] = reason or 'chain_evidence_unavailable'
    if components.get('Soutput') is None:
        reasons['Soutput'] = output_reason or 'output_evidence_unavailable'
    return reasons


def automatic_components(artifact, method, rows):
    selection, evidence = selection_grade(artifact, method)
    dependencies = verified_dependencies(artifact)
    tiers = [r['base_proof'] for r in rows if r['eligible'] and r['base_proof'] is not None]
    exploit = max(tiers) if tiers else None
    # A verified negative plus an unassessable executed candidate is not a
    # run-level verified negative; the component stays unavailable.
    if exploit == 0 and any(r['eligible'] and r['base_proof'] is None for r in rows):
        exploit = None
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
        row.pop('oracle_conflict', None)
        for negative in (False, True):
            field = 'negative_attestations' if negative else 'attestations'
            key = 'negative_oracle_ref' if negative else 'oracle_ref'
            matches = []
            for i, source in enumerate(sources):
                if source['origin'] != 'operator_fixture' and artifact.get('validation_scope') != 'offline_synthetic_fixture':
                    continue
                for j, att in enumerate(source['document'].get(field, [])):
                    if fixture_attestation_valid(att, row, source['document'], artifact,
                            outcome='not_confirmed' if negative else 'confirmed'):
                        matches.append(f'#/config/scoring_oracles/{i}/document/{field}/{j}')
            row.pop(key, None)
            if len(matches) == 1:
                row[key] = matches[0]
            elif len(matches) > 1:
                row['oracle_conflict'] = 'ambiguous_operator_attestations'
        if row.get('oracle_ref') and row.get('negative_oracle_ref'):
            row['oracle_conflict'] = 'contradictory_operator_attestations'
        if row.get('oracle_conflict'):
            row.pop('oracle_ref', None)
            row.pop('negative_oracle_ref', None)


def weak_opportunity_update(state):
    """Passive partial evidence; never changes nodes, eligibility or route priority."""
    from evaluation.thesis_scoring import PROOF_TIERS
    result = []
    history = state.get('weak_chain_opportunities', [])
    kg = get_attack_knowledge_graph()
    for i, row in enumerate(state.get('response_evidence', [])):
        if row.get('stage') not in {'exploit', 'bypass'} or not row.get('candidate_id') or not row.get('response_sha256') or row.get('status_code') != 200:
            continue
        if PROOF_TIERS.get(row.get('verification_reason')) not in (1, 2):
            continue
        # Only method evidence of incomplete material matches these source nodes.
        reason = row.get('verification_reason')
        source = 'credentials_extracted' if reason == 'partial_union_data' else (
            'authenticated_session' if reason == 'verified_login' else None)
        if source is None:
            continue
        if source == 'authenticated_session' and row.get('agent_id') not in {'bf_dictionary', 'bf_spray'}:
            continue
        missing = ['complete_credentials'] if source == 'credentials_extracted' else ['fresh_authenticated_session']
        for edge in kg.get_next_actions(source):
            if not edge.get('is_chain'):
                continue
            identifier = f"weak:{row['evidence_id']}:{edge['target']}"
            if any(h.get('evidence_id') == identifier for h in history):
                continue
            result.append({'evidence_id': identifier, 'opportunity_class': 'weak',
                'method': row['agent_id'], 'candidate_id': row['candidate_id'], 'visit_id': row['visit_id'],
                'source': source, 'target': edge['target'], 'target_agent': edge['target_agent'],
                'missing_material': missing, 'source_evidence_refs': [f'#/final_state/response_evidence/{i}'],
                'prerequisite_status': {p: 'unproved' for p in edge['preconditions']},
                'timestamp': datetime.now(timezone.utc).isoformat()})
    return {'weak_chain_opportunities': result} if result else {}
