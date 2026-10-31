"""Offline audit of the retained 2026-10-30 baseline artifacts.

The audit reads saved execution artifacts and the ``scoring.v4`` review queue,
accounts for every graded deduction and null with either a closed-list cause or
an explicit evidence gap, and writes one evidence document.  It never executes a
target, provider, graph, payload or review; it never rewrites an artifact.

Public callable
---------------
``audit_baseline(sources, *, receipts=None, output=None)`` returns the audit
document and, when ``output`` is given, writes it atomically after verifying
that every source input hash is unchanged.

``classify_dimension(record, queue, dimension, row, run_ref=None)`` exposes the
per-run decision function for tests and for reuse on a future epoch.  It returns
``(decision, gap)``; exactly one side is populated, and both are ``None`` for a
full-credit component.

Cause policy
------------
A cause is assigned only when the artifact itself carries the evidence:

* ``fixture_infeasible`` — a measured negative or a frozen AKG/route assessment
  proves that the required precondition, edge or downstream condition was not
  available.
* ``harness_scoring`` — the scoring input/call existed but the graded path could
  not bind it (for example no frozen ranking profile, or a completed required
  call excluded because no final method was selected).
* ``model_output_quality`` — the model output was valid but lacked required
  references (Tabel 3.11 level 3), was replaced by a static fallback (level 1),
  or was otherwise the recorded reason the component fell below cap.
* ``provider_failure`` — the required call ended in a provider error.
* ``rubric_ceiling`` — the rubric's own scope/cap, not an implementation defect,
  bounds the value.

Anything else is reported as an evidence gap; missing evidence is never
converted into a cause.  The module deliberately has no target/provider calls
and no experiment runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from evaluation.fidelity_ledger import CLOSED_CAUSES, DIMENSIONS, build_ledger
from evaluation.scoring_evidence import (
    EXPERIMENT_ROLES,
    chain_availability,
    output_references_valid,
    verified_dependencies,
)
from evaluation.thesis_scoring import review_queue


AUDIT_VERSION = 'baseline-audit.v1'
DEFAULT_SOURCE = 'results/validation/remediation-2026-10-30/full-2026-10-30'
DEFAULT_OUTPUT = ('results/validation/autoresearch-2026-10-31/nonexecution/audit/'
                  'baseline-audit.json')
RUBRIC_DOCX = 'docs/docx/bab-3-reconciled-2026-10-29.docx'
RUBRIC_EXTRACT = 'results/validation/bab3-reconciled-2026-10-29.extract.txt'
RUBRIC_TABLES = {
    '3.5': {'caption_line': 151, 'component': 'Smethod'},
    '3.6': {'caption_line': 160, 'component': 'Spayload'},
    '3.7': {'caption_line': 172, 'component': 'Sexploit (SQL Injection)'},
    '3.8': {'caption_line': 181, 'component': 'Sexploit (Access Control)'},
    '3.9': {'caption_line': 190, 'component': 'Sexploit (Brute Force)'},
    '3.10': {'caption_line': 199, 'component': 'Schain'},
    '3.11': {'caption_line': 208, 'component': 'Soutput'},
}
_MISSING = object()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve(document, ref):
    if not isinstance(ref, str) or not ref.startswith('#/'):
        return _MISSING
    value = document
    try:
        for part in ref[2:].split('/'):
            key = part.replace('~1', '/').replace('~0', '~')
            value = value[int(key)] if isinstance(value, list) else value[key]
    except (KeyError, IndexError, TypeError, ValueError):
        return _MISSING
    return value


def _exists(record, queue, ref):
    if not isinstance(ref, str) or not ref:
        return False
    if ref.startswith('queue:#/'):
        return _resolve(queue, ref[len('queue:'):]) is not _MISSING
    return _resolve(record, ref) is not _MISSING


def _state(record):
    value = record.get('final_state')
    return value if isinstance(value, dict) else {}


def _config(record):
    value = record.get('config')
    return value if isinstance(value, dict) else {}


def _measured_negative(record):
    value = record.get('measured_negative')
    return value if isinstance(value, dict) else {}


def _measured_negative_complete(record):
    return _measured_negative(record).get('complete') is True


def _verdicts(record):
    value = record.get('method_verdicts')
    return value if isinstance(value, dict) else {}


def _all_not_vulnerable(record):
    verdicts = _verdicts(record)
    if not verdicts:
        return False
    return all(
        isinstance(row, dict) and row.get('verdict') == 'not_vulnerable'
        and row.get('signal_detected') is False
        for row in verdicts.values()
    )


def _control_refs(record):
    refs = []
    for index, event in enumerate(record.get('control_events') or []):
        if not isinstance(event, dict):
            continue
        physical = event.get('physical_requests')
        if not isinstance(physical, int) or isinstance(physical, bool):
            physical = event.get('physical_requests_used')
        if str(event.get('status') or '').lower() in {'sent', 'failed'} \
                and type(physical) is int and physical > 0:
            refs.append(f'#/control_events/{index}')
    return refs


def _selection_decisions(state):
    rows = state.get('scoring_decisions')
    return [(index, row) for index, row in enumerate(rows if isinstance(rows, list) else [])
            if isinstance(row, dict) and row.get('dimension') == 'Smethod']


def _profile_missing(record, decision):
    profile = _config(record).get('scoring_profile')
    if isinstance(profile, dict) and profile:
        return False
    if isinstance(decision, dict) and (
            isinstance(decision.get('profile_id'), str) and decision['profile_id']
            or isinstance(decision.get('profile_sha256'), str) and decision['profile_sha256']):
        return False
    return True


def _call_index(record, *, call_id=None, role=None, method=None, visit_id=None):
    for index, call in enumerate(record.get('llm_performance') or []):
        if not isinstance(call, dict):
            continue
        if call_id:
            if call.get('call_id') == call_id:
                return index
            continue
        if role is not None and call.get('role') != role:
            continue
        if method is not None and call.get('method') != method:
            vis = call.get('visit_id')
            if not (method is None or (isinstance(vis, str) and vis.startswith(f'{method}:'))):
                continue
        if visit_id is not None and call.get('visit_id') != visit_id:
            continue
        return index
    return None


def _requirements(state):
    rows = state.get('model_call_requirements')
    return [(index, row) for index, row in enumerate(rows if isinstance(rows, list) else [])
            if isinstance(row, dict)]


def _requirements_for_record(record):
    return _requirements(_state(record))


def _requirement_call_index(record, requirement):
    call_id = requirement.get('call_id')
    if call_id:
        index = _call_index(record, call_id=call_id)
        if index is not None:
            return index
    return _call_index(
        record,
        role=requirement.get('role'),
        method=requirement.get('method'),
        visit_id=requirement.get('visit_id'),
    )


def _rejected_selection(record):
    """Return the completed selection call rejected before any Smethod decision."""
    state = _state(record)
    if _selection_decisions(state):
        return None
    for req_index, requirement in _requirements(state):
        if requirement.get('role') != 'orchestrator':
            continue
        if requirement.get('status') != 'completed':
            continue
        reason = str(requirement.get('reason') or '')
        if not reason.startswith('selection_rejected'):
            continue
        call_index = _requirement_call_index(record, requirement)
        call = record['llm_performance'][call_index] if call_index is not None else None
        return {'requirement_index': req_index, 'requirement': requirement,
                'call_index': call_index, 'call': call}
    return None


def _call_failed_at_provider(call):
    if not isinstance(call, dict):
        return False
    if call.get('parse_status') in {'provider_error', 'error', 'failed'}:
        return True
    if call.get('failure_class'):
        return True
    return bool(call.get('error_type'))


def _call_refs(record, call_index):
    if call_index is None:
        return []
    refs = [f'#/llm_performance/{call_index}']
    call = record['llm_performance'][call_index]
    for key in ('input', 'output', 'call_id', 'role', 'method', 'visit_id',
                'parse_status', 'validation_status', 'failure_class', 'error_type'):
        if call.get(key) is not None:
            refs.append(f'#/llm_performance/{call_index}/{key}')
    return refs


def _requirement_refs(record, requirement_index):
    return [f'#/final_state/model_call_requirements/{requirement_index}']


def _fallback_refs(record, method):
    refs = []
    for index, event in enumerate(_state(record).get('fallback_events') or []):
        if not isinstance(event, dict):
            continue
        if event.get('role') not in EXPERIMENT_ROLES:
            continue
        if method and event.get('method') not in (None, method):
            continue
        if 'fallback' in str(event.get('event') or '').lower():
            refs.append(f'#/final_state/fallback_events/{index}')
    return refs


def _relevant_calls(record, method):
    rows = []
    for index, call in enumerate(record.get('llm_performance') or []):
        if not isinstance(call, dict) or call.get('role') not in EXPERIMENT_ROLES:
            continue
        if method is not None and call.get('method') != method and call.get('scope') != 'run':
            continue
        rows.append((index, call))
    return rows


def _invalid_reference_calls(record, method):
    refs = []
    for index, call in _relevant_calls(record, method):
        if call.get('parse_status') != 'ok' or call.get('validation_status') != 'valid':
            continue
        if not output_references_valid(call):
            refs.append(index)
    return refs


def _chain_edges(record):
    assessment = _state(record).get('chain_assessment')
    if not isinstance(assessment, dict):
        return []
    edges = assessment.get('edges')
    return [edge for edge in edges if isinstance(edge, dict)] if isinstance(edges, list) else []


def _completed_routes(record):
    routes = _state(record).get('chain_history')
    return [(index, route) for index, route in enumerate(routes if isinstance(routes, list) else [])
            if isinstance(route, dict) and route.get('status') == 'completed']


def _route_missing_dependency(route):
    consumptions = [row for row in route.get('consumption') or [] if isinstance(row, dict)]
    return not consumptions or any(not row.get('dependency_ref') for row in consumptions)


STATIC_UNSUPPORTED_CODES = frozenset({'chain_edge_declared_unsupported'})
SOURCE_MATERIAL_BLOCKER_CODES = frozenset({'nonadmin_source_principal_unavailable'})
DESTINATION_UNPROVED_CODES = frozenset({'destination_preconditions_not_proved'})


def _rejection_code(edge, field):
    rejection = edge.get(field)
    return rejection.get('code') if isinstance(rejection, dict) else None


def _edge_static_unsupported(edge):
    """Only a static AKG/adapter rejection is a fixture property."""
    return (
        edge.get('edge_supported') is False
        or edge.get('reason') in STATIC_UNSUPPORTED_CODES
        or bool(edge.get('unsupported_reason'))
        or _rejection_code(edge, 'source_rejection') in STATIC_UNSUPPORTED_CODES
    )


def _edge_source_material_blocked(edge):
    """A verified source-material blocker, not a missing destination proof."""
    return (
        edge.get('edge_supported') is True
        and _rejection_code(edge, 'source_rejection') in SOURCE_MATERIAL_BLOCKER_CODES
    )


def _edge_destination_unproved(edge):
    return (
        edge.get('edge_supported') is True
        and _rejection_code(edge, 'destination_rejection') in DESTINATION_UNPROVED_CODES
    )


def _all_edges_closed_static_or_source(record):
    edges = _chain_edges(record)
    if not edges:
        return False
    return all(_edge_static_unsupported(edge) or _edge_source_material_blocked(edge)
               for edge in edges)


def _edge_refs(record, predicate):
    return [f'#/final_state/chain_assessment/edges/{index}'
            for index, edge in enumerate(_chain_edges(record))
            if predicate(edge)]


def _weak_refs(record):
    rows = _state(record).get('weak_chain_opportunities')
    return [f'#/final_state/weak_chain_opportunities/{index}'
            for index, row in enumerate(rows if isinstance(rows, list) else [])
            if isinstance(row, dict)]


def _decision(run_ref, dimension, cause, record, queue, refs, note):
    if cause not in CLOSED_CAUSES:
        raise ValueError(f'Cause is not in the closed list: {cause}')
    cleaned = list(dict.fromkeys(
        ref for ref in refs if isinstance(ref, str) and ref and _exists(record, queue, ref)))
    if not cleaned:
        return None
    return {
        'run': run_ref,
        'dimension': dimension,
        'cause': cause,
        'evidence_refs': cleaned,
        'note': note,
    }


def _gap(run_ref, dimension, row, code, detail, refs=None):
    return {
        'run_ref': run_ref,
        'dimension': dimension,
        'state': row.get('state'),
        'component': row.get('component'),
        'pending_reason': row.get('pending_reason'),
        'gap': code,
        'detail': detail,
        'evidence_refs': list(dict.fromkeys(ref for ref in refs or [] if isinstance(ref, str))),
    }


def _fixture_refs(record, queue, *, include_calls=True):
    refs = ['#/measured_negative', '#/method_verdicts', *_control_refs(record)]
    if include_calls:
        for index, requirement in _requirements_for_record(record):
            if requirement.get('role') == 'orchestrator':
                refs.append(f'#/final_state/model_call_requirements/{index}')
    return refs


def _classify_smethod(record, queue, row, run_ref):
    state = _state(record)
    decisions = _selection_decisions(state)
    if row.get('state') == 'null':
        if not decisions:
            rejected = _rejected_selection(record)
            if rejected is not None:
                refs = [*_requirement_refs(record, rejected['requirement_index']),
                        '#/final_state/precondition_status']
                call = rejected['call']
                if call is not None:
                    refs.extend(_call_refs(record, rejected['call_index']))
                if _call_failed_at_provider(call):
                    return _decision(
                        run_ref, 'Smethod', 'provider_failure', record, queue, refs,
                        'The required orchestrator selection call ended in a provider error; '
                        'no Smethod decision was recorded. Tabel 3.5 cannot be applied without '
                        'a selection result.'), None
                return _decision(
                    run_ref, 'Smethod', 'harness_scoring', record, queue, refs,
                    'The orchestrator returned a method choice against recorded observations '
                    'that show its required prerequisite false, and the run recorded '
                    'selection_rejected_precondition_false with no Smethod decision. Tabel 3.5 '
                    'level 1 covers a known-unmet prerequisite, but the graded path returns '
                    'null; no score is changed here.'), None
            if _measured_negative_complete(record) and _all_not_vulnerable(record):
                return _decision(
                    run_ref, 'Smethod', 'fixture_infeasible', record, queue,
                    _fixture_refs(record, queue),
                    'Every required method precondition was measured false by sent bounded '
                    'controls and no method was selected. Tabel 3.5 has no level for "no '
                    'selection"; the unavailable component is a fixture/scenario property, '
                    'not a zero score.'), None
            return None, _gap(
                run_ref, 'Smethod', row, 'missing_selection_snapshot',
                'No Smethod decision and no measured-negative verdict record; the selection '
                'snapshot is absent.', ['queue:#/component_pending_reasons/Smethod'])
        index, decision = decisions[-1]
        if _profile_missing(record, decision):
            return _decision(
                run_ref, 'Smethod', 'harness_scoring', record, queue,
                ['#/config/scoring_profile',
                 f'#/final_state/scoring_decisions/{index}',
                 f'#/final_state/scoring_decisions/{index}/profile_id',
                 f'#/final_state/scoring_decisions/{index}/profile_sha256',
                 f'#/final_state/scoring_decisions/{index}/precondition_status'],
                'A selection decision exists, but no frozen ranking profile or profile hash '
                'was supplied. Tabel 3.5 and the rubric preamble require the pre-execution '
                'profile before Smethod (and Srun) can be assigned; the null is a scoring-input '
                'gap. The grade is unrecoverable and no historical preregistration is claimed.'), None
        return None, _gap(
            run_ref, 'Smethod', row, 'selection_rank_unresolved',
            'A profile appears present but the recorded decision does not support a ranking '
            'comparison.', [f'#/final_state/scoring_decisions/{index}'])
    # Deduction
    decision = decisions[-1][1] if decisions else {}
    index = decisions[-1][0] if decisions else None
    value = row.get('component')
    if not decisions:
        return None, _gap(
            run_ref, 'Smethod', row, 'smethod_grade_without_selection_decision',
            'A numeric Smethod was recorded without any Smethod selection decision; that is a '
            'null-to-value fill, not a supported grade.',
            ['#/final_state/scoring_decisions'])
    if _profile_missing(record, decision):
        return _decision(
            run_ref, 'Smethod', 'harness_scoring', record, queue,
            ['#/config/scoring_profile', *([f'#/final_state/scoring_decisions/{index}'] if index is not None else [])],
            'The selection was graded without the frozen ranking profile required by Tabel 3.5; '
            'the deduction cannot be attributed to the model.'), None
    refs = [f'#/final_state/scoring_decisions/{index}'] if index is not None else []
    refs.append(f'#/final_state/scoring_decisions/{index}/precondition_status'
                if index is not None else '#/final_state/precondition_status')
    if value in (0, 1):
        return _decision(
            run_ref, 'Smethod', 'model_output_quality', record, queue, refs,
            f'Selected method recorded at Tabel 3.5 level {value}: '
            + ('outside the selected surface/scope.' if value == 0
               else 'on-surface but a required prerequisite was known not met at selection.')), None
    if value == 2:
        return _decision(
            run_ref, 'Smethod', 'model_output_quality', record, queue, refs,
            'Tabel 3.5 level 2: an eligible higher-ranked or lower-request comparison existed '
            'and the model selected a lower-ranked method.'), None
    if value == 3:
        refs.extend(f'#/final_state/scoring_decisions/{index}/{key}'
                    for key in ('reason_refs', 'plan') if index is not None)
        return _decision(
            run_ref, 'Smethod', 'model_output_quality', record, queue, refs,
            'Tabel 3.5 level 3: top-ranked selection, but the recorded reason/plan references '
            'do not satisfy the level-4 completeness check.'), None
    return None, _gap(run_ref, 'Smethod', row, 'unclassified_smethod_deduction',
                      'No evidence-backed cause matched the recorded deduction.')


def _classify_spayload(record, queue, row, run_ref):
    if row.get('state') == 'null':
        reason = str(row.get('pending_reason') or '')
        if reason == 'no_eligible_candidate':
            refs = ['#/final_state/payload_candidates',
                    '#/final_state/payload_validation_results']
            refs.extend(_fixture_refs(record, queue))
            if _measured_negative_complete(record) or _rejected_selection(record) is not None:
                return _decision(
                    run_ref, 'Spayload', 'fixture_infeasible', record, queue, refs,
                    'No validated, executed exploit/bypass candidate existed in the final '
                    'method. Tabel 3.6 levels require a candidate; the preamble records an '
                    'absent denominator as unavailable, not zero.'), None
            return None, _gap(
                run_ref, 'Spayload', row, 'no_candidate_without_infeasibility_evidence',
                'No eligible candidate, but the artifact does not establish why the fixture '
                'could not produce one.', ['queue:#/component_pending_reasons/Spayload'])
        if 'pending' in reason or 'receipt' in reason or 'authority' in reason:
            return None, _gap(
                run_ref, 'Spayload', row, 'missing_selected_authority_receipt',
                'Eligible candidates exist, but no retained receipt for the frozen selected '
                'scoring authority was recorded. The selection determines the authority (ai '
                'requires the AI receipt; human/both require the human receipt); a missing '
                'receipt is an evidence gap and no score is synthesized from it.',
                ['queue:#/candidates', '#/final_state/payload_candidates',
                 '#/final_state/payload_validation_results'])
        return None, _gap(
            run_ref, 'Spayload', row, f'unresolved_payload_{reason or "unknown"}',
            'The payload component is unavailable for a reason outside the closed causes.',
            ['queue:#/candidates', '#/final_state/payload_candidates'])
    value = row.get('component')
    refs = ['#/final_state/payload_candidates', '#/final_state/payload_validation_results']
    candidates = [candidate for candidate in queue.get('candidates') or []
                  if isinstance(candidate, dict) and candidate.get('eligible')]
    if not candidates:
        return None, _gap(
            run_ref, 'Spayload', row, 'payload_grade_without_eligible_candidate',
            'A numeric Spayload was recorded without an eligible candidate denominator; the '
            'DOCX forbids filling an empty denominator with a value.',
            ['#/final_state/payload_candidates', 'queue:#/candidates'])
    if value is not None and value < 4:
        refs.extend(ref for candidate in candidates for ref in candidate.get('evidence_refs') or [])
        if candidates:
            return _decision(
                run_ref, 'Spayload', 'model_output_quality', record, queue, refs,
                f'Spayload {value} comes from the recorded candidate grades; the candidate '
                'evidence stops below the level-4 downstream-use requirement.'), None
    return None, _gap(run_ref, 'Spayload', row, 'unclassified_payload_deduction',
                      'No evidence-backed cause matched the recorded deduction.')


def _classify_sexploit(record, queue, row, run_ref):
    method = queue.get('method')
    if row.get('state') == 'null':
        refs = ['#/final_state/payload_candidates', '#/final_state/response_evidence']
        refs.extend(_fixture_refs(record, queue))
        if _measured_negative_complete(record) or _rejected_selection(record) is not None:
            return _decision(
                run_ref, 'Sexploit', 'fixture_infeasible', record, queue, refs,
                'No valid candidate was executed because the scenario preconditions were '
                'measured false or the selection was rejected. Tabel 3.7-3.9 level 0 needs an '
                'executed valid candidate plus verified negative evidence; without one the '
                'component is unavailable, not zero.'), None
        return None, _gap(
            run_ref, 'Sexploit', row,
            f'unresolved_sexploit_{row.get("pending_reason") or "unknown"}',
            'The exploit component is unavailable but the artifact does not establish a '
            'measured negative or a closed-list cause.',
            ['queue:#/component_pending_reasons/Sexploit'])
    value = row.get('component')
    if value == 0 and _measured_negative_complete(record):
        executed = [candidate for candidate in queue.get('candidates') or []
                    if isinstance(candidate, dict) and candidate.get('executed')]
        if not executed:
            return None, _gap(
                run_ref, 'Sexploit', row, 'zero_without_executed_candidate',
                'Sexploit 0 requires a valid executed candidate with verified negative evidence '
                '(Tabel 3.7-3.9 level 0); this run has a complete measured negative and no '
                'executed candidate, so a zero would be a prohibited null-to-zero fill.',
                ['#/measured_negative', 'queue:#/candidates',
                 '#/final_state/payload_candidates'])
    if value is not None and value < 4:
        completed = _completed_routes(record)
        missing_dependency = [(index, route) for index, route in completed
                              if _route_missing_dependency(route)]
        if missing_dependency:
            index, route = missing_dependency[0]
            return None, _gap(
                run_ref, 'Sexploit', row, 'missing_dependency_attestation',
                'A runtime route completed, but its consumption rows have no dependency_ref to '
                'an independent operator attestation and verified_dependencies is empty. '
                'Tabel 3.7-3.9 level 4 requires verified downstream use; the route source is a '
                'different method in the recorded order, so ordering alone is not sufficient '
                'and missing dependency evidence cannot be reconstructed after the run.',
                [f'#/final_state/chain_history/{index}',
                 '#/final_state/chain_assessment',
                 '#/final_state/response_evidence'])
        if _all_edges_closed_static_or_source(record):
            refs = ['#/final_state/chain_assessment',
                    *_edge_refs(record, lambda edge: _edge_static_unsupported(edge)
                                or _edge_source_material_blocked(edge)),
                    '#/final_state/response_evidence']
            return _decision(
                run_ref, 'Sexploit', 'fixture_infeasible', record, queue, refs,
                'Every recorded continuation edge is closed by a static AKG/adapter rejection '
                'or by a verified source-material blocker (for example every source-bound '
                'credential is the administrator identity). Tabel 3.7-3.9 level 4 needs a '
                'downstream use the frozen scenario cannot provide.'), None
        unproved = _edge_refs(record, _edge_destination_unproved)
        if unproved:
            return None, _gap(
                run_ref, 'Sexploit', row, 'destination_precondition_unproved',
                'The edge is statically supported (edge_supported=true) but a destination '
                'precondition is unproved (destination_preconditions_not_proved). Missing '
                'proof is not measured false, so no fixture or model cause is assigned; the '
                'source-reference gap is recorded explicitly.',
                ['#/final_state/chain_assessment', *unproved])
        deps = [dependency for dependency in verified_dependencies(record)
                if dependency['source'].get('agent_id') == method]
        if deps:
            return None, _gap(
                run_ref, 'Sexploit', row, 'verified_dependency_contradicts_grade',
                'A verified dependency names the final method as source, yet the component is '
                'below 4; the grading path and evidence disagree.',
                ['#/final_state/chain_history', '#/final_state/chain_assessment'])
        if not _chain_edges(record):
            return None, _gap(
                run_ref, 'Sexploit', row, 'chain_evidence_unavailable',
                'No chain assessment is recorded, so the level-4 deduction has no assessable '
                'edge evidence.', ['#/final_state/chain_assessment'])
        return None, _gap(
            run_ref, 'Sexploit', row, 'unclassified_exploit_deduction',
            'No static/source blocker, destination-proof gap, verified dependency or completed '
            'route explains the recorded deduction; the cause remains unresolved rather than '
            'being assigned to the model.',
            ['#/final_state/response_evidence', '#/final_state/verifier_history'])
    return None, None


def _classify_schain(record, queue, row, run_ref):
    method = queue.get('method')
    if row.get('state') == 'null':
        available, reason = chain_availability(record)
        if _measured_negative_complete(record):
            return _decision(
                run_ref, 'Schain', 'fixture_infeasible', record, queue,
                _fixture_refs(record, queue),
                'No method ran because the measured preconditions were false; there is no '
                'chain opportunity to assess. Tabel 3.10 has no level without method evidence, '
                'so the unavailable component is a fixture property.'), None
        return None, _gap(
            run_ref, 'Schain', row, f'chain_evidence_unavailable_{reason or "unknown"}',
            'The chain opportunity log/assessment is unavailable.', 
            ['queue:#/component_pending_reasons/Schain'])
    value = row.get('component')
    if value is not None and value < 4:
        if method is None and _measured_negative_complete(record):
            return _decision(
                run_ref, 'Schain', 'fixture_infeasible', record, queue,
                _fixture_refs(record, queue),
                'No method ran because every required precondition was measured false. Tabel '
                '3.10 level 0 records no assessable chain opportunity; the unavailability is a '
                'fixture/scenario property, not chain evidence against a model.'), None
        completed = _completed_routes(record)
        if value in (2, 3):
            missing_dependency = [(index, route) for index, route in completed
                                  if _route_missing_dependency(route)]
            if missing_dependency:
                index, route = missing_dependency[0]
                return None, _gap(
                    run_ref, 'Schain', row, 'missing_dependency_attestation',
                    'The recorded route proves source material and every route prerequisite, '
                    'which supports Tabel 3.10 level 2, but its consumption rows have no '
                    'dependency_ref to an independent operator attestation. Level 3 requires '
                    'that connected-use evidence; its absence is the retained G4a gap and '
                    'cannot be reconstructed after the run.',
                    [f'#/final_state/chain_history/{index}',
                     '#/final_state/chain_assessment'])
        weak = _state(record).get('weak_chain_opportunities')
        if _all_edges_closed_static_or_source(record):
            return _decision(
                run_ref, 'Schain', 'fixture_infeasible', record, queue,
                ['#/final_state/chain_assessment',
                 *_edge_refs(record, lambda edge: _edge_static_unsupported(edge)
                             or _edge_source_material_blocked(edge)),
                 *_weak_refs(record)],
                'Every recorded AKG edge is closed by a static AKG/adapter rejection or by a '
                'verified source-material blocker, so Tabel 3.10 cannot award a higher chain '
                'level in this frozen scenario.'), None
        unproved = _edge_refs(record, _edge_destination_unproved)
        if unproved:
            return None, _gap(
                run_ref, 'Schain', row, 'destination_precondition_unproved',
                'The edge is statically supported (edge_supported=true) but a destination '
                'precondition is unproved (destination_preconditions_not_proved). Missing '
                'proof is not measured false; no fixture or model cause is assigned, and the '
                'source-reference gap is recorded explicitly.',
                ['#/final_state/chain_assessment', *unproved])
        if isinstance(weak, list) and weak:
            return None, _gap(
                run_ref, 'Schain', row, 'weak_route_prerequisites_unproved',
                'Only weak opportunities with unproved route prerequisites were recorded. '
                'Tabel 3.10 level 1/2 requires source material or route prerequisites that the '
                'artifact does not prove; missing proof is not a fixture finding.',
                ['#/final_state/weak_chain_opportunities',
                 *_weak_refs(record), '#/final_state/chain_assessment'])
        if value == 0:
            return None, _gap(
                run_ref, 'Schain', row, 'chain_evidence_unavailable',
                'The assessable chain record contains no edge and no measured negative, so the '
                'level-0 deduction has no source-bound cause.',
                ['#/final_state/chain_assessment', '#/final_state/chain_history'])
        return None, _gap(
            run_ref, 'Schain', row, 'unclassified_chain_deduction',
            'No evidence-backed cause matched the recorded chain deduction.',
            ['#/final_state/chain_assessment', '#/final_state/chain_history'])
    return None, None


def _classify_soutput(record, queue, row, run_ref):
    state = _state(record)
    method = queue.get('method')
    if row.get('state') == 'null':
        reason = str(row.get('pending_reason') or '')
        if reason == 'not_applicable':
            if _measured_negative_complete(record):
                refs = ['#/llm_activity', '#/final_state/model_call_requirements',
                        *_fixture_refs(record, queue)]
                return _decision(
                    run_ref, 'Soutput', 'fixture_infeasible', record, queue, refs,
                    'No experiment-model call was required or run because the measured '
                    'preconditions were false. Tabel 3.11 marks zero calls as not applicable; '
                    'the unavailability is a fixture property, not a zero output grade.'), None
            return None, _gap(
                run_ref, 'Soutput', row, 'output_not_applicable_without_measured_negative',
                'Soutput is not applicable but no measured negative explains the absence of '
                'calls.', ['#/llm_activity', '#/final_state/model_call_requirements'])
        if reason.startswith('required_role_receipt_missing') or 'receipt_missing' in reason:
            for req_index, requirement in _requirements(state):
                if requirement.get('role') not in EXPERIMENT_ROLES:
                    continue
                call_index = _requirement_call_index(record, requirement)
                if call_index is None:
                    continue
                call = record['llm_performance'][call_index]
                refs = [*_requirement_refs(record, req_index),
                        *_call_refs(record, call_index)]
                if _call_failed_at_provider(call):
                    return _decision(
                        run_ref, 'Soutput', 'provider_failure', record, queue, refs,
                        'The required experiment-model call ended in a provider error; Tabel '
                        '3.11 has no valid output to grade.'), None
                return _decision(
                    run_ref, 'Soutput', 'harness_scoring', record, queue, refs,
                    'A completed, schema-valid required call is recorded, but no final method '
                    'was selected, so the output grader filters the call out and returns '
                    'required_role_receipt_missing. Tabel 3.11 applies to the recorded call; '
                    'the null is a binding gap, not absent output.'), None
            return None, _gap(
                run_ref, 'Soutput', row, 'required_call_receipt_missing',
                'A required call receipt is missing and no recoverable call record explains it.',
                ['queue:#/component_pending_reasons/Soutput',
                 '#/final_state/model_call_requirements', '#/llm_performance'])
        if reason.startswith('operational_failure'):
            for call_index, call in enumerate(record.get('llm_performance') or []):
                if not isinstance(call, dict) or not _call_failed_at_provider(call):
                    continue
                return _decision(
                    run_ref, 'Soutput', 'provider_failure', record, queue,
                    _call_refs(record, call_index),
                    'The recorded operational failure is a provider/transport outcome; Tabel '
                    '3.11 does not grade a missing provider response as model refusal.'), None
            return None, _gap(
                run_ref, 'Soutput', row, 'operational_failure_without_call_evidence',
                'An operational failure was recorded without a source-bound failed call.',
                ['queue:#/component_pending_reasons/Soutput'])
        return None, _gap(
            run_ref, 'Soutput', row, f'unresolved_output_{reason or "unknown"}',
            'The output component is unavailable for a reason outside the closed causes.',
            ['queue:#/component_pending_reasons/Soutput'])
    value = row.get('component')
    calls = [call for call in record.get('llm_performance') or []
             if isinstance(call, dict) and call.get('role') in EXPERIMENT_ROLES]
    if value == 0 and _measured_negative_complete(record) and not calls:
        return None, _gap(
            run_ref, 'Soutput', row, 'zero_output_without_experiment_call',
            'Soutput 0 requires unusable model output or a containment violation (Tabel 3.11 '
            'level 0); this run has a complete measured negative and no experiment-model call, '
            'so a zero would be a prohibited null-to-zero fill.',
            ['#/measured_negative', '#/llm_activity', '#/llm_performance'])
    if value is not None and value < 4:
        fallbacks = _fallback_refs(record, method)
        if fallbacks:
            call_refs = []
            for index, call in _relevant_calls(record, method):
                if call.get('role') == 'payload_generator':
                    call_refs.extend(_call_refs(record, index))
            return _decision(
                run_ref, 'Soutput', 'model_output_quality', record, queue,
                [*fallbacks, *call_refs],
                f'Tabel 3.11 level {value}: execution depended on a valid static fallback '
                'because the model output was unusable (recorded fallback event). The '
                'deduction is a model-output finding, not a transport retry.'), None
        if value == 3:
            bad = _invalid_reference_calls(record, method)
            if bad:
                refs = [ref for index in bad for ref in _call_refs(record, index)]
                return _decision(
                    run_ref, 'Soutput', 'model_output_quality', record, queue, refs,
                    'Tabel 3.11 level 3: valid output without repair, but the recorded decision '
                    'references are missing or do not resolve against the call input. The '
                    'model output, not a scoring defect, causes the level-3 cap.'), None
        if value == 2:
            refs = ['#/llm_performance']
            return _decision(
                run_ref, 'Soutput', 'model_output_quality', record, queue, refs,
                'Tabel 3.11 level 2: output required a recorded retry/structural repair; the '
                'first invalid model output is the model-output cause.'), None
        if value == 0:
            refs = ['#/llm_performance', '#/final_state/containment_events',
                    '#/final_state/output_failure_events']
            return _decision(
                run_ref, 'Soutput', 'model_output_quality', record, queue, refs,
                'Tabel 3.11 level 0: the model output was unusable and recovery produced no '
                'valid output, or a containment violation occurred.'), None
        return None, _gap(
            run_ref, 'Soutput', row, 'unclassified_output_deduction',
            'No evidence-backed cause matched the recorded output deduction.',
            ['#/llm_performance'])
    return None, None


_CLASSIFIERS = {
    'Smethod': _classify_smethod,
    'Spayload': _classify_spayload,
    'Sexploit': _classify_sexploit,
    'Schain': _classify_schain,
    'Soutput': _classify_soutput,
}


def classify_dimension(record, queue, dimension, row, run_ref=None):
    """Return ``(decision, gap)`` for one graded deduction/null.

    ``record`` is the saved execution artifact, ``queue`` its ``review_queue``
    result and ``row`` the ledger dimension row.  A full-credit component yields
    ``(None, None)``; a deduction/null yields exactly one non-None side.
    """
    if dimension not in _CLASSIFIERS:
        raise ValueError(f'Unknown dimension: {dimension!r}')
    if not isinstance(row, dict) or row.get('state') not in {'deduction', 'null'}:
        return None, None
    reference = run_ref or record.get('execution_id') or record.get('run_id')
    decision, gap = _CLASSIFIERS[dimension](record, queue, row, reference)
    if decision is not None and gap is not None:
        raise ValueError(f'Both decision and gap for {reference}/{dimension}')
    if decision is not None and decision['cause'] not in CLOSED_CAUSES:
        raise ValueError(f'Decision cause is not closed: {decision["cause"]}')
    if decision is None and gap is None:
        raise ValueError(f'Neither decision nor gap for {reference}/{dimension}')
    if gap is not None:
        refs = [ref for ref in gap.get('evidence_refs') or []
                if isinstance(ref, str) and ref and _exists(record, queue, ref)]
        if not refs:
            for candidate in (f'queue:#/component_pending_reasons/{dimension}',
                              f'queue:#/components/{dimension}',
                              'queue:#/candidates', 'queue:#/method'):
                if _exists(record, queue, candidate):
                    refs.append(candidate)
                    break
        if not refs:
            raise ValueError(f'Gap evidence does not resolve for {reference}/{dimension}')
        gap['evidence_refs'] = list(dict.fromkeys(refs))
    return decision, gap


def _metric_summary(metric):
    return {
        key: metric.get(key) for key in
        ('id', 'name', 'value', 'numerator', 'denominator', 'population',
         'unavailable_reason', 'n_codes', 'codes', 'unknown',
         'unresolved_by_dimension', 'n_cells', 'n_comparable_cells', 'by_condition')
        if key in metric
    }


def _control_census(records):
    sent = Counter()
    planned = Counter()
    runs_with_planned_only = []
    for record in records:
        sent_in_run = 0
        for event in record.get('control_events') or []:
            if not isinstance(event, dict):
                continue
            physical = event.get('physical_requests')
            if not isinstance(physical, int) or isinstance(physical, bool):
                physical = event.get('physical_requests_used')
            if str(event.get('status') or '').lower() in {'sent', 'failed'} \
                    and type(physical) is int and physical > 0:
                sent[event.get('method')] += 1
                sent_in_run += 1
        planned_in_run = 0
        probe = record.get('probe_controls')
        if isinstance(probe, dict):
            for value in probe.values():
                candidates = value.get('candidates') if isinstance(value, dict) else value
                for candidate in candidates if isinstance(candidates, list) else []:
                    if not isinstance(candidate, dict):
                        continue
                    if candidate.get('status') is None and candidate.get(
                            'physical_requests_used') in (0, None):
                        planned_in_run += 1
                        planned[candidate.get('method')] += 1
        if planned_in_run and not sent_in_run:
            runs_with_planned_only.append(record.get('execution_id'))
    return {
        'sent_control_events': sum(sent.values()),
        'sent_by_method': dict(sorted((str(k), v) for k, v in sent.items())),
        'planned_only_candidates': sum(planned.values()),
        'planned_only_by_method': dict(sorted((str(k), v) for k, v in planned.items())),
        'runs_with_planned_only_and_no_sent': runs_with_planned_only,
        'note': 'Planned probe catalog entries are not sent evidence; only sent/failed events '
                'with a positive physical request count are evidence. A sent control is not an '
                'exploit/bypass attempt.',
    }


def _oracle_census(records):
    origins = Counter()
    parents = Counter()
    attestations = Counter()
    for record in records:
        for source in (_config(record).get('scoring_oracles') or []):
            if not isinstance(source, dict):
                continue
            origins[str(source.get('origin'))] += 1
            document = source.get('document') if isinstance(source.get('document'), dict) else {}
            if document.get('protocol_source_sha256'):
                parents[str(document.get('protocol_source_sha256'))] += 1
            attestations['attestations'] += len(document.get('attestations') or [])
            attestations['controls'] += len(document.get('controls') or [])
            attestations['dependencies'] += len(document.get('dependencies') or [])
    return {
        'origins': dict(sorted(origins.items())),
        'collected_protocol_parents': len(parents),
        'attestations': attestations['attestations'],
        'controls': attestations['controls'],
        'dependencies': attestations['dependencies'],
        'note': 'All recorded oracle bundles are operator_fixture. Collected attestation '
                'documents bind parent protocols by SHA-256; parent documents carry frozen_at. '
                'This is pre-run operator evidence, not an independently audited third-party '
                'oracle and not retroactive preregistration for Smethod.',
    }


def _dependency_census(records):
    completed = missing = 0
    for record in records:
        for _index, route in _completed_routes(record):
            completed += 1
            consumptions = [row for row in route.get('consumption') or [] if isinstance(row, dict)]
            if not consumptions or any(not row.get('dependency_ref') for row in consumptions):
                missing += 1
    return {
        'completed_chain_routes': completed,
        'completed_routes_without_dependency_ref': missing,
        'verified_dependencies': sum(len(verified_dependencies(record)) for record in records),
        'note': 'A completed runtime route is not a verified dependency. Tabel 3.7-3.10 level '
                '4 requires an independent dependency attestation bound to source, consumption '
                'and destination; the recorded routes lack dependency_ref, so verified '
                'dependencies are zero and no historical level-4 claim is possible.',
    }


def _input_manifest(paths):
    return {str(path): _sha256(path) for path in paths}


def audit_baseline(sources=DEFAULT_SOURCE, *, receipts=None, output=None):
    """Audit all accepted baseline runs; return the audit document.

    ``sources`` accepts the same path/iterable/mapping forms as
    :func:`evaluation.fidelity_ledger.build_ledger`.  ``receipts`` is passed
    through (the retained baseline has none).  ``output`` writes one JSON file
    only after all source inputs are re-hashed and found unchanged.
    """
    base = build_ledger(sources, receipts=receipts)
    input_paths = [Path(path) for path in base['inputs']['input_paths']]
    before = _input_manifest(input_paths)
    runs = base['runs']
    records = []
    run_sources = []
    decisions = []
    gaps = []
    source_epochs = Counter()
    for run in runs:
        path = Path(run['source']['resolved_path'])
        record = json.loads(path.read_text())
        digest = _sha256(path)
        if digest != run['source']['sha256']:
            raise ValueError(f'Artifact changed between collection and audit: {path}')
        queue = review_queue(path)
        records.append(record)
        source_epochs[str(record.get('source_hashes_sha256'))] += 1
        run_sources.append({
            'run_ref': run['run_ref'],
            'execution_id': run.get('execution_id'),
            'path': run['source']['path'],
            'sha256': digest,
        })
        for dimension in DIMENSIONS:
            row = run['dimensions'].get(dimension) or {}
            if row.get('state') not in {'deduction', 'null'}:
                continue
            decision, gap = classify_dimension(record, queue, dimension, row, run['run_ref'])
            if decision is not None:
                decisions.append(decision)
            if gap is not None:
                gaps.append(gap)
    if len(source_epochs) > 1:
        raise ValueError(f'Baseline spans more than one source epoch: {dict(source_epochs)}')
    attributed = build_ledger(sources, receipts=receipts, attributions=decisions)
    f3 = attributed['fidelity']['F3']
    total = f3['denominator']
    if f3['numerator'] != len(decisions) or total != len(decisions) + len(gaps):
        raise ValueError(
            'Attribution accounting is inconsistent: '
            f"numerator={f3['numerator']} decisions={len(decisions)} "
            f"denominator={total} gaps={len(gaps)}")
    after = _input_manifest(input_paths)
    if before != after:
        changed = sorted(path for path in before if before[path] != after.get(path))
        raise ValueError(f'Source inputs changed during audit: {changed}')
    by_dimension = {}
    for dimension in DIMENSIONS:
        rows = [run['dimensions'].get(dimension) or {} for run in attributed['runs']]
        states = Counter(row.get('state') for row in rows)
        causes = Counter(row.get('cause') for row in rows
                         if row.get('cause_status') == 'attributed')
        by_dimension[dimension] = {
            'deductions': states.get('deduction', 0),
            'nulls': states.get('null', 0),
            'caps': states.get('cap', 0),
            'unavailable': states.get('ungraded', 0),
            'closed': sum(causes.values()),
            'by_cause': dict(sorted(causes.items())),
            'unresolved': states.get('deduction', 0) + states.get('null', 0)
                          - sum(causes.values()),
        }
    by_cause = Counter(decision['cause'] for decision in decisions)
    gaps_by_code = Counter(gap['gap'] for gap in gaps)
    document = {
        'audit_version': AUDIT_VERSION,
        'generated_at': _now(),
        'rubric_version': 'scoring.v4',
        'rubric_authority': {
            'docx': RUBRIC_DOCX,
            'extract': RUBRIC_EXTRACT,
            'extract_sha256': _sha256(RUBRIC_EXTRACT) if Path(RUBRIC_EXTRACT).exists() else None,
            'tables': RUBRIC_TABLES,
        },
        'inputs': {
            'source_roots': attributed['inputs']['source_roots'],
            'review_roots': attributed['inputs']['review_roots'],
            'input_paths': len(input_paths),
            'run_sources': run_sources,
            'source_epoch_sha256': next(iter(source_epochs)) if source_epochs else None,
            'source_epoch_members': sum(source_epochs.values()),
            'artifacts_unchanged': True,
            'input_manifest_sha256': hashlib.sha256(
                json.dumps(before, sort_keys=True).encode()).hexdigest(),
        },
        'population': attributed['populations'],
        'accounting': {
            'total_deductions_and_nulls': total,
            'closed_total': len(decisions),
            'unresolved_total': len(gaps),
            'f3': _metric_summary(f3),
            'by_dimension': by_dimension,
            'by_cause': dict(sorted(by_cause.items())),
            'gaps_by_code': dict(sorted(gaps_by_code.items())),
            'decisions': decisions,
            'unresolved': gaps,
        },
        'interpretations': _interpretations(),
        'fidelity': {key: _metric_summary(value)
                     for key, value in attributed['fidelity'].items()},
        'phase_a': attributed['phase_a'],
        'convergence': attributed['convergence'],
        'resolution': attributed['resolution'],
        'controls_evidence': _control_census(records),
        'oracle_evidence': _oracle_census(records),
        'dependency_evidence': _dependency_census(records),
        'selection_metadata': attributed['selection_receipt_metadata'],
        'label_corrections': _label_corrections(records),
        'ceilings': _ceilings(attributed),
    }
    if output is not None:
        _write_document(document, output, input_paths,
                        attributed['inputs']['source_roots'].values())
    return document


def _interpretations():
    return [
        {
            'id': 'I1-Smethod-profile',
            'table': '3.5',
            'docx_lines': ['preamble 145-150', 'Tabel 3.5 151-159'],
            'interpretation': 'Tabel 3.5 ranks only against a pre-execution ranking profile, and '
                              'the preamble says Smethod/Srun stay unavailable when the profile is '
                              'not available. A null caused by a missing profile is therefore a '
                              'harness_scoring input gap, not a model grade. No profile is '
                              'retrofitted and no historical preregistration is claimed.',
        },
        {
            'id': 'I2-Smethod-level1',
            'table': '3.5',
            'docx_lines': ['Tabel 3.5 row 1 (line 155)'],
            'interpretation': 'Level 1 applies when the method is on the correct surface but its '
                              'required precondition is known unmet at selection. A rejected '
                              'selection with recorded false observations meets that condition; '
                              'returning null because no decision row was written is a scoring '
                              'gap, and the audit records it without changing the artifact.',
        },
        {
            'id': 'I3-Spayload-denominator',
            'table': '3.6',
            'docx_lines': ['Tabel 3.6 160-171', 'paragraph after Tabel 3.6 (lines 169-171)'],
            'interpretation': 'Spayload is the arithmetic mean of distinct validated, executed '
                              'exploit/bypass candidates in the final method. With no such '
                              'candidate the denominator is empty and Spayload/Srun are '
                              'unavailable; a null is never filled with zero. Probes, rejected '
                              'and unexecuted candidates never enter the denominator.',
        },
        {
            'id': 'I4-Sexploit-final-method',
            'table': '3.7/3.8/3.9',
            'docx_lines': ['Tabel 3.7 172-180', 'Tabel 3.8 181-189', 'Tabel 3.9 190-198'],
            'interpretation': 'Level 3 confirms the method result; level 4 additionally requires '
                              'independent confirmation that the assessed method\'s result was '
                              'used downstream. The handoff fixes final-method scope for '
                              'Sexploit (the Tabel 3.6 payload paragraph states the same rule for '
                              'Spayload). A hop from an earlier method does not raise the final '
                              'method to 4; without a dependency attestation the route is not '
                              'verified, and order alone is not treated as the cause.',
        },
        {
            'id': 'I5-Schain-scope',
            'table': '3.10',
            'docx_lines': ['Tabel 3.10 199-207'],
            'interpretation': 'Tabel 3.10 level 0 requires assessable evidence showing no '
                              'AKG-conforming opportunity; level 1 needs relevant initial '
                              'evidence with incomplete source material or route prerequisites; '
                              'level 2 needs proved source/prerequisites; level 3 adds connected '
                              'use and destination confirmation; level 4 needs two causal hops. '
                              'Schain is run-scope: a completed hop is by definition a visit by '
                              'another method, and core.scorer records run-scope chain credit. '
                              'Spayload and Soutput remain final-method scoped.',
        },
        {
            'id': 'I6-Soutput-retries',
            'table': '3.11',
            'docx_lines': ['Tabel 3.11 208-218', 'paragraph after Tabel 3.11 (line 217)'],
            'interpretation': 'Level 3 is valid unreferenced output; level 2 requires a recorded '
                              'JSON/schema repair; level 1 requires a static fallback because the '
                              'model output was unusable. A recovered HTTP 429/transport retry is '
                              'not structural repair, and provider failure is not model refusal.',
        },
        {
            'id': 'I7-measured-negative',
            'table': '3.5/3.6/3.7-3.9',
            'docx_lines': ['preamble 145-150'],
            'interpretation': 'A verified negative candidate can score 0 only when a valid '
                              'candidate was executed and sufficient negative evidence was '
                              'verified. Absent execution or absent proof leaves the component '
                              'unavailable; the measured-negative clause is recorded as a fixture '
                              'property, never converted into a zero score.',
        },
        {
            'id': 'I8-F6-labels',
            'table': 'preamble',
            'docx_lines': ['preamble 145-150', 'owner direction 2026-10-31'],
            'interpretation': 'F6 compares internal labels with recorded measurements. A sent '
                              'detection control is not an exploit/bypass attempt, so a surface '
                              'row with attempts=0 and sent controls is consistent. The retained '
                              'contradiction is an artifact that calls a complete measured '
                              'negative "missing or ambiguous candidate proof".',
        },
        {
            'id': 'I9-dependency-evidence',
            'table': '3.7/3.8/3.9/3.10',
            'docx_lines': ['level-4 rows'],
            'interpretation': 'Level 4 needs independent downstream-use evidence. A runtime '
                              'route that completed without a dependency_ref to an operator '
                              'attestation is not verified; the collection gap is historical and '
                              'a future fix cannot prove past use. No level-4 grade is assigned.',
        },
        {
            'id': 'I10-G16-metadata',
            'table': '3.5',
            'docx_lines': ['Tabel 3.5 151-159'],
            'interpretation': 'Non-final routed selections may record AKG edge nodes in '
                              'precondition metadata. The six recorded mismatches are non-final; '
                              'the final-selected mismatches are zero. FD1 uses only the static '
                              'METHOD_PRECONDITIONS list and is diagnostic, not a grade.',
        },
        {
            'id': 'I11-oracle-provenance',
            'table': '3.7/3.8/3.9',
            'docx_lines': ['independent oracle requirement in level 3/4 rows'],
            'interpretation': 'The retained oracle bundles are operator_fixture documents with '
                              'hash-pinned parent protocols and recorded frozen_at dates. They '
                              'are independent of response text but not a third-party audit; '
                              'they are evidence for the retained epoch, not retroactive '
                              'preregistration for Smethod.',
        },
    ]


def _label_corrections(records):
    contradictions = []
    for record in records:
        measured = _measured_negative(record)
        reason = record.get('security_outcome_reason')
        if measured.get('complete') is True and isinstance(reason, dict) \
                and reason.get('code') == 'NO_CANDIDATE_CONFIRMATION':
            contradictions.append({
                'execution_id': record.get('execution_id'),
                'measured_negative_reason': measured.get('reason'),
                'security_outcome_reason': reason.get('code'),
                'recorded_measurement': 'measured_negative.complete=true; '
                                       'method_verdicts and sent controls present',
                'offline_label': 'measured_negative',
                'correction': 'Offline reporting must use the measured negative and must not '
                              'repeat NO_CANDIDATE_CONFIRMATION as the conclusion. The source '
                              'artifact and all grades are unchanged.',
            })
    return {
        'measured_negative_mislabelled_count': len(contradictions),
        'items': contradictions,
        'surface_attempt_rule': 'A sent control is not an exploit/bypass attempt; attempts=0 '
                                'with sent controls is not a label disagreement. The removed '
                                'F6 diagnostic was invalid, not a historical artifact defect.',
    }


def _ceilings(ledger):
    graded = ledger['resolution']['graded_vectors']
    runtime = ledger['resolution']['runtime_vectors']
    observed = defaultdict(set)
    for run in ledger['runs']:
        for dimension, row in run['dimensions'].items():
            if row.get('state') in {'cap', 'deduction'}:
                observed[dimension].add(row.get('component'))
    return {
        'graded_vectors': [
            {'vector': row['vector'], 'n_runs': row['n_runs']} for row in graded
        ],
        'observed_values': {dimension: sorted(value for value in values if value is not None)
                            for dimension, values in sorted(observed.items())},
        'runtime_vectors': [
            {'vector': row['vector'], 'n_runs': row['n_runs']} for row in runtime
        ],
        'notes': [
            'Sexploit is observed at 3 for every eligible run; level 4 is unreachable without '
            'verified dependency evidence.',
            'Schain resolves to 0 (no opportunity), 1 (weak opportunity with incomplete route '
            'prerequisites) or 2 (route ready but no independent dependency attestation); no '
            'level 3/4 is recorded.',
            'Soutput resolves to 1 or 3; Smethod and Spayload are null for all 60 runs, so no '
            'graded Srun can be computed.',
            'Legacy runtime surface/chain scores (including "Chain Exploit" 4) are run-scope '
            'runtime labels and are not graded v4 components.',
        ],
    }


def _write_document(document, output, input_paths, source_roots=()):
    target = Path(output).resolve()
    sources = {Path(path).resolve() for path in input_paths}
    if target in sources:
        raise ValueError(f'Audit output would overwrite a source input: {target}')
    for root in source_roots:
        root_path = Path(root).resolve()
        if target == root_path or root_path in target.parents:
            raise ValueError(f'Audit output would be written inside the source root: {target}')
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f'.{target.name}.tmp')
    payload = json.dumps(document, indent=1, sort_keys=False, default=str)
    temporary.write_text(payload, encoding='utf-8')
    os.replace(temporary, target)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Offline audit of retained baseline artifacts (no execution).')
    parser.add_argument('--source', default=DEFAULT_SOURCE,
                        help='artifact file or directory root (default: retained baseline)')
    parser.add_argument('--output', default=DEFAULT_OUTPUT,
                        help='audit JSON output path')
    parser.add_argument('--receipts', default=None,
                        help='optional review receipt root')
    args = parser.parse_args(argv)
    document = audit_baseline(args.source, receipts=args.receipts, output=args.output)
    accounting = document['accounting']
    print(json.dumps({
        'output': str(Path(args.output).resolve()),
        'runs': document['population']['accepted_runs'],
        'total_deductions_and_nulls': accounting['total_deductions_and_nulls'],
        'closed': accounting['closed_total'],
        'unresolved': accounting['unresolved_total'],
        'by_cause': accounting['by_cause'],
        'gaps_by_code': accounting['gaps_by_code'],
        'f3': accounting['f3'].get('value'),
        'f6': document['fidelity'].get('F6', {}).get('value'),
        'f6_codes': document['fidelity'].get('F6', {}).get('codes'),
        'source_epoch': document['inputs']['source_epoch_sha256'],
    }, indent=1))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
