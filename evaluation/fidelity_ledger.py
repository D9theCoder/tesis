"""Offline fidelity ledger for the Chapter 3 research loop (P-1 / P0 / P1).

The ledger restates saved artifacts under the pinned ``scoring.v4`` graded path
(P-1), attributes every graded deduction and null to a closed-list cause with
evidence pointers (P0), and orders explicit hypotheses with the handoff section
5.3 lexicographic rule (P1).  It is read-only over artifacts: no provider,
DVWA, graph, payload or review execution occurs here.  The only file it writes
is the requested ledger document.

The runtime ``composite_score`` vector is retained solely inside a clearly
labelled ``legacy_runtime`` block.  It never substitutes for a graded component
and no graded component is invented, backfilled or inferred.

The thesis final assessment is human.  An AI receipt is experimental and
provisional: it is reported separately and is never promoted to human signoff,
and the ledger never chooses between a human and an AI workflow.  Consequently,
``Spayload`` is numeric only when a validated human workflow supplies it, and
``Srun_final`` is present only from a validated final human receipt, even if an
AI receipt is final.  With no manual reviews the graded vector contains the
automatic dimensions and an explicitly pending ``Spayload``; phase A remains
incomplete until human grades exist and every non-Smethod deduction/null has a
closed-list cause.  ``converged`` is never true from this offline ledger alone:
``offline_fidelity_ready`` is reported separately, and full convergence always
requires a fresh epoch, phase B and frozen-invariant acceptance.

Calling API
-----------
``build_ledger(sources, receipts=None, *, attributions=None, hypotheses=None,
output=None)`` accepts

* ``sources``: one path, an iterable of paths, or a mapping of root id to path.
  A path may be a run artifact or a directory root.  ``_superseded_*`` path
  parts and sidecar files are excluded.
* ``receipts``: optional review receipt/status path(s) or root(s).  Only
  receipts validated by ``evaluation.observer_reviews.discover_reviews`` can
  contribute a numeric ``Spayload`` or ``Srun_final``; without one,
  ``Spayload`` stays pending and ``Srun_final`` is ``None``.
* ``attributions``: optional iterable of explicit closed-cause decisions:
  ``{"run": <run_ref|execution_id|source_sha256|run_id>, "dimension":
  <dimension>, "cause": <CLOSED_CAUSES member>, "evidence_refs": [...]}``.
  Evidence must resolve and bind the dimension (artifact ``#/...`` or
  ``queue:#/...``).
* ``hypotheses``: optional P1 hypothesis rows.  See ``rank_hypotheses``.
* ``output``: optional ledger path.  Inputs are hashed and verified unchanged
  before publication; an output that resolves to an input is refused.

The module exposes ``build_ledger``, ``write_ledger`` and ``rank_hypotheses``;
it deliberately has no CLI or runner.
"""
from __future__ import annotations

import json
import math
import os
from collections import Counter, defaultdict
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE
from evaluation.observer_reviews import discover_reviews
from evaluation.thesis_scoring import WEIGHTS, review_queue
from tesis.artifact_catalog import ArtifactCatalog


LEDGER_VERSION = 'fidelity-ledger.v1'
RUNTIME_PROVISIONAL_LABEL = 'runtime_provisional_scoring.v2'
DIMENSIONS = ('Smethod', 'Spayload', 'Sexploit', 'Schain', 'Soutput')
CLOSED_CAUSES = frozenset({
    'model_output_quality',
    'harness_ordering',
    'harness_budget',
    'harness_scoring',
    'provider_failure',
    'fixture_infeasible',
    'rubric_ceiling',
    'label',
})
SUPERSEDED_PREFIX = '_superseded'
SIDECAR_SUFFIXES = (
    '.jsonl', '.rich.json', '.failure.json', '.review-history.json',
    '.evaluator.json', '.resume.json',
)
RISK_ORDER = {
    'none': 0,
    'needs §4.2': 1, 'needs_4.2': 1,
    'needs §4.3': 2, 'needs_4.3': 2,
}
EVIDENCE_ORDER = {'artifact-only': 0, 'artifact+replay': 1, 'needs-live': 2}
A2_FREEZE_PROVENANCE_CAVEAT = (
    'A2: the static AKG yardstick has no frozen_at stamp in the recorded '
    'akg.snapshot.json; its before-the-run status rests on the repository '
    'source-tree hash/commit, not on artifact provenance.'
)
POINTER_MISSING = object()
DATA_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, IndexError)
POPULATION_BLOCKING_CODES = frozenset({
    'duplicate_execution_identity', 'ambiguous_execution_id', 'ambiguous_matrix_identity',
    'missing_execution_id', 'unreadable_json', 'unreadable_review', 'missing_root',
    'scope_violation', 'invalid_artifact_schema', 'invalid_matrix_child',
    'missing_or_ambiguous_primary', 'ambiguous_parent', 'review_discovery_failed',
})


def _now():
    return datetime.now(timezone.utc).isoformat()


def _is_number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _source_binding(entry):
    return {
        'root_id': entry.source.get('root_id'),
        'path': entry.source.get('path'),
        'pointer': entry.source.get('pointer', ''),
        'sha256': entry.source.get('sha256'),
        'resolved_path': str(entry.path),
    }


def _run_ref(entry):
    execution_id = entry.record.get('execution_id')
    if isinstance(execution_id, str) and execution_id:
        return execution_id
    return f"source:{entry.source.get('sha256')}:{entry.source.get('pointer') or '/'}"


def _normalize_roots(spec, prefix, *, explicit_files_must_exist=True):
    if isinstance(spec, Mapping):
        roots = {}
        for identifier, path in spec.items():
            if not isinstance(identifier, str) or not identifier:
                raise ValueError('Root identifiers must be nonempty strings')
            roots[identifier] = Path(path).resolve()
        if not roots:
            raise ValueError('At least one root is required')
        return roots
    values = [spec] if isinstance(spec, (str, Path)) else list(spec)
    if not values:
        raise ValueError('At least one source path is required')
    roots = {}
    for index, value in enumerate(values, start=1):
        path = Path(value).resolve()
        if explicit_files_must_exist and not path.exists():
            raise ValueError(f'Source path does not exist: {value}')
        roots[f'{prefix}{index}'] = path
    return roots


def _excluded_reason(entry):
    parts = Path(entry.source.get('path') or entry.path.name).parts
    if any(part.startswith(SUPERSEDED_PREFIX) for part in parts):
        return 'superseded_epoch'
    if entry.path.name.endswith(SIDECAR_SUFFIXES):
        return 'sidecar'
    return None


def _collect_runs(catalog):
    """Exclude superseded/sidecar files and de-duplicate execution identity."""
    selected, excluded, diagnostics = [], [], []
    for entry in catalog.runs:
        reason = _excluded_reason(entry)
        if reason is not None:
            excluded.append({'source': _source_binding(entry), 'reason': reason})
            continue
        selected.append(entry)
    groups = defaultdict(list)
    for entry in selected:
        execution_id = entry.record.get('execution_id')
        key = ('execution_id', execution_id) if isinstance(execution_id, str) and execution_id \
            else ('source', str(entry.path), entry.source.get('pointer') or '')
        groups[key].append(entry)
    runs = []
    for key, entries in groups.items():
        if len(entries) > 1 or any(entry.ambiguous for entry in entries):
            execution_id = entries[0].record.get('execution_id')
            diagnostic = {
                'code': 'duplicate_execution_identity',
                'execution_id': execution_id,
                'sources': [_source_binding(entry) for entry in entries],
                'detail': 'conflicting or duplicate execution identity excluded from every metric',
            }
            diagnostics.append(diagnostic)
            for entry in entries:
                excluded.append({'source': _source_binding(entry), 'reason': 'duplicate_execution_identity'})
            continue
        runs.append(entries[0])
    runs.sort(key=lambda entry: (str(entry.path), entry.source.get('pointer') or ''))
    return runs, excluded, diagnostics


def _resolve_pointer(document, ref):
    if not isinstance(ref, str) or not ref.startswith('#/'):
        return POINTER_MISSING
    value = document
    try:
        for part in ref[2:].split('/'):
            key = part.replace('~1', '/').replace('~0', '~')
            value = value[int(key)] if isinstance(value, list) else value[key]
    except (KeyError, IndexError, TypeError, ValueError):
        return POINTER_MISSING
    return value


def _summary(record):
    report = record.get('report')
    return report.get('summary') if isinstance(report, dict) and isinstance(report.get('summary'), dict) else {}


def _availability_field(record, name):
    value = record.get(name)
    if value is None:
        value = _summary(record).get(name)
    return value


def _runtime_vector(record):
    """Return (components, source_label) or (None, reason) for the legacy vector."""
    components = record.get('composite_components')
    source = 'artifact.composite_components'
    if not isinstance(components, dict):
        components = _summary(record).get('run_composite_components')
        source = 'artifact.report.summary.run_composite_components'
    if not isinstance(components, dict):
        return None, 'composite_components_missing'
    missing = [dimension for dimension in DIMENSIONS if dimension not in components]
    if missing:
        return None, 'composite_components_missing:' + ','.join(missing)
    invalid = [dimension for dimension in DIMENSIONS if not _is_number(components[dimension])
               or not 0 <= components[dimension] <= 4]
    if invalid:
        return None, 'composite_components_invalid:' + ','.join(invalid)
    return {dimension: components[dimension] for dimension in DIMENSIONS}, source


def _legacy_runtime(record):
    components, component_source = _runtime_vector(record)
    return {
        'label': RUNTIME_PROVISIONAL_LABEL,
        'note': 'runtime provisional vector retained for audit only; never a graded component',
        'composite_score': record.get('composite_score'),
        'composite_components': components,
        'composite_components_source': component_source,
        'composite_score_status': record.get('composite_score_status'),
        'score_epoch': record.get('score_epoch'),
    }


def _payload_pending_reason(queue):
    if any(row.get('eligible') for row in queue.get('candidates') or []):
        return 'pending_candidate_grades'
    return 'no_eligible_candidate'


def _workflow_summary(workflow):
    return {
        'status': workflow.get('status'),
        'reason': workflow.get('reason'),
        'component_pending_reasons': workflow.get('component_pending_reasons') or {},
        'components': workflow.get('components'),
        'Spayload_final': workflow.get('Spayload_final'),
        'Srun_final': workflow.get('Srun_final'),
        'numerator': workflow.get('numerator'),
        'denominator': workflow.get('denominator'),
        'candidate_grade_count': len(workflow.get('candidate_grades') or []),
        'candidate_grades': [
            {key: grade.get(key) for key in ('candidate_id', 'score', 'payload_source', 'decision_id')}
            for grade in workflow.get('candidate_grades') or [] if isinstance(grade, dict)
        ],
        'generated_at': workflow.get('generated_at'),
        'rubric_version': workflow.get('rubric_version'),
        'scoring_rule_sha256': workflow.get('scoring_rule_sha256'),
        'receipt': workflow.get('receipt'),
        'review_status': workflow.get('review_status'),
        'decision_ledger': workflow.get('decision_ledger'),
    }


def _authoritative_mode(selection):
    """Human review is the authoritative thesis assessment.

    AI receipts are experimental/provisional and are never promoted to human
    signoff, and the ledger never chooses between the two.
    """
    if selection in {'human', 'both'}:
        return 'human'
    return None


def _graded_block(entry, workflows, selection):
    run_ref = _run_ref(entry)
    if entry.source.get('pointer'):
        return {
            'available': False,
            'reason': 'embedded_artifact_without_primary_source',
            'components': {dimension: None for dimension in DIMENSIONS},
            'component_pending_reasons': {dimension: 'graded_path_unavailable'
                                          for dimension in DIMENSIONS},
            'Srun_final': None,
            'Srun_final_reason': 'no_primary_artifact_to_grade',
            'workflows': {},
        }
    try:
        queue = review_queue(entry.path)
    except DATA_ERRORS as exc:  # one incompatible artifact must not abort the ledger
        return {
            'available': False,
            'reason': f'{type(exc).__name__}: {exc}',
            'error_type': type(exc).__name__,
            'components': {dimension: None for dimension in DIMENSIONS},
            'component_pending_reasons': {dimension: 'graded_path_unavailable'
                                          for dimension in DIMENSIONS},
            'Srun_final': None,
            'Srun_final_reason': 'graded_path_unavailable',
            'workflows': {},
            '_queue': None,
        }
    queue_components = queue.get('components') if isinstance(queue.get('components'), dict) else {}
    components = {dimension: queue_components.get(dimension) for dimension in DIMENSIONS}
    reasons = dict(queue.get('component_pending_reasons') or {})
    authoritative_mode = _authoritative_mode(selection)
    workflow = (workflows.get(authoritative_mode) if authoritative_mode else None) or {}
    workflow_components = workflow.get('components') if isinstance(workflow.get('components'), dict) else {}
    for dimension in DIMENSIONS:
        value = workflow_components.get(dimension)
        if value is not None:
            components[dimension] = value
    workflow_reasons = workflow.get('component_pending_reasons') if isinstance(
        workflow.get('component_pending_reasons'), dict) else {}
    for dimension, reason in workflow_reasons.items():
        if isinstance(reason, str) and reason.strip():
            reasons[dimension] = reason
    if components['Spayload'] is None:
        if not any(row.get('eligible') for row in queue.get('candidates') or []):
            reasons['Spayload'] = 'no_eligible_candidate'
        elif selection == 'ai':
            reasons['Spayload'] = 'human_payload_review_required'
        else:
            reasons.setdefault('Spayload', _payload_pending_reason(queue))
    for dimension in DIMENSIONS:
        if components[dimension] is not None:
            reasons.pop(dimension, None)
        elif not isinstance(reasons.get(dimension), str) or not reasons[dimension].strip():
            reasons.pop(dimension, None)
    for dimension, value in components.items():
        if value is not None and (not _is_number(value) or not 0 <= value <= 4):
            raise ValueError(f'Graded {dimension} outside [0, 4] for {run_ref}: {value!r}')
    experimental_ai = None
    if selection in {'ai', 'both'} and 'ai' in workflows:
        experimental_ai = workflows['ai']
    status = workflow.get('status')
    srun = workflow.get('Srun_final')
    if status == 'final' and _is_number(srun):
        srun_source = 'validated_final_human_receipt'
        srun_reason = None
    else:
        srun = None
        srun_source = None
        srun_reason = ('pending_human_workflow:' + str(workflow.get('reason'))
                       if status == 'pending' and workflow.get('reason')
                       else 'no_human_review_receipt' if authoritative_mode
                       else 'human_review_not_configured')
    spayload_final = workflow.get('Spayload_final')
    if not _is_number(spayload_final):
        spayload_final = None
    diagnostics = []
    if status == 'final' and not _is_number(workflow.get('Srun_final')):
        diagnostics.append({'code': 'final_workflow_missing_Srun_final'})
    if components['Spayload'] is not None and 'Spayload' in workflow_reasons:
        diagnostics.append({'code': 'numeric_payload_with_pending_reason',
                            'reason': workflow_reasons['Spayload']})
    if experimental_ai is not None and selection == 'ai':
        diagnostics.append({'code': 'ai_receipt_is_experimental_not_human_signoff'})
    if experimental_ai is not None and selection == 'both' and isinstance(
            experimental_ai.get('components'), dict):
        diagnostics.append({'code': 'experimental_ai_workflow_reported_separately'})
    return {
        'available': True,
        'rubric_version': queue.get('rubric_version'),
        'components': components,
        'component_pending_reasons': reasons,
        'authoritative_mode': authoritative_mode,
        'human_payload_review': components['Spayload'] is not None and authoritative_mode == 'human',
        'human_final_receipt': status == 'final' and srun_source == 'validated_final_human_receipt',
        'workflows': workflows,
        'experimental_ai_workflow': experimental_ai,
        'component_evidence_refs': queue.get('component_evidence_refs') or {},
        'selection_evidence': queue.get('selection_evidence'),
        'output_reason': queue.get('output_reason'),
        'workflow_status': status or 'missing',
        'Spayload_final': spayload_final,
        'Srun_final': srun,
        'Srun_final_source': srun_source,
        'Srun_final_reason': srun_reason,
        'source_sha256': queue.get('source_sha256'),
        'scoring_rule_sha256': queue.get('scoring_rule_sha256'),
        'source_scoring_rule_sha256': queue.get('source_scoring_rule_sha256'),
        'diagnostics': diagnostics,
        '_queue': queue,
    }


def _dimension_ledger(graded, attributions_by_dimension, run_ref, diagnostics):
    components = graded['components']
    reasons = graded['component_pending_reasons']
    result = {}
    for dimension in DIMENSIONS:
        value = components.get(dimension)
        attribution = attributions_by_dimension.get(dimension)
        pending_reason = reasons.get(dimension)
        if value is None:
            state = 'null'
        elif _is_number(value) and 0 <= value < 4:
            state = 'deduction'
        elif _is_number(value) and value == 4:
            state = 'cap'
        else:
            raise ValueError(f'Graded {dimension} outside [0, 4] for {run_ref}: {value!r}')
        if attribution is not None and state not in {'deduction', 'null'}:
            raise ValueError(f'Attribution does not bind a deduction or null: {run_ref}/{dimension}')
        if state == 'cap':
            cause_status, cause, evidence_refs = 'not_required', None, []
        elif attribution is not None:
            cause_status, cause, evidence_refs = 'attributed', attribution['cause'], attribution['evidence_refs']
        else:
            cause_status, cause, evidence_refs = 'unresolved', None, []
        if state == 'null' and not pending_reason:
            diagnostics.append({
                'code': 'missing_component_pending_reason',
                'dimension': dimension,
                'detail': 'a null graded component must record why it is unavailable',
            })
        result[dimension] = {
            'component': value,
            'state': state,
            'cause': cause,
            'cause_status': cause_status,
            'evidence_refs': evidence_refs,
            'pending_reason': pending_reason,
            'distance_from_cap': (4 - value) if state == 'deduction' else None,
        }
    return result


def _normalise_tristate(value):
    if value is True or (isinstance(value, str) and value.strip().lower() == 'true'):
        return 'true'
    if value is False or (isinstance(value, str) and value.strip().lower() == 'false'):
        return 'false'
    return 'unknown'


def _selected_method(record):
    state = record.get('final_state') if isinstance(record.get('final_state'), dict) else {}
    method = record.get('selected_method') or state.get('selected_method')
    if method is None and isinstance(state.get('verifier_decision'), dict):
        method = state['verifier_decision'].get('agent_id')
    return method


def _selection_precondition(entry):
    record = entry.record
    state = record.get('final_state') if isinstance(record.get('final_state'), dict) else {}
    method = _selected_method(record)
    result = {
        'diagnostic': True,
        'excluded_from': ['Smethod', 'Srun'],
        'selected_method': method,
        'snapshot_status': None,
        'required_preconditions': None,
        'states': {},
        'consistent': None,
        'g16': None,
        'decision_pointer': None,
        'a2_freeze_provenance_caveat': A2_FREEZE_PROVENANCE_CAVEAT,
    }
    if not isinstance(method, str) or not method:
        result['snapshot_status'] = 'no_selected_method'
        return result
    decisions = []
    decision_rows = state.get('scoring_decisions')
    for index, row in enumerate(decision_rows if isinstance(decision_rows, list) else []):
        if isinstance(row, dict) and row.get('dimension') == 'Smethod' and row.get('method') == method:
            decisions.append((index, row))
    if not decisions:
        result['snapshot_status'] = 'missing_selected_method_snapshot'
        return result
    index, decision = decisions[-1]
    result['decision_pointer'] = f'#/final_state/scoring_decisions/{index}'
    required = AttackKnowledgeGraph.METHOD_PRECONDITIONS.get(method)
    if not required:
        result['snapshot_status'] = 'unknown_static_method_preconditions'
        return result
    result['required_preconditions'] = list(required)
    result['snapshot_status'] = 'assessed'
    observations = decision.get('observations') if isinstance(decision.get('observations'), dict) else {}
    statuses = decision.get('precondition_status') if isinstance(
        decision.get('precondition_status'), dict) else {}
    states = {}
    for precondition in required:
        value_source = None
        if statuses and precondition in statuses:
            value, value_source = statuses.get(precondition), 'precondition_status'
        elif precondition in observations:
            value, value_source = observations.get(precondition), 'observations'
        else:
            value = None
        states[precondition] = {
            'value': value,
            'tri_state': _normalise_tristate(value),
            'source': value_source,
        }
    result['states'] = states
    result['consistent'] = all(row['tri_state'] == 'true' for row in states.values())
    recorded = []
    recorded_present = False
    for field in ('preconditions', 'required_preconditions'):
        value = decision.get(field)
        if isinstance(value, list):
            recorded_present = True
            recorded.extend(node for node in value if isinstance(node, str))
    if recorded_present:
        recorded_set, static_set = set(recorded), set(required)
        if recorded_set != static_set:
            result['g16'] = {
                'recorded': sorted(recorded_set),
                'static_akg': sorted(static_set),
                'missing_from_recorded': sorted(static_set - recorded_set),
                'extra_in_recorded': sorted(recorded_set - static_set),
                'detail': 'routed selections may record AKG edge nodes; FD1 uses only '
                          'AttackKnowledgeGraph.METHOD_PRECONDITIONS',
            }
    return result


def _coordinate(record):
    config = record.get('config') if isinstance(record.get('config'), dict) else {}
    return {
        'provider': config.get('provider'),
        'model': config.get('model'),
        'experiment_condition': config.get('experiment_condition'),
        'surface': config.get('surface'),
        'security_level': config.get('security_level'),
        'payload_mode': config.get('payload_mode'),
        'repeat_index': config.get('repeat_index'),
        'target_method': config.get('target_method'),
    }


def _valid_evidence_refs(queue, dimension):
    refs = set((queue.get('component_evidence_refs') or {}).get(dimension) or [])
    if dimension in (queue.get('components') or {}):
        refs.add(f'queue:#/components/{dimension}')
    if dimension in (queue.get('component_pending_reasons') or {}):
        refs.add(f'queue:#/component_pending_reasons/{dimension}')
    if dimension == 'Spayload':
        refs.update({
            '#/final_state/payload_candidates',
            '#/final_state/payload_validation_results',
            '#/final_state/payload_provenance',
            'queue:#/candidates',
        })
        for row in queue.get('candidates') or []:
            refs.update(row.get('evidence_refs') or [])
    if dimension == 'Smethod':
        refs.add('#/config/scoring_profile')
    if dimension == 'Schain':
        refs.add('#/final_state/chain_assessment')
    return refs


def _resolve_attribution_ref(ref, record, queue):
    if ref.startswith('queue:#/'):
        return _resolve_pointer(queue, ref[len('queue:'):])
    return _resolve_pointer(record, ref)


def _normalise_attributions(items, records, queues):
    if items is None:
        return {}, []
    if isinstance(items, Mapping):
        raise ValueError('Attributions must be an iterable of decision objects')
    by_ref = {}
    for record, entry in records:
        by_ref[_run_ref(entry)] = (record, entry)
    by_execution_id = defaultdict(list)
    by_source_sha256 = defaultdict(list)
    by_run_id = defaultdict(list)
    for run_ref, (record, entry) in by_ref.items():
        execution_id = record.get('execution_id')
        if isinstance(execution_id, str) and execution_id:
            by_execution_id[execution_id].append(run_ref)
        source_sha256 = entry.source.get('sha256')
        if isinstance(source_sha256, str) and source_sha256:
            by_source_sha256[source_sha256].append(run_ref)
        run_id = record.get('run_id')
        if isinstance(run_id, str) and run_id:
            by_run_id[run_id].append(run_ref)
    decisions, normalised = {}, []
    for item in items:
        if not isinstance(item, Mapping):
            raise ValueError('Attribution must be an object')
        run_key = item.get('run') or item.get('run_ref')
        if not isinstance(run_key, str) or not run_key:
            raise ValueError('Attribution requires a run_ref or execution_id')
        if run_key in by_ref:
            run_ref = run_key
        elif len(by_execution_id.get(run_key, [])) == 1:
            run_ref = by_execution_id[run_key][0]
        elif len(by_source_sha256.get(run_key, [])) == 1:
            run_ref = by_source_sha256[run_key][0]
        elif len(by_run_id.get(run_key, [])) == 1:
            run_ref = by_run_id[run_key][0]
        else:
            raise ValueError(f'Attribution run does not resolve uniquely: {run_key}')
        record, entry = by_ref[run_ref]
        dimension = item.get('dimension')
        if dimension not in DIMENSIONS:
            raise ValueError(f'Attribution dimension is not graded: {dimension!r}')
        cause = item.get('cause')
        if cause not in CLOSED_CAUSES:
            raise ValueError(f'Attribution cause is not in the closed list: {cause!r}')
        refs = item.get('evidence_refs')
        if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) or not ref for ref in refs):
            raise ValueError('Attribution requires a nonempty evidence_refs list')
        refs = list(dict.fromkeys(refs))
        queue = queues.get(run_ref)
        if queue is None:
            raise ValueError(f'Attribution cannot bind an ungraded run: {run_ref}')
        valid = _valid_evidence_refs(queue, dimension)
        if not set(refs) & valid:
            raise ValueError(f'Attribution evidence does not bind {dimension}: {run_ref}')
        for ref in refs:
            resolved = _resolve_attribution_ref(ref, record, queue)
            if resolved is POINTER_MISSING:
                raise ValueError(f'Attribution evidence does not resolve: {ref}')
        if (run_ref, dimension) in decisions:
            raise ValueError(f'Duplicate attribution for {run_ref}/{dimension}')
        decision = {
            'run_ref': run_ref,
            'execution_id': record.get('execution_id'),
            'dimension': dimension,
            'cause': cause,
            'evidence_refs': refs,
            'note': item.get('note'),
        }
        decisions[run_ref, dimension] = decision
        normalised.append(decision)
    return decisions, normalised


def _condition_label(run):
    return run['coordinate'].get('experiment_condition') or 'unlabelled'


def _ratio(numerator, denominator, reason):
    if denominator:
        return numerator / denominator, None
    return None, reason


def _metric_f1(runs):
    by_condition = defaultdict(lambda: {'numerator': 0, 'denominator': 0})
    total = receipts = 0
    for run in runs:
        record = run['_record']
        for receipt in record.get('candidate_budget_receipts') or []:
            if not isinstance(receipt, dict):
                continue
            generated = receipt.get('generated')
            executed = receipt.get('executed')
            generated = generated if isinstance(generated, list) else []
            executed = executed if isinstance(executed, list) else []
            if not any('_llm_' in str(candidate) for candidate in generated):
                continue
            total += 1
            bucket = by_condition[_condition_label(run)]
            bucket['denominator'] += 1
            if any('_llm_' in str(candidate) for candidate in executed):
                receipts += 1
                bucket['numerator'] += 1
    value, reason = _ratio(receipts, total, 'no_llm_candidate_receipts')
    return {
        'id': 'F1',
        'name': 'model_candidate_execution_rate',
        'value': value,
        'numerator': receipts,
        'denominator': total,
        'population': 'candidate_budget_receipts_with_an_llm_candidate',
        'source': ['artifact.candidate_budget_receipts'],
        'definition': 'receipts with an _llm_ candidate executed / receipts with an _llm_ candidate',
        'unavailable_reason': reason,
        'by_condition': dict(sorted(by_condition.items())),
        'no_condition_pooling': 'per-condition buckets reported alongside the pooled handoff definition',
    }


def _metric_f2(runs):
    by_condition = defaultdict(lambda: {'numerator': 0, 'denominator': 0})
    numerator = denominator = excluded_ungraded = 0
    for run in runs:
        record = run['_record']
        score = record.get('composite_score')
        if not _is_number(score):
            continue
        if not run['graded'].get('available'):
            excluded_ungraded += 1
            continue
        denominator += 1
        bucket = by_condition[_condition_label(run)]
        bucket['denominator'] += 1
        counted = [row.get('candidate_id') for row in (run.get('_queue') or {}).get('candidates') or []
                   if row.get('eligible')]
        if any('_llm_' in str(candidate) for candidate in counted):
            numerator += 1
            bucket['numerator'] += 1
    value, reason = _ratio(numerator, denominator, 'no_graded_scored_runs')
    return {
        'id': 'F2',
        'name': 'generated_grade_share',
        'value': value,
        'numerator': numerator,
        'denominator': denominator,
        'population': 'graded_runs_with_a_numeric_runtime_composite_score',
        'source': ['artifact.composite_score', 'review_queue.candidates'],
        'definition': 'scored runs whose counted payload candidate set contains an _llm_ candidate / scored runs',
        'unavailable_reason': reason,
        'excluded_ungraded_scored_runs': excluded_ungraded,
        'by_condition': dict(sorted(by_condition.items())),
        'no_condition_pooling': 'per-condition buckets reported alongside the pooled handoff definition',
    }


def _metric_f3(runs):
    denominator = numerator = 0
    unresolved = []
    by_dimension = defaultdict(lambda: {'deductions_or_nulls': 0, 'attributed': 0})
    for run in runs:
        if not run['graded'].get('available'):
            continue
        for dimension, row in run['dimensions'].items():
            if row['state'] not in {'deduction', 'null'}:
                continue
            denominator += 1
            by_dimension[dimension]['deductions_or_nulls'] += 1
            if row['cause_status'] == 'attributed':
                numerator += 1
                by_dimension[dimension]['attributed'] += 1
            else:
                unresolved.append({
                    'run_ref': run['run_ref'],
                    'dimension': dimension,
                    'state': row['state'],
                    'pending_reason': row['pending_reason'],
                })
    value, reason = _ratio(numerator, denominator, 'no_graded_deductions_or_nulls')
    return {
        'id': 'F3',
        'name': 'attribution_completeness',
        'value': value,
        'numerator': numerator,
        'denominator': denominator,
        'population': 'graded_component_deductions_and_nulls',
        'source': ['review_queue.components', 'explicit_closed_cause_attributions'],
        'definition': 'deductions + nulls with a closed-list cause / all deductions + nulls',
        'unavailable_reason': reason,
        'unknown': len(unresolved),
        'unresolved_by_dimension': {dimension: row['deductions_or_nulls'] - row['attributed']
                                    for dimension, row in sorted(by_dimension.items())},
        'by_dimension': dict(sorted(by_dimension.items())),
        'unresolved': unresolved,
        'closed_causes': sorted(CLOSED_CAUSES),
    }


def _metric_f4(runs):
    failures = []
    denominator = numerator = 0
    for run in runs:
        record = run['_record']
        if 'composite_score' not in record or record['composite_score'] is not None:
            continue
        denominator += 1
        availability = _availability_field(record, 'metric_availability') or {}
        reasons = _availability_field(record, 'metric_unavailable_reason') or {}
        measured_negative = record.get('measured_negative') or {}
        checks = {
            'metric_availability_composite_score_false': isinstance(availability, dict)
                and availability.get('composite_score') is False,
            'metric_unavailable_reason_composite_score': isinstance(reasons, dict)
                and isinstance(reasons.get('composite_score'), str)
                and bool(reasons['composite_score'].strip()),
            'measured_negative_complete': isinstance(measured_negative, dict)
                and measured_negative.get('complete') is True,
        }
        if all(checks.values()):
            numerator += 1
        else:
            failures.append({'run_ref': run['run_ref'], **checks})
    value, reason = _ratio(numerator, denominator, 'no_null_composite_runs')
    return {
        'id': 'F4',
        'name': 'null_discipline',
        'value': value,
        'numerator': numerator,
        'denominator': denominator,
        'population': 'runs_with_a_null_composite_score',
        'source': ['artifact.metric_availability', 'artifact.metric_unavailable_reason',
                   'artifact.measured_negative'],
        'definition': 'nulls with metric_unavailable_reason and a complete measured negative / nulls',
        'unavailable_reason': reason,
        'failures': failures,
    }


def _metric_f5(runs):
    failures = []
    denominator = numerator = 0
    for run in runs:
        record = run['_record']
        score = record.get('composite_score')
        if not _is_number(score):
            continue
        denominator += 1
        components, source = _runtime_vector(record)
        if components is None:
            failures.append({'run_ref': run['run_ref'], 'reason': source})
            continue
        expected = round(sum(WEIGHTS[dimension] * components[dimension] for dimension in WEIGHTS), 4)
        if abs(expected - score) <= 1e-9:
            numerator += 1
        else:
            failures.append({
                'run_ref': run['run_ref'],
                'reason': 'composite_score_does_not_recompute',
                'stored': score,
                'recomputed': expected,
                'delta': score - expected,
                'components_source': source,
            })
    value, reason = _ratio(numerator, denominator, 'no_scored_runs')
    return {
        'id': 'F5',
        'name': 'arithmetic_consistency',
        'value': value,
        'numerator': numerator,
        'denominator': denominator,
        'population': 'runs_with_a_numeric_runtime_composite_score',
        'source': ['artifact.composite_components', 'thesis_scoring.WEIGHTS'],
        'definition': 'scored runs whose composite_components reproduce composite_score under v4 weights',
        'unavailable_reason': reason,
        'failures': failures,
    }


def _surface_for_method(method):
    for surface, methods in METHODS_BY_SURFACE.items():
        if method in methods:
            return surface
    return None


def _control_event_identity(event):
    return (
        event.get('method'),
        event.get('visit_id'),
        event.get('control_id'),
        event.get('request_id'),
        event.get('at'),
        event.get('phase'),
    )


def _iter_sent_control_events(record):
    """Yield deduplicated recorded sent/failed physical control events.

    Planned probe catalog entries and root/state/probe mirrors are not evidence
    of a sent control.  Only an explicit sent/failed status with a positive
    physical request count counts.
    """
    seen = set()
    state = record.get('final_state') if isinstance(record.get('final_state'), dict) else {}
    sources = [
        record.get('control_events') if isinstance(record.get('control_events'), list) else [],
        state.get('control_events') if isinstance(state.get('control_events'), list) else [],
    ]
    probe_controls = record.get('probe_controls')
    if isinstance(probe_controls, dict):
        for value in probe_controls.values():
            candidates = value.get('candidates') if isinstance(value, dict) else value
            if isinstance(candidates, list):
                sources.append(candidates)
    for events in sources:
        for event in events:
            if not isinstance(event, dict):
                continue
            status = str(event.get('status') or '').strip().lower()
            physical = event.get('physical_requests')
            if not isinstance(physical, int) or isinstance(physical, bool):
                physical = event.get('physical_requests_used')
            sent = status in {'sent', 'failed'} and type(physical) is int and physical > 0
            if not sent:
                continue
            identity = _control_event_identity(event)
            if identity in seen:
                continue
            seen.add(identity)
            yield event


def _surface_controls(record):
    controls = Counter()
    for event in _iter_sent_control_events(record):
        surface = _surface_for_method(event.get('method'))
        if surface:
            controls[surface] += 1
    measured_negative = record.get('measured_negative')
    if isinstance(measured_negative, dict):
        surface = measured_negative.get('surface')
        sent = measured_negative.get('control_events_sent')
        if isinstance(surface, str) and type(sent) is int and sent > 0 and controls[surface] == 0:
            controls[surface] += sent
    return controls


def _metric_f6(runs):
    disagreements = []
    codes = Counter()
    denominator = 0
    for run in runs:
        record = run['_record']
        denominator += 1
        found = []
        config = record.get('config') if isinstance(record.get('config'), dict) else {}
        epoch = record.get('score_epoch') if isinstance(record.get('score_epoch'), dict) else {}
        rubric = config.get('scoring_rubric_version')
        thesis_final = epoch.get('thesis_final')
        if isinstance(rubric, str) and isinstance(thesis_final, str) and rubric != thesis_final:
            found.append({'code': 'epoch_rubric_mismatch',
                          'scoring_rubric_version': rubric, 'thesis_final': thesis_final})
        measured_negative = record.get('measured_negative') or {}
        security_reason = record.get('security_outcome_reason') or {}
        if isinstance(measured_negative, dict) and measured_negative.get('complete') is True \
                and isinstance(security_reason, dict) \
                and security_reason.get('code') == 'NO_CANDIDATE_CONFIRMATION':
            found.append({'code': 'measured_negative_described_as_missing_proof',
                          'measured_negative_reason': measured_negative.get('reason'),
                          'security_outcome_reason': security_reason.get('code')})
        surface_scores = ((record.get('report') or {}).get('surface_scores')
                          if isinstance(record.get('report'), dict) else {})
        controls = _surface_controls(record)
        if isinstance(surface_scores, dict):
            for surface, row in surface_scores.items():
                if not isinstance(row, dict) or controls.get(surface, 0) <= 0:
                    continue
                attempts = row.get('attempts')
                if type(attempts) is int and attempts == 0:
                    found.append({'code': 'surface_attempts_zero_with_controls',
                                  'surface': surface,
                                  'control_events': controls[surface],
                                  'surface_label': row.get('label')})
        if found:
            for item in found:
                codes[item['code']] += 1
            disagreements.append({'run_ref': run['run_ref'], 'disagreements': found})
    value, reason = _ratio(len(disagreements), denominator, 'no_artifacts_checked')
    return {
        'id': 'F6',
        'name': 'label_consistency',
        'value': value,
        'numerator': len(disagreements),
        'denominator': denominator,
        'population': 'accepted_artifacts',
        'source': ['artifact.score_epoch', 'artifact.config.scoring_rubric_version',
                   'artifact.measured_negative', 'artifact.security_outcome_reason',
                   'artifact.report.surface_scores',
                   'artifact.control_events[status=sent|failed, physical_requests>0]'],
        'definition': 'artifacts with at least one internal label disagreement / artifacts checked',
        'target': '0 disagreements (zero runs, zero categories)',
        'n_codes': len(codes),
        'codes': dict(sorted(codes.items())),
        'unavailable_reason': reason,
        'disagreements': disagreements,
    }


def _identity_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, default=str)
    return value


def _f7_identity(run):
    record = run['_record']
    config = record.get('config') if isinstance(record.get('config'), dict) else {}
    profile = config.get('scoring_profile') if isinstance(config.get('scoring_profile'), dict) else {}
    epoch = record.get('score_epoch') if isinstance(record.get('score_epoch'), dict) else {}
    return {
        'source_root_id': run['source'].get('root_id'),
        'scoring_mode': config.get('scoring_mode'),
        'payload_mode': config.get('payload_mode'),
        'target_method': config.get('target_method'),
        'source_hashes_sha256': _identity_value(record.get('source_hashes_sha256')),
        'runtime_provisional': epoch.get('runtime_provisional'),
        'runtime_rule_sha256': epoch.get('scoring_rule_sha256'),
        'profile_sha256': profile.get('sha256'),
    }


def _metric_f7(runs):
    cells = defaultdict(lambda: {'runs': [], 'vectors': [], 'missing_vectors': []})
    for run in runs:
        coordinate = run['coordinate']
        if coordinate.get('surface') == 'access_control' and coordinate.get('security_level') == 'high':
            continue
        identity = _f7_identity(run)
        key = (
            coordinate.get('model'),
            coordinate.get('provider'),
            coordinate.get('experiment_condition'),
            coordinate.get('surface'),
            coordinate.get('security_level'),
            identity['source_root_id'],
            identity['scoring_mode'],
            identity['payload_mode'],
            identity['target_method'],
            identity['source_hashes_sha256'],
            identity['runtime_provisional'],
            identity['runtime_rule_sha256'],
            identity['profile_sha256'],
        )
        cell = cells[key]
        cell['runs'].append(run['run_ref'])
        components, source = _runtime_vector(run['_record'])
        if components is None:
            cell['missing_vectors'].append({'run_ref': run['run_ref'], 'reason': source})
            continue
        cell['vectors'].append({
            'run_ref': run['run_ref'],
            'repeat_index': coordinate.get('repeat_index'),
            'vector': [components[dimension] for dimension in DIMENSIONS],
        })
    results = []
    stable = 0
    comparable = []
    by_condition = defaultdict(lambda: {'n_cells': 0, 'n_comparable_cells': 0, 'stable_cells': 0})
    for key, cell in sorted(cells.items(), key=lambda item: tuple(str(part) for part in item[0])):
        distinct = sorted({tuple(row['vector']) for row in cell['vectors']})
        repeats = [row['repeat_index'] for row in cell['vectors']]
        if any(index is None for index in repeats):
            repeat_identity_status = 'missing_repeat_index'
        elif len(set(repeats)) != len(repeats):
            repeat_identity_status = 'duplicate_repeat_index'
        else:
            repeat_identity_status = None
        is_comparable = len(cell['vectors']) >= 2 and repeat_identity_status is None
        if is_comparable and len(distinct) == 1:
            stable += 1
        if is_comparable:
            comparable.append(key)
        condition = key[2] or 'unlabelled'
        by_condition[condition]['n_cells'] += 1
        if is_comparable:
            by_condition[condition]['n_comparable_cells'] += 1
            if len(distinct) == 1:
                by_condition[condition]['stable_cells'] += 1
        if not cell['vectors']:
            reason = 'no_runtime_vectors'
        elif len(cell['vectors']) < 2:
            reason = 'fewer_than_two_runtime_vectors'
        else:
            reason = repeat_identity_status
        results.append({
            'model': key[0], 'provider': key[1], 'experiment_condition': key[2],
            'surface': key[3], 'security_level': key[4],
            'source_root_id': key[5], 'scoring_mode': key[6], 'payload_mode': key[7],
            'target_method': key[8], 'source_hashes_sha256': key[9],
            'runtime_provisional': key[10], 'runtime_rule_sha256': key[11],
            'profile_sha256': key[12],
            'run_refs': cell['runs'],
            'n_runs': len(cell['runs']),
            'n_vectors': len(cell['vectors']),
            'n_distinct_vectors': len(distinct),
            'repeat_indices': repeats,
            'repeat_identity_status': repeat_identity_status,
            'repeat_stability_available': is_comparable,
            'vectors': cell['vectors'],
            'distinct_vectors': [list(vector) for vector in distinct],
            'missing_vectors': cell['missing_vectors'],
            'unavailable_reason': reason,
        })
    value, reason = _ratio(stable, len(comparable), 'no_cells_with_two_runtime_vectors')
    return {
        'id': 'F7',
        'name': 'repeat_stability',
        'value': value,
        'numerator': stable,
        'denominator': len(comparable),
        'population': 'identity_partitioned_non_access_control_high_cells_with_at_least_two_distinct_repeats',
        'source': ['artifact.composite_components', 'artifact.config.scoring_mode',
                   'artifact.config.payload_mode', 'artifact.config.target_method',
                   'artifact.config.scoring_profile.sha256', 'artifact.source_hashes_sha256',
                   'artifact.score_epoch'],
        'definition': 'comparable identity-partitioned cells with one distinct runtime composite vector / comparable cells',
        'descriptive_only': True,
        'target': 'reported, not optimised',
        'no_condition_pooling': 'cell key includes model, provider, experiment_condition, root, '
                                'scoring_mode, payload_mode, target_method, source epoch and profile',
        'unavailable_reason': reason,
        'n_cells': len(results),
        'n_comparable_cells': len(comparable),
        'by_condition': {condition: dict(counts)
                         for condition, counts in sorted(by_condition.items())},
        'cells': results,
    }


def _metric_f8(runs):
    graded = [run for run in runs if run['graded'].get('available')]
    ungraded = [{'run_ref': run['run_ref'], 'reason': run['graded'].get('reason')}
                for run in runs if not run['graded'].get('available')]
    scored = [run for run in runs if _is_number(run['legacy_runtime'].get('composite_score'))]
    scored_graded = [run for run in scored if run['graded'].get('available')]
    null_with_reason = null_components = 0
    for run in graded:
        for dimension, row in run['dimensions'].items():
            if row['state'] != 'null':
                continue
            null_components += 1
            if row.get('pending_reason'):
                null_with_reason += 1
    value, reason = _ratio(len(graded), len(runs), 'no_artifacts')
    discipline, discipline_reason = _ratio(null_with_reason, null_components, 'no_null_components')
    scored_value, scored_reason = _ratio(len(scored_graded), len(scored), 'no_scored_runs')
    return {
        'id': 'F8',
        'name': 'thesis_rubric_coverage',
        'value': value,
        'numerator': len(graded),
        'denominator': len(runs),
        'population': 'accepted_artifacts',
        'source': ['review_queue'],
        'definition': 'runs whose reported components come from the graded path / runs reported',
        'unavailable_reason': reason,
        'scored_run_coverage': {
            'value': scored_value,
            'numerator': len(scored_graded),
            'denominator': len(scored),
            'definition': 'scored runs whose reported components come from the graded path / scored runs',
            'unavailable_reason': scored_reason,
        },
        'null_reason_discipline': {
            'value': discipline,
            'numerator': null_with_reason,
            'denominator': null_components,
            'definition': 'null graded components with a recorded reason / null graded components',
            'unavailable_reason': discipline_reason,
        },
        'ungraded': ungraded,
    }


def _selection_receipt_metadata(runs):
    rows = []
    for run in runs:
        record = run['_record']
        state = record.get('final_state') if isinstance(record.get('final_state'), dict) else {}
        selected = _selected_method(record)
        decisions = state.get('scoring_decisions')
        decisions = decisions if isinstance(decisions, list) else []
        smethod = [(index, decision) for index, decision in enumerate(decisions)
                   if isinstance(decision, dict) and decision.get('dimension') == 'Smethod']
        final_index = None
        if isinstance(selected, str):
            matching = [index for index, decision in smethod if decision.get('method') == selected]
            if matching:
                final_index = matching[-1]
        for index, decision in smethod:
            method = decision.get('method')
            static = sorted(AttackKnowledgeGraph.METHOD_PRECONDITIONS.get(method, [])) \
                if isinstance(method, str) else []
            preconditions = decision.get('preconditions')
            required = decision.get('required_preconditions')
            recorded_present = isinstance(preconditions, list) or isinstance(required, list)
            recorded = sorted({
                node for field in (preconditions, required)
                if isinstance(field, list) for node in field if isinstance(node, str)
            })
            mismatch = None
            if recorded_present and recorded != static:
                mismatch = {
                    'static_akg': static,
                    'recorded': recorded,
                    'recorded_preconditions': preconditions if isinstance(preconditions, list) else None,
                    'recorded_required_preconditions': required if isinstance(required, list) else None,
                    'missing_from_recorded': sorted(set(static) - set(recorded)),
                    'extra_in_recorded': sorted(set(recorded) - set(static)),
                }
            rows.append({
                'run_ref': run['run_ref'],
                'execution_id': record.get('execution_id'),
                'source_sha256': run['source'].get('sha256'),
                'method': method,
                'visit_id': decision.get('visit_id'),
                'origin': (decision.get('selection_source') or decision.get('decision_origin')),
                'pointer': f'#/final_state/scoring_decisions/{index}',
                'final_selected': index == final_index,
                'mismatch': mismatch,
            })
    mismatches = [row for row in rows if row['mismatch']]
    return {
        'population': 'all_smethod_scoring_decisions',
        'source': ['artifact.final_state.scoring_decisions',
                   'AttackKnowledgeGraph.METHOD_PRECONDITIONS'],
        'definition': 'every recorded Smethod decision whose preconditions/required_preconditions '
                      'differ from the static method precondition list',
        'n_rows': len(rows),
        'n_mismatches': len(mismatches),
        'n_nonfinal_mismatches': sum(not row['final_selected'] for row in mismatches),
        'n_final_selected_mismatches': sum(row['final_selected'] for row in mismatches),
        'mismatches': mismatches,
        'rows': rows,
        'note': 'diagnostic only; not the FD1 denominator and not a rubric decision. '
                'This does not repair routing, agent or runtime metadata.',
    }


def _metric_fd1(runs):
    assessed, missing = [], []
    numerator = denominator = 0
    inconsistent, g16_mismatches = [], []
    for run in runs:
        selection = run['selection_precondition']
        if not run['graded'].get('available'):
            missing.append({
                'run_ref': run['run_ref'],
                'selected_method': selection.get('selected_method'),
                'reason': 'graded_path_unavailable',
            })
            continue
        if selection['snapshot_status'] != 'assessed':
            missing.append({
                'run_ref': run['run_ref'],
                'selected_method': selection.get('selected_method'),
                'reason': selection['snapshot_status'],
            })
            continue
        denominator += 1
        if selection['consistent'] is True:
            numerator += 1
        else:
            inconsistent.append({
                'run_ref': run['run_ref'],
                'selected_method': selection.get('selected_method'),
                'states': selection['states'],
            })
        if selection.get('g16'):
            g16_mismatches.append({'run_ref': run['run_ref'], **selection['g16']})
    value, reason = _ratio(numerator, denominator, 'no_runs_with_a_selection_snapshot')
    assessed.extend(run['run_ref'] for run in runs
                    if run['selection_precondition']['snapshot_status'] == 'assessed')
    return {
        'id': 'FD1',
        'name': 'selection_precondition_consistency',
        'value': value,
        'numerator': numerator,
        'denominator': denominator,
        'population': 'accepted_runs_with_a_selected_method_snapshot',
        'source': ['artifact.final_state.scoring_decisions',
                   'core.knowledge_graph.AttackKnowledgeGraph.METHOD_PRECONDITIONS'],
        'definition': 'graded runs whose selected method had every static-AKG precondition '
                      'observed true in the selection snapshot / runs with a snapshot',
        'diagnostic': True,
        'excluded_from': ['Smethod', 'Srun'],
        'label': 'diagnostic, not a rubric dimension; FD1=1.00 means no self-contradiction, not good selection',
        'unavailable_reason': reason,
        'missing_snapshots': missing,
        'inconsistent_runs': inconsistent,
        'g16_mismatches': g16_mismatches,
        'assessed_run_refs': assessed,
        'a2_freeze_provenance_caveat': A2_FREEZE_PROVENANCE_CAVEAT,
    }


def _resolution(runs):
    graded_vectors = Counter()
    graded_refs = defaultdict(list)
    scored_vectors = Counter()
    scored_refs = defaultdict(list)
    runtime_vectors = Counter()
    runtime_refs = defaultdict(list)
    for run in runs:
        graded = run['graded']
        if graded.get('available'):
            vector = tuple(graded['components'].get(dimension) for dimension in DIMENSIONS)
            graded_vectors[vector] += 1
            graded_refs[vector].append(run['run_ref'])
            if _is_number(run['legacy_runtime'].get('composite_score')):
                scored_vectors[vector] += 1
                scored_refs[vector].append(run['run_ref'])
        components, _source = _runtime_vector(run['_record'])
        if components is not None:
            vector = tuple(components[dimension] for dimension in DIMENSIONS)
            runtime_vectors[vector] += 1
            runtime_refs[vector].append(run['run_ref'])
    return {
        'graded_vectors': [
            {
                'vector': dict(zip(DIMENSIONS, vector)),
                'n_runs': count,
                'run_refs': graded_refs[vector],
            }
            for vector, count in sorted(graded_vectors.items(), key=lambda item: str(item[0]))
        ],
        'scored_graded_vectors': [
            {
                'vector': dict(zip(DIMENSIONS, vector)),
                'n_runs': count,
                'run_refs': scored_refs[vector],
            }
            for vector, count in sorted(scored_vectors.items(), key=lambda item: str(item[0]))
        ],
        'runtime_vectors': [
            {
                'label': RUNTIME_PROVISIONAL_LABEL,
                'vector': dict(zip(DIMENSIONS, vector)),
                'n_runs': count,
                'run_refs': runtime_refs[vector],
            }
            for vector, count in sorted(runtime_vectors.items(), key=lambda item: str(item[0]))
        ],
        'separate': True,
        'no_condition_pooling': True,
        'note': 'graded resolution and runtime repeat stability are reported separately; '
                'scored_graded_vectors restricts graded resolution to runs with a numeric runtime '
                'composite; runtime vectors are legacy labels, never graded components',
    }


def _population_integrity(excluded, diagnostics):
    dropped = [item for item in excluded or []
               if item.get('reason') == 'duplicate_execution_identity']
    issues = [item for item in diagnostics or []
              if item.get('code') in POPULATION_BLOCKING_CODES]
    return dropped, issues


def _phase_a(runs, excluded=None, diagnostics=None):
    graded = [run for run in runs if run['graded'].get('available')]
    payload_required = []
    human_payload = []
    null_with_reason = Counter()
    null_without_reason = defaultdict(list)
    deduction_without_cause = defaultdict(list)
    null_without_cause = defaultdict(list)
    for run in graded:
        queue = run.get('_queue') or {}
        if any(row.get('eligible') for row in queue.get('candidates') or []):
            payload_required.append(run['run_ref'])
            if run['graded'].get('human_payload_review'):
                human_payload.append(run['run_ref'])
        for dimension in ('Spayload', 'Sexploit', 'Schain', 'Soutput'):
            row = run['dimensions'][dimension]
            if row['state'] == 'null':
                if row.get('pending_reason'):
                    null_with_reason[dimension] += 1
                else:
                    null_without_reason[dimension].append(run['run_ref'])
                if row.get('cause_status') != 'attributed':
                    null_without_cause[dimension].append(run['run_ref'])
            elif row['state'] == 'deduction' and row.get('cause_status') != 'attributed':
                deduction_without_cause[dimension].append(run['run_ref'])
    missing_reviews = sorted(set(payload_required) - set(human_payload))
    dropped, issues = _population_integrity(excluded, diagnostics)
    blocking = []
    if not graded:
        blocking.append('no_graded_artifacts')
    if dropped:
        blocking.append(f"dropped_duplicate_execution_identities={len(dropped)}")
    if issues:
        codes = sorted({str(item.get('code')) for item in issues})
        blocking.append('population_integrity_issues=' + ','.join(codes))
    if len(graded) != len(runs):
        blocking.append(f"ungraded_artifacts={len(runs) - len(graded)}")
    if missing_reviews:
        blocking.append(f"human_payload_reviews_missing={len(missing_reviews)}")
    for dimension, refs in null_without_reason.items():
        if refs:
            blocking.append(f"{dimension}_null_without_reason={len(refs)}")
    for dimension, refs in deduction_without_cause.items():
        if refs:
            blocking.append(f"{dimension}_deduction_without_closed_cause={len(refs)}")
    for dimension, refs in null_without_cause.items():
        if refs:
            blocking.append(f"{dimension}_null_without_closed_cause={len(refs)}")
    return {
        'complete': not blocking,
        'blocking_reasons': blocking,
        'population_integrity_ok': not dropped and not issues,
        'dropped_inputs': len(dropped),
        'population_integrity_issues': sorted({str(item.get('code')) for item in issues}),
        'artifacts_restated': len(graded),
        'artifacts_total': len(runs),
        'payload_required_runs': len(payload_required),
        'payload_no_eligible_runs': len(graded) - len(payload_required),
        'human_payload_reviewed_runs': len(human_payload),
        'human_payload_missing_review_runs': missing_reviews,
        'null_components_with_reason': dict(sorted(null_with_reason.items())),
        'null_components_without_reason': {dimension: len(refs)
                                           for dimension, refs in sorted(null_without_reason.items())},
        'deduction_components_without_closed_cause': {
            dimension: len(refs) for dimension, refs in sorted(deduction_without_cause.items())
        },
        'null_components_without_closed_cause': {dimension: len(refs)
                                                 for dimension, refs in sorted(null_without_cause.items())},
        'deduction_components_without_closed_cause_run_refs': dict(sorted(deduction_without_cause.items())),
        'null_components_without_closed_cause_run_refs': dict(sorted(null_without_cause.items())),
        'note': 'phase A closes only when human payload reviews exist where candidates exist and '
                'every deduction or null non-Smethod component carries a closed-list cause; '
                'AI receipts are experimental and separate',
    }


def _convergence(fidelity, runs, phase_a, excluded=None, diagnostics=None):
    blocking = []
    dropped, issues = _population_integrity(excluded, diagnostics)
    if not runs:
        blocking.append('no_accepted_runs')
    if dropped:
        blocking.append(f"dropped_duplicate_execution_identities={len(dropped)}")
    if issues:
        codes = sorted({str(item.get('code')) for item in issues})
        blocking.append('population_integrity_issues=' + ','.join(codes))
    for metric_id in ('F3', 'F4', 'F5'):
        metric = fidelity[metric_id]
        if metric['value'] is None:
            blocking.append(f"{metric_id}:{metric['unavailable_reason']}")
        elif metric['value'] != 1:
            blocking.append(f"{metric_id}:value={metric['value']}")
    f6 = fidelity['F6']
    if f6['value'] is None:
        blocking.append(f"F6:{f6['unavailable_reason']}")
    elif f6['numerator'] or f6['n_codes']:
        blocking.append(f"F6:disagreements={f6['numerator']},codes={f6['n_codes']}")
    unresolved = fidelity['F3']['unknown']
    if unresolved:
        blocking.append(f"F3:unresolved_causes={unresolved}")
    harness = sum(1 for run in runs if run['graded'].get('available')
                  for row in run['dimensions'].values()
                  if isinstance(row.get('cause'), str) and row['cause'].startswith('harness_'))
    if harness:
        blocking.append(f"open_harness_causes={harness}")
    ungraded = len([run for run in runs if not run['graded'].get('available')])
    if ungraded:
        blocking.append(f"ungraded_runs={ungraded}")
    if not phase_a['complete']:
        blocking.extend(f"phase_a:{reason}" for reason in phase_a['blocking_reasons'])
    not_assessed = [
        'fresh_epoch_acceptance_not_assessed',
        'phase_b_not_assessed',
        'frozen_invariants_not_assessed',
    ]
    population_ok = bool(runs) and not dropped and not issues
    return {
        'converged': False,
        'scope': 'offline_fidelity_only',
        'offline_fidelity_ready': not blocking,
        'offline_blocking_reasons': blocking,
        'blocking_reasons': [*blocking, *not_assessed],
        'fresh_epoch_acceptance': 'not_assessed',
        'phase_b': 'not_assessed',
        'frozen_invariants': 'not_assessed',
        'population_integrity_ok': population_ok,
        'dropped_inputs': len(dropped),
        'population_integrity_issues': sorted({str(item.get('code')) for item in issues}),
        'unresolved_causes': unresolved,
        'open_harness_causes': harness,
        'ungraded_runs': ungraded,
        'rule': 'offline F3-F6 and phase A can establish only offline_fidelity_ready; '
                'full convergence always requires a fresh epoch, phase B and frozen-invariant '
                'acceptance, and unresolved causes are never inferred away',
    }


def rank_hypotheses(hypotheses):
    """Order explicit P1 hypotheses by the handoff section 5.3 rule.

    Sorting is lexicographic: benchmax risk ascending (none -> needs §4.2 ->
    needs §4.3), evidence strength descending (artifact-only -> artifact+replay
    -> needs-live), runs affected descending; the hypothesis id breaks ties.
    Falsified hypotheses are retained but excluded from the ordered queue.
    """
    rows = list(hypotheses or [])
    if not rows:
        raise ValueError('P1 requires at least one explicit hypothesis')
    ordered, falsified, seen = [], [], set()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ValueError(f'Hypothesis {index} must be an object')
        identifier = row.get('id')
        if not isinstance(identifier, str) or not identifier.strip():
            raise ValueError(f'Hypothesis {index} requires a nonempty id')
        if identifier in seen:
            raise ValueError(f'Duplicate hypothesis id: {identifier}')
        seen.add(identifier)
        component = row.get('component')
        if component not in DIMENSIONS and component not in {
                'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'FD1'}:
            raise ValueError(f'Hypothesis {identifier} must name one graded/fidelity component')
        risk = row.get('benchmax_risk')
        if risk not in RISK_ORDER:
            raise ValueError(f'Hypothesis {identifier} has invalid benchmax_risk: {risk!r}')
        evidence = row.get('evidence_strength')
        if evidence not in EVIDENCE_ORDER:
            raise ValueError(f'Hypothesis {identifier} has invalid evidence_strength: {evidence!r}')
        affected = row.get('runs_affected')
        if type(affected) is not int or affected < 0:
            raise ValueError(f'Hypothesis {identifier} requires a nonnegative integer runs_affected')
        prediction = row.get('prediction')
        if not prediction or (isinstance(prediction, str) and not prediction.strip()):
            raise ValueError(f'Hypothesis {identifier} requires a pre-change prediction')
        control = row.get('control')
        if not isinstance(control, str) or not control.strip():
            raise ValueError(f'Hypothesis {identifier} requires one named discriminating control')
        attempts = row.get('falsification_attempts', 0)
        if type(attempts) is not int or attempts < 0:
            raise ValueError(f'Hypothesis {identifier} requires nonnegative falsification_attempts')
        state = row.get('falsification_state', 'open')
        if state not in {'open', 'falsified'}:
            raise ValueError(f'Hypothesis {identifier} has invalid falsification_state: {state!r}')
        if attempts >= 2 and state != 'falsified':
            raise ValueError(f'Hypothesis {identifier} has two failures and must be recorded falsified')
        evidence_refs = row.get('evidence_refs', [])
        if not isinstance(evidence_refs, list) or any(not isinstance(ref, str) or not ref for ref in evidence_refs):
            raise ValueError(f'Hypothesis {identifier} evidence_refs must be nonempty strings')
        normalised = {
            'id': identifier,
            'component': component,
            'benchmax_risk': risk,
            'evidence_strength': evidence,
            'runs_affected': affected,
            'prediction': prediction,
            'control': control,
            'falsification_attempts': attempts,
            'falsification_state': state,
            'evidence_refs': list(evidence_refs),
            'note': row.get('note'),
        }
        (falsified if state == 'falsified' else ordered).append(normalised)
    ordered.sort(key=lambda row: (RISK_ORDER[row['benchmax_risk']],
                                  EVIDENCE_ORDER[row['evidence_strength']],
                                  -row['runs_affected'], row['id']))
    return {
        'definition_version': 'p1-ranking.v1',
        'sort': 'lexicographic: risk asc, evidence strength desc, runs affected desc, id asc',
        'ordered': ordered,
        'falsified': falsified,
        'falsified_excluded': True,
    }


def _is_prior_ledger(path):
    try:
        document = json.loads(Path(path).read_text())
    except (OSError, ValueError, UnicodeError):
        return False
    return isinstance(document, dict) and document.get('ledger_version') == LEDGER_VERSION


def _atomic_write(document, output, input_paths):
    output = Path(output).resolve()
    if output in input_paths and not _is_prior_ledger(output):
        raise ValueError(f'Ledger output would overwrite an input: {output}')
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f'.{output.name}.{os.getpid()}.tmp')
    if temporary in input_paths:
        raise ValueError(f'Ledger temporary path collides with an input: {temporary}')
    try:
        temporary.write_text(json.dumps(document, indent=2, ensure_ascii=False) + '\n')
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_ledger(document, output):
    """Write a built ledger, refusing any path that resolves to an input."""
    inputs = set()
    for path in document.get('inputs', {}).get('input_paths', []):
        inputs.add(Path(path).resolve())
    _atomic_write(document, output, inputs)
    return Path(output).resolve()


def _inside_roots(path, roots):
    return any(root.is_dir() and path.is_relative_to(root) for root in roots)


def build_ledger(sources, receipts=None, *, attributions=None, hypotheses=None, output=None):
    """Build the offline fidelity ledger; see the module docstring for the API."""
    source_roots = _normalize_roots(sources, 'source_')
    review_roots = _normalize_roots(receipts, 'review_') if receipts is not None else {}
    catalog = ArtifactCatalog(source_roots, review_roots).scan()
    input_paths = sorted(str(path) for path in catalog.inputs)
    if output is not None:
        resolved_output = Path(output).resolve()
        if resolved_output in {Path(path) for path in input_paths} \
                and not _is_prior_ledger(resolved_output):
            raise ValueError(f'Ledger output would overwrite an input: {resolved_output}')
        if resolved_output.exists() and _inside_roots(
                resolved_output, [*source_roots.values(), *review_roots.values()]):
            try:
                existing = json.loads(resolved_output.read_text())
            except (OSError, ValueError, UnicodeError):
                existing = None
            if not isinstance(existing, dict) or existing.get('ledger_version') != LEDGER_VERSION:
                raise ValueError(
                    f'Ledger output would overwrite an existing artifact inside a source root: {resolved_output}')
    entries, excluded, collection_diagnostics = _collect_runs(catalog)
    records = [(entry.record, entry) for entry in entries]
    runs = []
    queues = {}
    for entry in entries:
        record = entry.record
        run_ref = _run_ref(entry)
        workflows = {}
        review_diagnostics = []
        if review_roots:
            try:
                discovered = discover_reviews(catalog, entry)
            except DATA_ERRORS as exc:
                discovered = {}
                review_diagnostics.append({'code': 'review_discovery_failed',
                                           'error_type': type(exc).__name__, 'error': str(exc)})
            selection = (record.get('config') or {}).get('scoring_mode') if isinstance(
                record.get('config'), dict) else None
            selected_modes = {'human', 'ai'} if selection == 'both' else {selection}
            for mode, workflow in (discovered or {}).items():
                if mode in selected_modes:
                    workflows[mode] = _workflow_summary(workflow)
        selection = (record.get('config') or {}).get('scoring_mode') if isinstance(
            record.get('config'), dict) else None
        graded = _graded_block(entry, workflows, selection)
        queue = graded.pop('_queue', None)
        if isinstance(queue, dict):
            queues[run_ref] = queue
        graded_diagnostics = graded.pop('diagnostics', [])
        diagnostics = [*review_diagnostics, *graded_diagnostics,
                       *[item for item in entry.diagnostics if isinstance(item, dict)]]
        runs.append({
            'run_ref': run_ref,
            'execution_id': record.get('execution_id'),
            'run_id': record.get('run_id'),
            'source': _source_binding(entry),
            'coordinate': _coordinate(record),
            'graded': graded,
            'legacy_runtime': _legacy_runtime(record),
            'selection_precondition': _selection_precondition(entry),
            'diagnostics': diagnostics,
            '_record': record,
            '_queue': queue,
        })
    attribution_decisions, attribution_rows = _normalise_attributions(attributions, records, queues)
    for run in runs:
        by_dimension = {dimension: decision for (run_ref, dimension), decision in attribution_decisions.items()
                        if run_ref == run['run_ref']}
        if run['graded'].get('available'):
            run['dimensions'] = _dimension_ledger(
                run['graded'], by_dimension, run['run_ref'], run['diagnostics'])
        else:
            run['dimensions'] = {
                dimension: {
                    'component': None,
                    'state': 'ungraded',
                    'cause': None,
                    'cause_status': 'unresolved',
                    'evidence_refs': [],
                    'pending_reason': run['graded'].get('reason'),
                    'distance_from_cap': None,
                }
                for dimension in DIMENSIONS
            }
    fidelity = {
        'F1': _metric_f1(runs),
        'F2': _metric_f2(runs),
        'F3': _metric_f3(runs),
        'F4': _metric_f4(runs),
        'F5': _metric_f5(runs),
        'F6': _metric_f6(runs),
        'F7': _metric_f7(runs),
        'F8': _metric_f8(runs),
        'FD1': _metric_fd1(runs),
    }
    resolution = _resolution(runs)
    selection_receipts = _selection_receipt_metadata(runs)
    fidelity['FD1']['selection_receipt_metadata'] = {
        'pointer': 'selection_receipt_metadata',
        'n_rows': selection_receipts['n_rows'],
        'n_mismatches': selection_receipts['n_mismatches'],
        'n_nonfinal_mismatches': selection_receipts['n_nonfinal_mismatches'],
        'n_final_selected_mismatches': selection_receipts['n_final_selected_mismatches'],
        'note': selection_receipts['note'],
    }
    all_diagnostics = [*catalog.diagnostics, *collection_diagnostics]
    phase_a = _phase_a(runs, excluded, all_diagnostics)
    convergence = _convergence(fidelity, runs, phase_a, excluded, all_diagnostics)
    p1 = rank_hypotheses(hypotheses) if hypotheses is not None else None
    if output is not None:
        catalog.verify_unchanged()
    for run in runs:
        run.pop('_record', None)
        run.pop('_queue', None)
    document = {
        'ledger_version': LEDGER_VERSION,
        'generated_at': _now(),
        'rubric_version': 'scoring.v4',
        'runtime_label': RUNTIME_PROVISIONAL_LABEL,
        'inputs': {
            'source_roots': {identifier: str(path) for identifier, path in source_roots.items()},
            'review_roots': {identifier: str(path) for identifier, path in review_roots.items()},
            'input_paths': input_paths,
            'excluded': excluded,
            'diagnostics': [*catalog.diagnostics, *collection_diagnostics],
        },
        'populations': {
            'accepted_runs': len(runs),
            'graded_runs': len([run for run in runs if run['graded'].get('available')]),
            'reviewed_runs': len([run for run in runs if any(
                workflow.get('status') in {'final', 'pending', 'stale'}
                for workflow in run['graded'].get('workflows', {}).values())]),
            'human_payload_reviewed_runs': len([run for run in runs
                                                if run['graded'].get('human_payload_review')]),
            'ai_experimental_runs': len([run for run in runs
                                         if run['graded'].get('experimental_ai_workflow')]),
            'runtime_scored_runs': len([run for run in runs
                                        if _is_number(run['legacy_runtime'].get('composite_score'))]),
        },
        'phase_a': phase_a,
        'attribution_decisions': attribution_rows,
        'selection_receipt_metadata': selection_receipts,
        'runs': runs,
        'fidelity': fidelity,
        'resolution': resolution,
        'convergence': convergence,
        'p1': p1,
    }
    if output is not None:
        _atomic_write(document, output, {Path(path) for path in input_paths})
    return document
