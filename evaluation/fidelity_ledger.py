"""Offline fidelity ledger for the Chapter 3 research loop (P-1 / P0 / P1).

The ledger restates saved artifacts under the pinned ``thesis-scoring`` graded path
(P-1), attributes every graded deduction and null to a closed-list cause with
evidence pointers (P0), and orders explicit hypotheses with the handoff section
5.3 lexicographic rule (P1).  It is read-only over artifacts: no provider,
DVWA, graph, payload or review execution occurs here.  The only file it writes
is the requested ledger document.

The runtime ``composite_score`` vector is retained solely inside a clearly
labelled ``legacy_runtime`` block.  It never substitutes for a graded component
and no graded component is invented, backfilled or inferred.

The frozen selection's scoring authority supplies the graded assessment.  An
``ai`` selection is scored by its validated final AI receipt; ``human`` and
``both`` retain human authority, with the AI workflow reported separately and
never pooled into the selected vector.  Consequently, ``Spayload`` is numeric
only when a validated workflow for the selected authority supplies it, and
``Srun_final`` is present only from that authority's validated final receipt.
With no receipt the graded vector contains the automatic dimensions and an
explicitly pending ``Spayload``; phase A remains incomplete until selected-mode
payload reviews exist and every non-Smethod deduction/null has a closed-list
cause.  ``converged`` is never true from this offline ledger alone:
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
  <dimension>, "cause": <CLOSED_CAUSES member>, "evidence_refs": [...],
  "proof_links": [...], "candidate_ids": [...], "primary": <bool>}``.
  Evidence must resolve and bind the dimension (artifact ``#/...`` or
  ``queue:#/...``).  ``proof_links`` default to ``evidence_refs`` and must
  substantiate the stated cause; a component value alone is never admitted.
  Rows are collapsed to one decision per (run, component): candidate-level
  causes become secondary cause entries, never extra F3 numerator units.
  Missing controls or missing scoring records stay unresolved.
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
from core.payload_policy import MODEL_ORIGIN_KINDS
from core.state import ALL_METHOD_AGENTS
from evaluation.observer_reviews import discover_reviews
from evaluation.thesis_scoring import WEIGHTS, review_queue
from tesis.artifact_catalog import ArtifactCatalog


LEDGER_VERSION = 'fidelity-ledger'
RUNTIME_PROVISIONAL_LABEL = 'runtime-provisional'
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
#: Admissible proof classes per closed cause.  A cause is never admitted from a
#: component value alone: the resolved proof document must carry a signal that
#: substantiates the stated cause.  Missing controls or missing scoring records
#: stay unresolved rather than becoming a cause.
CAUSE_EVIDENCE_CONTRACT = {
    'model_output_quality': (
        'an evaluated-model call/decision record with a specific output deficiency '
        '(invalid, unparseable, unresolved decision references, failed structural repair '
        'or an unusable fallback), a recorded model selection below the ranked/eligible '
        'comparison, or a generated candidate rejected before execution; provenance, a '
        'generic status or a signal-absent executed candidate is not enough'
    ),
    'harness_ordering': (
        'an explicit routing/ordering record or reason showing that method/route order '
        'affected the outcome'
    ),
    'harness_budget': (
        'an explicit budget exhaustion/exclusion record or reason; a configured budget '
        'alone is not evidence that the budget caused the deduction'
    ),
    'harness_scoring': (
        'a recorded scoring/verifier/queue decision or reason showing that the grading '
        'path could not apply the rubric to otherwise assessable evidence'
    ),
    'provider_failure': (
        'a recorded provider/transport failure class or error on a required call'
    ),
    'fixture_infeasible': (
        'a complete measured-negative verdict, explicit false/denied precondition '
        'observation, or bound control denial'
    ),
    'rubric_ceiling': (
        'a recorded proof ceiling or grading cap below the component cap'
    ),
    'label': (
        'a recorded label/reason disagreement that identifies the mislabelled field'
    ),
}
MODEL_EVIDENCE_ROLES = frozenset({'orchestrator', 'payload_generator', *ALL_METHOD_AGENTS})
EXPERIMENT_OUTPUT_ROLES = frozenset({'orchestrator', 'payload_generator'})
COMPONENT_ONLY_PREFIXES = ('queue:#/components/',)
FIXTURE_EVIDENCE_PREFIXES = (
    '#/measured_negative', '#/method_verdicts', '#/control_events', '#/probe_controls',
)
PROVIDER_FAILURE_TERMS = (
    'provider', 'transport', 'timeout', 'timed_out', 'rate_limit', 'quota',
    'connection', 'gateway', 'auth',
)
ORDERING_TERMS = ('order', 'route', 'routing', 'sequence', 'precedence', 'before', 'after')
BUDGET_TERMS = ('budget', 'limit', 'exhaust', 'quota', 'cap', 'maximum request')
SCORING_EVIDENCE_PREFIXES = (
    '#/final_state/scoring_decisions', '#/final_state/verifier_history',
    '#/final_state/verifier_decision', '#/final_state/method_verdicts',
    '#/final_state/response_evidence', 'queue:#/components', 'queue:#/candidates',
    'queue:#/component_pending_reasons', 'queue:#/candidates/',
)

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
    """The frozen selected scoring authority supplies the graded vector.

    ``ai`` selection is scored by the validated AI receipt; ``human`` and
    ``both`` retain the established human authority, with the AI workflow
    reported separately.  The ledger never pools components across modes.
    """
    if selection == 'ai':
        return 'ai'
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
    parallel_ai = workflows.get('ai') if selection == 'both' else None
    status = workflow.get('status')
    srun = workflow.get('Srun_final')
    if status == 'final' and _is_number(srun):
        srun_source = 'validated_final_selected_receipt'
        srun_reason = None
    else:
        srun = None
        srun_source = None
        srun_reason = ('pending_selected_workflow:' + str(workflow.get('reason'))
                       if status == 'pending' and workflow.get('reason')
                       else 'no_selected_review_receipt' if authoritative_mode
                       else 'selected_review_not_configured')
    spayload_final = workflow.get('Spayload_final')
    if not _is_number(spayload_final):
        spayload_final = None
    diagnostics = []
    if status == 'final' and not _is_number(workflow.get('Srun_final')):
        diagnostics.append({'code': 'final_workflow_missing_Srun_final'})
    if components['Spayload'] is not None and 'Spayload' in workflow_reasons:
        diagnostics.append({'code': 'numeric_payload_with_pending_reason',
                            'reason': workflow_reasons['Spayload']})
    if parallel_ai is not None and isinstance(parallel_ai.get('components'), dict):
        diagnostics.append({'code': 'parallel_ai_workflow_reported_separately'})
    return {
        'available': True,
        'rubric_version': queue.get('rubric_version'),
        'components': components,
        'component_pending_reasons': reasons,
        'authoritative_mode': authoritative_mode,
        'selected_payload_review': components['Spayload'] is not None and authoritative_mode is not None,
        'selected_final_receipt': status == 'final' and srun_source == 'validated_final_selected_receipt',
        'workflows': workflows,
        'parallel_ai_workflow': parallel_ai,
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
            'primary_cause': attribution.get('primary_cause') if attribution else None,
            'secondary_causes': (attribution.get('secondary_causes') or []) if attribution else [],
            'cause_status': cause_status,
            'evidence_refs': evidence_refs,
            'proof_links': (attribution.get('proof_links') or []) if attribution else [],
            'candidate_ids': (attribution.get('candidate_ids') or []) if attribution else [],
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


_EVIDENCE_FAMILIES = {
    'Smethod': (
        '#/config/scoring_profile',
        '#/final_state/scoring_decisions',
        '#/final_state/precondition_status',
        '#/measured_negative',
        '#/method_verdicts',
        '#/control_events',
        '#/final_state/model_call_requirements',
        '#/security_outcome_reason',
    ),
    'Spayload': (
        '#/control_events',
        '#/final_state/payload_candidates',
        '#/final_state/payload_validation_results',
        '#/final_state/payload_provenance',
        '#/final_state/response_evidence',
        '#/final_state/scoring_decisions',
        '#/measured_negative',
        '#/method_verdicts',
        '#/security_outcome_reason',
    ),
    'Sexploit': (
        '#/final_state/response_evidence',
        '#/final_state/verifier_history',
        '#/final_state/scoring_decisions',
        '#/final_state/chain_assessment',
        '#/final_state/chain_history',
        '#/measured_negative',
        '#/method_verdicts',
        '#/control_events',
        '#/final_state/model_call_requirements',
        '#/security_outcome_reason',
    ),
    'Schain': (
        '#/final_state/chain_assessment',
        '#/final_state/chain_history',
        '#/final_state/weak_chain_opportunities',
        '#/final_state/scoring_decisions',
        '#/measured_negative',
        '#/method_verdicts',
        '#/control_events',
        '#/security_outcome_reason',
    ),
    'Soutput': (
        '#/llm_performance',
        '#/llm_activity',
        '#/final_state/model_call_requirements',
        '#/final_state/scoring_decisions',
        '#/final_state/fallback_events',
        '#/final_state/invalid_json_events',
        '#/final_state/output_failure_events',
        '#/final_state/guardrail_activations',
        '#/final_state/containment_events',
        '#/measured_negative',
        '#/method_verdicts',
        '#/security_outcome_reason',
    ),
}


def _expand_evidence_refs(refs, record, pointer):
    value = _resolve_pointer(record, pointer)
    if value is POINTER_MISSING:
        return
    refs.add(pointer)
    if isinstance(value, list):
        for index, item in enumerate(value):
            refs.add(f'{pointer}/{index}')
            if isinstance(item, dict):
                for key in ('profile_id', 'profile_sha256', 'reason', 'status', 'verdict',
                            'decision', 'role', 'method', 'visit_id', 'call_id', 'event',
                            'failure_class', 'error_type', 'input', 'output', 'diagnostic'):
                    if key in item:
                        refs.add(f'{pointer}/{index}/{key}')
    elif isinstance(value, dict):
        for key in value:
            refs.add(f'{pointer}/{key}')


def _valid_evidence_refs(queue, dimension, record=None):
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
    if record is not None:
        for pointer in _EVIDENCE_FAMILIES.get(dimension, ()):
            _expand_evidence_refs(refs, record, pointer)
        if dimension == 'Smethod':
            # A rejected or accepted orchestrator selection is the primary
            # selection evidence; only orchestrator calls bind Smethod.
            for index, call in enumerate(record.get('llm_performance') or []):
                if not isinstance(call, dict) or call.get('role') != 'orchestrator':
                    continue
                refs.add(f'#/llm_performance/{index}')
                for key in ('input', 'output', 'attempt_records', 'call_id', 'method',
                            'visit_id', 'parse_status', 'validation_status', 'failure_class',
                            'error_type'):
                    if key in call:
                        refs.add(f'#/llm_performance/{index}/{key}')
    return refs


def _resolve_attribution_ref(ref, record, queue):
    if ref.startswith('queue:#/'):
        return _resolve_pointer(queue, ref[len('queue:'):])
    return _resolve_pointer(record, ref)


def _walk_evidence(value, depth=5):
    """Yield one resolved evidence subtree without inventing missing nodes."""
    yield value
    if depth <= 0:
        return
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _walk_evidence(item, depth - 1)
    elif isinstance(value, list):
        for item in value[:64]:
            yield from _walk_evidence(item, depth - 1)


def _evidence_text(value, depth=5):
    parts = []
    for node in _walk_evidence(value, depth):
        if isinstance(node, str):
            parts.append(node.lower())
        elif isinstance(node, Mapping):
            for key in ('reason', 'detail', 'status', 'decision', 'verdict', 'failure_class',
                        'error_type', 'cause', 'label', 'code', 'pending_reason'):
                if isinstance(node.get(key), str):
                    parts.append(node[key].lower())
    return ' '.join(parts)


def _truthy(node, keys):
    return isinstance(node, Mapping) and any(node.get(key) is True for key in keys)


def _queue_method(queue):
    method = (queue or {}).get('method') if isinstance(queue, Mapping) else None
    return method if isinstance(method, str) and method else None


def _queue_candidate_ids(queue):
    if not isinstance(queue, Mapping):
        return set()
    return {
        str(row.get('candidate_id'))
        for row in queue.get('candidates') or []
        if isinstance(row, Mapping) and row.get('candidate_id')
    }


def _node_methods(node):
    """Method identities recorded on one evidence node or its provenance."""
    values = set()
    if not isinstance(node, Mapping):
        return values
    for key in ('method', 'agent_id', 'selected_method', 'target_method'):
        value = node.get(key)
        if isinstance(value, str) and value:
            values.add(value)
    provenance = node.get('provenance')
    if isinstance(provenance, Mapping):
        value = provenance.get('method')
        if isinstance(value, str) and value:
            values.add(value)
    return values


def _node_visits(node):
    values = set()
    if not isinstance(node, Mapping):
        return values
    for key in ('visit_id', 'selected_visit', 'source_visit_id'):
        value = node.get(key)
        if isinstance(value, str) and value:
            values.add(value)
    return values


def _node_candidate_id(node):
    if not isinstance(node, Mapping):
        return None
    value = node.get('candidate_id')
    return value if isinstance(value, str) and value else None


def _node_binds_selected_scope(node, queue):
    """Whether one evidence node belongs to the deducted component's method.

    Run-scope records (a payload-generator call without ``method``) are not
    accepted for a method-scoped deduction unless a candidate/visit identity
    links them to the selected method.
    """
    method = _queue_method(queue)
    if method is None:
        return True
    if str(node.get('scope') or '') in {'run', 'global'}:
        return True
    if method in _node_methods(node):
        return True
    if any(visit.startswith(f'{method}:') for visit in _node_visits(node)):
        return True
    candidate_id = _node_candidate_id(node)
    return bool(candidate_id and candidate_id in _queue_candidate_ids(queue))


def _node_dimension(node):
    if not isinstance(node, Mapping):
        return None
    for key in ('dimension', 'component', 'metric', 'outcome'):
        value = node.get(key)
        if isinstance(value, str) and value:
            return 'Srun' if value == 'Srun_final' else value
    return None


def _deducted_components(queue):
    components = (queue or {}).get('components') if isinstance(queue, Mapping) else None
    if not isinstance(components, Mapping):
        return set()
    return {
        name for name, value in components.items()
        if name in DIMENSIONS and not _is_number(value)
        or (name in DIMENSIONS and _is_number(value) and float(value) < 4)
    }


MODEL_SELECTION_SOURCES = frozenset({
    'model_orchestrator', 'model', 'llm', 'planner',
})
MODEL_SELECTION_REASONS = frozenset({
    'higher_ranked_comparison_exists',
    'selected_method_unranked_reference_pending',
    'prerequisites_not_proved_at_selection',
    'outside_selected_surface',
})
NEGATIVE_VERDICTS = frozenset({
    'not_vulnerable', 'not_confirmed', 'denied', 'rejected', 'not_applicable',
    'false', 'infeasible', 'measured_false',
})
POSITIVE_VERDICTS = frozenset({
    'vulnerable', 'confirmed', 'succeeded', 'success', 'allowed', 'granted',
    'exploitable', 'bypass_succeeded',
})
NEGATIVE_VERDICT_REASONS = frozenset({
    'every_required_precondition_measured_false', 'every_precondition_false',
    'not_vulnerable', 'denied', 'measured_false', 'not_applicable', 'infeasible',
})
STATIC_EDGE_CODES = frozenset({'chain_edge_declared_unsupported'})
SOURCE_BLOCKER_CODES = frozenset({'nonadmin_source_principal_unavailable'})
PROVIDER_FAILURE_CLASSES = frozenset({
    'provider_error', 'provider_failure', 'transport_error', 'transport_failure',
    'timeout', 'timed_out', 'rate_limit', 'rate_limited', 'quota_exhausted',
    'connection_error', 'connection_reset', 'gateway_error', 'auth_error',
    'operational_failure', 'http_error',
})
SCORING_DEFECT_CODES = frozenset({
    'ranking_unavailable', 'profile_missing', 'missing_scoring_profile',
    'grading_path_unavailable', 'required_role_receipt_missing',
    'review_receipt_missing', 'scoring_input_missing', 'missing_selection_snapshot',
    'no_selected_method', 'binding_gap', 'receipt_unavailable',
})
SUCCESS_PHRASES = (
    'positive_control_succeeded', 'control_succeeded', 'positive control succeeded',
    'bypass_succeeded', 'successfully exploited',
)


def _success_signal(node):
    """Whether a resolved node records a successful control/exploit outcome."""
    if not isinstance(node, Mapping):
        return False
    if node.get('positive_control') is True or node.get('control_succeeded') is True:
        return True
    if node.get('success') is True or node.get('establishes_exploit') is True:
        return True
    if node.get('signal_detected') is True:
        return True
    verdict = str(node.get('verdict') or node.get('decision') or '').lower()
    if verdict in POSITIVE_VERDICTS:
        return True
    status = str(node.get('status') or '').lower()
    if status in {'succeeded', 'success', 'confirmed', 'vulnerable'}:
        return True
    raw = ' '.join(str(node.get(key) or '') for key in (
        'reason', 'detail', 'event', 'note',
    )).lower()
    return any(phrase in raw for phrase in SUCCESS_PHRASES)


def _node_success_signal(value):
    return any(_success_signal(node) for node in _walk_evidence(value))


def _negative_verdict_row(row):
    """A verdict row proves a measured negative only when it says so explicitly."""
    if isinstance(row, str):
        return row.lower() in NEGATIVE_VERDICTS
    if not isinstance(row, Mapping):
        return False
    if str(row.get('verdict') or '').lower() not in NEGATIVE_VERDICTS:
        return False
    if row.get('signal_detected') is not False:
        return False
    if _node_success_signal(row):
        return False
    observed = row.get('observed')
    if isinstance(observed, Mapping) and any(
        value not in (False, 'false', 'denied', 'not_applicable', 'infeasible')
        for value in observed.values()
    ):
        return False
    reason = str(row.get('reason') or '').lower()
    if reason and reason not in NEGATIVE_VERDICT_REASONS and any(
        term in reason for term in ('success', 'confirmed', 'positive_control')
    ):
        return False
    return True


def _measured_negative_proof(resolved, record):
    """Validate a complete measured negative against every recorded verdict."""
    nodes = [value for _ref, value in resolved]
    measured = [
        node for node in _walk_evidence(nodes)
        if isinstance(node, Mapping) and node.get('complete') is True
        and (
            'measured_negative' in str(node.get('basis') or '')
            or 'methods_required' in node
            or 'methods_with_verdict' in node
            or 'methods_missing_verdict' in node
            or 'verdicts' in node
            or str(node.get('reason') or '') in NEGATIVE_VERDICT_REASONS
        )
    ]
    for node in measured:
        if _node_success_signal(node):
            continue
        reason = str(node.get('reason') or '').lower()
        if any(phrase in reason for phrase in SUCCESS_PHRASES):
            continue
        if reason in {'not_measured_negative', 'attempted', 'signal_detected'}:
            continue
        verdicts = {}
        for source in (record.get('method_verdicts'), node.get('verdicts')):
            if isinstance(source, Mapping):
                verdicts.update(source)
        required = [str(method) for method in node.get('methods_required') or []]
        if required and any(method not in verdicts for method in required):
            continue
        if node.get('methods_missing_verdict'):
            continue
        if not verdicts:
            continue
        if not all(_negative_verdict_row(row) for row in verdicts.values()):
            continue
        controls = [event for event in record.get('control_events') or []
                    if isinstance(event, Mapping)]
        if any(_success_signal(event) for event in controls):
            continue
        return True
    return False


def _edge_closed(edge):
    """A static AKG rejection or a proved source-material blocker."""
    if not isinstance(edge, Mapping) or _success_signal(edge):
        return False
    source_rejection = edge.get('source_rejection')
    source_code = (source_rejection.get('code')
                   if isinstance(source_rejection, Mapping) else None)
    if edge.get('edge_supported') is False:
        code = str(edge.get('reason') or source_code or '')
        detail = edge.get('unsupported_reason') or (
            source_rejection.get('detail') if isinstance(source_rejection, Mapping) else None
        ) or code
        return code in STATIC_EDGE_CODES and bool(str(detail).strip())
    if edge.get('edge_supported') is True and source_code in SOURCE_BLOCKER_CODES:
        detail = source_rejection.get('detail') if isinstance(source_rejection, Mapping) else None
        return bool(str(detail or '').strip())
    return False


def _edge_closure_proof(resolved, record, queue):
    """Every assessed edge must be closed by static AKG or source-material proof."""
    assessments = [
        node for _ref, value in resolved for node in _walk_evidence(value)
        if isinstance(node, Mapping) and node.get('assessed') is True
        and isinstance(node.get('edges'), list) and node.get('edges')
    ]
    if not assessments:
        return False
    for assessment in assessments:
        edges = assessment['edges']
        if not edges or any(not _edge_closed(edge) for edge in edges):
            return False
        if any(
            isinstance(edge, Mapping) and str(edge.get('status') or '') in {
                'confirmed', 'completed', 'available',
            }
            for edge in edges
        ):
            return False
    method = (queue or {}).get('method')
    if isinstance(method, str) and method:
        try:
            from evaluation.scoring_evidence import verified_dependencies
            dependencies = verified_dependencies(record)
        except (ValueError, KeyError, TypeError, AttributeError, IndexError):
            dependencies = []
        for dependency in dependencies:
            for side in ('source', 'destination'):
                if (dependency.get(side) or {}).get('agent_id') == method:
                    return False
    return True


def _nonempty(value):
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Mapping):
        return bool(value)
    return value is not None


def _bound_denial_proof(resolved, queue):
    """A bound denial with principal, object/action, policy and matched control.

    A bare ``denied`` decision naming a method is not proof that the fixture
    neutralised a component: the denial must identify who was denied access to
    what, under which independent policy, with a matched positive reference and
    a recorded response.  Missing controls remain an evidence gap.
    """
    method = _queue_method(queue)
    for _ref, value in resolved:
        for node in _walk_evidence(value):
            if not isinstance(node, Mapping) or _success_signal(node):
                continue
            decision = str(node.get('decision') or node.get('status') or '').lower()
            if decision not in {'denied', 'blocked', 'not_allowed', 'forbidden'}:
                continue
            node_methods = _node_methods(node)
            if method and (not node_methods or method not in node_methods):
                continue
            principal = next((node.get(key) for key in (
                'principal', 'user', 'username', 'identity', 'role', 'actor',
                'session_principal',
            ) if _nonempty(node.get(key))), None)
            target = next((node.get(key) for key in (
                'object', 'object_id', 'action', 'endpoint', 'path', 'resource',
                'operation', 'url',
            ) if _nonempty(node.get(key))), None)
            policy = next((node.get(key) for key in (
                'policy', 'authorization_policy', 'permission_policy',
                'independent_policy', 'denied_by_policy',
            ) if _nonempty(node.get(key))), None)
            matched = next((node.get(key) for key in (
                'positive_control', 'positive_reference', 'matched_controls',
                'allowed_control', 'reference_allowed',
            ) if _nonempty(node.get(key))), None)
            response = next((node.get(key) for key in (
                'status_code', 'http_status', 'observed_status', 'response_sha256',
                'response',
            ) if _nonempty(node.get(key))), None)
            if not all((principal, target, policy, matched, response)):
                continue
            if node.get('expected_allowed') is True:
                continue
            return True
    return False


def _component_contradiction(record, queue, dimension):
    """A fixture-neutralized scenario cannot also carry a numeric result."""
    if not dimension or not isinstance(queue, Mapping):
        return False
    components = queue.get('components')
    component = components.get(dimension) if isinstance(components, Mapping) else None
    if _is_number(component) and component > 0:
        return True
    candidates = [row for row in queue.get('candidates') or [] if isinstance(row, Mapping)]
    if dimension == 'Spayload' and any(row.get('eligible') is True for row in candidates):
        return True
    if dimension == 'Sexploit' and any(
        row.get('eligible') is True and row.get('executed') is True for row in candidates
    ):
        return True
    if dimension == 'Smethod' and isinstance(queue.get('method'), str) and queue['method']:
        return True
    if dimension == 'Soutput' and any(
        isinstance(call, Mapping) and call.get('role') in MODEL_EVIDENCE_ROLES
        and call.get('parse_status') == 'ok' and call.get('validation_status') == 'valid'
        for call in record.get('llm_performance') or []
    ):
        return True
    return False


def _fixture_infeasible_signal(resolved, record, queue, dimension):
    if _measured_negative_proof(resolved, record):
        # A complete measured negative explains an absent/null outcome, never a
        # numeric component in the same run.
        return not _component_contradiction(record, queue, dimension)
    if _edge_closure_proof(resolved, record, queue):
        return dimension in (None, 'Sexploit', 'Schain')
    if _bound_denial_proof(resolved, queue):
        return not _component_contradiction(record, queue, dimension)
    return False


def _attempt_failed(attempt):
    if not isinstance(attempt, Mapping):
        return False
    if attempt.get('valid') is False or attempt.get('parse_status') in {
        'invalid', 'incomplete', 'error', 'failed', 'provider_error',
    }:
        return True
    if attempt.get('validation_status') not in (None, 'valid', 'ok'):
        return True
    return bool(attempt.get('failure_class') or attempt.get('error_type')
                or attempt.get('error') or attempt.get('error_message'))


def _model_call_output_defect(call):
    """A specific evaluated-model output deficiency, never mere provenance."""
    if not isinstance(call, Mapping) or call.get('role') not in MODEL_EVIDENCE_ROLES:
        return False
    failure_class = str(call.get('failure_class') or '').lower()
    if failure_class in PROVIDER_FAILURE_CLASSES:
        return False
    parse_status = str(call.get('parse_status') or '').lower()
    validation_status = str(call.get('validation_status') or '').lower()
    if parse_status and parse_status not in {'ok', 'valid', 'parsed'}:
        return True
    if validation_status and validation_status not in {'valid', 'ok'}:
        return True
    inputs, output = call.get('input'), call.get('output')
    if not isinstance(inputs, Mapping) or not isinstance(output, Mapping):
        return False
    from evaluation.scoring_evidence import evidence_hash, output_references_valid
    if call.get('input_sha256') != evidence_hash(inputs):
        return False
    if call.get('output_sha256') != evidence_hash(output):
        return False
    if not output_references_valid(call):
        return True
    attempts = call.get('attempt_records')
    if isinstance(attempts, list) and len(attempts) > 1:
        return any(_attempt_failed(attempt) for attempt in attempts[:-1])
    return False


def _selection_evidence_signal(resolved, queue, dimension):
    """Prove that the model's recorded selection was itself below the rubric."""
    if dimension not in (None, 'Smethod'):
        return False
    method = (queue or {}).get('method')
    for _ref, value in resolved:
        for node in _walk_evidence(value):
            if not isinstance(node, Mapping) or node.get('status') != 'assessed':
                continue
            if str(node.get('selection_source') or '') not in MODEL_SELECTION_SOURCES:
                continue
            reason = str(node.get('reason') or '')
            top = [str(name) for name in node.get('top_methods') or [] if str(name)]
            comparison = node.get('comparison')
            comparison = comparison if isinstance(comparison, Mapping) else {}
            if reason == 'higher_ranked_comparison_exists' and method and method not in top:
                selected = comparison.get(method)
                selected_fit = selected.get('fit_level') if isinstance(selected, Mapping) else None
                top_fits = [
                    comparison[name].get('fit_level') for name in top
                    if isinstance(comparison.get(name), Mapping)
                    and comparison[name].get('eligible') is True
                    and isinstance(comparison[name].get('fit_level'), int)
                ]
                if isinstance(selected_fit, int) and top_fits and max(top_fits) > selected_fit:
                    return True
            if reason == 'selected_method_unranked_reference_pending' and method not in top:
                selected = comparison.get(method)
                if isinstance(selected, Mapping) and selected.get('unranked') is True:
                    return True
            if reason in {'prerequisites_not_proved_at_selection',
                          'outside_selected_surface'} and method:
                return True
            if method and method in top and (
                node.get('reason_refs_valid') is False or node.get('plan_valid') is False
            ):
                return True
    return False


def _generated_candidate_defect(resolved, queue=None, *, bind_scope=False):
    """A generated candidate rejected before execution, never a signal absence."""
    for _ref, value in resolved:
        for node in _walk_evidence(value):
            if not isinstance(node, Mapping):
                continue
            origin = node.get('origin_kind')
            provenance = node.get('provenance')
            if origin is None and isinstance(provenance, Mapping):
                origin = provenance.get('origin_kind')
            if origin not in MODEL_ORIGIN_KINDS:
                continue
            if bind_scope and not _node_binds_selected_scope(node, queue):
                continue
            status = str(
                node.get('status') or node.get('validation_status')
                or node.get('execution_status') or ''
            ).lower()
            if status in {'invalid', 'rejected', 'validation_failed', 'schema_invalid',
                          'unparseable', 'truncated'}:
                return True
    return False


def _fallback_output_defect(resolved, queue, dimension=None):
    method = _queue_method(queue)
    for _ref, value in resolved:
        for node in _walk_evidence(value):
            if not isinstance(node, Mapping):
                continue
            event = str(node.get('event') or '').lower()
            reason = str(node.get('reason') or '').lower()
            role = node.get('role')
            node_method = node.get('method') or node.get('selected_method')
            if dimension is not None:
                if dimension == 'Soutput':
                    if role not in EXPERIMENT_OUTPUT_ROLES:
                        continue
                elif dimension == 'Smethod':
                    if role != 'orchestrator':
                        continue
                elif dimension in ('Spayload', 'Sexploit'):
                    if role not in MODEL_EVIDENCE_ROLES:
                        continue
                    if not _node_binds_selected_scope(node, queue):
                        continue
                else:
                    continue
            if role not in MODEL_EVIDENCE_ROLES and not (method and node_method == method):
                continue
            if 'fallback' not in event:
                continue
            if node.get('provider_failure') is True:
                continue
            text = f'{event} {reason}'
            if any(term in text for term in (
                'invalid', 'unusable', 'no_valid', 'schema', 'rejected', 'truncated',
                'no_usable', 'unusable_output', 'incomplete',
            )):
                return True
    return False


def _model_output_signal(resolved, record, queue, dimension):
    if dimension not in (None, *DIMENSIONS):
        return False
    paths = [
        ref[len('queue:'):] if ref.startswith('queue:') else ref
        for ref, _value in resolved
    ]
    if all(path.startswith(FIXTURE_EVIDENCE_PREFIXES) for path in paths):
        return False
    if _selection_evidence_signal(resolved, queue, dimension):
        return True
    if dimension in (None, 'Spayload', 'Sexploit'):
        if _generated_candidate_defect(
            resolved, queue, bind_scope=dimension in ('Spayload', 'Sexploit')
        ):
            return True
    if dimension in (None, 'Smethod', 'Spayload', 'Sexploit', 'Soutput'):
        if _fallback_output_defect(resolved, queue, dimension):
            return True
    if dimension == 'Schain':
        # Chain deductions are about route/edge evidence, not payload/model
        # generation quality.
        return False
    allowed_roles_by_dimension = {
        None: MODEL_EVIDENCE_ROLES,
        'Smethod': frozenset({'orchestrator'}),
        'Spayload': MODEL_EVIDENCE_ROLES,
        'Sexploit': frozenset(),
        'Soutput': EXPERIMENT_OUTPUT_ROLES,
    }
    allowed_roles = allowed_roles_by_dimension.get(dimension, frozenset())
    for ref, value in resolved:
        path = ref[len('queue:'):] if ref.startswith('queue:') else ref
        if not path.startswith((
            '#/llm_performance', '#/llm_activity', '#/final_state/model_call_requirements',
            '#/final_state/scoring_decisions', '#/final_state/fallback_events',
            '#/final_state/payload_candidates', '#/final_state/payload_provenance',
            '#/final_state/candidate_lifecycle', '#/candidates',
        )):
            continue
        for node in _walk_evidence(value):
            if not _model_call_output_defect(node):
                continue
            if isinstance(node, Mapping) and node.get('role') not in allowed_roles:
                continue
            if dimension in ('Spayload', 'Sexploit') and not _node_binds_selected_scope(
                node, queue
            ):
                continue
            return True
    return False


def _provider_failure_signal(resolved, queue=None, dimension=None):
    for _ref, value in resolved:
        for node in _walk_evidence(value):
            if not isinstance(node, Mapping):
                continue
            failure = (
                node.get('provider_error') is True
                or node.get('transport_error') is True
                or any(
                    str(node.get(key) or '').lower() in PROVIDER_FAILURE_CLASSES
                    for key in ('failure_class', 'error_type', 'parse_status')
                )
            )
            if not failure:
                error = str(node.get('error') or node.get('error_message') or '').lower()
                failure = bool(error) and any(term in error for term in (
                    'timeout', 'timed out', 'rate limit', 'quota', 'connection reset',
                    'gateway',
                ))
            if not failure:
                continue
            if dimension in ('Smethod', 'Soutput'):
                if node.get('role') not in EXPERIMENT_OUTPUT_ROLES and not _node_binds_selected_scope(
                    node, queue
                ):
                    continue
            elif dimension in ('Spayload', 'Sexploit', 'Schain'):
                if not _node_binds_selected_scope(node, queue):
                    continue
            return True
    return False


def _harness_budget_signal(resolved, queue=None, dimension=None):
    for _ref, value in resolved:
        for node in _walk_evidence(value):
            if not isinstance(node, Mapping):
                continue
            explicit = _truthy(node, ('candidate_budget_exceeded', 'budget_exhausted',
                                      'budget_limited', 'limit_reached', 'quota_exhausted'))
            raw = ' '.join(str(node.get(key) or '') for key in (
                'reason', 'detail', 'status', 'code', 'pending_reason'))
            if not explicit and not (
                any(term in raw.lower() for term in BUDGET_TERMS) and any(
                    key in node for key in ('candidate_id', 'candidate_ids', 'budget', 'executed')
                )
            ):
                continue
            if dimension is not None and not _node_binds_selected_scope(node, queue):
                continue
            return True
    return False


ORDERING_DEFECT_TERMS = (
    'out_of_order', 'out-of-order', 'wrong order', 'ordering failure',
    'ordering_failure', 'ordering error', 'ordering_error', 'ordering defect',
    'ordering_defect', 'sequence failure', 'sequence_failure', 'precedence',
    'rejected the destination', 'order rejected', 'order_rejected',
)
ORDERING_SUCCESS_STATUSES = frozenset({
    'completed', 'success', 'succeeded', 'confirmed', 'ok', 'passed', 'available',
})


def _harness_ordering_signal(resolved, queue=None, dimension=None):
    """Only an explicit ordering defect can substantiate an ordering cause."""
    if dimension not in (None, 'Schain'):
        return False
    for _ref, value in resolved:
        for node in _walk_evidence(value):
            if not isinstance(node, Mapping):
                continue
            if node.get('ordering_defect') is True or node.get('ordering_failure') is True:
                return True
            raw = ' '.join(str(node.get(key) or '') for key in (
                'reason', 'detail', 'status', 'code', 'decision', 'event'))
            lowered = raw.lower()
            if not any(term in lowered for term in ORDERING_TERMS):
                continue
            if _success_signal(node) or str(
                node.get('status') or node.get('decision') or ''
            ).lower() in ORDERING_SUCCESS_STATUSES:
                # A completed/working route is never evidence that ordering
                # caused a deduction.
                continue
            if any(term in lowered for term in ORDERING_DEFECT_TERMS + (
                'reject', 'fail', 'error', 'blocked', 'deferred', 'mismatch',
                'unexpected',
            )):
                return True
    return False


def _harness_scoring_signal(resolved, queue, dimension):
    component = None
    if isinstance(queue, Mapping) and dimension:
        components = queue.get('components')
        component = components.get(dimension) if isinstance(components, Mapping) else None
    if not _is_number(component):
        for ref, value in resolved:
            if not ref.startswith('queue:#/component_pending_reasons/'):
                continue
            if not isinstance(value, str) or not value.strip():
                continue
            lowered = value.lower()
            if any(term in lowered for term in (
                'candidate', 'fixture', 'precondition', 'no_eligible', 'measured_negative',
            )):
                continue
            if any(term in lowered for term in (
                'ranking_unavailable', 'profile_missing', 'scoring_input', 'grading_path',
                'receipt_missing', 'review_missing', 'missing_selection',
            )):
                return True
    for _ref, value in resolved:
        for node in _walk_evidence(value):
            if not isinstance(node, Mapping):
                continue
            node_dimension = _node_dimension(node)
            if dimension is not None and node_dimension is not None \
                    and node_dimension != dimension:
                continue
            for key in ('reason', 'code', 'pending_reason', 'verification_reason'):
                raw_value = str(node.get(key) or '')
                lowered = raw_value.lower()
                if lowered in SCORING_DEFECT_CODES:
                    return True
                if any(code in lowered for code in SCORING_DEFECT_CODES) and not any(
                    term in lowered for term in (
                        'candidate', 'fixture', 'precondition', 'no_eligible',
                        'measured_negative',
                    )
                ):
                    return True
    return False


def _ceiling_scope_matches(node, queue, dimension):
    node_dimension = _node_dimension(node)
    if dimension is not None:
        if node_dimension is not None:
            return node_dimension == dimension
        candidate_id = _node_candidate_id(node)
        if candidate_id and dimension in ('Spayload', 'Sexploit'):
            return candidate_id in _queue_candidate_ids(queue)
        return False
    if node_dimension is not None:
        return node_dimension in _deducted_components(queue)
    candidate_id = _node_candidate_id(node)
    if candidate_id and candidate_id in _queue_candidate_ids(queue):
        return True
    return False


def _rubric_ceiling_signal(resolved, queue=None, dimension=None):
    for _ref, value in resolved:
        for node in _walk_evidence(value):
            if not isinstance(node, Mapping):
                continue
            ceiling = next((
                node.get(key) for key in (
                    'proof_ceiling', 'ceiling', 'cap', 'maximum_score', 'max_score',
                ) if isinstance(node.get(key), int) and not isinstance(node.get(key), bool)
            ), None)
            if ceiling is not None and ceiling < 4:
                if _ceiling_scope_matches(node, queue, dimension):
                    return True
                continue
            raw = ' '.join(str(node.get(key) or '') for key in ('reason', 'detail', 'note'))
            if any(term in raw.lower() for term in ('ceiling', 'capped', 'maximum score')):
                if _ceiling_scope_matches(node, queue, dimension):
                    return True
    return False


def _label_signal(resolved, queue=None, dimension=None):
    paths = [
        ref[len('queue:'):] if ref.startswith('queue:') else ref
        for ref, _value in resolved
    ]
    labelled_path = any(
        any(term in ref.lower() for term in ('label', 'outcome_reason', 'measured_negative'))
        for ref in paths
    )
    for _ref, value in resolved:
        for node in _walk_evidence(value):
            if not isinstance(node, Mapping):
                continue
            node_dimension = _node_dimension(node)
            if dimension is not None and node_dimension is not None \
                    and node_dimension != dimension:
                continue
            has_label = labelled_path or any(key in node for key in (
                'label', 'label_status', 'security_outcome_reason', 'measured_negative',
                'recorded', 'expected',
            ))
            raw = ' '.join(str(node.get(key) or '') for key in (
                'reason', 'detail', 'code', 'label', 'label_status'))
            if has_label and any(term in raw.lower() for term in (
                'label', 'mismatch', 'disagree', 'incorrect', 'mislabel',
            )):
                return True
    return False


def _cause_signal(cause, resolved, *, record=None, queue=None, dimension=None):
    """Return whether resolved proof links substantiate ``cause`` itself."""
    if cause == 'model_output_quality':
        return _model_output_signal(resolved, record or {}, queue or {}, dimension)
    if cause == 'provider_failure':
        return _provider_failure_signal(resolved, queue or {}, dimension)
    if cause == 'fixture_infeasible':
        return _fixture_infeasible_signal(resolved, record or {}, queue or {}, dimension)
    if cause == 'harness_budget':
        return _harness_budget_signal(resolved, queue or {}, dimension)
    if cause == 'harness_ordering':
        return _harness_ordering_signal(resolved, queue or {}, dimension)
    if cause == 'harness_scoring':
        return _harness_scoring_signal(resolved, queue or {}, dimension)
    if cause == 'rubric_ceiling':
        return _rubric_ceiling_signal(resolved, queue or {}, dimension)
    if cause == 'label':
        return _label_signal(resolved, queue or {}, dimension)
    return False


def cause_evidence_problem(cause, refs, record, queue, *, dimension=None):
    """Return why proof links do not substantiate ``cause``, or ``None``.

    This is the admission boundary for F3.  A component value, a pending reason
    with no scoring record, an absent control, candidate provenance, a generic
    status or a control that succeeded is never accepted as proof of a model,
    fixture or provider cause.  ``dimension`` binds the cause to the specific
    deducted run/component; callers that omit it still receive the strict
    cause-specific checks.
    """
    if cause not in CLOSED_CAUSES:
        return f'cause is not in the closed list: {cause!r}'
    if not isinstance(refs, list) or not refs or any(
        not isinstance(ref, str) or not ref for ref in refs
    ):
        return 'cause requires at least one proof link'
    proof_refs = [
        ref for ref in dict.fromkeys(refs)
        if not ref.startswith(COMPONENT_ONLY_PREFIXES)
    ]
    if not proof_refs:
        return 'a component value alone does not substantiate a cause'
    resolved = []
    for ref in proof_refs:
        value = _resolve_attribution_ref(ref, record, queue)
        if value is POINTER_MISSING:
            return f'proof link does not resolve: {ref}'
        resolved.append((ref, value))
    if _cause_signal(cause, resolved, record=record, queue=queue, dimension=dimension):
        return None
    return (
        f'proof links do not substantiate {cause}; expected '
        f'{CAUSE_EVIDENCE_CONTRACT[cause]}'
    )


def _attribution_rows(items, by_ref, by_execution_id, by_source_sha256, by_run_id, queues):
    """Resolve attribution rows without collapsing candidate-level evidence yet."""
    rows = []
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
        record, _entry = by_ref[run_ref]
        dimension = item.get('dimension')
        if dimension not in DIMENSIONS:
            raise ValueError(f'Attribution dimension is not graded: {dimension!r}')
        cause = item.get('cause')
        if cause not in CLOSED_CAUSES:
            raise ValueError(f'Attribution cause is not in the closed list: {cause!r}')
        refs = item.get('evidence_refs')
        if not isinstance(refs, list) or not refs or any(
            not isinstance(ref, str) or not ref for ref in refs
        ):
            raise ValueError('Attribution requires a nonempty evidence_refs list')
        refs = list(dict.fromkeys(refs))
        proof_links = item.get('proof_links', refs)
        if not isinstance(proof_links, list) or not proof_links or any(
            not isinstance(ref, str) or not ref for ref in proof_links
        ):
            raise ValueError('Attribution proof_links must be a nonempty list of references')
        proof_links = list(dict.fromkeys(proof_links))
        queue = queues.get(run_ref)
        if queue is None:
            raise ValueError(f'Attribution cannot bind an ungraded run: {run_ref}')
        component = (queue.get('components') or {}).get(dimension)
        if _is_number(component) and component == 4:
            raise ValueError(f'Attribution does not bind a deduction or null: {run_ref}/{dimension}')
        valid = _valid_evidence_refs(queue, dimension, record)
        if not set(refs) & valid:
            raise ValueError(f'Attribution evidence does not bind {dimension}: {run_ref}')
        for ref in [*refs, *proof_links]:
            if _resolve_attribution_ref(ref, record, queue) is POINTER_MISSING:
                raise ValueError(f'Attribution evidence does not resolve: {ref}')
        problem = cause_evidence_problem(
            cause, proof_links, record, queue, dimension=dimension)
        if problem:
            raise ValueError(
                f'Attribution cause evidence does not substantiate {cause} '
                f'for {run_ref}/{dimension}: {problem}'
            )
        candidate_ids = item.get('candidate_ids')
        if candidate_ids is None and item.get('candidate_id') is not None:
            candidate_ids = [item.get('candidate_id')]
        candidate_ids = [
            str(value) for value in candidate_ids or []
            if isinstance(value, (str, int)) and not isinstance(value, bool)
        ]
        known_candidates = _queue_candidate_ids(queue)
        unknown_candidates = [
            candidate_id for candidate_id in candidate_ids
            if candidate_id not in known_candidates
        ]
        if unknown_candidates:
            raise ValueError(
                'Attribution candidate_ids do not bind the graded candidate population '
                f'for {run_ref}/{dimension}: {unknown_candidates}'
            )
        rows.append({
            'run_ref': run_ref,
            'execution_id': record.get('execution_id'),
            'dimension': dimension,
            'cause': cause,
            'evidence_refs': refs,
            'proof_links': proof_links,
            'candidate_ids': list(dict.fromkeys(candidate_ids)),
            'primary': item.get('primary') is True,
            'note': item.get('note'),
        })
    return rows


def _merge_attribution_rows(rows):
    """Collapse candidate-level rows to one admitted decision per run/component."""
    grouped = defaultdict(list)
    for row in rows:
        grouped[row['run_ref'], row['dimension']].append(row)
    decisions, normalised = {}, []
    for (run_ref, dimension), group in grouped.items():
        primary_rows = [row for row in group if row['primary']]
        if len(primary_rows) > 1:
            raise ValueError(f'Multiple primary causes for {run_ref}/{dimension}')
        primary = primary_rows[0] if primary_rows else group[0]
        cause_entries = []
        by_cause = {}
        for row in group:
            if row is primary or row['cause'] == primary['cause']:
                # Same-cause rows are evidence for the admitted primary decision.
                continue
            if row['cause'] in by_cause:
                entry = by_cause[row['cause']]
                entry['evidence_refs'] = list(dict.fromkeys(
                    [*entry['evidence_refs'], *row['evidence_refs']]
                ))
                entry['proof_links'] = list(dict.fromkeys(
                    [*entry['proof_links'], *row['proof_links']]
                ))
                entry['candidate_ids'] = list(dict.fromkeys(
                    [*entry['candidate_ids'], *row['candidate_ids']]
                ))
                continue
            entry = {
                'cause': row['cause'],
                'evidence_refs': row['evidence_refs'],
                'proof_links': row['proof_links'],
                'candidate_ids': row['candidate_ids'],
                'note': row['note'],
            }
            by_cause[row['cause']] = entry
            cause_entries.append(entry)
        decision = {
            'run_ref': run_ref,
            'execution_id': primary['execution_id'],
            'dimension': dimension,
            'cause': primary['cause'],
            'primary_cause': primary['cause'],
            'secondary_causes': cause_entries,
            'evidence_refs': list(dict.fromkeys(
                ref for row in group for ref in row['evidence_refs']
            )),
            'proof_links': list(dict.fromkeys(
                ref for row in group for ref in row['proof_links']
            )),
            'candidate_ids': list(dict.fromkeys(
                candidate for row in group for candidate in row['candidate_ids']
            )),
            'n_candidate_rows': len(group),
            'note': primary['note'],
        }
        decisions[run_ref, dimension] = decision
        normalised.append(decision)
    return decisions, normalised


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
    rows = _attribution_rows(
        items, by_ref, by_execution_id, by_source_sha256, by_run_id, queues
    )
    return _merge_attribution_rows(rows)



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
    by_cause = Counter()
    secondary_causes = Counter()
    candidate_rows = 0
    components_with_candidates = 0
    proof_links = 0
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
                by_cause[row['primary_cause']] += 1
                for secondary in row.get('secondary_causes') or []:
                    secondary_causes[secondary.get('cause')] += 1
                if row.get('candidate_ids'):
                    components_with_candidates += 1
                    candidate_rows += len(row['candidate_ids'])
                proof_links += len(row.get('proof_links') or [])
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
        'source': ['review_queue.components', 'admitted_source_bound_cause_evidence'],
        'definition': (
            'run/component deductions + nulls with one admitted source-bound cause '
            '/ all run/component deductions + nulls; candidate rows are evidence, '
            'never extra numerator units'
        ),
        'unavailable_reason': reason,
        'unknown': len(unresolved),
        'by_cause': dict(sorted(by_cause.items())),
        'secondary_cause_counts': dict(sorted(secondary_causes.items())),
        'components_with_secondary_causes': sum(
            1 for run in runs if run['graded'].get('available')
            for row in run['dimensions'].values()
            if row['cause_status'] == 'attributed' and row.get('secondary_causes')
        ),
        'components_with_candidate_evidence': components_with_candidates,
        'candidate_evidence_rows': candidate_rows,
        'proof_link_count': proof_links,
        'cause_evidence_contract': dict(sorted(CAUSE_EVIDENCE_CONTRACT.items())),
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
                   'artifact.measured_negative', 'artifact.security_outcome_reason'],
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
    selected_payload = []
    null_with_reason = Counter()
    null_without_reason = defaultdict(list)
    deduction_without_cause = defaultdict(list)
    null_without_cause = defaultdict(list)
    for run in graded:
        queue = run.get('_queue') or {}
        if any(row.get('eligible') for row in queue.get('candidates') or []):
            payload_required.append(run['run_ref'])
            if run['graded'].get('selected_payload_review'):
                selected_payload.append(run['run_ref'])
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
    missing_reviews = sorted(set(payload_required) - set(selected_payload))
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
        blocking.append(f"payload_reviews_missing={len(missing_reviews)}")
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
        'payload_reviewed_runs': len(selected_payload),
        'payload_missing_review_runs': missing_reviews,
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
        'note': 'phase A closes only when a payload review exists for the frozen selected '
                'scoring authority where candidates exist and every deduction or null '
                'non-Smethod component carries a closed-list cause; a missing selected-mode '
                'receipt is an evidence gap, never a synthesized score',
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
        'definition_version': 'hypothesis-ranking',
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
        'rubric_version': 'thesis-scoring',
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
            'payload_reviewed_runs': len([run for run in runs
                                          if run['graded'].get('selected_payload_review')]),
            'parallel_ai_workflow_runs': len([run for run in runs
                                              if run['graded'].get('parallel_ai_workflow')]),
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
