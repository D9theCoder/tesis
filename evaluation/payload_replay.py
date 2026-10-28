"""Revalidate and execute a saved method input without making provider calls.

API only: no new experiment runner or CLI flag. Replay evidence stays diagnostic.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import inspect
from typing import Annotated, NotRequired, get_args, get_origin, get_type_hints

from core.graph_builder import RUNTIME_AGENT_HANDLERS
from core.payload_policy import (
    LEGACY_CONTROL_POLICY_VERSION,
    PAYLOAD_POLICY_BASIS_HISTORICAL,
    PAYLOAD_POLICY_BASIS_STATE_KEY,
    RECORDED_POLICY_STATE_KEY,
    control_snapshot_policy_version,
)
from core.scorer import scorer
from core.state import ExploitationState, _merge_validation_maps, new_default_state
from evaluation.manual_scoring_sheet import manual_scoring_rows
from evaluation.reporter import link_exported_request_evidence, write_json_report
from evaluation.scoring_evidence import evidence_hash
from foundation.payload_library import PayloadLibrary
from foundation.payload_validator import validate_payload_candidates, validate_probe_controls
from llm.runtime import LLMRuntime
from core.graph_builder import _serialized_http_handler
from tesis.runtime_events import redact_secrets


def _template_registry_mapping(value):
    """Normalize a recorded template registry snapshot to the validator shape."""
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        rows = {}
        for row in value:
            if not isinstance(row, dict):
                continue
            method = str(row.get('method') or '')
            level = str(row.get('security_level') or '')
            if method and level:
                rows[f"template.{method}.{level}"] = dict(row)
        return rows
    return None


def _recorded_payload_policy(original, state):
    """Read the artifact's recorded payload identity; never infer history live.

    New artifacts persist ``recorded_payload_policy`` (policy version plus the
    frozen neutral-template registry). Legacy artifacts have no snapshot; the
    replay contract is then explicitly the pre-versioned one, with an empty
    recorded policy so no current registry/version check is smuggled in.
    """
    recorded = None
    for container in (original, state):
        for key in (RECORDED_POLICY_STATE_KEY, 'payload_policy_snapshot'):
            value = container.get(key)
            if isinstance(value, dict) and value:
                recorded = dict(value)
                break
        if recorded:
            break
    recorded = recorded or {}
    try:
        from foundation.payload_snapshot import verify_payload_policy_snapshot
    except ImportError:
        verify_payload_policy_snapshot = None
    if verify_payload_policy_snapshot is not None and recorded.get('snapshot_version'):
        issues = verify_payload_policy_snapshot(recorded)
        if issues:
            recorded['snapshot_integrity'] = 'invalid'
            recorded['snapshot_issues'] = [str(row.get('reason')) for row in issues]
            recorded.pop('template_registry', None)
    version = (
        recorded.get('policy_version')
        or state.get('payload_policy_version')
        or original.get('payload_policy_version')
        or (original.get('config') or {}).get('payload_policy_version')
    )
    if version:
        recorded.setdefault('policy_version', str(version))
    registry = recorded.get('template_registry')
    if registry is None and recorded.get('snapshot_integrity') != 'invalid':
        for container in (original, state):
            registry = container.get('template_registry')
            if registry is not None:
                break
            payload_policy = container.get('payload_policy')
            if isinstance(payload_policy, dict) and payload_policy.get('template_registry') is not None:
                registry = payload_policy.get('template_registry')
                break
    registry = _template_registry_mapping(registry)
    if registry is not None:
        recorded_registry_hash = str(recorded.get('template_registry_sha256') or '')
        if recorded_registry_hash and recorded_registry_hash != evidence_hash(registry):
            # A hash-pinned snapshot that no longer matches its recorded
            # registry identity is unavailable, never silently trusted.
            recorded.pop('template_registry', None)
            recorded['template_registry_integrity'] = 'mismatch'
        else:
            recorded['template_registry'] = registry
    return recorded


def _legacy_probe_controls_valid(state, controls):
    """Validate a pre-versioned complete canonical probe set.

    Legacy snapshots were the ordered canonical probe catalogue with a content
    hash. They are detection controls, so the current exploit-only candidate
    origin/stage gate must not reject them; the complete-set + hash + method
    identity checks are the historical contract.
    """
    method = str(state.get('selected_method') or '')
    rows = controls.get('candidates') if isinstance(controls, dict) else None
    if not method or not isinstance(rows, list):
        return [{'valid': False, 'reason': 'probe_control_candidates_invalid'}]
    if str(controls.get('method') or '') != method:
        return [{'valid': False, 'reason': 'probe_control_method_mismatch'}]
    visit_id = state.get('selected_visit_id')
    if visit_id and controls.get('visit_id') != visit_id:
        return [{'valid': False, 'reason': 'probe_control_visit_mismatch'}]
    if controls.get('sha256') != evidence_hash(rows):
        return [{'valid': False, 'reason': 'probe_control_hash_mismatch'}]
    canonical = [
        candidate for candidate in PayloadLibrary().load_seed_candidates(
            method, state.get('security_level', 'low'))
        if candidate.get('stage') == 'probe'
    ]
    def identity(row):
        return (str(row.get('candidate_id') or ''), str(row.get('payload_or_logic') or ''),
                str(row.get('stage') or ''), str(row.get('method') or ''),
                str(row.get('security_level') or ''))
    if [identity(row) for row in rows] != [identity(row) for row in canonical]:
        return [{'valid': False, 'reason': 'probe_control_catalog_mismatch'}]
    return [{'valid': True, 'reason': 'ok', 'control_id': row.get('candidate_id')}
            for row in rows]


def _recorded_probe_controls_valid(state, controls):
    """Validate a versioned snapshot against its OWN recorded catalog identity.

    A historical reader cannot compare a recorded snapshot with today's mutable
    catalogue. Structural scope, hash and safety/budget identities stay
    fail-closed; a missing snapshot identity remains an explicit rejection.
    """
    method = str(state.get('selected_method') or '')
    if not isinstance(controls, dict):
        return [{'valid': False, 'reason': 'probe_control_snapshot_missing'}]
    issues = []
    if not controls.get('policy_version') or not controls.get('catalog_id') or not controls.get('catalog_version'):
        issues.append({'valid': False, 'reason': 'probe_control_catalog_identity_missing'})
    if not controls.get('catalog_sha256'):
        issues.append({'valid': False, 'reason': 'probe_control_catalog_identity_missing'})
    if str(controls.get('method') or '') != method:
        issues.append({'valid': False, 'reason': 'probe_control_method_mismatch'})
    visit_id = state.get('selected_visit_id')
    if visit_id and controls.get('visit_id') != visit_id:
        issues.append({'valid': False, 'reason': 'probe_control_visit_mismatch'})
    scope = controls.get('scope') if isinstance(controls.get('scope'), dict) else {}
    for key in ('fixture_id', 'protocol_version'):
        expected = state.get(key)
        observed = scope.get(key)
        if expected and str(expected) != str(observed):
            issues.append({'valid': False, 'reason': f'probe_control_{key}_mismatch'})
    rows = controls.get('candidates')
    if not isinstance(rows, list):
        return [*issues, {'valid': False, 'reason': 'probe_control_candidates_invalid'}]
    if not rows:
        issues.append({'valid': False, 'reason': 'probe_control_candidates_missing'})
    if controls.get('sha256') != evidence_hash(rows):
        issues.append({'valid': False, 'reason': 'probe_control_hash_mismatch'})
    identity_fields = (
        'candidate_id', 'control_id', 'payload_or_logic', 'method', 'security_level',
        'phase', 'purpose', 'expected_signal', 'safety_class', 'request_budget',
        'physical_request_budget',
    )
    if any(not isinstance(row, dict) or any(key not in row for key in identity_fields)
           for row in rows):
        issues.append({'valid': False, 'reason': 'probe_control_catalog_identity_missing'})
    else:
        recorded_catalog = {
            'catalog_id': controls.get('catalog_id'),
            'catalog_version': controls.get('catalog_version'),
            'controls': [{key: row[key] for key in identity_fields} for row in rows],
        }
        if controls.get('catalog_sha256') != evidence_hash(recorded_catalog):
            issues.append({'valid': False, 'reason': 'probe_control_catalog_hash_mismatch'})
    if controls.get('quarantined'):
        issues.append({'valid': False, 'reason': 'probe_control_quarantined'})
    logical_budget = sum(int(row.get('request_budget') or 1) for row in rows if isinstance(row, dict))
    physical_budget = sum(int(row.get('physical_request_budget') or 1) for row in rows if isinstance(row, dict))
    if int(controls.get('requests_used') or 0) > int(controls.get('request_budget') or logical_budget):
        issues.append({'valid': False, 'reason': 'probe_control_requests_exceeded'})
    if int(controls.get('physical_requests_used') or 0) > physical_budget:
        issues.append({'valid': False, 'reason': 'probe_control_physical_requests_exceeded'})
    for row in rows:
        if not isinstance(row, dict):
            issues.append({'valid': False, 'reason': 'probe_control_candidate_invalid'})
            continue
        if row.get('method') != method:
            issues.append({'valid': False, 'reason': 'probe_control_method_mismatch'})
        if row.get('source') not in {'static_seed', 'catalog_synthetic'}:
            issues.append({'valid': False, 'reason': 'probe_control_source_invalid'})
        if row.get('source') == 'static_seed' and not str(row.get('source_seed_id') or '').startswith(
                f"{method}_{row.get('security_level')}_probe_"):
            issues.append({'valid': False, 'reason': 'probe_control_seed_invalid'})
        if str(row.get('stage')) != 'probe':
            issues.append({'valid': False, 'reason': 'probe_control_stage_invalid'})
        if str(row.get('safety_class')) != 'precondition_only':
            issues.append({'valid': False, 'reason': 'probe_control_unsafe_control'})
        if row.get('establishes_exploit') is not False:
            issues.append({'valid': False, 'reason': 'probe_control_establishes_exploit'})
        if int(row.get('requests_used') or 0) > int(row.get('request_budget') or 0):
            issues.append({'valid': False, 'reason': 'probe_control_row_budget_exceeded'})
        if int(row.get('physical_requests_used') or 0) > int(row.get('physical_request_budget') or 0):
            issues.append({'valid': False, 'reason': 'probe_control_row_physical_budget_exceeded'})
    if issues:
        return issues
    return [{'valid': True, 'reason': 'ok', 'control_id': row.get('control_id')}
            for row in rows]


def _validated_probe_controls(state, controls):
    """Historical control validation dispatch for diagnostic replay."""
    policy_version = control_snapshot_policy_version(controls)
    if policy_version != LEGACY_CONTROL_POLICY_VERSION:
        live_results = validate_probe_controls(state, controls)
        if live_results and all(row.get('valid') is True for row in live_results):
            return live_results
        return _recorded_probe_controls_valid(state, controls)
    return _legacy_probe_controls_valid(state, controls)


def _apply_state_update(state: dict, updates: dict) -> dict:
    """Apply the runtime schema's reducers to a partial diagnostic update."""
    final = deepcopy(state)
    defaults = new_default_state()
    annotations = get_type_hints(ExploitationState, include_extras=True)
    for field, value in updates.items():
        annotation = annotations.get(field)
        if get_origin(annotation) is NotRequired:
            annotation = get_args(annotation)[0]
        if get_origin(annotation) is Annotated:
            final[field] = get_args(annotation)[-1](final.get(field, defaults[field]), value)
        else:
            final[field] = deepcopy(value)
    return final


def replay_method_inputs(
    source_path: str | Path, *, output_path: str | Path, input_index: int = 0,
    candidate_ids: list[str] | None = None,
) -> dict:
    """Replay an artifact's frozen validated queue against fresh DVWA sessions.

    The source pins the target. Validation must preserve every input ID/value;
    a changed/rejected/budgeted queue stops before HTTP, without seed fallback.
    Optional selection uses only saved exploit IDs and retains saved detection
    controls. Legacy inputs must include saved probes in the candidate queue.
    A missing stage cannot trigger the methods' legacy static fallback.
    Caller supplies a diagnostic output path and retains the source artifact.
    Manual rows cover fresh response-backed candidates; final state retains history.
    """
    source = Path(source_path)
    output = Path(output_path)
    if source.resolve() == output.resolve() or output.exists():
        raise ValueError('Replay output must be a new path separate from the source')
    raw = source.read_bytes()
    original = json.loads(raw)
    inputs = original.get('method_execution_inputs', [])
    if not inputs:
        raise ValueError('Source has no frozen pre-execution method inputs')
    frozen = inputs[input_index]
    method = frozen['method']
    if method not in RUNTIME_AGENT_HANDLERS:
        raise ValueError('Unknown method in frozen input')
    state = deepcopy(frozen['state'])
    if state.get('target_url') != original.get('config', {}).get('target_url'):
        raise ValueError('Frozen target does not match source scope')
    if state.get('selected_method') != method:
        raise ValueError('Frozen method does not match selected method')
    queue = state.get('payload_candidates', {}).get(method, [])
    if candidate_ids is not None:
        saved_ids = {c['candidate_id'] for c in queue}
        if not candidate_ids or not set(candidate_ids) <= saved_ids:
            raise ValueError('Replay selection must contain only saved candidate IDs')
        queue = [c for c in queue if c['candidate_id'] in candidate_ids or c.get('stage') == 'probe']
        state['payload_candidates'] = {method: queue}
    recorded_policy = _recorded_payload_policy(original, state)
    if (recorded_policy.get('snapshot_integrity') == 'invalid'
            or recorded_policy.get('template_registry_integrity') == 'mismatch'):
        raise ValueError('Recorded payload policy integrity failed; replay is prohibited')
    recorded_version = str(recorded_policy.get('policy_version') or '')
    frozen_exec = [c for c in queue if c.get('stage') in {'exploit', 'bypass'}]
    frozen_probes = [c for c in queue if c.get('stage') == 'probe']
    # Replay is a historical reader: validate the exact queue under the
    # artifact's recorded contract, never today's live policy/registry.
    state[PAYLOAD_POLICY_BASIS_STATE_KEY] = PAYLOAD_POLICY_BASIS_HISTORICAL
    state[RECORDED_POLICY_STATE_KEY] = recorded_policy
    check = validate_payload_candidates(state, policy_basis=PAYLOAD_POLICY_BASIS_HISTORICAL)
    executable = [c for c in check.get('payload_candidates', {}).get(method, [])
                  if c.get('stage') in {'exploit', 'bypass'}]
    signature = lambda rows: sorted(
        ({key: value for key, value in c.items() if key != 'validation'} for c in rows),
        key=lambda c: str(c.get('candidate_id')),
    )
    rejections = [r for r in check.get('payload_validation_results', {}).get(method, []) if r.get('valid') is not True]
    active = state.get('active_payload_candidates', {}).get(method)
    visit_id = state.get('selected_visit_id')
    if active is not None and (
        not visit_id or active.get('status') != 'validated' or active.get('visit_id') != visit_id
    ):
        rejections.append({'reason': 'frozen_active_visit_not_validated', 'valid': False})
    # A versioned policy moves detection probes out of the exploit queue; legacy
    # snapshots may still contain them. Compare exploit/bypass identity only.
    if not frozen_exec or signature(frozen_exec) != signature(executable):
        rejections.append({'reason': 'frozen_queue_changed_or_empty', 'valid': False})
    if recorded_version and frozen_probes:
        rejections.append({'reason': 'probe_row_in_versioned_exploit_queue', 'valid': False})
    controls = state.get('probe_controls', {}).get(method)
    if controls is None and frozen_probes and not recorded_version:
        # Legacy snapshots kept probes in the exploit queue. Reconstruct the
        # frozen legacy control snapshot from those saved rows so the probe
        # stage sees the same complete ordered canonical set.
        controls = {
            'method': method, 'visit_id': visit_id,
            'sha256': evidence_hash(frozen_probes),
            'candidates': frozen_probes,
        }
        state['probe_controls'] = {method: controls}
    catalog_policy = controls.get('policy_version') if isinstance(controls, dict) else None
    controls_valid = True
    if isinstance(controls, dict):
        # Recorded/live version dispatch is historical here: legacy snapshots
        # keep the complete ordered canonical-set rule, versioned snapshots are
        # validated against their own recorded catalog identity.
        control_results = _validated_probe_controls(state, controls)
        rejections.extend(r for r in control_results if r.get('valid') is not True)
        controls_valid = bool(control_results) and all(r.get('valid') is True for r in control_results)
    if recorded_version:
        if controls is None or not catalog_policy:
            rejections.append({'reason': 'unversioned_control_catalog', 'valid': False})
        elif not controls.get('candidates') or not controls_valid:
            rejections.append({'reason': 'probe_control_catalog_invalid', 'valid': False})
    elif not (controls_valid and (controls or {}).get('candidates')) and not frozen_probes:
        rejections.append({'reason': 'missing_saved_execution_stage', 'valid': False})
    if not frozen_exec:
        rejections.append({'reason': 'missing_saved_execution_stage', 'valid': False})
    updates = {}
    # Installing a real runtime context also forbids the legacy provider path;
    # method handlers currently use no models. Audit any unexpected future call.
    runtime = LLMRuntime(max_concurrency=1)
    def forbid_provider(**kwargs):
        raise RuntimeError('Provider calls are forbidden during frozen-input replay')
    runtime.invoke = forbid_provider
    try:
        with runtime.coordinate(coordinate_id='diagnostic-replay', default_provider='openai_compatible') as context:
            if not rejections:
                # Fresh ranking can differ from append-only validation history.
                # Revalidate membership, then execute in the saved queue order.
                receipts = {str(r['candidate_id']): dict(r, visit_id=visit_id)
                    for r in check['payload_validation_results'][method]}
                saved_results = state.get('payload_validation_results', {})
                execution_queue = list(frozen_exec)
                if not recorded_version:
                    # Legacy snapshots may only retain probe rows in the queue;
                    # keep their saved receipts so the probe stage still runs.
                    for probe in frozen_probes:
                        key = str(probe.get('candidate_id'))
                        if key in receipts:
                            continue
                        saved = next((r for r in saved_results.get(method, [])
                                      if str(r.get('candidate_id')) == key), None)
                        if saved is None:
                            rejections.append({'reason': 'missing_validation_receipt',
                                               'candidate_id': key, 'valid': False})
                            break
                        receipts[key] = dict(saved, visit_id=visit_id)
                        execution_queue.append(probe)
                if rejections:
                    ordered_receipts = []
                else:
                    ordered_receipts = [receipts[str(c['candidate_id'])] for c in execution_queue]
                if not rejections:
                    execution_ids = [c['candidate_id'] for c in execution_queue]
                    state['payload_candidates'] = {method: execution_queue}
                    if active is not None:
                        state['payload_validation_results'] = _merge_validation_maps(
                            saved_results, {method: ordered_receipts})
                        state['active_payload_candidates'] = {
                            **state['active_payload_candidates'], method: {
                                **active, 'candidate_ids': execution_ids,
                            },
                        }
                    else:
                        queued_ids = set(execution_ids)
                        history = [r for r in saved_results.get(method, []) if r.get('candidate_id') not in queued_ids]
                        state['payload_validation_results'] = {
                            **saved_results, method: [*history, *ordered_receipts],
                        }
                    updates = _serialized_http_handler(RUNTIME_AGENT_HANDLERS[method])(state)
            if context.records:
                raise RuntimeError('Method replay unexpectedly called a provider')
    finally:
        runtime.close()
    final = _apply_state_update(state, updates)
    final = _apply_state_update(final, scorer(final))
    artifact = {
        'kind': 'diagnostic_replay', 'source_path': str(source),
        'source_sha256': sha256(raw).hexdigest(), 'input_index': input_index,
        'fresh_provider_calls': 0, 'config': original['config'],
        'selected_candidate_ids': candidate_ids,
        'probe_controls': deepcopy(state.get('probe_controls', {})),
        'payload_policy': {
            'policy_basis': PAYLOAD_POLICY_BASIS_HISTORICAL,
            'payload_policy_version': final.get('payload_policy_version')
                or recorded_version or original.get('config', {}).get('payload_policy_version'),
            'recorded_policy_version': recorded_version or None,
            'recorded_policy_sha256': evidence_hash(recorded_policy) if recorded_policy else None,
            'template_registry_recorded': bool(recorded_policy.get('template_registry')),
            'control_policy_version': final.get('control_policy_version')
                or original.get('config', {}).get('control_policy_version'),
            'control_catalog_id': (state.get('probe_controls', {}).get(method) or {}).get('catalog_id')
                if isinstance(state.get('probe_controls', {}).get(method), dict) else None,
        },
        'candidate_lifecycle': deepcopy(final.get('candidate_lifecycle', [])),
        'manual_scoring_scope': 'fresh_replay_execution',
        'code_sha256': {
            str(path): sha256(path.read_bytes()).hexdigest()
            for path in {
                Path(inspect.getfile(RUNTIME_AGENT_HANDLERS[method])),
                Path('agents/state_utils.py'), Path('foundation/verifier.py'),
                Path('foundation/payload_validator.py'), Path('core/scorer.py'),
                Path(inspect.getfile(manual_scoring_rows)),
                Path(inspect.getfile(link_exported_request_evidence)),
                Path('core/state.py'), Path(__file__),
            }
        },
        'validation_rejections': rejections, 'final_state': redact_secrets(final),
        'execution_log': [
            {
                'event_type': str(event.get('event') or event.get('event_type') or 'runtime.event'),
                'method': method,
                'data': redact_secrets(event.get('payload') or {}),
            }
            for event in updates.get('telemetry_events', [])
            if isinstance(event, dict)
        ],
        'scoring_decisions': updates.get('scoring_decisions', []),
        'response_evidence': redact_secrets(updates.get('response_evidence', [])),
        'timing_evidence': updates.get('timing_evidence', []),
        'verifier_decision': updates.get('verifier_decision'),
        'confirmed_vulns': final.get('confirmed_vulns', []),
        'achieved_outcomes': final.get('achieved_outcomes', []),
    }
    link_exported_request_evidence(artifact)
    artifact['manual_scoring_evidence'] = manual_scoring_rows(artifact)
    write_json_report(output, artifact)
    return artifact
