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
from core.scorer import scorer
from core.state import ExploitationState, new_default_state
from evaluation.manual_scoring_sheet import manual_scoring_rows
from evaluation.reporter import write_json_report
from foundation.payload_validator import validate_payload_candidates
from llm.runtime import LLMRuntime
from core.graph_builder import _serialized_http_handler
from tesis.runtime_events import redact_secrets


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
    Optional selection uses only saved IDs; include saved probes and exploits
    so a missing stage cannot trigger the methods' legacy static fallback.
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
        queue = [c for c in queue if c['candidate_id'] in candidate_ids]
        state['payload_candidates'] = {method: queue}
    # Validate the exact queue again without implicitly adding new candidates.
    check = validate_payload_candidates(state)
    executable = check.get('payload_candidates', {}).get(method, [])
    signature = lambda rows: sorted(
        ({key: value for key, value in c.items() if key != 'validation'} for c in rows),
        key=lambda c: str(c.get('candidate_id')),
    )
    rejections = [r for r in check.get('payload_validation_results', {}).get(method, []) if r.get('valid') is not True]
    if not queue or signature(queue) != signature(executable):
        rejections.append({'reason': 'frozen_queue_changed_or_empty', 'valid': False})
    stages = {c.get('stage') for c in queue}
    if 'probe' not in stages or not stages & {'exploit', 'bypass'}:
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
                receipts = {r['candidate_id']: r for r in check['payload_validation_results'][method]}
                saved_results = state.get('payload_validation_results', {})
                queued_ids = {c['candidate_id'] for c in queue}
                history = [r for r in saved_results.get(method, []) if r.get('candidate_id') not in queued_ids]
                state['payload_validation_results'] = {
                    **saved_results, method: [*history, *[receipts[c['candidate_id']] for c in queue]],
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
        'manual_scoring_scope': 'fresh_replay_execution',
        'code_sha256': {
            str(path): sha256(path.read_bytes()).hexdigest()
            for path in {
                Path(inspect.getfile(RUNTIME_AGENT_HANDLERS[method])),
                Path('agents/state_utils.py'), Path('foundation/verifier.py'),
                Path('foundation/payload_validator.py'), Path('core/scorer.py'),
                Path(inspect.getfile(manual_scoring_rows)),
                Path('core/state.py'), Path(__file__),
            }
        },
        'validation_rejections': rejections, 'final_state': redact_secrets(final),
        'scoring_decisions': updates.get('scoring_decisions', []),
        'response_evidence': redact_secrets(updates.get('response_evidence', [])),
        'timing_evidence': updates.get('timing_evidence', []),
        'verifier_decision': updates.get('verifier_decision'),
        'confirmed_vulns': final.get('confirmed_vulns', []),
        'achieved_outcomes': final.get('achieved_outcomes', []),
    }
    artifact['manual_scoring_evidence'] = manual_scoring_rows(artifact)
    write_json_report(output, artifact)
    return artifact
