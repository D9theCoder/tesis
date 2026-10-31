"""Evidence-backed research metrics for Chapter 3 (availability-tracked).

Every metric is computed from retained artifact evidence when that evidence is
sufficient, and is otherwise returned as ``None`` with a precise reason,
numerator/denominator, population, origin and visit identity. Missing values are
never filled with zero and nothing here changes the published v4 rubric, proof
ceilings, final-method candidate denominator or the weighted formula.

Runtime ``scoring.v2`` values remain provisional; they are exposed only inside
``provisional`` and never substitute for a final component.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
import math

from evaluation.scoring_evidence import (
    STATIC_ORIGIN_KINDS,
    candidate_execution_evidence,
    candidate_execution_rows,
    candidate_lifecycle_status,
    origin_kind as _origin_kind,
    ranking_comparison,
    _is_fallback_use_event,
)
from core.payload_policy import (
    MODEL_ORIGIN_KINDS,
    is_model_output_failure_reason,
    is_provider_failure_reason,
)
from core.state import ALL_METHOD_AGENTS


METRIC_SCHEMA_VERSION = 'research-metrics.v2'
# v4.3 changes only the scoring-rule digest construction to the canonical
# four-file function; the metric definitions themselves are unchanged. Stored
# v4.2 documents and recorded epoch digests remain historical identity.
SCORING_POLICY_VERSION = 'scoring-policy.v4.3'
EXPERIMENT_ROLES = frozenset({'orchestrator', 'payload_generator'})
CONTROL_IDENTITY_KINDS = frozenset({'probe_candidate', 'derived_control', 'independent_control', 'unresolved'})
RATE_DEFINITION_VERSION = 'event-rates.v2'
SCORING_SOURCE_FILES = (
    'evaluation/thesis_scoring.py',
    'evaluation/scoring_evidence.py',
    'evaluation/research_metrics.py',
    'foundation/verifier.py',
)
#: The canonical digest hashes every scoring source file, verifier included.
#: The definition is recorded so a stored digest can never be mistaken for one
#: produced under a different construction; recorded artifact epochs stay
#: untouched and are returned separately as historical identity.
SCORING_RULE_DIGEST_DEFINITION = 'sha256(concat(per-file sha256 hexdigest for SCORING_SOURCE_FILES))'
PROVISIONAL_LABEL = 'provisional_scoring.v2'

DEFINITIONS = {
    'first_choice_accuracy': 'Binary accuracy of the first actual model-origin selection decision against the frozen ranking snapshot top set.',
    'model_selection_decisions': 'Count of selection decisions whose trusted origin is the experiment model.',
    'deterministic_selection_decisions': 'Count of deterministic fallback selection decisions; never model accuracy.',
    'forced_selection_decisions': 'Count of forced-target selections; never model accuracy.',
    'route_selection_decisions': 'Count of AKG route selections; never model accuracy.',
    'adaptation_rate': 'Share of genuine re-selection opportunities after a supported failure in which the model chose a different method.',
    'adaptation_opportunities': 'Count of model-origin selection decisions that occurred after a supported method failure.',
    'akg_path_validity': 'Share of recorded AKG routes whose static edge, prerequisites and decision trace validate.',
    'akg_routes_recorded': 'Count of chain routes recorded in the artifact.',
    'akg_routes_valid': 'Count of recorded routes passing the static-edge and prerequisite-evidence checks.',
    'payload_validity_rate': 'Validated exploit/bypass candidates divided by all validated queue rows (combined origins).',
    'model_payload_validity_rate': 'Validated model-origin candidates divided by parsed model-origin candidates.',
    'payload_execution_success_rate': 'Executed and assessed candidates at confirmed tier divided by valid exploit/bypass candidates (v4 denominator).',
    'assessable_executed_confirmation_rate': 'Confirmed candidates divided by assessable executed candidates.',
    'payload_improvement_rate': 'Method visits where the best executed model candidate outperforms the best executed static baseline for the same method and visit.',
    'method_alignment_rate': 'Positive independent method-alignment verdicts divided by evidence-linked verdicts for executed assessed candidates; validation alone is not a verdict.',
    'full_exploit_flag': 'Binary v4 flag: Sexploit >= 3, not a route count.',
    'chain_enabled_exploit_flag': 'Binary v4 flag: Schain >= 3, not a route count.',
    'chain_route_count': 'Count of independently verified completed chain routes.',
    'attempts_to_success': 'One-based position of the first confirmed candidate in distinct executed-candidate order.',
    'candidate_attempts': 'Distinct executed exploit/bypass candidate IDs; not a physical request count.',
    'physical_requests_total': 'Actual contained HTTP requests from the run-scoped client counter; unavailable, never derived from evidence rows.',
    'evidence_requests_total': 'Evidence rows recorded for the assessed method; a row count, not a physical request count.',
    'request_retries': 'Actual contained-client retry dispatches from the run-scoped counter.',
    'redirect_hops': 'Actual contained-client redirect hops from the run-scoped counter.',
    'failed_requests': 'Actual failed transport dispatches from the run-scoped counter.',
    'rejected_model_selections': 'Model-origin first decisions rejected by the runtime evidence/precondition gate; never replaced by the next accepted choice.',
    'failed_request_candidates': 'Candidates whose own request failed without response evidence; attempted but never executed or assessed.',
    'probe_requests': 'Detection-control requests, excluded from candidate counts.',
    'verifier_control_requests': 'Candidate-bound derived and independent verification control requests.',
    'invalid_json_rate': 'Unique experiment-model calls with a returned invalid-JSON event divided by unique experiment-model calls.',
    'guardrail_activation_rate': 'Unique experiment-model calls with a guardrail event divided by unique experiment-model calls.',
    'fallback_rate': 'Unique experiment-model calls with an evidenced fallback USE event divided by unique experiment-model calls; provider failures, strict no-candidate and budget-exclusion events are not uses.',
    'token_usage_input': 'Summed provider-reported input tokens for experiment-model calls.',
    'token_usage_output': 'Summed provider-reported output tokens for experiment-model calls.',
    'token_usage_total': 'Summed provider-reported total tokens for experiment-model calls.',
    'token_cost': 'Cost from retained usage and a frozen timestamped price schedule applicable to the provider/model, always reported with its accounting_basis: an api_equivalent_estimate is a list-price estimate, not a billed charge.',
    'token_cost_per_success': 'Run cost divided by confirmed candidate successes, carrying the same accounting_basis; unavailable without cost or a confirmed success.',
    'provider_cache_read_rate': 'Token-weighted provider input-cache read rate; distinct from saved response reuse.',
    'response_cache_hit_rate': 'Share of logical experiment-model calls served from the runtime response cache.',
    'wall_time_ms': 'Elapsed wall time of the whole run.',
    'summed_call_duration_ms': 'Sum of experiment-model call durations; never elapsed wall time.',
    'per_run_llm_concurrency': 'Per-run configured/peak LLM concurrency; matrix-wide concurrency is reported by the matrix aggregate.',
    'methods_attempted': 'Distinct registered methods with execution or selection evidence; unattempted methods are not zero-score failures.',
    'methods_unattempted': 'Registered methods with no execution or selection evidence in this run.',
    'generation_opportunities': 'Recorded payload generation opportunities for this method.',
    'generation_calls': 'Actual payload-generator model calls in the final method context.',
    'model_refusals': 'Generation opportunities whose returned model output was a refusal.',
    'invalid_model_outputs': 'Generation opportunities whose returned model output was malformed or schema-invalid.',
    'provider_failures': 'Generation opportunities/Calls with a provider or transport failure, never described as model refusals.',
    'parsed_model_candidates': 'Distinct model-origin candidates parsed from generation output.',
    'valid_model_candidates': 'Parsed model-origin candidates that validated in their visit.',
    'executed_model_candidates': 'Model-origin candidates with their own visit-bound exploit/bypass request.',
    'assessable_executed_model_candidates': 'Executed model-origin candidates with an assessable proof tier.',
    'confirmed_model_candidates': 'Executed model-origin candidates at confirmed tier (>=3) with candidate-bound evidence.',
}

DEFINITION_VERSIONS = {name: 'research-metrics.v2' for name in DEFINITIONS}
DEFINITION_VERSIONS.update({
    'payload_validity_rate': 'research-metrics.v1',
    'attempts_to_success': 'research-metrics.v1',
    'full_exploit_flag': 'research-metrics.v1',
    'chain_enabled_exploit_flag': 'research-metrics.v1',
    'method_alignment_rate': 'method-alignment.v1',
})

RESEARCH_METRIC_NAMES = tuple(DEFINITIONS)


def scoring_source_hashes():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    return {path: sha256((root / path).read_bytes()).hexdigest() for path in SCORING_SOURCE_FILES}


def _rule_hash(source_hashes):
    return sha256(''.join(source_hashes.values()).encode()).hexdigest()


def scoring_rule_hash():
    return _rule_hash(scoring_source_hashes())


def scoring_policy(artifact=None):
    """Identify the scoring/metric policy epoch without relabeling history.

    ``scoring_rule_sha256`` is the canonical :func:`scoring_rule_hash` over every
    file in ``SCORING_SOURCE_FILES`` (verifier included). ``digest_definition``
    records how that value was constructed so a stored digest is never compared
    against a different definition. A recorded artifact epoch digest is echoed
    as ``recorded_scoring_rule_sha256``; it is historical identity, never
    rewritten to the canonical value.
    """
    artifact = artifact if isinstance(artifact, dict) else {}
    epoch = artifact.get('score_epoch')
    epoch = epoch if isinstance(epoch, dict) else {}
    source_hashes = scoring_source_hashes()
    return {
        'policy_version': SCORING_POLICY_VERSION,
        'metrics_epoch': METRIC_SCHEMA_VERSION,
        'rate_definition_version': RATE_DEFINITION_VERSION,
        'rubric_version': (artifact.get('config') or {}).get('scoring_rubric_version'),
        'scoring_rule_sha256': _rule_hash(source_hashes),
        'digest_definition': SCORING_RULE_DIGEST_DEFINITION,
        'source_files': list(SCORING_SOURCE_FILES),
        'source_hashes': source_hashes,
        'recorded_scoring_rule_sha256': epoch.get('scoring_rule_sha256'),
    }


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def _timestamp(value):
    parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Schedules and run timestamps require a timezone')
    return parsed


def _price(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


PRICE_CATEGORY_KEYS = {
    'input': ('input_per_million', 'input'),
    'output': ('output_per_million', 'output'),
    'cache_read': ('cache_read_per_million', 'cache_read'),
    'cache_write': ('cache_write_per_million', 'cache_write'),
}

# A schedule (or a single price row) may declare what its prices measure.  An
# ``api_equivalent_estimate`` is a list-price estimate for a route whose actual
# charge is not established (for example a subscription/OAuth profile); it must
# never be reported as a billed charge.  A missing declaration is
# ``unspecified``, never silently upgraded to ``billed``.
ACCOUNTING_BASES = ('api_equivalent_estimate', 'billed', 'unspecified')
DEFAULT_ACCOUNTING_BASIS = 'unspecified'

# Optional per-row multipliers for a documented long-context price regime.  The
# schedule must state the multiplier; the code never infers one.
LONG_CONTEXT_MULTIPLIERS = {
    'input': 'input_multiplier',
    'output': 'output_multiplier',
    'cache_read': 'cache_read_multiplier',
    'cache_write': 'cache_write_multiplier',
}

PRICE_ROUTE_FIELD = 'price_routes'


def accounting_label(container, price_key=None):
    """Return the accounting label declared by a schedule or one price row.

    ``accounting_basis`` defaults to ``unspecified`` when absent.  A price row
    may override the schedule-level ``accounting_basis``/``billing_route``/
    ``notes`` because one schedule can mix a billed route and an API-equivalent
    estimate for an OAuth profile.  Undeclared values inherit the schedule.
    """
    label = {'accounting_basis': DEFAULT_ACCOUNTING_BASIS,
             'billing_route': None, 'notes': None}
    if not isinstance(container, dict):
        return label
    basis = container.get('accounting_basis')
    if isinstance(basis, str) and basis in ACCOUNTING_BASES:
        label['accounting_basis'] = basis
    route = container.get('billing_route')
    if isinstance(route, str) and route.strip():
        label['billing_route'] = route.strip()
    notes = container.get('notes')
    if isinstance(notes, str) and notes.strip():
        label['notes'] = notes
    prices = container.get('prices')
    if price_key is not None and isinstance(prices, dict):
        row = prices.get(price_key)
        if isinstance(row, dict):
            row_basis = row.get('accounting_basis')
            if isinstance(row_basis, str) and row_basis in ACCOUNTING_BASES:
                label['accounting_basis'] = row_basis
            row_route = row.get('billing_route')
            if isinstance(row_route, str) and row_route.strip():
                label['billing_route'] = row_route.strip()
            row_notes = row.get('notes')
            if isinstance(row_notes, str) and row_notes.strip():
                label['notes'] = row_notes
    return label


def _validate_accounting_fields(container, path):
    """Validate optional accounting label fields without requiring them."""
    basis = container.get('accounting_basis')
    if basis is not None and (not isinstance(basis, str) or basis not in ACCOUNTING_BASES):
        raise ValueError(f'{path}.accounting_basis must be one of {", ".join(ACCOUNTING_BASES)}')
    route = container.get('billing_route')
    if route is not None and (not isinstance(route, str) or not route.strip()):
        raise ValueError(f'{path}.billing_route must be a non-empty string')
    notes = container.get('notes')
    if notes is not None and not isinstance(notes, str):
        raise ValueError(f'{path}.notes must be a string')


def _validate_long_context(row, path):
    """Validate the optional documented long-context multipliers of one row."""
    long_context = row.get('long_context')
    if long_context is None:
        return
    if not isinstance(long_context, dict) or not long_context:
        raise ValueError(f'{path}.long_context must be a non-empty mapping')
    threshold = long_context.get('above_input_tokens')
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 0:
        raise ValueError(f'{path}.long_context.above_input_tokens must be a non-negative integer')
    multipliers = {key: value for key, value in long_context.items() if key != 'above_input_tokens'}
    if not multipliers:
        raise ValueError(f'{path}.long_context requires at least one multiplier')
    for key, value in multipliers.items():
        if key not in LONG_CONTEXT_MULTIPLIERS.values():
            raise ValueError(f'{path}.long_context.{key} is not a supported multiplier')
        if not _price(value):
            raise ValueError(f'{path}.long_context.{key} must be a non-negative number')


def validate_token_price_schedule(schedule):
    """Validate the frozen price schedule shape without inferring any price.

    Shape is owned by tesis.config_loader: schedule_id, version, effective_at,
    currency and prices{provider/model: {input_per_million, output_per_million,
    optional cache categories}}. Prices are per million tokens.

    Optional top-level fields are never required, so existing frozen schedules
    stay valid:

    ``accounting_basis``
        ``api_equivalent_estimate``, ``billed`` or ``unspecified``.
    ``billing_route``
        Non-empty string naming the route actually charged (for example a
        subscription/OAuth profile).
    ``notes``
        Free-text provenance for the accounting label.
    ``price_routes``
        ``{runtime_route_key: price_row_key}`` explicit API-equivalent mapping.
        It must reference an existing price row; a mapped route is never priced
        from a different row.

    A price row may repeat ``accounting_basis``/``billing_route``/``notes`` to
    override the schedule label for that row, and may declare a documented
    ``long_context`` multiplier regime.  No price or modifier is inferred.
    """
    if not isinstance(schedule, dict) or not schedule:
        raise ValueError('token price schedule must be a non-empty mapping')
    for field in ('schedule_id', 'version', 'effective_at', 'currency', 'prices'):
        if schedule.get(field) in (None, ''):
            raise ValueError(f'token price schedule requires {field}')
    _timestamp(schedule['effective_at'])
    if not isinstance(schedule['currency'], str) or len(schedule['currency']) != 3:
        raise ValueError('token price schedule currency must be an ISO 4217 code')
    prices = schedule['prices']
    if not isinstance(prices, dict) or not prices:
        raise ValueError('token price schedule prices must map provider models')
    for model_key, row in prices.items():
        if not isinstance(model_key, str) or not model_key.strip():
            raise ValueError('price schedule model keys must be non-empty')
        if not isinstance(row, dict):
            raise ValueError(f'token price schedule prices.{model_key} must be a mapping')
        if not any(any(key in row for key in keys) for keys in
                   (PRICE_CATEGORY_KEYS['input'], PRICE_CATEGORY_KEYS['output'])):
            raise ValueError(f'token price schedule prices.{model_key} requires input/output prices')
        for keys in PRICE_CATEGORY_KEYS.values():
            for key in keys:
                if key in row and not _price(row[key]):
                    raise ValueError(f'token price schedule prices.{model_key}.{key} must be non-negative')
        _validate_accounting_fields(row, f'token price schedule prices.{model_key}')
        _validate_long_context(row, f'token price schedule prices.{model_key}')
    _validate_accounting_fields(schedule, 'token price schedule')
    routes = schedule.get(PRICE_ROUTE_FIELD)
    if routes is not None:
        if not isinstance(routes, dict) or not routes:
            raise ValueError(f'token price schedule {PRICE_ROUTE_FIELD} must be a non-empty mapping')
        for route_key, target in routes.items():
            if not isinstance(route_key, str) or not route_key.strip():
                raise ValueError(f'token price schedule {PRICE_ROUTE_FIELD} keys must be non-empty')
            if not isinstance(target, str) or not target.strip():
                raise ValueError(
                    f'token price schedule {PRICE_ROUTE_FIELD}.{route_key} must name a price row')
            if target not in prices:
                raise ValueError(
                    f'token price schedule {PRICE_ROUTE_FIELD}.{route_key} references unknown '
                    f'price row {target}')
    return schedule


def _normalized_price_row(row):
    normalized = {}
    for category, keys in PRICE_CATEGORY_KEYS.items():
        value = next((row[key] for key in keys if key in row), None)
        if value is not None:
            normalized[category] = value
    return normalized


def resolve_price_entry(schedule, provider, model, model_profile=None, route=None):
    """Return ``(per-million prices, resolution)`` for a provider/model call.

    ``route`` is an explicit runtime route identity (a configured profile id or
    ``provider/profile`` key).  An explicit ``price_routes`` mapping wins over a
    directly keyed row: the mapping states that the row is the accounting rate
    chosen for that route, so the billed route is never silently substituted.
    A mapped route resolves only the mapped row; it never falls back.
    """
    validate_token_price_schedule(schedule)
    routes = schedule.get(PRICE_ROUTE_FIELD) or {}
    identity = [route] if isinstance(route, str) and route.strip() else []
    identity.append(f'{provider}/{model}')
    if model_profile:
        identity.append(f'{provider}/{model_profile}')
    identity.append(model)
    for key in identity:
        if isinstance(key, str) and key in routes:
            target = routes[key]
            return _normalized_price_row(schedule['prices'][target]), {
                'price_key': target, 'matched_route': key, 'mapped': True}
    price_key = next((key for key in identity if isinstance(key, str) and key in schedule['prices']), None)
    if price_key is None:
        raise KeyError('price_schedule_model_unavailable')
    return _normalized_price_row(schedule['prices'][price_key]), {
        'price_key': price_key, 'matched_route': price_key, 'mapped': False}


def price_entry(schedule, provider, model, model_profile=None, route=None):
    """Return normalized per-million prices applicable to the provider/model."""
    return resolve_price_entry(schedule, provider, model, model_profile, route)[0]


class MetricSet:
    """One metric value with availability, reason and denominator identity."""

    def __init__(self):
        self.values: dict[str, object] = {}
        self.availability: dict[str, bool] = {}
        self.reasons: dict[str, str | None] = {}
        self.denominators: dict[str, object] = {}
        self.definitions: dict[str, str] = {}

    def put(self, name, value, *, numerator=None, denominator=None, population=None,
            origin=None, method=None, visit_id=None, coverage=None, reason=None, detail=None):
        if isinstance(value, bool):
            value = float(value)
        available = value is not None
        self.values[name] = value
        self.availability[name] = available
        self.reasons[name] = None if available else str(reason or 'insufficient_evidence')
        self.definitions[name] = DEFINITIONS.get(name, '')
        entry = {
            'numerator': numerator,
            'denominator': denominator,
            'population': population,
            'origin': origin,
            'method': method,
            'visit_id': visit_id,
        }
        if coverage is not None:
            entry['coverage'] = coverage
        if not available:
            entry['reason'] = self.reasons[name]
        if detail:
            entry.update(detail)
        self.denominators[name] = entry

    def count(self, name, value, **kwargs):
        self.put(name, value, **kwargs)

    def document(self, rubric_version, provisional, notes=None):
        payload = {
            'schema_version': METRIC_SCHEMA_VERSION,
            'metrics_epoch': SCORING_POLICY_VERSION,
            'rubric_version': rubric_version,
            'rate_definition_version': RATE_DEFINITION_VERSION,
            'values': self.values,
            'availability': self.availability,
            'unavailable_reason': self.reasons,
            'denominators': self.denominators,
            'definitions': self.definitions,
            'definition_versions': {name: DEFINITION_VERSIONS.get(name, METRIC_SCHEMA_VERSION)
                                    for name in self.values},
            'provisional': provisional,
        }
        if notes:
            payload['notes'] = notes
        return payload


def _state(artifact):
    state = artifact.get('final_state')
    return state if isinstance(state, dict) else {}


def _config(artifact):
    config = artifact.get('config')
    return config if isinstance(config, dict) else {}


def _method(artifact):
    state = _state(artifact)
    method = artifact.get('selected_method') or state.get('selected_method')
    if not method:
        decision = state.get('verifier_decision')
        method = decision.get('agent_id') if isinstance(decision, dict) else None
    return method


def _calls(artifact):
    rows = artifact.get('llm_performance')
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _experiment_calls(artifact):
    return [row for row in _calls(artifact) if row.get('role') in EXPERIMENT_ROLES]


def _method_calls(artifact, method):
    """Experiment calls whose usage/cost belongs to ``method`` or the run.

    Call records do not always carry ``scope``.  When no final method is
    selected, the run scope is the whole experiment call set: filtering on a
    ``scope`` tag that was never written would price zero calls and report a
    false ``0.0`` cost.  When a method is selected, its calls and run-scope
    calls are kept; an empty selection over a run that recorded experiment
    calls is reported by ``_cost`` as an attribution failure, not as zero.
    """
    calls = _experiment_calls(artifact)
    if method is None:
        return calls
    return [row for row in calls if row.get('method') == method or row.get('scope') == 'run']


def _rate(numerator, denominator):
    if not denominator:
        return None
    return round(numerator / denominator, 6)


def _as_int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _visit_ordinal(visit_id):
    if not isinstance(visit_id, str):
        return None
    for marker in (':visit:', ':legacy:'):
        if marker in visit_id:
            try:
                return int(visit_id.rsplit(marker, 1)[1])
            except ValueError:
                return None
    return None


def _decision_origin(decision):
    origin = decision.get('decision_origin')
    if isinstance(origin, str) and origin:
        return {'model': 'model', 'forced': 'forced', 'deterministic_fallback': 'deterministic_fallback',
                'route': 'route', 'akg_route': 'route'}.get(origin, origin)
    source = decision.get('selection_source')
    return {'model_orchestrator': 'model', 'forced': 'forced',
            'deterministic_fallback': 'deterministic_fallback', 'akg_route': 'route'}.get(source, None)


def _selection_decisions(artifact):
    return [d for d in _state(artifact).get('scoring_decisions', [])
            if isinstance(d, dict) and d.get('dimension') == 'Smethod' and d.get('method')]


def _candidate_queue(artifact, method):
    state = _state(artifact)
    candidates = state.get('payload_candidates', {}).get(method) or []
    return [c for c in candidates if isinstance(c, dict) and c.get('candidate_id')]


def _validation_rows(artifact, method):
    state = _state(artifact)
    rows = state.get('payload_validation_results', {}).get(method) or []
    return [row for row in rows if isinstance(row, dict) and row.get('candidate_id') is not None]


def _provenance(artifact, method):
    state = _state(artifact)
    provenance = state.get('payload_provenance')
    return provenance if isinstance(provenance, dict) else {}


def _execution_evidence_refs(artifact, execution):
    """Reference the exact execution rows the shared identity contract returned."""
    state = _state(artifact)
    container = '#/final_state/response_evidence' if isinstance(state.get('response_evidence'), list) \
        else '#/response_evidence'
    return [f'{container}/{index}' for index, _row in execution]


def _candidate_view(artifact, method, rows=None):
    """One view per candidate queue row with execution/proof evidence.

    Frozen review rows are passed through unchanged. Without them the view is
    derived from the same ``scoring_evidence`` proof API the review queue uses;
    runtime ``payload_scores`` are never read, and every unavailable assessment
    keeps a precise per-candidate reason.
    """
    if rows is not None:
        return [{'candidate_id': row.get('candidate_id'), 'valid': (row.get('validation') or {}).get('valid') is True,
                 'stage': row.get('stage'), 'executed': bool(row.get('eligible')),
                 'assessed': row.get('proof_ceiling') is not None,
                 'proof': row.get('proof_ceiling'), 'provenance': row.get('provenance') or {},
                 'evidence_refs': list(row.get('evidence_refs') or [])}
                for row in rows if isinstance(row, dict) and row.get('candidate_id')]
    provenance = _provenance(artifact, method)
    valid_ids = {str(row['candidate_id']) for row in _validation_rows(artifact, method) if row.get('valid') is True}
    rows_out = []
    for candidate in _candidate_queue(artifact, method):
        cid = candidate['candidate_id']
        execution = candidate_execution_evidence(artifact, cid, method)
        refs = _execution_evidence_refs(artifact, execution)
        row = {'candidate_id': cid, 'valid': str(cid) in valid_ids,
               'stage': candidate.get('stage'), 'executed': bool(execution),
               'assessed': False, 'proof': None,
               'provenance': provenance.get(cid, {}), 'evidence_refs': refs}
        # Revoking execution here keeps this view identical to the queue's
        # lifecycle/visit binding; proof is never assessed for an unbound row.
        bound = _visit_bound_execution(artifact, row, method)
        row['executed'] = bound
        if not execution:
            reason = 'candidate_not_executed'
        elif not bound:
            reason = f"candidate_{candidate_lifecycle_status(artifact, cid, method) or 'execution_unbound'}"
        elif not row['valid']:
            reason = 'candidate_validation_unavailable'
        elif row['stage'] not in {'exploit', 'bypass'}:
            reason = 'candidate_stage_not_exploit_or_bypass'
        elif not provenance.get(cid):
            reason = 'candidate_provenance_unavailable'
        else:
            from evaluation.scoring_evidence import candidate_base
            proof = candidate_base(artifact, cid, method, refs)
            row['assessed'] = proof is not None
            row['proof'] = proof
            reason = None if proof is not None else 'candidate_proof_evidence_unavailable'
        row['assessment_reason'] = reason
        rows_out.append(row)
    return rows_out


def _execution_rows(artifact, candidate_id, method):
    """Candidate execution rows from the shared identity contract."""
    return candidate_execution_rows(artifact, candidate_id, method)


def _visit_bound_execution(artifact, candidate_view_row, method):
    """Revoke execution when candidate lifecycle or visit binding contradicts it."""
    status = candidate_lifecycle_status(artifact, candidate_view_row['candidate_id'], method)
    if status in {'stopped_before_execution', 'budget_excluded', 'rejected', 'conflicting', 'request_failed'}:
        return False
    if not candidate_view_row.get('executed'):
        return False
    evidence = _execution_rows(artifact, candidate_view_row['candidate_id'], method)
    return bool(evidence)


def _requirements(artifact):
    state = _state(artifact)
    rows = state.get('model_call_requirements')
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    return None


def _generation_prompts(artifact):
    state = _state(artifact)
    rows = state.get('generation_prompts')
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _generated_payloads(artifact, method):
    state = _state(artifact)
    rows = state.get('generated_payloads', {}).get(method) or []
    return [row for row in rows if isinstance(row, dict)]


def _call_identifier(row, index):
    call_id = row.get('call_id')
    return str(call_id) if call_id else f'index:{index}'


def _call_failure_class(row):
    for field in ('failure_class', 'failure_kind'):
        value = row.get(field)
        if isinstance(value, str) and value:
            return value
    failure = row.get('failure')
    if isinstance(failure, dict):
        for field in ('failure_class', 'kind', 'type'):
            value = failure.get(field)
            if isinstance(value, str) and value:
                return value
    return None


def _call_is_operational_failure(row):
    if str(row.get('parse_status')) == 'provider_error':
        return True
    failure = _call_failure_class(row)
    return bool(failure) and is_provider_failure_reason(failure)


def _event_call_binding(event, call_index):
    """Map one run event to at most one experiment call, never across visits."""
    if not isinstance(event, dict):
        return None
    call_id = event.get('call_id')
    if call_id is not None:
        return str(call_id) if str(call_id) in {key for key, _row in call_index} else None
    role = event.get('role') or {'orchestrator': 'orchestrator',
                                 'payload_generator': 'payload_generator',
                                 'payload_validator': 'payload_generator'}.get(str(event.get('origin')))
    visit_id = event.get('visit_id')
    method = event.get('method') or event.get('selected_method')
    matches = []
    for key, row in call_index:
        if role and row.get('role') != role:
            continue
        if visit_id and row.get('visit_id') != visit_id:
            continue
        if method and row.get('method') not in (None, method) and row.get('scope') != 'run':
            continue
        matches.append(key)
    distinct = list(dict.fromkeys(matches))
    return distinct[0] if len(distinct) == 1 else None


def _event_rates(artifact):
    """Unique-call event rates; raw counts and unbound events are retained."""
    calls = _experiment_calls(artifact)
    call_index = [(_call_identifier(row, index), row) for index, row in enumerate(calls)]
    denominator = len(call_index)
    state = _state(artifact)
    fields = {'invalid_json_rate': 'invalid_json_events',
              'guardrail_activation_rate': 'guardrail_activations',
              'fallback_rate': 'fallback_events'}
    result = {}
    for name, field in fields.items():
        events = [event for event in state.get(field, []) if isinstance(event, dict)]
        if name == 'fallback_rate':
            # The rate is fallback USE per unique call; provider failures,
            # strict no-candidate events and budget exclusions are not uses.
            events = [event for event in events if _is_fallback_use_event(event)]
        bound, unbound = set(), 0
        for event in events:
            key = _event_call_binding(event, call_index)
            if key is None:
                unbound += 1
            else:
                bound.add(key)
        result[name] = {
            'numerator': len(bound), 'denominator': denominator,
            'raw_events': len(events), 'unbound_events': unbound,
            'bound_call_ids': sorted(bound),
        }
    result['unique_experiment_calls'] = denominator
    return result


def _usage_summary(rows):
    """Sum provider usage once per logical call; cache hits send no request."""
    totals = {'input': 0, 'output': 0, 'total': 0, 'cache_read': 0, 'cache_write': 0}
    reported = 0
    dispatched = 0
    complete = True
    for row in rows:
        if row.get('cache_hit'):
            continue
        dispatched += 1
        usage = row.get('provider_usage')
        if not isinstance(usage, dict) or not usage:
            complete = False
            continue
        input_tokens = usage.get('input_tokens')
        output_tokens = usage.get('output_tokens', usage.get('completion_tokens'))
        total_tokens = usage.get('total_tokens')
        if not isinstance(input_tokens, int) or isinstance(input_tokens, bool) or not isinstance(output_tokens, int) or isinstance(output_tokens, bool):
            complete = False
            continue
        cache_read, cache_write = _cache_tokens(usage, row.get('provider_usage_raw'))
        if cache_read is None:
            complete = False
            continue
        reported += 1
        totals['input'] += input_tokens
        totals['output'] += output_tokens
        totals['total'] += total_tokens if isinstance(total_tokens, int) and not isinstance(total_tokens, bool) else input_tokens + output_tokens
        totals['cache_read'] += cache_read
        totals['cache_write'] += cache_write or 0
    return {'totals': totals, 'reported': reported, 'dispatched': dispatched,
            'complete': complete and reported == dispatched}


def _cache_tokens(usage, raw_usage):
    from llm.cache_metrics import provider_cache_tokens
    _total, cached = provider_cache_tokens(usage, raw_usage if isinstance(raw_usage, dict) else None)
    write = usage.get('input_token_details', {}) if isinstance(usage.get('input_token_details'), dict) else {}
    cache_write = write.get('cache_write')
    if not (isinstance(cache_write, int) and not isinstance(cache_write, bool) and cache_write >= 0):
        cache_write = None
    return cached, cache_write


def _price_schedule(artifact):
    """Return the run's price schedule mapping (config first, then artifact)."""
    schedule = _config(artifact).get('token_price_schedule') or artifact.get('token_price_schedule')
    return schedule if isinstance(schedule, dict) else {}


def _cost_scope(method, calls):
    """Whether the priced calls are method-attributed or the whole run.

    ``run`` means the cost covers the run: no final method was selected, so
    every experiment call is priced as run scope, or the selected method has no
    call of its own in the priced set.  ``method`` means the priced set carries
    calls attributed to the selected method (call records written by the
    runtime carry ``method``; they do not always carry a ``scope`` tag).
    """
    if method is None:
        return 'run'
    return 'method' if any(row.get('method') == method for row in calls) else 'run'


def _cost_detail(schedule, used):
    """Describe what a cost value measures, never inflating an estimate.

    ``accounting_basis`` is ``unspecified`` when nothing was declared, the one
    declared basis when every priced row agrees, and ``mixed`` when a run
    combines a billed route with an API-equivalent estimate.
    """
    schedule_label = accounting_label(schedule)
    bases = {key: label['accounting_basis'] for key, label in used.items()}
    routes = {key: label['billing_route'] for key, label in used.items() if label['billing_route']}
    distinct = sorted(set(bases.values()))
    if not distinct:
        basis = schedule_label['accounting_basis']
        billing_route = schedule_label['billing_route']
    elif len(distinct) == 1:
        basis = distinct[0]
        row_routes = {label['billing_route'] for label in used.values() if label['billing_route']}
        billing_route = row_routes.pop() if len(row_routes) == 1 else (
            schedule_label['billing_route'] if not row_routes else None)
    else:
        basis, billing_route = 'mixed', None
    detail = {'accounting_basis': basis, 'billing_route': billing_route,
              'accounting_basis_by_price_key': bases}
    if routes:
        detail['billing_route_by_price_key'] = routes
    if schedule_label['notes']:
        detail['accounting_notes'] = schedule_label['notes']
    return detail


def _long_context_prices(entry, row, totals):
    """Apply only the row's declared long-context multipliers; never infer one."""
    long_context = row.get('long_context') if isinstance(row, dict) else None
    if not isinstance(long_context, dict):
        return entry, None
    if totals['input'] <= long_context['above_input_tokens']:
        return entry, None
    quantities = {'input': totals['input'] - totals['cache_read'] - totals['cache_write'],
                  'output': totals['output'], 'cache_read': totals['cache_read'],
                  'cache_write': totals['cache_write']}
    adjusted = dict(entry)
    for category, multiplier_key in LONG_CONTEXT_MULTIPLIERS.items():
        if not quantities.get(category):
            continue
        multiplier = long_context.get(multiplier_key)
        if multiplier is None:
            # The regime triggered but the schedule never stated this category.
            return entry, f'price_modifier_unavailable:{category}'
        if category in adjusted:
            adjusted[category] = adjusted[category] * multiplier
    return adjusted, None


def _cost(artifact, calls):
    """Return ``(cost, schedule_id, reason, usage, detail)`` for the call set.

    ``detail`` always carries ``accounting_basis`` (default ``unspecified``)
    and ``billing_route`` so an API-equivalent estimate is never presented as a
    billed charge.  Cost is never a fabricated zero: an empty selection over a
    run that did record experiment calls is an attribution failure.
    """
    schedule = _price_schedule(artifact)
    usage = _usage_summary(calls)
    used = {}
    mapped_routes = {}
    undocumented = []

    def result(cost=None, schedule_id=None, reason=None):
        detail = _cost_detail(schedule, used)
        if mapped_routes:
            detail['price_routes_used'] = dict(mapped_routes)
        if undocumented:
            detail['undocumented_price_rows'] = sorted(set(undocumented))
        return cost, schedule_id, reason, usage, detail

    if not schedule:
        return result(reason='token_price_schedule_missing')
    try:
        validate_token_price_schedule(schedule)
    except (ValueError, TypeError) as exc:
        return result(reason=f'token_price_schedule_invalid:{exc}')
    if not usage['complete']:
        return result(reason='incomplete_token_usage')
    started = (artifact.get('timing') or {}).get('started_at')
    try:
        if started and _timestamp(schedule['effective_at']) > _timestamp(started):
            return result(reason='schedule_not_effective_at_run')
    except (ValueError, TypeError):
        return result(reason='schedule_timestamp_invalid')
    if not calls and _experiment_calls(artifact):
        return result(reason='cost_call_attribution_unavailable')
    cost = 0.0
    for call in calls:
        if call.get('cache_hit'):
            continue
        provider, model = call.get('provider'), call.get('model')
        if not isinstance(provider, str) or not isinstance(model, str):
            return result(reason='call_model_identity_unavailable')
        try:
            entry, resolution = resolve_price_entry(
                schedule, provider, model, call.get('model_profile'))
        except KeyError:
            return result(reason='price_schedule_model_unavailable')
        label = accounting_label(schedule, resolution['price_key'])
        if resolution['mapped'] and label['accounting_basis'] != 'api_equivalent_estimate':
            # A mapped route is a proxy for the charged route; labelling it as
            # billed (or leaving it unspecified) would misreport the estimate.
            return result(reason='price_route_requires_api_equivalent_basis')
        used[resolution['price_key']] = label
        if resolution['mapped']:
            mapped_routes[resolution['matched_route']] = resolution['price_key']
        if 'accounting_basis' not in schedule and \
                'accounting_basis' not in schedule['prices'][resolution['price_key']]:
            undocumented.append(resolution['price_key'])
        if 'input' not in entry or 'output' not in entry:
            return result(reason='price_category_unavailable:input_or_output')
        totals = _usage_summary((call,))['totals']
        cache_read, cache_write = totals['cache_read'], totals['cache_write']
        uncached_input = totals['input'] - cache_read - cache_write
        if uncached_input < 0:
            return result(reason='inconsistent_usage_details')
        if cache_read and 'cache_read' not in entry:
            return result(reason='price_category_unavailable:cache_read')
        if cache_write and 'cache_write' not in entry:
            return result(reason='price_category_unavailable:cache_write')
        entry, modifier_reason = _long_context_prices(
            entry, schedule['prices'][resolution['price_key']], totals)
        if modifier_reason:
            return result(reason=modifier_reason)
        cost += (
            uncached_input * entry['input']
            + cache_read * entry.get('cache_read', 0)
            + cache_write * entry.get('cache_write', 0)
            + totals['output'] * entry['output']
        ) / 1_000_000
    return result(round(cost, 8), schedule.get('schedule_id'))


def _chain_context(artifact):
    state = _state(artifact)
    assessment = state.get('chain_assessment')
    routes = [row for row in state.get('chain_history', []) if isinstance(row, dict)]
    return assessment if isinstance(assessment, dict) else None, routes


def _supported_failure(artifact, method, visit_id):
    """Failure of that method visit supported by evidence, not by absence alone."""
    state = _state(artifact)
    decisions = [d for d in state.get('verifier_history', [])
                 if isinstance(d, dict) and d.get('agent_id') == method
                 and (not visit_id or d.get('visit_id') == visit_id)]
    if decisions and all(d.get('decision') in {'not_confirmed', 'unverified'} for d in decisions):
        return True
    lifecycle = [row for row in state.get('candidate_lifecycle', []) if isinstance(row, dict)
                 and row.get('method') == method and (not visit_id or row.get('visit_id') == visit_id)]
    if any(row.get('status') in {'stopped_before_execution', 'rejected'} for row in lifecycle):
        return True
    return False


def _attempted_methods(artifact):
    state = _state(artifact)
    attempted = set()
    for decision in state.get('verifier_history', []):
        if isinstance(decision, dict) and decision.get('agent_id') in ALL_METHOD_AGENTS:
            attempted.add(decision['agent_id'])
    for row in state.get('candidate_lifecycle', []):
        if isinstance(row, dict) and row.get('status') in {'executed', 'stopped_before_execution'} \
                and row.get('method') in ALL_METHOD_AGENTS:
            attempted.add(row['method'])
    for row in state.get('response_evidence', []):
        if isinstance(row, dict) and (row.get('agent_id') or row.get('method')) in ALL_METHOD_AGENTS:
            attempted.add(row.get('agent_id') or row.get('method'))
    return attempted


def _ordered_selection_stream(artifact):
    """Ordered accepted selections and rejected model choices (B receipts)."""
    state = _state(artifact)
    entries = []
    for index, decision in enumerate(_selection_decisions(artifact)):
        entries.append({'kind': 'decision', 'origin': _decision_origin(decision),
                        'method': decision.get('method'), 'visit_id': decision.get('visit_id'),
                        'payload': decision,
                        'order': (str(decision.get('selected_at') or ''), index)})
    rejections = state.get('selection_rejections') if isinstance(state.get('selection_rejections'), list) else []
    for index, row in enumerate(rejections):
        if not isinstance(row, dict):
            continue
        origin = _decision_origin(row)
        source = str(row.get('decision_origin') or row.get('source') or '').strip()
        if origin is None:
            origin = {'model': 'model', 'model_orchestrator': 'model', 'forced': 'forced',
                      'deterministic_fallback': 'deterministic_fallback',
                      'akg_route': 'route', 'route': 'route'}.get(source)
        entries.append({'kind': 'rejection', 'origin': origin, 'method': row.get('method'),
                        'visit_id': row.get('visit_id'), 'payload': row,
                        'order': (str(row.get('rejected_at') or ''), 100000 + index)})
    entries.sort(key=lambda entry: (entry['order'][0], entry['order'][1]))
    return entries


def _first_choice_metric(metrics, artifact, method):
    decisions = _selection_decisions(artifact)
    stream = _ordered_selection_stream(artifact)
    model_entries = [entry for entry in stream if entry['origin'] == 'model']
    rejected = [entry for entry in stream if entry['kind'] == 'rejection' and entry['origin'] == 'model']
    metrics.count('model_selection_decisions', len(model_entries), denominator=len(stream),
                  population='selection_decisions_and_model_rejections', method=method)
    metrics.count('rejected_model_selections', len(rejected), denominator=len(model_entries),
                  population='model_origin_decisions', origin='model', method=method)
    metrics.count('deterministic_selection_decisions',
                  sum(1 for entry in stream if entry['origin'] == 'deterministic_fallback'),
                  denominator=len(stream), population='selection_decisions', method=method)
    metrics.count('forced_selection_decisions',
                  sum(1 for entry in stream if entry['origin'] == 'forced'),
                  denominator=len(stream), population='selection_decisions', method=method)
    metrics.count('route_selection_decisions',
                  sum(1 for entry in stream if entry['origin'] == 'route'),
                  denominator=len(stream), population='selection_decisions', method=method)
    if not model_entries:
        metrics.put('first_choice_accuracy', None, population='first_model_selection_decision',
                    method=method, reason='forced_or_deterministic_selection' if stream else 'no_selection_decision')
        return
    first = model_entries[0]
    chosen = first.get('method')
    if first['kind'] == 'rejection':
        payload = first['payload']
        if isinstance(payload.get('observations'), dict) and payload.get('profile_sha256'):
            selection = {**payload, 'method': chosen, 'selection_source': payload.get('source'),
                         'decision_origin': payload.get('decision_origin') or 'model'}
            top, reason, detail = ranking_comparison(artifact, selection)
            if top is None:
                metrics.put('first_choice_accuracy', None, population='first_model_selection_decision',
                            origin='model', method=chosen, visit_id=first['visit_id'],
                            reason=reason, detail={**detail, 'chosen_method': chosen})
                return
            statuses = payload.get('precondition_status') if isinstance(payload.get('precondition_status'), dict) else {}
            required = payload.get('required_preconditions') or []
            viable = all(statuses.get(key) == 'true' for key in required) if required else True
            numerator = 1 if viable and chosen in top else 0
            metrics.put('first_choice_accuracy', float(numerator), numerator=numerator, denominator=1,
                        population='first_model_selection_decision', origin='model', method=chosen,
                        visit_id=first['visit_id'],
                        detail={'chosen_method': chosen, 'top_methods': sorted(top),
                                'rejected_choice': True})
            return
        metrics.put('first_choice_accuracy', None, population='first_model_selection_decision',
                    origin='model', method=chosen, visit_id=first['visit_id'],
                    reason='rejected_choice_ranking_snapshot_unavailable',
                    detail={'chosen_method': chosen, 'rejected_choice': True,
                            'reason_code': payload.get('reason_code')})
        return
    top, reason, detail = ranking_comparison(artifact, first['payload'])
    if top is None:
        metrics.put('first_choice_accuracy', None, population='first_model_selection_decision',
                    origin='model', method=chosen, visit_id=first['visit_id'],
                    reason=reason, detail={**detail, 'chosen_method': chosen})
        return
    numerator = 1 if chosen in top else 0
    metrics.put('first_choice_accuracy', float(numerator), numerator=numerator, denominator=1,
                population='first_model_selection_decision', origin='model', method=chosen,
                visit_id=first['visit_id'], detail={'chosen_method': chosen, 'top_methods': sorted(top)})


def _adaptation_metric(metrics, artifact, method):
    stream = _ordered_selection_stream(artifact)
    opportunities = 0
    adapted = 0
    for previous, current in zip(stream, stream[1:]):
        if current['origin'] != 'model':
            continue
        if previous['kind'] == 'rejection' and previous['origin'] == 'model':
            supported = True
        elif previous['kind'] == 'decision':
            supported = bool(previous['visit_id']) and _supported_failure(
                artifact, previous['method'], previous['visit_id'])
        else:
            supported = False
        if not supported:
            continue
        opportunities += 1
        if current.get('method') != previous.get('method'):
            adapted += 1
    metrics.count('adaptation_opportunities', opportunities, denominator=len(stream),
                  population='model_reselection_after_supported_failure', method=method)
    rate = _rate(adapted, opportunities)
    metrics.put('adaptation_rate', rate, numerator=adapted, denominator=opportunities,
                population='model_reselection_after_supported_failure', origin='model',
                method=method, reason='no_adaptation_opportunity')


def _akg_metrics(metrics, artifact, method, components):
    assessment, routes = _chain_context(artifact)
    metrics.count('akg_routes_recorded', len(routes), population='recorded_chain_routes', method=method)
    if _config(artifact).get('experiment_condition') != 'akg_guided_hybrid':
        metrics.put('akg_path_validity', None, numerator=0, denominator=len(routes),
                    population='recorded_chain_routes', method=method, reason='not_applicable_non_akg')
        metrics.count('akg_routes_valid', None, denominator=len(routes),
                      population='recorded_chain_routes', method=method,
                      reason='not_applicable_non_akg')
        return
    if assessment is not None and assessment.get('assessed') is not True:
        metrics.put('akg_path_validity', None, numerator=None, denominator=len(routes),
                    population='recorded_chain_routes', method=method,
                    reason=assessment.get('reason') or assessment.get('status') or 'chain_assessment_unavailable')
        metrics.count('akg_routes_valid', None, denominator=len(routes),
                      population='recorded_chain_routes', method=method,
                      reason=assessment.get('reason') or 'chain_assessment_unavailable')
        return
    if not routes:
        metrics.put('akg_path_validity', None, numerator=0, denominator=0,
                    population='recorded_chain_routes', method=method, reason='no_recorded_route_trace')
        metrics.count('akg_routes_valid', None, denominator=0,
                      population='recorded_chain_routes', method=method,
                      reason='no_recorded_route_trace')
        return
    from evaluation.scoring_evidence import edge_for, prerequisite_proof
    valid = 0
    for route in routes:
        edge = edge_for(route)
        if not edge or set(route.get('preconditions', [])) != set(edge.get('preconditions', [])):
            continue
        if prerequisite_proof(artifact, route):
            valid += 1
    metrics.count('akg_routes_valid', valid, denominator=len(routes), population='recorded_chain_routes', method=method)
    metrics.put('akg_path_validity', _rate(valid, len(routes)), numerator=valid, denominator=len(routes),
                population='recorded_chain_routes', method=method)


def _payload_metrics(metrics, artifact, method, view, calls):
    state = _state(artifact)
    validations = _validation_rows(artifact, method)
    valid = [row for row in view if row['valid'] and row['stage'] in {'exploit', 'bypass'}]
    executed = [row for row in view if row['executed'] and _visit_bound_execution(artifact, row, method)]
    assessed = [row for row in executed if row['assessed']]
    confirmed = [row for row in assessed if (row['proof'] or 0) >= 3]
    metrics.put('payload_validity_rate', _rate(len(valid), len(validations)), numerator=len(valid),
                denominator=len(validations), population='validated_queue_rows',
                origin='all', method=method, reason='no_validated_candidates')
    success_rate = _rate(len(confirmed), len(valid))
    reason = None
    if not valid:
        reason = 'no_valid_exploit_candidate'
    elif not executed:
        reason = 'no_executed_candidate'
    elif len(assessed) != len(executed):
        reason = 'unassessable_executed_candidate'
    unassessed = [{'candidate_id': row['candidate_id'],
                   'reason': row.get('assessment_reason') or 'candidate_proof_evidence_unavailable'}
                  for row in executed if not row['assessed']]
    metrics.put('payload_execution_success_rate', success_rate if reason is None else None,
                numerator=len(confirmed), denominator=len(valid), population='valid_exploit_bypass_candidates',
                origin='all', method=method, reason=reason, coverage=_rate(len(assessed), len(executed)),
                detail={'unassessed_candidates': unassessed} if unassessed else None)
    metrics.put('assessable_executed_confirmation_rate', _rate(len(confirmed), len(assessed)),
                numerator=len(confirmed), denominator=len(assessed),
                population='assessable_executed_candidates', origin='all', method=method,
                reason='no_assessable_executed_candidate')
    _model_payload_metrics(metrics, artifact, method, view, calls)
    _improvement_metric(metrics, artifact, method, executed)
    _alignment_metric(metrics, artifact, method, executed)


def _generation_requirements(artifact, method):
    """Unique payload-generation opportunities, generation receipt preferred."""
    state = _state(artifact)
    coverage = artifact.get('payload_generation_opportunity_coverage')
    if not isinstance(coverage, dict):
        coverage = state.get('payload_generation_opportunity_coverage')
    coverage = coverage if isinstance(coverage, dict) else {}
    coverage_status = str(coverage.get('status') or '')
    coverage_reason = str(coverage.get('reason') or '') or None
    exported_generation = artifact.get('payload_generation_opportunities')
    if not isinstance(exported_generation, list):
        exported_generation = state.get('payload_generation_opportunities')
    exported_validation = artifact.get('payload_validation_opportunities')
    if not isinstance(exported_validation, list):
        exported_validation = state.get('payload_validation_opportunities')
    if isinstance(exported_generation, list) and (exported_generation or exported_validation):
        generation_rows = [row for row in exported_generation
                           if isinstance(row, dict) and row.get('role', 'payload_generator') == 'payload_generator'
                           and row.get('method') in (None, method)]
        validation_rows = [row for row in (exported_validation or [])
                           if isinstance(row, dict) and row.get('role', 'payload_generator') == 'payload_generator'
                           and row.get('method') in (None, method)]
        if coverage_status == 'unavailable':
            return None, validation_rows, coverage_reason or 'generation_receipt_missing'
        if coverage_status == 'not_applicable':
            return None, validation_rows, coverage_reason or 'payload_generation_not_applicable'
        if not generation_rows and validation_rows:
            # A validation receipt proves an opportunity existed; an empty
            # generation export is missing coverage, not a measured zero.
            return None, validation_rows, coverage_reason or 'generation_receipt_missing'
        if not generation_rows and exported_generation:
            return [], validation_rows, coverage_reason
        return generation_rows, validation_rows, coverage_reason
    records = _requirements(artifact)
    if records is None:
        return None, [], coverage_reason or 'generation_requirements_unavailable'
    if coverage_status in {'unavailable', 'not_applicable'}:
        return None, [], coverage_reason or 'generation_receipt_missing'
    selected = [row for row in records
                if row.get('role', 'payload_generator') == 'payload_generator'
                and row.get('method') in (None, method)]
    by_opportunity = {}
    for row in selected:
        key = str(row.get('opportunity_id') or f"{row.get('method')}:{row.get('visit_id')}")
        stage = 'validation' if str(row.get('receipt_stage') or 'generation') == 'validation' else 'generation'
        by_opportunity.setdefault(key, {}).setdefault(stage, row)
    generation_rows = [bucket['generation'] for bucket in by_opportunity.values() if 'generation' in bucket]
    validation_rows = [bucket['validation'] for bucket in by_opportunity.values() if 'validation' in bucket]
    if not generation_rows and validation_rows:
        return None, validation_rows, coverage_reason or 'generation_receipt_missing'
    return generation_rows, validation_rows, coverage_reason


def _model_payload_metrics(metrics, artifact, method, view, calls):
    state = _state(artifact)
    opportunity_rows, validation_receipts, opportunity_coverage_reason = _generation_requirements(artifact, method)
    generation_available = opportunity_rows is not None
    requirements = opportunity_rows or []
    generation_calls = [row for row in calls if row.get('role') == 'payload_generator']
    prompts = [row for row in _generation_prompts(artifact) if row.get('method') in (None, method)]
    parsed = set()
    validated = set()
    if any(isinstance(row.get('parsed_candidate_ids'), list) for row in [*requirements, *validation_receipts]):
        for row in requirements:
            parsed.update(str(cid) for cid in row.get('parsed_candidate_ids') or [])
        for row in validation_receipts:
            parsed.update(str(cid) for cid in row.get('parsed_candidate_ids') or [])
        for row in [*requirements, *validation_receipts]:
            validated.update(str(cid) for cid in row.get('valid_candidate_ids') or [])
    else:
        provenance = _provenance(artifact, method)
        for candidate_id, details in provenance.items():
            if _origin_kind(details) in MODEL_ORIGIN_KINDS:
                parsed.add(str(candidate_id))
        for row in _validation_rows(artifact, method):
            if row.get('valid') is True and _origin_kind(provenance.get(row['candidate_id'])) in MODEL_ORIGIN_KINDS:
                validated.add(str(row['candidate_id']))
        for candidate in _generated_payloads(artifact, method):
            if candidate.get('candidate_id') is not None:
                parsed.add(str(candidate['candidate_id']))
    model_view = [row for row in view if str(row['candidate_id']) in parsed]
    executed_model = [row for row in model_view if row['executed']
                      and _visit_bound_execution(artifact, row, method)]
    assessable_model = [row for row in executed_model if row['assessed']]
    confirmed_model = [row for row in assessable_model if (row['proof'] or 0) >= 3]
    have_generation_evidence = bool(validation_receipts or requirements or generation_calls or prompts or parsed)
    generation_reason = None if have_generation_evidence else 'generation_evidence_unavailable'
    opportunity_reason = (None if generation_available else
                          opportunity_coverage_reason or 'generation_receipt_missing') or generation_reason
    metrics.count('generation_opportunities',
                  len(requirements) if generation_available else None,
                  population='payload_generation_opportunities', method=method,
                  reason=opportunity_reason,
                  detail={'validation_receipts_present': len(validation_receipts)})
    metrics.count('generation_calls', len(generation_calls), denominator=None,
                  population='payload_generator_calls', method=method,
                  reason='llm_performance_unavailable' if not isinstance(artifact.get('llm_performance'), list) else None)
    def _reason(row):
        return str(row.get('failure_reason') or row.get('failure_reason_detail')
                   or row.get('reason') or '')
    refusal_reasons = {'guardrail_refusal', 'refusal', 'model_refusal'}
    refusals = sum(1 for row in requirements if _reason(row) in refusal_reasons)
    invalid = sum(1 for row in requirements
                  if _reason(row) and _reason(row) not in refusal_reasons
                  and is_model_output_failure_reason(_reason(row)))
    provider = sum(1 for row in requirements if is_provider_failure_reason(_reason(row)))
    if not requirements:
        if prompts:
            def _prompt_reason(row):
                return str(row.get('failure_reason') or row.get('fallback_reason') or '')
            refusals = sum(1 for row in prompts if _prompt_reason(row) in refusal_reasons)
            invalid = sum(1 for row in prompts
                          if _prompt_reason(row) and _prompt_reason(row) not in refusal_reasons
                          and is_model_output_failure_reason(_prompt_reason(row)))
        if not generation_available and not generation_calls:
            # Validation-only coverage: failure classes come from the joined
            # validation receipts, not from an invented zero.
            validation_reasons = [_reason(row) for row in validation_receipts]
            refusals = sum(1 for reason in validation_reasons if reason in refusal_reasons)
            invalid = sum(1 for reason in validation_reasons
                          if reason and reason not in refusal_reasons
                          and is_model_output_failure_reason(reason))
            provider = sum(1 for reason in validation_reasons if is_provider_failure_reason(reason))
        else:
            provider = sum(1 for row in generation_calls if _call_is_operational_failure(row))
            for row in generation_calls:
                if _call_is_operational_failure(row):
                    continue
                failure = _call_failure_class(row)
                if failure in refusal_reasons:
                    refusals += 1
                elif str(row.get('parse_status')) in {'invalid', 'incomplete'}:
                    invalid += 1
    metrics.count('model_refusals', refusals if have_generation_evidence else None,
                  population='payload_generation_opportunities', method=method, reason=generation_reason)
    metrics.count('invalid_model_outputs', invalid if have_generation_evidence else None,
                  population='payload_generation_opportunities', method=method, reason=generation_reason)
    metrics.count('provider_failures', provider if have_generation_evidence else None,
                  population='payload_generation_opportunities', method=method, reason=generation_reason)
    metrics.count('parsed_model_candidates', len(parsed) if parsed or have_generation_evidence else None,
                  population='parsed_model_origin_candidates', origin='model', method=method,
                  reason=generation_reason if not parsed else None)
    metrics.put('model_payload_validity_rate', _rate(len(validated), len(parsed)),
                numerator=len(validated), denominator=len(parsed),
                population='parsed_model_origin_candidates', origin='model', method=method,
                reason='no_parsed_model_candidates')
    metrics.count('valid_model_candidates', len(validated) if parsed else None,
                  denominator=len(parsed), population='parsed_model_origin_candidates',
                  origin='model', method=method, reason='no_parsed_model_candidates')
    metrics.count('executed_model_candidates', len(executed_model) if parsed else None,
                  denominator=len(parsed), population='model_origin_candidates', origin='model',
                  method=method, reason='no_parsed_model_candidates')
    metrics.count('assessable_executed_model_candidates', len(assessable_model) if executed_model else None,
                  denominator=len(executed_model), population='executed_model_candidates',
                  origin='model', method=method, reason='no_executed_model_candidate')
    metrics.count('confirmed_model_candidates', len(confirmed_model) if assessable_model else None,
                  denominator=len(assessable_model), population='assessable_executed_model_candidates',
                  origin='model', method=method, reason='no_assessable_executed_model_candidate')


def _improvement_metric(metrics, artifact, method, executed):
    model = {row['candidate_id']: row for row in executed
             if _origin_kind(row.get('provenance')) in MODEL_ORIGIN_KINDS}
    static = {row['candidate_id']: row for row in executed
              if _origin_kind(row.get('provenance')) in STATIC_ORIGIN_KINDS}
    if not model:
        metrics.put('payload_improvement_rate', None, numerator=0, denominator=0,
                    population='method_visits_with_model_and_static_execution', origin='model',
                    method=method, reason='no_executed_model_candidate')
        return
    assessed_model = [row for row in model.values() if row['assessed']]
    if not assessed_model:
        metrics.put('payload_improvement_rate', None, numerator=0, denominator=0,
                    population='method_visits_with_model_and_static_execution', origin='model',
                    method=method, reason='model_candidate_unassessable')
        return
    if not static:
        metrics.put('payload_improvement_rate', None, numerator=0, denominator=0,
                    population='method_visits_with_model_and_static_execution', origin='model',
                    method=method, reason='no_comparable_static_baseline')
        return
    assessed_static = [row for row in static.values() if row['assessed']]
    if not assessed_static:
        metrics.put('payload_improvement_rate', None, numerator=0, denominator=0,
                    population='method_visits_with_model_and_static_execution', origin='model',
                    method=method, reason='static_baseline_unassessable')
        return
    best_model = max((row['proof'] or 0) for row in assessed_model)
    best_static = max((row['proof'] or 0) for row in assessed_static)
    improved = int(best_model > best_static)
    metrics.put('payload_improvement_rate', float(improved), numerator=improved, denominator=1,
                population='method_visits_with_model_and_static_execution', origin='model',
                method=method, detail={'best_model_proof': best_model, 'best_static_proof': best_static})


def _alignment_metric(metrics, artifact, method, executed):
    verdicts = artifact.get('method_alignment_verdicts')
    if not isinstance(verdicts, list):
        verdicts = _state(artifact).get('method_alignment_verdicts')
    verdicts = verdicts if isinstance(verdicts, list) else []
    candidates = [row for row in executed if row['assessed']]
    aligned = assessed = 0
    for candidate in candidates:
        execution = _execution_rows(artifact, candidate['candidate_id'], method)
        visits = {row.get('visit_id') for _index, row in execution}
        refs = {f'#/final_state/response_evidence/{index}' for index, _row in execution}
        matching = [
            row for row in verdicts
            if isinstance(row, dict)
            and row.get('definition_version') == 'method-alignment.v1'
            and row.get('candidate_id') == candidate['candidate_id']
            and row.get('method') == method
            and row.get('visit_id') and row['visit_id'] in visits
            and type(row.get('aligned')) is bool
            and row.get('source') in {'human_review', 'independent_evaluator'}
            and isinstance(row.get('reviewer_id'), str) and row['reviewer_id'].strip()
            and isinstance(row.get('reason'), str) and row['reason'].strip()
            and isinstance(row.get('evidence_refs'), list) and row['evidence_refs']
            and all(isinstance(ref, str) for ref in row['evidence_refs'])
            and set(row['evidence_refs']) <= refs
        ]
        values = {row['aligned'] for row in matching}
        if len(values) != 1:
            continue
        assessed += 1
        aligned += int(values.pop())
    metrics.put(
        'method_alignment_rate', _rate(aligned, assessed),
        numerator=aligned, denominator=assessed,
        population='independently_assessed_method_alignment_verdicts', method=method,
        coverage=_rate(assessed, len(candidates)),
        reason=('no_executed_candidate' if not executed else
                'validator_does_not_record_separate_alignment_verdict'),
        detail={'definition_version': 'method-alignment.v1',
                'executed_assessable_candidates': len(candidates)},
    )


def _exploit_flags(metrics, components, method, artifact):
    exploit = components.get('Sexploit') if isinstance(components, dict) else None
    chain = components.get('Schain') if isinstance(components, dict) else None
    graded = bool(components)
    metrics.put('full_exploit_flag', None if exploit is None else float(int(exploit >= 3)),
                numerator=None if exploit is None else int(exploit >= 3), denominator=1,
                population='final_method_exploit_component', method=method,
                reason=None if exploit is not None else (
                    'exploit_evidence_unavailable' if graded else 'graded_component_evidence_unavailable'))
    metrics.put('chain_enabled_exploit_flag', None if chain is None else float(int(chain >= 3)),
                numerator=None if chain is None else int(chain >= 3), denominator=1,
                population='final_method_chain_component', method=method,
                reason=None if chain is not None else (
                    'chain_evidence_unavailable' if graded else 'graded_component_evidence_unavailable'))
    from evaluation.scoring_evidence import verified_dependencies
    assessment, _routes = _chain_context(artifact)
    try:
        route_count = len(verified_dependencies(artifact))
        reason = None
    except (ValueError, TypeError, KeyError):
        route_count, reason = None, 'chain_dependency_evidence_unavailable'
    metrics.count('chain_route_count', route_count, population='verified_completed_routes',
                  method=method, reason=reason)


def _nonnegative_int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _captured_physical_totals(counters):
    """Return ``(total, phase_sum, reason)`` for provably captured run totals.

    A counter proves its physical totals only when its capture receipt says
    ``complete`` or ``partial``, the run total is a valid non-negative integer,
    every phase (and, when recorded, role) bucket is a valid non-negative
    integer, and the phase buckets sum to the total. ``partial`` attribution is
    deliberately accepted: an unattributed dispatch still counts toward the
    captured total, but it never makes attribution complete. Missing, unknown,
    invalid or non-conserving counters keep the totals unavailable rather than
    guessed.
    """
    if not isinstance(counters, dict) or not counters:
        return None, None, 'http_request_counters_unavailable'
    status = str(counters.get('capture_status') or '')
    if status not in {'complete', 'partial'}:
        # Only an actual capture receipt may prove totals. A missing/unknown
        # status is not a capture, and an explicitly unavailable one stays named.
        reason = 'http_request_capture_unavailable' if status == 'unavailable' \
            else 'http_request_capture_status_unknown'
        return None, None, reason
    total = _nonnegative_int(counters.get('total_requests'))
    if total is None:
        return None, None, 'http_counter_total_invalid'
    by_phase = counters.get('by_phase')
    if not isinstance(by_phase, dict) or not by_phase:
        return None, None, 'http_counter_phase_totals_invalid'
    buckets = [_nonnegative_int(value) for value in by_phase.values()]
    if any(value is None for value in buckets):
        return None, None, 'http_counter_phase_totals_invalid'
    phase_sum = sum(value for value in buckets if value is not None)
    if phase_sum != total:
        return None, phase_sum, 'http_counter_conservation_mismatch'
    by_role = counters.get('by_role')
    if by_role is not None:
        # A recorded role split must agree with the captured total. Missing
        # role buckets are old schema, not proof of loss; contradictory ones
        # mean the capture receipt cannot be trusted.
        if not isinstance(by_role, dict):
            return None, phase_sum, 'http_counter_role_totals_invalid'
        if by_role:
            role_buckets = [_nonnegative_int(value) for value in by_role.values()]
            if any(value is None for value in role_buckets):
                return None, phase_sum, 'http_counter_role_totals_invalid'
            if sum(value for value in role_buckets if value is not None) != total:
                return None, phase_sum, 'http_counter_role_conservation_mismatch'
    return total, phase_sum, None


def _counter_reading(counters, key, *, missing_reason, invalid_reason, totals_available, totals_reason):
    """Read one independent physical counter only when run totals are proven."""
    if not totals_available:
        return None, totals_reason or 'http_request_counters_unavailable'
    raw = counters.get(key) if isinstance(counters, dict) else None
    value = _nonnegative_int(raw)
    if value is not None:
        return value, None
    return None, missing_reason if raw is None else invalid_reason


def _attempt_metrics(metrics, artifact, method, executed):
    state = _state(artifact)
    rows = state.get('response_evidence')
    available = isinstance(rows, list)
    order = []
    if available:
        for row in rows:
            if not isinstance(row, dict):
                continue
            if (row.get('agent_id') or row.get('method')) not in (None, method):
                continue
            cid = row.get('candidate_id')
            if cid is None or cid in order:
                continue
            if not candidate_execution_rows(artifact, cid, method):
                continue
            order.append(cid)
    executed_ids = {row['candidate_id'] for row in executed}
    by_id = {row['candidate_id']: row for row in executed}
    complete = available and set(order) == executed_ids
    attempts = None
    if complete:
        attempts = next((index + 1 for index, cid in enumerate(order)
                         if by_id[cid]['assessed'] and (by_id[cid]['proof'] or 0) >= 3), None)
    attempts_reason = None
    if not available:
        attempts_reason = 'response_evidence_unavailable'
    elif not complete:
        attempts_reason = 'execution_order_incomplete'
    elif attempts is None:
        attempts_reason = 'no_assessable_success' if any(row['assessed'] for row in executed) \
            else 'no_assessable_candidate'
    metrics.put('attempts_to_success', attempts, numerator=attempts,
                denominator=len(order) if available else None,
                population='distinct_executed_candidate_order', method=method,
                reason=attempts_reason,
                coverage=_rate(len(executed_ids & set(order)), len(executed_ids)) if executed_ids else None)
    counters = artifact.get('http_request_counters') or state.get('http_request_counters')
    counters = counters if isinstance(counters, dict) else None
    counter_status = str((counters or {}).get('capture_status') or '')
    counter_complete = bool(counters) and (counters.get('complete') is True or counter_status == 'complete')
    by_phase = counters.get('by_phase') if isinstance((counters or {}).get('by_phase'), dict) else {}
    per_method_map = (counters or {}).get('per_method')
    per_method = per_method_map.get(method) if isinstance(per_method_map, dict) else None
    per_method = per_method if isinstance(per_method, dict) else {}
    method_by_role = per_method.get('by_role') if isinstance(per_method.get('by_role'), dict) else {}
    probe_rows = sum(1 for row in (rows or []) if isinstance(row, dict)
                     and row.get('identity_kind') in {'probe_candidate'}
                     and (row.get('agent_id') or row.get('method')) in (None, method))
    verifier_rows = sum(1 for row in (rows or []) if isinstance(row, dict)
                        and row.get('identity_kind') in {'derived_control', 'independent_control'}
                        and (row.get('agent_id') or row.get('method')) in (None, method))
    total_rows = sum(1 for row in (rows or []) if isinstance(row, dict)
                     and (row.get('agent_id') or row.get('method')) in (None, method))
    controls = state.get('probe_controls', {}).get(method) if isinstance(state.get('probe_controls'), dict) else None
    control_requests = None
    control_events = []
    if isinstance(controls, dict):
        for key in ('physical_requests_used', 'requests_used'):
            control_requests = _as_int(controls.get(key))
            if control_requests is not None:
                break
        control_events = [row for row in controls.get('control_events', []) or [] if isinstance(row, dict)]
    # Per-method populations only: a run-wide by_role total is not this
    # method's request count. Fall back to frozen control accounting with its
    # source named, never to the unrelated run total.
    probe_requests = _as_int(method_by_role.get('detection_control'))
    probe_source = 'per_method_http_counter' if probe_requests is not None else None
    if probe_requests is None:
        probe_requests = control_requests
        probe_source = 'frozen_detection_control_accounting' if probe_requests is not None else None
    verifier_requests = _as_int(method_by_role.get('candidate_verification'))
    verifier_source = 'per_method_http_counter' if verifier_requests is not None else None
    if verifier_requests is None:
        sent = sum(1 for event in control_events
                   if event.get('control_class') == 'candidate_verification'
                   and event.get('status') in {'sent', 'failed'})
        verifier_requests = sent if control_events else None
        verifier_source = 'frozen_verification_control_events' if verifier_requests is not None else None
    oracle_declared = bool(_config(artifact).get('scoring_oracles'))
    oracle_unattributed = bool(oracle_declared and counter_complete
                               and _as_int(by_phase.get('verification')) in (None, 0))
    lifecycle_rows = state.get('candidate_lifecycle') if isinstance(state.get('candidate_lifecycle'), list) else []
    failed_requests = sum(1 for row in lifecycle_rows if isinstance(row, dict)
                          and row.get('method') in (None, method)
                          and str(row.get('status')) == 'stopped_before_execution'
                          and str(row.get('reason')) == 'request_failed')
    metrics.count('candidate_attempts', len(executed_ids),
                  population='distinct_executed_candidates', method=method,
                  detail={'repeat_index': _config(artifact).get('repeat_index')})
    metrics.count('evidence_requests_total', total_rows, population='method_evidence_rows',
                  method=method, detail={'note': 'row count, not physical requests'})
    physical_total, phase_sum, totals_reason = _captured_physical_totals(counters)
    totals_available = physical_total is not None
    physical_retries, retry_reason = _counter_reading(
        counters, 'retries', missing_reason='http_counter_retries_missing',
        invalid_reason='http_counter_retries_invalid', totals_available=totals_available,
        totals_reason=totals_reason)
    physical_redirects, redirect_reason = _counter_reading(
        counters, 'redirect_hops', missing_reason='http_counter_redirects_missing',
        invalid_reason='http_counter_redirects_invalid', totals_available=totals_available,
        totals_reason=totals_reason)
    physical_failures, failure_reason = _counter_reading(
        counters, 'failed_requests', missing_reason='http_counter_failures_missing',
        invalid_reason='http_counter_failures_invalid', totals_available=totals_available,
        totals_reason=totals_reason)
    attribution_reason = None if counter_complete else (
        'http_request_counters_unavailable' if not counters else f'http_request_capture_{counter_status or "partial"}')
    metrics.count('physical_requests_total', physical_total,
                  population='run_physical_http_requests', method=method, reason=totals_reason,
                  detail={'counter_policy_version': (counters or {}).get('policy_version'),
                          'capture_status': counter_status or None,
                          'attribution_complete': counter_complete,
                          'attribution_reason': attribution_reason,
                          'run_totals_available': totals_available,
                          'phase_total_requests': phase_sum,
                          'unattributed_requests': _nonnegative_int((counters or {}).get('unattributed_requests')),
                          'observed_total_requests': _nonnegative_int((counters or {}).get('total_requests')),
                          'repeat_index': _config(artifact).get('repeat_index')})
    metrics.count('request_retries', physical_retries,
                  population='run_physical_http_requests', method=method, reason=retry_reason)
    metrics.count('redirect_hops', physical_redirects,
                  population='run_physical_http_requests', method=method, reason=redirect_reason)
    metrics.count('failed_requests', physical_failures,
                  population='run_physical_http_requests', method=method, reason=failure_reason)
    metrics.count('probe_requests', probe_requests, population='detection_control_requests',
                  method=method, reason=('method_request_counter_unavailable'
                      if probe_requests is None else None),
                  detail={'counter_source': probe_source, 'evidence_probe_rows': probe_rows})
    metrics.count('verifier_control_requests', verifier_requests,
                  population='candidate_verification_control_requests', method=method,
                  reason=('method_request_counter_unavailable' if verifier_requests is None else
                          'verification_requests_unattributed' if oracle_unattributed else None),
                  detail={'counter_source': verifier_source, 'evidence_verifier_rows': verifier_rows,
                          'run_verification_phase_requests': _as_int(by_phase.get('verification'))})
    metrics.count('failed_request_candidates', failed_requests if isinstance(state.get('candidate_lifecycle'), list) else None,
                  population='attempted_candidates_without_response', method=method,
                  reason='candidate_lifecycle_unavailable')


def _telemetry_metrics(metrics, artifact, calls, method, view):
    rates = _event_rates(artifact)
    for name in ('invalid_json_rate', 'guardrail_activation_rate', 'fallback_rate'):
        entry = rates[name]
        value = _rate(entry['numerator'], entry['denominator'])
        metrics.put(name, value, numerator=entry['numerator'], denominator=entry['denominator'],
                    population='unique_experiment_model_calls', method=method,
                    reason='no_experiment_calls', detail={'raw_events': entry['raw_events'],
                        'unbound_events': entry['unbound_events'], 'rate_definition_version': RATE_DEFINITION_VERSION})
    cost, schedule_id, cost_reason, usage, cost_detail = _cost(artifact, calls)
    totals = usage['totals']
    usage_complete = usage['complete']
    usage_reason = None if usage_complete else 'incomplete_token_usage'
    for name, key in (('token_usage_input', 'input'), ('token_usage_output', 'output'), ('token_usage_total', 'total')):
        metrics.put(name, totals[key] if usage_complete else None,
                    numerator=totals[key], denominator=None, population='experiment_model_calls',
                    method=method, reason=usage_reason,
                    coverage=_rate(usage['reported'], usage['dispatched']) if usage['dispatched'] else None)
    confirmed = sum(1 for row in view if row['assessed'] and (row['proof'] or 0) >= 3)
    confirmed += 0 if view else sum(1 for row in _candidate_view(artifact, method)
                                     if row['assessed'] and (row['proof'] or 0) >= 3)
    schedule = _price_schedule(artifact)
    metrics.put('token_cost', cost, numerator=None, denominator=None,
                population='experiment_model_calls', method=method, reason=cost_reason,
                detail={'price_schedule_id': schedule_id,
                        'price_schedule_version': schedule.get('version'),
                        'price_schedule_sha256': _digest(schedule) if schedule else None,
                        'currency': schedule.get('currency'),
                        'cost_scope': _cost_scope(method, calls),
                        'cost_call_count': sum(1 for row in calls if not row.get('cache_hit')),
                        **cost_detail})
    per_success_reason = cost_reason if cost is None else (
        'no_confirmed_success' if not confirmed else None)
    metrics.put('token_cost_per_success', round(cost / confirmed, 8) if cost is not None and confirmed else None,
                numerator=cost if cost is not None and confirmed else None,
                denominator=confirmed, population='confirmed_candidates',
                method=method, reason=per_success_reason,
                detail={'cost_available': cost is not None, 'currency': schedule.get('currency'),
                        'confirmed_candidates': confirmed,
                        'cost_scope': _cost_scope(method, calls),
                        'accounting_basis': cost_detail['accounting_basis'],
                        'billing_route': cost_detail['billing_route'],
                        'accounting_bases_by_price_key':
                            cost_detail['accounting_basis_by_price_key']})
    from llm.cache_metrics import cache_performance_summary
    summary = cache_performance_summary(calls)
    provider_rate = summary.get('cache_hit_rate')
    metrics.put('provider_cache_read_rate', provider_rate,
                numerator=summary.get('observed_provider_cached_input_tokens'),
                denominator=summary.get('observed_provider_input_tokens'),
                population='provider_input_tokens', method=method,
                reason=f"provider_cache_usage_{summary.get('provider_cache_usage_status')}",
                detail={'provider_cache_usage_status': summary.get('provider_cache_usage_status'),
                        'provider_cache_usage_coverage': summary.get('provider_cache_usage_coverage')})
    metrics.put('response_cache_hit_rate', summary.get('response_cache_hit_rate') if calls else None,
                numerator=summary.get('response_cache_hits'), denominator=len(calls),
                population='logical_experiment_model_calls', method=method,
                reason='no_experiment_calls')
    timing = artifact.get('timing') if isinstance(artifact.get('timing'), dict) else {}
    wall = timing.get('duration_ms')
    metrics.put('wall_time_ms', wall if _as_int(wall) is not None else None,
                population='run_wall_time', method=method, reason='wall_time_unavailable')
    durations = [row.get('call_duration_ms') for row in calls]
    summed = None
    if durations and all(_as_int(value) is not None for value in durations):
        summed = sum(durations)
    metrics.put('summed_call_duration_ms', summed, numerator=summed, denominator=len(durations),
                population='experiment_model_calls', method=method,
                reason='no_experiment_calls' if not durations else 'call_duration_incomplete')
    config = _config(artifact)
    run_concurrency = _as_int(config.get('llm_max_concurrency'))
    if run_concurrency is None:
        summary_block = artifact.get('llm_performance_summary')
        if isinstance(summary_block, dict):
            run_concurrency = _as_int(summary_block.get('peak_llm_concurrency'))
    metrics.count('per_run_llm_concurrency', run_concurrency, population='run_configuration',
                  method=method, reason='per_run_concurrency_unavailable')
    attempted = _attempted_methods(artifact)
    metrics.count('methods_attempted', len(attempted), denominator=len(ALL_METHOD_AGENTS),
                  population='registered_methods', method=method,
                  detail={'ids': sorted(attempted)})
    unattempted = [agent for agent in ALL_METHOD_AGENTS if agent not in attempted]
    metrics.count('methods_unattempted', len(unattempted), denominator=len(ALL_METHOD_AGENTS),
                  population='registered_methods', method=method, detail={'ids': unattempted})


def _provisional(artifact):
    state = _state(artifact)
    return {
        'label': PROVISIONAL_LABEL,
        'formula_note': 'Runtime scoring.v2 components are provisional and never substitute for final v4 values.',
        'composite_scores': state.get('composite_scores', {}),
        'output_scores': state.get('output_scores', {}),
        'method_scores': state.get('method_scores', {}),
        'payload_scores': state.get('payload_scores', {}),
    }


def legacy_run_metrics(artifact, rows, components):
    """Preserve the historical v3 metric readouts without relabeling them."""
    state = _state(artifact)
    valid = [r for r in rows if r.get('validation', {}).get('valid') is True and r.get('stage') in {'exploit', 'bypass'}]
    executed = [r for r in rows if r.get('eligible')]
    assessed = [r for r in executed if r.get('proof_ceiling') is not None]
    successes = sum((r.get('proof_ceiling') or 0) >= 3 for r in assessed)
    calls = artifact.get('llm_activity', {}).get('completed', 0) if isinstance(artifact.get('llm_activity'), dict) else 0
    by_id = {r['candidate_id']: r for r in executed}
    order = list(dict.fromkeys(r.get('candidate_id') for r in state.get('response_evidence', [])
        if isinstance(r, dict) and r.get('candidate_id') in by_id and r.get('stage') in {'exploit', 'bypass'}))
    attempts = next((i + 1 for i, cid in enumerate(order) if by_id[cid].get('proof_ceiling') is not None
        and by_id[cid]['proof_ceiling'] >= 3), None) if set(order) == set(by_id) else None
    values = {
        'payload_validity_rate': sum(r.get('validation', {}).get('valid') is True for r in rows) / len(rows) if rows else None,
        'payload_execution_success_rate': successes / len(valid) if valid and len(assessed) == len(executed) else None,
        'full_exploit_rate': int(components['Sexploit'] >= 3) if components.get('Sexploit') is not None else None,
        'attempts_to_success': attempts,
        'chain_enabled_exploit_count': int(components['Schain'] >= 3) if components.get('Schain') is not None else None,
        'invalid_json_rate': min(len(state.get('invalid_json_events', [])) / calls, 1) if calls else None,
        'guardrail_activation_rate': min(len(state.get('guardrail_activations', [])) / calls, 1) if calls else None,
        'fallback_rate': min(len(state.get('fallback_events', [])) / calls, 1) if calls else None,
        'first_choice_accuracy': None, 'method_alignment_rate': None, 'akg_path_validity': None,
        'token_cost_per_success': None,
    }
    reasons = {'first_choice_accuracy': 'no_preregistered_optimal_method_ranking',
               'method_alignment_rate': 'validator_does_not_record_separate_alignment_verdict',
               'akg_path_validity': 'selection_trace_is_not_an_edge_by_edge_graph_path',
               'token_cost_per_success': 'no_frozen_token_price_schedule'}
    metrics = MetricSet()
    for name, value in values.items():
        metrics.put(name, value, reason=reasons.get(name, 'insufficient_evidence_or_not_applicable'))
    for key, value in (('valid_exploit_candidates', len(valid)),
                       ('executed_candidates', len(executed)),
                       ('assessed_candidates', len(assessed)),
                       ('returned_llm_outputs', calls)):
        metrics.denominators[key] = value
    document = metrics.document('scoring.v3', _provisional(artifact))
    document['legacy_metric_epoch'] = 'scoring.v3'
    return document


def build_research_metrics(source):
    """Return the evidence-backed metrics bundle for an artifact, queue, or receipt.

    Receipts and review queues carry the bundle computed from their frozen
    artifact; pass it through unchanged instead of recomputing or zero-filling.
    """
    if not isinstance(source, dict):
        raise ValueError('research metrics require a mapping artifact, queue, or receipt')
    metrics = source.get('metrics')
    if isinstance(metrics, dict) and isinstance(metrics.get('values'), dict) \
            and isinstance(metrics.get('availability'), dict):
        return metrics
    if isinstance(source.get('final_state'), dict):
        return compute_run_metrics(source)
    raise ValueError('research metrics require an execution artifact, review queue, or receipt')


def _view_component_rows(view, method):
    """Minimal graded rows from a derived candidate view.

    Eligibility mirrors the queue contract (valid, executed, exploit/bypass);
    the proof itself is already the ``candidate_base`` result, never a runtime
    score. Unassessable rows stay ``base_proof=None`` so the central graded API
    keeps the component unavailable instead of zero.
    """
    rows = []
    for row in view:
        if not isinstance(row, dict) or not row.get('candidate_id'):
            continue
        eligible = bool(row.get('valid') and row.get('executed')
                        and row.get('stage') in {'exploit', 'bypass'})
        rows.append({'candidate_id': row['candidate_id'], 'method': method,
                     'eligible': eligible, 'base_proof': row.get('proof') if eligible else None})
    return rows


def _derive_component_evidence(artifact, method, rows, view=None):
    """Derive graded components via the central ``automatic_components`` API.

    Queue-schema rows (``eligible`` and ``base_proof``) are passed through.
    Otherwise the derived candidate view is converted to the same minimal row
    contract, so the proof is still the graded ``candidate_base`` result.
    Runtime ``composite_components`` are never an input.
    """
    graded_rows = rows
    if graded_rows is None or not all(
            isinstance(row, dict) and 'eligible' in row and 'base_proof' in row for row in graded_rows):
        graded_rows = _view_component_rows(view, method) if view is not None else None
    if graded_rows is None:
        return None
    from evaluation.scoring_evidence import automatic_components
    return automatic_components(artifact, method, graded_rows)[0]


def _legacy_runtime_components(artifact):
    """Explicitly labeled runtime scoring.v2 vector; never graded evidence."""
    report = artifact.get('report') if isinstance(artifact.get('report'), dict) else {}
    summary = report.get('summary') if isinstance(report.get('summary'), dict) else {}
    components = artifact.get('composite_components')
    source = 'artifact.composite_components'
    if not isinstance(components, dict):
        components = summary.get('run_composite_components')
        source = 'report.summary.run_composite_components'
    if not isinstance(components, dict) or not components:
        return None
    numeric = {key: value for key, value in components.items()
               if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)}
    if not numeric:
        return None
    return {
        'label': PROVISIONAL_LABEL,
        'score_epoch': 'runtime_provisional_scoring.v2',
        'source': source,
        'note': ('Runtime scoring.v2 components are provisional; they are never '
                 'graded v4 evidence and never substitute for a final component.'),
        'components': numeric,
        'flags': {
            'full_exploit_flag_legacy': float(int(numeric['Sexploit'] >= 3)) if 'Sexploit' in numeric else None,
            'chain_enabled_exploit_flag_legacy': float(int(numeric['Schain'] >= 3)) if 'Schain' in numeric else None,
        },
    }


def compute_run_metrics(artifact, *, rubric_version=None, rows=None, components=None):
    """Compute every metric family with explicit availability and denominators.

    Graded flags come only from caller-supplied graded components or from the
    central ``automatic_components`` API over queue-schema rows or the derived
    candidate view. Runtime ``composite_components`` are never graded; when the
    caller supplies no components they are attached separately under
    ``legacy_runtime_components`` for audit only.
    """
    if not isinstance(artifact, dict):
        raise ValueError('artifact must be a mapping')
    rubric = rubric_version or (_config(artifact).get('scoring_rubric_version') or 'scoring.v3')
    method = _method(artifact)
    if rubric != 'scoring.v4':
        return legacy_run_metrics(artifact, rows or [], components or {})
    metrics = MetricSet()
    view = _candidate_view(artifact, method, rows)
    calls = _method_calls(artifact, method)
    derived_components = components is None
    component_evidence = components if components is not None else _derive_component_evidence(
        artifact, method, rows, view)
    _first_choice_metric(metrics, artifact, method)
    _adaptation_metric(metrics, artifact, method)
    _akg_metrics(metrics, artifact, method, component_evidence)
    _payload_metrics(metrics, artifact, method, view, calls)
    _exploit_flags(metrics, component_evidence or {}, method, artifact)
    _attempt_metrics(metrics, artifact, method, view)
    _telemetry_metrics(metrics, artifact, calls, method, view)
    document = metrics.document(rubric, _provisional(artifact))
    if derived_components:
        legacy = _legacy_runtime_components(artifact)
        if legacy is not None:
            document['legacy_runtime_components'] = legacy
    return document
