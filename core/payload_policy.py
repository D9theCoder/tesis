"""Versioned payload, candidate-budget, and detection-control policy identities.

Every slice imports these names instead of hardcoding a second copy.  The module
is dependency-free on purpose: ``core.state`` imports it for the payload-mode
registry, so it must not import state, the knowledge graph, evaluation, or any
LLM runtime.

What lives here:

* policy/prompt/schema version strings recorded in new artifacts;
* the payload-mode registry and the mode -> trusted-origin matrix;
* the single per-visit exploit-candidate budget rule;
* the frozen hybrid candidate order (valid generated candidates first, static
  seeds after them as the exhaustion fallback);
* append-only candidate-lifecycle and generation-opportunity fact builders;
* the closed observation allowlist for Template prompts;
* event names shared by the generator, validator, runner, and scoring readers.

Historical semantics never change through this module.  Artifacts record the
version they were produced under and readers dispatch on that recorded version.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from typing import Any

PAYLOAD_POLICY_VERSION = "payload-policy.v2"
CONTROL_POLICY_VERSION = "detection-controls.v2"
BUDGET_POLICY_VERSION = "candidate-budget.v2"
EXPERIMENT_POLICY_VERSION = "chapter3-flow.v2"

# Historical detection-control snapshots were frozen as a complete ordered
# canonical probe set with a bare content hash.  Readers must keep dispatching
# on the recorded policy version rather than reinterpreting old snapshots.
LEGACY_CONTROL_POLICY_VERSION = "detection-controls.v1"

DEFAULT_CANDIDATE_BUDGET = 5

# ``llm_template`` is displayed as Template in the TUI/CLI/Doctor surfaces.
PAYLOAD_MODES: tuple[str, ...] = (
    "static_only",
    "hybrid",
    "llm_mutation_only",
    "llm_template",
)
PAYLOAD_MODE_LABELS: dict[str, str] = {
    "static_only": "Static",
    "hybrid": "Hybrid",
    "llm_mutation_only": "Mutation-only",
    "llm_template": "Template",
}
STATIC_PAYLOAD_MODES = frozenset({"static_only"})
MODEL_PAYLOAD_MODES = frozenset({"hybrid", "llm_mutation_only", "llm_template"})
# Modes that permit ONLY current-visit, trusted model-origin exploit/bypass
# candidates: a generator or validator failure never revives a seed, a stale
# candidate, or a chain-derived substitute at any layer.
STRICT_PAYLOAD_MODES = frozenset({"llm_mutation_only", "llm_template"})
TEMPLATE_PAYLOAD_MODES = frozenset({"llm_template"})

# Frozen hybrid candidate-order policy (owner decision).  Trigger: a hybrid
# visit whose generation call produced at least one valid model-generated
# exploit/bypass candidate.  Effect: those generated candidates are queued
# ahead of the static seed candidates; the static seeds stay queued behind them
# as the exhaustion fallback and remain the whole queue when generation produced
# no valid candidate.  ``static_only`` and the strict modes are unchanged: a
# strict mode never gains static fallback, and ``static_only`` never generates.
CANDIDATE_ORDER_POLICY_VERSION = "candidate-order.v1"
CANDIDATE_ORDER_POLICY = "validated_generated_first_static_fallback"
CANDIDATE_ORDER_TRIGGER = "hybrid_valid_generated_candidate"

ORIGIN_KINDS = frozenset(
    {
        "static_seed",
        "seed_mutation",
        "template_generation",
        "chain_derived",
        "derived_control",
    }
)
MODEL_ORIGIN_KINDS = frozenset({"seed_mutation", "template_generation"})
CANDIDATE_QUEUE_ORIGIN_KINDS = frozenset(
    {"static_seed", "seed_mutation", "template_generation", "chain_derived"}
)

EXPLOIT_STAGES = frozenset({"exploit", "bypass"})
CANDIDATE_STAGES = frozenset({"probe", "exploit", "bypass"})

# Immutable candidate lifecycle facts (append-only, keyed by method/visit/id).
CANDIDATE_LIFECYCLE_STATUSES = frozenset(
    {
        "generated",
        "valid",
        "queued",
        "executed",
        "stopped_before_execution",
        "budget_excluded",
        "rejected",
    }
)
CANDIDATE_STATUSES = CANDIDATE_LIFECYCLE_STATUSES

# One opportunity per planned payload-generation role/visit decision.
GENERATION_OPPORTUNITY_STATUSES = frozenset(
    {"completed", "failed", "not_required", "not_run"}
)
GENERATION_ROLE = "payload_generator"

# Validation basis. ``live`` is the only basis a running graph may use; the
# historical contract is available ONLY when a replay reader passes the
# artifact's recorded basis/identity explicitly. Missing fields are never
# evidence that an artifact is historical.
PAYLOAD_POLICY_BASIS_LIVE = "live"
PAYLOAD_POLICY_BASIS_HISTORICAL = "historical"
PAYLOAD_POLICY_BASES = frozenset({PAYLOAD_POLICY_BASIS_LIVE, PAYLOAD_POLICY_BASIS_HISTORICAL})
PAYLOAD_POLICY_BASIS_STATE_KEY = "payload_policy_basis"
RECORDED_POLICY_STATE_KEY = "recorded_payload_policy"

# Generation/reference failure vocabulary added by the correction release.
REASON_SEED_NOT_SUPPLIED = "seed_not_supplied"
REASON_PROBE_SEED_PROVENANCE = "probe_seed_provenance_not_executable"
REASON_NO_SUPPLIED_SEED = "no_supplied_seed"
REASON_MISSING_POLICY_IDENTITY = "missing_payload_policy_identity"
REASON_TEMPLATE_REGISTRY_UNAVAILABLE = "historical_template_registry_unavailable"
REASON_MISSING_PROMPT_SEEDS = "missing_prompt_supplied_seed_receipt"
REASON_BUDGET_EXCLUDED_MODEL = "budget_excluded_model_candidate"
REASON_AMBIGUOUS_MATCH = "multiple_matching_artifacts"
REASON_SOURCE_HASH_MISMATCH = "source_hash_mismatch"
REASON_TOKEN_PRICE_MISMATCH = "token_price_schedule_mismatch"
REASON_GUARDRAIL_MISMATCH = "guardrail_policy_mismatch"
REASON_ATTESTATION_MISSING = "fixture_restoration_attestation_missing"
EVENT_MODEL_BUDGET_EXCLUDED = "payload_validation.model_candidate_budget_excluded"
EVENT_NO_SUPPLIED_SEED = "payload_generation.no_supplied_seed"

# Prompt/schema identities.  The mutation response schema changed with the
# trusted-origin contract, so generated candidates carry a new schema version
# while historical artifacts keep their recorded one.
MUTATION_PROMPT_ID = "payload_generation.constrained_variant"
TEMPLATE_PROMPT_ID = "payload_generation.template_construction"
PAYLOAD_SCHEMA_VERSION = "payload-variants.v3"
PAYLOAD_TEMPLATE_SCHEMA_VERSION = "payload-template.v1"
TEMPLATE_REGISTRY_VERSION = "dvwa-neutral-template.v1"
# Template candidates carry a construction label, never a seed-mutation label.
TEMPLATE_MUTATION_TYPE = "template_construction"

# Provenance groups.  ``origin_ref`` binds either the supplied seed or the real
# neutral template; a Template candidate NEVER fabricates ``source_seed_id``.
SEED_ORIGIN_REF_FIELDS = ("seed_id",)
TEMPLATE_ORIGIN_REF_FIELDS = ("template_id", "template_version", "template_sha256")

# Closed allowlist of sanitized observations a Template prompt may see.  These
# are fixture/session facts, not payload text, control responses, credentials,
# prior successes, profile helper fields, or history.
TEMPLATE_OBSERVATION_ALLOWLIST = frozenset(
    {"authenticated_crawl", "low_priv_session_available"}
)

# Shared event names.  The runner keys provider-failure detection on these
# identities instead of on a single historical fallback event.
EVENT_STATIC_FALLBACK = "payload_generation.static_seed_fallback"
EVENT_STRICT_NO_CANDIDATE = "payload_generation.strict_no_candidate"
EVENT_PROVIDER_FAILURE = "payload_generation.provider_failure"
EVENT_TEMPLATE_UNAVAILABLE = "payload_generation.template_unavailable"
EVENT_VALIDATION_STRICT_NO_CANDIDATE = "payload_validation.strict_no_candidate"
EVENT_VALIDATION_NO_USABLE = "payload_validation.no_usable_candidate"
EVENT_TARGET_NO_VALID_PAYLOADS = "target_method.no_valid_payloads"

# Failure taxonomy for one generation opportunity.  Provider/transport failures
# are operational and MUST stay distinguishable from a returned model refusal or
# malformed output.
PROVIDER_FAILURE_REASONS = frozenset(
    {"llm_error", "provider_error", "transport_error", "timeout"}
)
MODEL_OUTPUT_FAILURE_REASONS = frozenset(
    {
        "guardrail_refusal",
        "invalid_json",
        "invalid_schema",
        "schema_violation",
        "response_mode_mismatch",
        "incomplete_response",
        "malformed_payload",
        "template_parameter_mismatch",
        "template_signal_mismatch",
        "unexpected_candidate_field",
        "seed_not_supplied",
        "probe_seed_provenance_not_executable",
    }
)
GENERATION_FAILURE_REASONS = frozenset(
    {
        *PROVIDER_FAILURE_REASONS,
        *MODEL_OUTPUT_FAILURE_REASONS,
        "empty_candidates",
        "probe_seed_for_exploit",
        "no_supplied_seed",
        "candidate_budget_zero",
        "template_reference_mismatch",
        "template_unavailable",
        "template_infeasible",
    }
)

BUDGET_EXCLUSION_REASON = "candidate_budget_exceeded"
QUEUE_ROLE_EXPLOIT = "exploit_candidate"
QUEUE_ROLE_DETECTION = "detection_control"


def canonical_sha256(value: Any) -> str:
    """Return the canonical content hash used for template identities."""
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def normalize_payload_mode(value: Any) -> str:
    """Return the lower-cased mode string without inventing a fallback mode."""
    return str(value or "").strip().lower()


def is_supported_payload_mode(value: Any) -> bool:
    """Return whether ``value`` is a registered payload mode."""
    return normalize_payload_mode(value) in PAYLOAD_MODES


def coerce_payload_mode(value: Any, default: str = "static_only") -> str:
    """Return a registered mode, falling back to ``default`` when unknown."""
    mode = normalize_payload_mode(value)
    return mode if mode in PAYLOAD_MODES else default


def require_payload_mode(value: Any, *, default: str = "static_only") -> str:
    """Resolve a live run's mode, failing closed on an unknown value.

    An absent value keeps the documented default; a provided but unregistered
    mode is a configuration error and must never silently become the static
    ablation.  Historical readers use :func:`coerce_payload_mode` explicitly.
    """
    mode = normalize_payload_mode(value)
    if not mode:
        return default
    if mode not in PAYLOAD_MODES:
        raise ValueError(f"unknown payload mode: {value!r}")
    return mode


def resolve_policy_basis(value: Any) -> str:
    """Return the explicit validation basis, defaulting to the live contract."""
    basis = str(value or "").strip().lower()
    return basis if basis in PAYLOAD_POLICY_BASES else PAYLOAD_POLICY_BASIS_LIVE


def mode_display_label(value: Any) -> str:
    """Return the operator-facing label for a payload mode."""
    return PAYLOAD_MODE_LABELS.get(normalize_payload_mode(value), "Static")


def is_strict_mode(value: Any) -> bool:
    """Return whether the mode forbids every non-model exploit candidate."""
    return normalize_payload_mode(value) in STRICT_PAYLOAD_MODES


def is_template_mode(value: Any) -> bool:
    """Return whether the mode generates from a neutral template."""
    return normalize_payload_mode(value) in TEMPLATE_PAYLOAD_MODES


def requires_model_candidate(value: Any) -> bool:
    """Return whether the mode needs a model-generated exploit/bypass candidate."""
    return normalize_payload_mode(value) in MODEL_PAYLOAD_MODES


def requires_generation_call(value: Any) -> bool:
    """Return whether the mode must attempt a payload-generation model call."""
    return requires_model_candidate(value)


def allows_static_candidates(value: Any) -> bool:
    """Return whether validated static seed candidates may enter the queue."""
    return normalize_payload_mode(value) in {"static_only", "hybrid"}


def allows_chain_derived(value: Any) -> bool:
    """Return whether a route-derived credential candidate may join the queue."""
    return normalize_payload_mode(value) in {"static_only", "hybrid"}


def candidate_order_metadata(
    mode: Any, *, generated_count: int = 0, static_count: int = 0
) -> dict[str, Any]:
    """Return the frozen candidate-order decision for one built queue.

    The trigger is recorded even when it did not fire, so a static-only or
    strict queue states that the generated-first ordering was not applicable.
    """
    normalized = normalize_payload_mode(mode)
    return {
        "policy_version": CANDIDATE_ORDER_POLICY_VERSION,
        "candidate_order_policy": CANDIDATE_ORDER_POLICY,
        "trigger": CANDIDATE_ORDER_TRIGGER,
        "triggered": normalized == "hybrid" and int(generated_count) > 0,
        "generated_count": max(0, int(generated_count)),
        "static_count": max(0, int(static_count)),
    }


def expected_origin_kind(value: Any) -> str | None:
    """Return the trusted model origin kind a mode generates, if any."""
    mode = normalize_payload_mode(value)
    if mode == "llm_mutation_only":
        return "seed_mutation"
    if mode == "llm_template":
        return "template_generation"
    return None


def origin_kind_permitted(mode: Any, origin_kind: Any) -> bool:
    """Return whether ``origin_kind`` may enter this mode's exploit queue.

    Detection/verification controls (``derived_control``) are never queue
    candidates in any mode: they are separate, budgeted control activity that
    cannot stand in for a model candidate or earn model credit.
    """
    mode = normalize_payload_mode(mode)
    kind = str(origin_kind or "").strip()
    if kind not in CANDIDATE_QUEUE_ORIGIN_KINDS:
        return False
    if mode == "static_only":
        return kind in {"static_seed", "chain_derived"}
    if mode == "hybrid":
        return kind in {"static_seed", "seed_mutation", "chain_derived"}
    if mode == "llm_mutation_only":
        return kind == "seed_mutation"
    if mode == "llm_template":
        return kind == "template_generation"
    return False


def is_model_origin(origin_kind: Any) -> bool:
    """Return whether a candidate origin is a model-produced exploit candidate."""
    return str(origin_kind or "").strip() in MODEL_ORIGIN_KINDS


def is_exploit_stage(stage: Any) -> bool:
    """Return whether a candidate/disposition stage is an exploit/bypass stage."""
    return str(stage or "").strip().lower() in EXPLOIT_STAGES


def is_provider_failure_reason(reason: Any) -> bool:
    """Return whether a generation failure reason is operational (not a model act)."""
    return str(reason or "").strip().lower() in PROVIDER_FAILURE_REASONS


def is_model_output_failure_reason(reason: Any) -> bool:
    """Return whether a failure reason is a returned model output problem."""
    return str(reason or "").strip().lower() in MODEL_OUTPUT_FAILURE_REASONS


def coerce_budget(value: Any, default: int = DEFAULT_CANDIDATE_BUDGET) -> int:
    """Normalize a configured budget; an explicit zero is preserved."""
    if value is None or value == "":
        return max(0, int(default))
    try:
        number = int(value)
    except (TypeError, ValueError):
        return max(0, int(default))
    return max(0, number)


def exploit_queue_limit(
    configured_budget: Any, profile: Mapping[str, Any] | None = None
) -> int:
    """Return the per-visit budget for distinct exploit/bypass candidate IDs.

    One versioned rule applies across ALL origins and both primary conditions:
    the configured candidate budget, capped by the method profile's own payload
    budget as an AKG containment ceiling.  Detection controls, candidate
    verification controls, and physical HTTP retries never consume this budget.
    """
    configured = coerce_budget(configured_budget)
    profile = profile or {}
    ceiling = coerce_budget(profile.get("payload_budget"), default=configured)
    return max(0, min(configured, ceiling))


def generation_budget(
    configured_budget: Any, profile: Mapping[str, Any] | None = None
) -> int:
    """Return how many model candidates one generation opportunity may request.

    Generation can never exceed the exploit queue it feeds, and the profile's
    ``max_generated_candidates`` remains an independent generation ceiling.
    """
    limit = exploit_queue_limit(configured_budget, profile)
    profile = profile or {}
    generated_ceiling = coerce_budget(
        profile.get("max_generated_candidates"), default=limit
    )
    return max(0, min(limit, generated_ceiling))


def lifecycle_fact(
    *,
    method: str,
    visit_id: str | None,
    candidate_id: str | None,
    origin_kind: str,
    status: str,
    reason: str | None = None,
    evidence_refs: list[str] | None = None,
    policy_version: str = PAYLOAD_POLICY_VERSION,
) -> dict[str, Any]:
    """Build one append-only candidate lifecycle fact.

    Producers append facts; consumers derive receipts (generated/valid/queued/
    executed/budget-excluded) from them instead of maintaining mutable counters.
    """
    normalized_status = str(status or "").strip()
    if normalized_status not in CANDIDATE_LIFECYCLE_STATUSES:
        raise ValueError(f"unknown candidate lifecycle status: {status!r}")
    normalized_origin = str(origin_kind or "").strip()
    if normalized_origin not in ORIGIN_KINDS:
        raise ValueError(f"unknown candidate origin kind: {origin_kind!r}")
    return {
        "method": str(method),
        "visit_id": visit_id,
        "candidate_id": candidate_id,
        "origin_kind": normalized_origin,
        "status": normalized_status,
        "reason": reason,
        "evidence_refs": list(evidence_refs or []),
        "policy_version": policy_version,
    }


def generation_opportunity(
    *,
    method: str,
    visit_id: str | None,
    mode: str,
    required: bool,
    status: str,
    reason: str | None = None,
    call_id: str | None = None,
    prompt_id: str = MUTATION_PROMPT_ID,
    schema_version: str = PAYLOAD_SCHEMA_VERSION,
    origin_kind: str | None = None,
    opportunity_id: str | None = None,
    policy_version: str = PAYLOAD_POLICY_VERSION,
    receipt_stage: str = "generation",
    parsed_candidate_ids: list[str] | None = None,
    valid_candidate_ids: list[str] | None = None,
    failure_reason_detail: str | None = None,
) -> dict[str, Any]:
    """Build one append-only payload-generation opportunity receipt.

    ``required`` states whether the mode needs a model candidate at all;
    ``status`` records whether the call actually ran, so a valid generator
    receipt can never hide a missing required generation opportunity.

    One opportunity produces at most two receipts that share ``opportunity_id``:
    ``receipt_stage="generation"`` from the generator and
    ``receipt_stage="validation"`` from the validator.  Consumers count
    opportunities by the generation receipt and join validation by id, so a
    rejected candidate never inflates the call denominator.
    """
    normalized_status = str(status or "").strip()
    if normalized_status not in GENERATION_OPPORTUNITY_STATUSES:
        raise ValueError(
            f"unknown generation opportunity status: {status!r}"
        )
    normalized_mode = coerce_payload_mode(mode)
    row = {
        "opportunity_id": opportunity_id
        or f"{GENERATION_ROLE}:{method}:{visit_id}",
        "receipt_stage": str(receipt_stage or "generation"),
        "role": GENERATION_ROLE,
        "method": str(method),
        "visit_id": visit_id,
        "payload_mode": normalized_mode,
        "required": bool(required),
        "status": normalized_status,
        "reason": reason,
        "call_id": call_id,
        "prompt_id": prompt_id,
        "schema_version": schema_version,
        "origin_kind": origin_kind,
        "policy_version": policy_version,
        "parsed_candidate_ids": list(parsed_candidate_ids or []),
        "valid_candidate_ids": (
            list(valid_candidate_ids) if valid_candidate_ids is not None else None
        ),
        "failure_reason_detail": failure_reason_detail,
    }
    return row


def control_snapshot_policy_version(snapshot: Mapping[str, Any] | None) -> str:
    """Return the detected-control policy version recorded by a snapshot.

    Snapshots written before the versioned catalog carry no ``policy_version``;
    they are legacy complete-canonical-set snapshots.
    """
    if not isinstance(snapshot, Mapping):
        return ""
    recorded = str(snapshot.get("policy_version") or "").strip()
    return recorded or LEGACY_CONTROL_POLICY_VERSION


__all__ = [
    "BUDGET_EXCLUSION_REASON",
    "BUDGET_POLICY_VERSION",
    "CANDIDATE_LIFECYCLE_STATUSES",
    "CANDIDATE_ORDER_POLICY",
    "CANDIDATE_ORDER_POLICY_VERSION",
    "CANDIDATE_ORDER_TRIGGER",
    "CANDIDATE_QUEUE_ORIGIN_KINDS",
    "CANDIDATE_STAGES",
    "CANDIDATE_STATUSES",
    "CONTROL_POLICY_VERSION",
    "DEFAULT_CANDIDATE_BUDGET",
    "EVENT_MODEL_BUDGET_EXCLUDED",
    "EVENT_NO_SUPPLIED_SEED",
    "EVENT_PROVIDER_FAILURE",
    "EVENT_STATIC_FALLBACK",
    "EVENT_STRICT_NO_CANDIDATE",
    "EVENT_TARGET_NO_VALID_PAYLOADS",
    "EVENT_TEMPLATE_UNAVAILABLE",
    "EVENT_VALIDATION_NO_USABLE",
    "EVENT_VALIDATION_STRICT_NO_CANDIDATE",
    "EXPERIMENT_POLICY_VERSION",
    "EXPLOIT_STAGES",
    "GENERATION_FAILURE_REASONS",
    "GENERATION_OPPORTUNITY_STATUSES",
    "GENERATION_ROLE",
    "LEGACY_CONTROL_POLICY_VERSION",
    "MODEL_ORIGIN_KINDS",
    "MODEL_OUTPUT_FAILURE_REASONS",
    "MODEL_PAYLOAD_MODES",
    "MUTATION_PROMPT_ID",
    "ORIGIN_KINDS",
    "PAYLOAD_MODES",
    "PAYLOAD_MODE_LABELS",
    "PAYLOAD_POLICY_BASES",
    "PAYLOAD_POLICY_BASIS_HISTORICAL",
    "PAYLOAD_POLICY_BASIS_LIVE",
    "PAYLOAD_POLICY_BASIS_STATE_KEY",
    "PAYLOAD_POLICY_VERSION",
    "PAYLOAD_SCHEMA_VERSION",
    "PAYLOAD_TEMPLATE_SCHEMA_VERSION",
    "PROVIDER_FAILURE_REASONS",
    "RECORDED_POLICY_STATE_KEY",
    "QUEUE_ROLE_DETECTION",
    "QUEUE_ROLE_EXPLOIT",
    "SEED_ORIGIN_REF_FIELDS",
    "STATIC_PAYLOAD_MODES",
    "STRICT_PAYLOAD_MODES",
    "TEMPLATE_MUTATION_TYPE",
    "TEMPLATE_OBSERVATION_ALLOWLIST",
    "TEMPLATE_ORIGIN_REF_FIELDS",
    "TEMPLATE_PAYLOAD_MODES",
    "REASON_AMBIGUOUS_MATCH",
    "REASON_ATTESTATION_MISSING",
    "REASON_BUDGET_EXCLUDED_MODEL",
    "REASON_GUARDRAIL_MISMATCH",
    "REASON_MISSING_POLICY_IDENTITY",
    "REASON_MISSING_PROMPT_SEEDS",
    "REASON_NO_SUPPLIED_SEED",
    "REASON_PROBE_SEED_PROVENANCE",
    "REASON_SEED_NOT_SUPPLIED",
    "REASON_SOURCE_HASH_MISMATCH",
    "REASON_TEMPLATE_REGISTRY_UNAVAILABLE",
    "REASON_TOKEN_PRICE_MISMATCH",
    "TEMPLATE_PROMPT_ID",
    "TEMPLATE_REGISTRY_VERSION",
    "allows_chain_derived",
    "allows_static_candidates",
    "candidate_order_metadata",
    "canonical_sha256",
    "coerce_budget",
    "coerce_payload_mode",
    "control_snapshot_policy_version",
    "expected_origin_kind",
    "exploit_queue_limit",
    "generation_budget",
    "generation_opportunity",
    "is_exploit_stage",
    "is_model_origin",
    "is_model_output_failure_reason",
    "is_provider_failure_reason",
    "is_strict_mode",
    "is_supported_payload_mode",
    "is_template_mode",
    "lifecycle_fact",
    "mode_display_label",
    "normalize_payload_mode",
    "origin_kind_permitted",
    "resolve_policy_basis",
    "require_payload_mode",
    "requires_generation_call",
    "requires_model_candidate",
]
