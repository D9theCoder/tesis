"""Final-receipt-backed Chapter 3 summaries and exploratory rank-sum analysis.

Ownership: the study module owns block/target/repeat matching, planned-status
accounting, fixture-equivalence eligibility, and paired statistics. Score
semantics and receipt compatibility stay with the scorer: this module consumes
``evaluation.thesis_scoring.compare_receipts`` (grouping and repeat-aware
summaries), ``pair_compatibility_key``/``pair_compatibility_mismatches`` (matched-pair identity), and
``evaluation.metrics.aggregate_research_metrics`` (availability-tracked
research metrics). It never recomputes the v4 composite, never fills a missing
value with zero, and never pools conditions, blocks, targets, fixtures,
protocols, epochs, rubrics, metrics epochs or graders.

Paired analysis uses the same model/block/surface/level/target/repeat/
fixture/protocol/policy-epoch coordinate across the two primary conditions. A
pair is eligible only when both sides carry a ready readiness receipt with
matching requested/observed level and attested fixture restoration, and both
receipts share rubric, scoring-rule hash, metrics epoch, grader mode and recorded
reviewer identity/version. A missing, empty or malformed grader identity is
unavailable, never treated as a compatible grader. Unmatched or pending
coordinates are counted with reasons, never dropped.
"""

from __future__ import annotations

from core.historical_contracts import read_contract

import argparse
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from itertools import combinations
from pathlib import Path
from statistics import median
from typing import Any

from core.payload_policy import (
    REASON_AMBIGUOUS_MATCH,
    REASON_GUARDRAIL_MISMATCH,
    REASON_SOURCE_HASH_MISMATCH,
    REASON_TOKEN_PRICE_MISMATCH,
)
from evaluation.metrics import aggregate_research_metrics
from evaluation.observer_reviews import discover_reviews
from evaluation.research_metrics import RESEARCH_METRIC_NAMES
from evaluation.scoring_evidence import evidence_hash
from evaluation.thesis_scoring import (
    EPOCH_BINDING_VERSION,
    RECEIPT_CONTRACT,
    compare_receipts,
    pair_compatibility_key,
    pair_compatibility_mismatches,
)
from tesis.artifact_catalog import ArtifactCatalog

ANALYSIS_SCHEMA_VERSION = 'study-analysis'
SUPPORTED_PLAN_VERSIONS = ('study-plan',)
PRIMARY_CONDITIONS: tuple[str, ...] = ("linear_hybrid", "akg_guided_hybrid")
COMPONENT_NAMES = ("Smethod", "Spayload", "Sexploit", "Schain", "Soutput", "Srun_final")
FAMILY_OUTCOMES = ("Smethod", "Spayload", "Sexploit", "Schain", "Soutput", "Srun")
OUTCOME_LABELS = {name: ("Srun" if name == "Srun_final" else name) for name in COMPONENT_NAMES}
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 20261028
DIFFERENCE_DIRECTION = "linear_hybrid_minus_akg_guided_hybrid"
STUDY_DESIGN_VERSION = 'study-design'

#: Explicit receipt epoch identity emitted by the scorer interface.  The
#: repeat-invariant population key is ``epoch_sha256``; ``source_execution_sha256``
#: is per receipt and must never be used to compare repeats.  Historical receipts
#: without this block remain readable within their own recorded epoch, but an
#: aggregation row may not mix bound and unbound receipts, and no reader may pool
#: different explicit epoch keys.
EPOCH_BINDING_KEY = 'epoch_binding'
EPOCH_BINDING_REQUIRED = (
    'epoch_sha256', 'scoring_epoch_id', 'source_execution_sha256',
)
EPOCH_BINDING_OPTIONAL = (
    'experiment_epoch_id', 'plan_sha256', 'config_sha256', 'fixture_id',
    'protocol_version', 'oracle_sha256', 'scoring_rule_sha256',
    'binding_sha256', 'binding_version',
)
EPOCH_BINDING_EXPLICIT = 'explicit'
EPOCH_BINDING_LEGACY = 'legacy_unbound'
EPOCH_BINDING_INVALID = 'invalid'


def _hex_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in '0123456789abcdefABCDEF' for character in value
    )


def _embedded_research_design(plan: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The source-bound design declaration embedded in a frozen plan."""
    research_config = plan.get('research_config')
    if isinstance(research_config, Mapping):
        declaration = research_config.get('declaration')
        if isinstance(declaration, Mapping):
            design = declaration.get('design')
            if isinstance(design, Mapping):
                return design
    analysis_declaration = plan.get('analysis_declaration')
    if isinstance(analysis_declaration, Mapping):
        design = analysis_declaration.get('design')
        if isinstance(design, Mapping):
            return design
        if isinstance(analysis_declaration.get('family'), Mapping):
            return analysis_declaration
    design = plan.get('design')
    return design if isinstance(design, Mapping) else None


def plan_requires_receipt_epoch_binding(plan: Mapping[str, Any]) -> bool:
    """Whether a plan declares that every receipt must carry explicit epoch identity.

    The marker is prospective: historical plans without it remain readable in
    their recorded read-only context, while a prospective plan can never accept
    an unbound or plan-less receipt.  A top-level boolean is the canonical form;
    a ``receipt_epoch_binding`` object is accepted as the equivalent structured
    declaration so a freeze can carry plan/config/fixture identities together.
    A plan that embeds a six-outcome condition-contrast declaration is also
    prospective: the declaration is only meaningful for a frozen plan whose
    receipts must bind it.
    """
    if plan.get('epoch_binding_required') is True:
        return True
    contract = plan.get('receipt_epoch_binding')
    if isinstance(contract, Mapping) and contract.get('required') is True:
        return True
    design = _embedded_research_design(plan)
    return isinstance(design, Mapping) and isinstance(
        design.get('condition_contrast_family'), Mapping
    )


def _epoch_binding(document: Mapping[str, Any]) -> dict[str, Any]:
    """Read one receipt's explicit epoch binding without inventing identity."""
    raw = document.get(EPOCH_BINDING_KEY)
    contract = document.get('receipt_contract')
    if raw is None and contract is None:
        return {'status': EPOCH_BINDING_LEGACY, 'binding': None, 'problems': []}
    problems = []
    if contract != RECEIPT_CONTRACT:
        problems.append('receipt_contract_missing_or_unknown')
    if not isinstance(raw, Mapping):
        return {
            'status': EPOCH_BINDING_INVALID, 'binding': None,
            'problems': [*problems, 'epoch_binding_not_an_object'],
        }
    if raw.get('binding_version') != EPOCH_BINDING_VERSION:
        problems.append('epoch_binding_version_unknown')
    binding: dict[str, Any] = {}
    for field in EPOCH_BINDING_REQUIRED:
        value = raw.get(field)
        if not isinstance(value, str) or not value.strip():
            problems.append(f'{field}_missing')
        else:
            binding[field] = value.strip()
    for field in EPOCH_BINDING_OPTIONAL:
        value = raw.get(field)
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            problems.append(f'{field}_invalid')
        else:
            binding[field] = value.strip()
    for field in ('epoch_sha256', 'source_execution_sha256', 'binding_sha256',
                  'plan_sha256', 'config_sha256', 'oracle_sha256',
                  'scoring_rule_sha256', 'scoring_epoch_id'):
        if field in binding and not _hex_digest(binding[field]):
            problems.append(f'{field}_invalid')
    if 'scoring_rule_sha256' in binding and 'scoring_epoch_id' in binding \
            and binding['scoring_rule_sha256'] != binding['scoring_epoch_id']:
        problems.append('scoring_epoch_rule_mismatch')
    return {
        'status': EPOCH_BINDING_INVALID if problems else EPOCH_BINDING_EXPLICIT,
        'binding': binding,
        'problems': problems,
    }


def _epoch_binding_problem(document: Mapping[str, Any]) -> str | None:
    info = _epoch_binding(document)
    if info['status'] == EPOCH_BINDING_INVALID:
        return 'receipt_epoch_binding_invalid:' + ';'.join(info['problems'])
    return None


def _epoch_population_problem(documents: Iterable[Mapping[str, Any]]) -> str | None:
    """Refuse mixed or conflicting receipt epochs in one aggregation group."""
    infos = [_epoch_binding(document) for document in documents]
    if not infos:
        return None
    invalid = [info for info in infos if info['status'] == EPOCH_BINDING_INVALID]
    if invalid:
        return 'receipt_epoch_binding_invalid'
    statuses = {info['status'] for info in infos}
    if len(statuses) > 1:
        return 'receipt_epoch_binding_mixed'
    explicit = [info['binding'] for info in infos if info['status'] == EPOCH_BINDING_EXPLICIT]
    if explicit and len({value.get('epoch_sha256') for value in explicit}) > 1:
        return 'receipt_epoch_binding_mismatch'
    if explicit and len({
        value.get('plan_sha256') for value in explicit if value.get('plan_sha256')
    }) > 1:
        return 'receipt_plan_identity_mismatch'
    if explicit and any(not value.get('plan_sha256') for value in explicit):
        return 'receipt_plan_identity_missing'
    return None


def refuse_epoch_pooling(documents: Iterable[Mapping[str, Any]]) -> str:
    """Return one epoch id or refuse to aggregate across declared epochs.

    Analysis/audit documents must name their epoch explicitly.  Aggregating
    compatible cells is allowed inside one epoch; a caller that supplies more
    than one epoch identity is refused before any statistic is computed.
    """
    epochs: dict[str, int] = Counter()
    for index, document in enumerate(documents):
        if not isinstance(document, Mapping):
            raise ValueError(f'Aggregation document {index} is not an object')
        epoch = document.get('epoch_id')
        if not isinstance(epoch, str) or not epoch.strip():
            raise ValueError(
                f'Aggregation document {index} does not declare epoch_id; '
                'unidentified populations cannot be pooled'
            )
        epochs[epoch.strip()] += 1
    if not epochs:
        raise ValueError('Aggregation requires at least one declared epoch')
    if len(epochs) > 1:
        raise ValueError(f'Refusing to pool declared epochs: {dict(sorted(epochs.items()))}')
    return next(iter(epochs))


def _receipt_epoch_problem(
    document: Mapping[str, Any],
    plan: Mapping[str, Any],
    entry: Any,
    constraints: Mapping[str, Any],
) -> tuple[str | None, dict[str, Any]]:
    """Compare one receipt's explicit binding with the declared plan/execution.

    A historical unbound receipt is not an error by itself: it remains readable
    for its recorded epoch.  It cannot share a population with bound receipts,
    and it can never be treated as a receipt for the current plan.
    """
    prospective = plan_requires_receipt_epoch_binding(plan)
    info = _epoch_binding(document)
    if info['status'] == EPOCH_BINDING_LEGACY:
        if prospective:
            return 'receipt_epoch_binding_missing', info
        return None, info
    if info['status'] == EPOCH_BINDING_INVALID:
        return 'receipt_epoch_binding_invalid:' + ';'.join(info['problems']), info
    binding = info['binding'] or {}
    plan_epoch = plan.get('epoch_id')
    receipt_epoch = binding.get('experiment_epoch_id')
    plan_sha = plan.get('plan_sha256')
    bound_plan = binding.get('plan_sha256')
    if prospective:
        if not isinstance(plan_sha, str) or not plan_sha.strip():
            return 'receipt_plan_identity_unavailable_for_prospective_plan', info
        if not isinstance(bound_plan, str) or not bound_plan.strip():
            return 'receipt_plan_identity_missing', info
        if bound_plan != plan_sha:
            return 'receipt_plan_identity_mismatch', info
    else:
        # Any bound receipt claims a prospective plan identity, even when the
        # plan lacks the explicit prospective marker.  The reader must not let
        # a numeric-looking binding stand in for a missing/mismatched plan.
        if not isinstance(plan_sha, str) or not plan_sha.strip():
            return 'receipt_plan_identity_unavailable_for_bound_receipt', info
        if not isinstance(bound_plan, str) or not bound_plan.strip():
            return 'receipt_plan_identity_missing', info
        if bound_plan != plan_sha:
            return 'receipt_plan_identity_mismatch', info
    if not isinstance(plan_epoch, str) or not plan_epoch.strip():
        return 'receipt_experiment_epoch_identity_unavailable', info
    if receipt_epoch != plan_epoch:
        return 'receipt_experiment_epoch_mismatch', info
    source_sha = entry.source.get('sha256') if isinstance(entry.source, Mapping) else None
    bound_execution = binding.get('source_execution_sha256')
    receipt_source = document.get('source_sha256')
    if source_sha and bound_execution != source_sha:
        return 'receipt_source_execution_mismatch', info
    if bound_execution and receipt_source and bound_execution != receipt_source:
        return 'receipt_source_execution_mismatch', info
    if source_sha and receipt_source and source_sha != receipt_source:
        return 'receipt_source_execution_mismatch', info
    recorded_rule = document.get('scoring_rule_sha256')
    if binding.get('scoring_rule_sha256') and recorded_rule \
            and binding['scoring_rule_sha256'] != recorded_rule:
        return 'receipt_scoring_rule_identity_mismatch', info
    if binding.get('scoring_epoch_id') and recorded_rule \
            and binding['scoring_epoch_id'] != recorded_rule:
        return 'receipt_scoring_epoch_identity_mismatch', info
    for field, constraint in (
        ('fixture_id', constraints.get('fixture_id')),
        ('protocol_version', constraints.get('protocol_version')),
    ):
        if constraint and binding.get(field) and binding[field] != constraint:
            return f'receipt_epoch_{field}_mismatch', info
    return None, info


def _canonical_sha256(value: Any) -> str:
    import hashlib
    payload = json.dumps(
        value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str
    ).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def _file_sha256(path: Path) -> str | None:
    import hashlib
    try:
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b''):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _parse_timestamp(value: Any) -> float | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        from datetime import datetime
        parsed = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


def _earliest_receipt_timestamp(
    observations: Iterable[Mapping[str, Any]],
) -> tuple[float | None, str | None, int]:
    values = []
    document_count = 0
    for observation in observations:
        for _mode, binding in (observation.get('documents') or {}).items():
            document = binding[1] if isinstance(binding, (tuple, list)) and len(binding) > 1 else None
            if isinstance(document, Mapping):
                document_count += 1
                timestamp = _parse_timestamp(document.get('generated_at'))
                if timestamp is not None:
                    values.append((timestamp, document.get('generated_at')))
    if not values:
        return None, None, document_count
    timestamp, text = min(values, key=lambda row: row[0])
    return timestamp, text, document_count


def _implemented_family() -> dict[str, Any]:
    return {
        'unit': 'model x surface x level condition-contrast row',
        'contrast': 'linear_hybrid vs akg_guided_hybrid',
        'outcomes': list(FAMILY_OUTCOMES),
        'family_size': len(FAMILY_OUTCOMES),
        'adjustment': 'Holm-Bonferroni step-down',
        'alpha': 0.05,
        'raw_p_field': 'p_value_raw',
        'adjusted_p_field': 'p_value_holm',
        'missing_outcome_policy': (
            'A missing or untestable outcome keeps its null value and does not reduce '
            'the declared six-outcome family. Available p-values remain adjusted against '
            'family size six.'
        ),
        'supplementary_families': [
            {'name': 'paired_wilcoxon', 'role': 'supplementary'},
            {'name': 'bootstrap_interval', 'role': 'supplementary'},
        ],
    }


def _family_from_design(design: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Parse an exact, source-bound family declaration; never arbitrary text."""
    from evaluation.research_plan import (
        CONDITION_CONTRAST_MISSING_POLICY,
        CONDITION_CONTRAST_MULTIPLICITY,
        CONDITION_CONTRAST_OUTCOMES,
        validate_condition_contrast_declaration,
    )
    family = design.get('condition_contrast_family')
    if not isinstance(family, Mapping):
        return {}, 'condition_contrast_family_missing'
    try:
        validated = validate_condition_contrast_declaration(design)
    except ValueError as exc:
        return {}, f'condition_contrast_family_invalid:{exc}'
    if list(validated.get('outcomes') or []) != list(CONDITION_CONTRAST_OUTCOMES):
        return {}, 'condition_contrast_family_outcomes_mismatch'
    if int(validated.get('family_size') or 0) != len(FAMILY_OUTCOMES):
        return {}, 'condition_contrast_family_size_mismatch'
    declared = {
        'unit': validated.get('stratum'),
        'contrast': validated.get('contrast'),
        'outcomes': list(CONDITION_CONTRAST_OUTCOMES),
        'family_size': int(validated.get('family_size') or len(FAMILY_OUTCOMES)),
        'adjustment': 'Holm-Bonferroni step-down',
        'alpha': 0.05,
        'raw_p_field': 'p_value_raw',
        'adjusted_p_field': 'p_value_holm',
        'missing_outcome_policy': validated.get(
            'missing_outcome_policy', CONDITION_CONTRAST_MISSING_POLICY
        ),
        'multiplicity': validated.get('multiplicity', CONDITION_CONTRAST_MULTIPLICITY),
        'supplementary_families': list(
            validated.get('supplementary_families') or []
        ),
    }
    return declared, None


def _analysis_declaration(
    plan: Mapping[str, Any],
    observations: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Bind the family declaration to its plan/source/chronology.

    A hard-coded boolean is never proof of preregistration.  A prospective plan
    must carry a valid six-outcome declaration whose exact source file hash is
    recorded in the plan and whose plan timestamp precedes the final receipts.
    A historical plan without such a declaration is reported as an explicitly
    labelled recomputation diagnostic, not as a preregistered family.
    """
    prospective = plan_requires_receipt_epoch_binding(plan)
    design = _embedded_research_design(plan) or {}
    family, family_problem = _family_from_design(design)
    research_config = plan.get('research_config')
    source: dict[str, Any] = {}
    problems: list[str] = []
    if isinstance(research_config, Mapping):
        path = research_config.get('path')
        recorded_sha = research_config.get('sha256')
        source = {
            'type': 'frozen_research_config',
            'path': str(path) if path else None,
            'recorded_sha256': recorded_sha,
            'declaration_sha256': _canonical_sha256(research_config.get('declaration')),
        }
        if not isinstance(path, str) or not path.strip():
            problems.append('declaration_source_path_missing')
        else:
            resolved = Path(path)
            if not resolved.is_absolute():
                resolved = Path(__file__).resolve().parents[1] / resolved
            observed_sha = _file_sha256(resolved)
            source['observed_sha256'] = observed_sha
            if observed_sha is None:
                problems.append('declaration_source_unavailable')
            elif recorded_sha != observed_sha:
                problems.append('declaration_source_hash_mismatch')
    else:
        plans_declaration = plan.get('analysis_declaration')
        if isinstance(plans_declaration, Mapping):
            source = {
                'type': 'plan_analysis_declaration',
                'path': None,
                'recorded_sha256': plans_declaration.get('sha256'),
                'declaration_sha256': _canonical_sha256(plans_declaration),
            }
        else:
            problems.append('declaration_source_missing')
    plan_sha = plan.get('plan_sha256')
    if not isinstance(plan_sha, str) or not plan_sha.strip():
        problems.append('plan_sha256_missing')
    plan_ts = _parse_timestamp(plan.get('generated_at'))
    receipt_ts, receipt_text, receipt_documents = _earliest_receipt_timestamp(observations)
    chronology = {
        'plan_generated_at': plan.get('generated_at'),
        'earliest_final_receipt_generated_at': receipt_text,
        'final_receipt_documents': receipt_documents,
        'plan_precedes_final_receipts': (
            None if plan_ts is None or receipt_ts is None else plan_ts <= receipt_ts
        ),
        'status': (
            'no_final_receipts' if receipt_documents == 0
            else 'verified' if receipt_ts is not None and plan_ts is not None
            and plan_ts <= receipt_ts
            else 'unverified'
        ),
    }
    if prospective:
        if family_problem:
            problems.append(family_problem)
        if plan_ts is None:
            problems.append('plan_generated_at_missing_or_invalid')
        if receipt_documents and receipt_ts is None:
            problems.append('earliest_final_receipt_generated_at_missing_or_invalid')
        elif receipt_ts is not None and plan_ts is not None and plan_ts > receipt_ts:
            problems.append('plan_not_before_final_receipts')
    if prospective and not problems:
        return {
            'status': 'verified',
            'declared_before_analysis': True,
            'role': 'prospective_preregistered_family',
            'family': family,
            'source': source,
            'chronology': chronology,
            'problems': [],
            'reason': None,
        }
    if prospective:
        return {
            'status': 'invalid',
            'declared_before_analysis': False,
            'role': 'prospective_declaration_unverified',
            'family': family or _implemented_family(),
            'source': source,
            'chronology': chronology,
            'problems': list(dict.fromkeys(problems)),
            'reason': 'prospective analysis family declaration is not source-bound',
        }
    return {
        'status': 'historical_unverified',
        'declared_before_analysis': False,
        'role': 'historical_recomputation_diagnostic',
        'family': _implemented_family(),
        'source': source,
        'chronology': chronology,
        'problems': list(dict.fromkeys(problems)),
        'reason': 'no source-bound preselection family declaration was available',
    }


def _family_record(declaration: Mapping[str, Any]) -> dict[str, Any]:
    family = dict(declaration.get('family') or {})
    return {
        'declared_before_analysis': declaration.get('declared_before_analysis') is True,
        'declaration_status': declaration.get('status'),
        'role': declaration.get('role'),
        'source': dict(declaration.get('source') or {}),
        'chronology': dict(declaration.get('chronology') or {}),
        'problems': list(declaration.get('problems') or []),
        **family,
        'family_size': int(family.get('family_size') or len(FAMILY_OUTCOMES)),
        'outcomes': list(family.get('outcomes') or FAMILY_OUTCOMES),
    }


# Axes that must agree for a coordinate pair to be compared. Repeat is a
# pairing axis (paired by repeat) and is dropped only when pooling pairs.
PAIR_AXES = (
    "experiment_block", "provider", "model", "surface", "security_level",
    "target_method", "payload_mode", "repeat_index", "fixture_id",
    "protocol_version", "policy_epoch_id", "guardrail_retry_enabled",
    "guardrail_handling", "token_price_schedule_sha256",
)
RECEIPT_AXES = (
    "scoring_mode", "reviewer_id", "review_version", "rubric_version",
    "scoring_rule_sha256", "metrics_epoch",
)

OBSERVATION_STATES = (
    "final", "pending_review", "unassessable", "error", "interrupted", "missing",
    "epoch_mismatch", "identity_incomplete", "ambiguous_match",
)

# One descriptive row per planned model × surface × level × method/condition
# coordinate. Repeats are listed individually and are never collapsed into a
# best-of-N value.
SPREAD_AXES = (
    "block", "policy_epoch_id", "fixture_id", "protocol_version",
    "candidate_budget", "provider", "model", "surface", "security_level",
    "experiment_condition", "target_method", "payload_mode",
    "guardrail_retry_enabled", "guardrail_handling",
)

# Model contrasts compare separate executions, so provider/model are excluded
# from the stratum key. Provider and model are not pairing axes: repeat indices
# are design-aligned only and never form a matched pair.
MODEL_STRATUM_AXES = (
    "block", "policy_epoch_id", "fixture_id", "protocol_version",
    "candidate_budget", "surface", "security_level", "target_method",
    "payload_mode", "guardrail_retry_enabled", "guardrail_handling",
)


def _recorded_snapshot_sha(document: Mapping[str, Any]) -> str | None:
    """Return the run's frozen payload policy/template identity, if recorded.

    The runner persists it as ``config.policy_epoch.recorded_payload_policy_sha256``
    and as ``config.recorded_payload_policy.snapshot_sha256``; the study plan
    also carries the flat ``payload_policy_snapshot_sha256`` constraint name.
    """
    raw_config = document.get("config")
    config: Mapping[str, Any] = raw_config if isinstance(raw_config, Mapping) else {}
    direct = config.get("payload_policy_snapshot_sha256")
    if isinstance(direct, str) and direct:
        return direct
    raw_epoch = config.get("policy_epoch")
    epoch: Mapping[str, Any] = raw_epoch if isinstance(raw_epoch, Mapping) else {}
    recorded_hash = epoch.get("recorded_payload_policy_sha256")
    if isinstance(recorded_hash, str) and recorded_hash:
        return recorded_hash
    raw_recorded = config.get("recorded_payload_policy")
    if isinstance(raw_recorded, Mapping):
        digest = raw_recorded.get("snapshot_sha256")
        if isinstance(digest, str) and digest:
            return digest
    return None


def _identity(entry: Any) -> dict[str, Any]:
    """Read one execution artifact's declared study identity (never inferred)."""
    record = entry.record
    config = record.get("config") if isinstance(record.get("config"), dict) else {}
    epoch = record.get("policy_epoch")
    if not isinstance(epoch, dict):
        epoch = record.get("scoring_policy_epoch") if isinstance(record.get("scoring_policy_epoch"), dict) else {}
    profile = config.get("scoring_profile")
    return {
        "execution_id": record.get("execution_id"),
        "run_id": record.get("run_id"),
        "provider": record.get("provider") or config.get("provider"),
        "model": record.get("model") or config.get("model"),
        "surface": record.get("surface") or config.get("surface"),
        "security_level": record.get("security_level") or config.get("security_level"),
        "payload_mode": record.get("payload_mode") or config.get("payload_mode"),
        "experiment_condition": record.get("experiment_condition") or config.get("experiment_condition"),
        "experiment_block": record.get("experiment_block") or config.get("experiment_block"),
        "target_method": record.get("target_method") if record.get("target_method") is not None else config.get("target_method"),
        "repeat_index": record.get("repeat_index") if record.get("repeat_index") is not None else config.get("repeat_index"),
        "policy_epoch_id": epoch.get("epoch_id"),
        "policy_source_hashes_sha256": epoch.get("source_hashes_sha256"),
        "fixture_id": config.get("fixture_id"),
        "protocol_version": config.get("protocol_version"),
        "candidate_budget": config.get("candidate_budget"),
        "scoring_profile_sha256": profile.get("sha256") if isinstance(profile, dict) else None,
        "guardrail_retry_enabled": (
            config.get("guardrail_retry_enabled")
            if config.get("guardrail_retry_enabled") is not None
            else config.get("evasion_enabled")
        ),
        "guardrail_handling": (
            config.get("guardrail_handling")
            if config.get("guardrail_handling") is not None
            else config.get("evasion_mode")
        ),
        "token_price_schedule_sha256": (
            evidence_hash(config["token_price_schedule"])
            if isinstance(config.get("token_price_schedule"), dict) else None
        ),
        "source_sha256": entry.source.get("sha256") if isinstance(entry.source, Mapping) else None,
        "payload_policy_snapshot_sha256": _recorded_snapshot_sha(record),
    }


def _readiness_ok(record: Mapping[str, Any]) -> tuple[bool, str | None]:
    """Return whether the run's own readiness receipt supports pairing."""
    readiness = record.get("readiness")
    if not isinstance(readiness, Mapping):
        final_state = record.get("final_state")
        readiness = final_state.get("readiness") if isinstance(final_state, Mapping) else None
    if not isinstance(readiness, Mapping):
        return False, "readiness_receipt_missing"
    if readiness.get("status") != "ready":
        return False, f"readiness_{readiness.get('status') or 'unknown'}"
    if readiness.get("requested_level") != readiness.get("observed_level"):
        return False, "observed_level_mismatch"
    restoration = readiness.get("fixture_restoration")
    if not isinstance(restoration, Mapping) or restoration.get("equivalence") != "attested":
        return False, "fixture_restoration_not_attested"
    return True, None


def _workflow_final(workflow: Mapping[str, Any]) -> bool:
    return workflow.get("status") == "final" and isinstance(workflow.get("components"), dict) and all(
        isinstance(workflow["components"].get(name), (int, float))
        and not isinstance(workflow["components"].get(name), bool)
        for name in ("Smethod", "Spayload", "Sexploit", "Schain", "Soutput")
    ) and isinstance(workflow.get("Srun_final"), (int, float))


def _absolute(binding: Mapping[str, Any], catalog: ArtifactCatalog) -> Path | None:
    """Resolve a catalog binding to the absolute document path."""
    root_id = binding.get("root_id")
    relative = binding.get("path")
    if not isinstance(root_id, str) or not isinstance(relative, str):
        return None
    root = catalog.roots.get(root_id)
    if root is None:
        return None
    return root if root.is_file() else root / relative


def _final_receipts(
    catalog: ArtifactCatalog, reviews: Mapping[str, Mapping[str, Any]]
) -> tuple[dict[str, tuple[Path, dict[str, Any]]], dict[str, str]]:
    """Return final receipt documents per grader mode, plus review reasons."""
    documents: dict[str, tuple[Path, dict[str, Any]]] = {}
    reasons: dict[str, str] = {}
    for mode, workflow in reviews.items():
        if not _workflow_final(workflow):
            reasons[mode] = str(workflow.get("reason") or workflow.get("status") or "pending")
            continue
        binding = workflow.get("receipt")
        path = _absolute(binding, catalog) if isinstance(binding, Mapping) else None
        if path is None:
            reasons[mode] = "receipt_path_unavailable"
            continue
        try:
            document = catalog.read(path)
        except (OSError, ValueError, KeyError, TypeError):
            reasons[mode] = "receipt_unreadable"
            continue
        if (
            document.get("artifact_type") != "thesis_score_receipt"
            or document.get("status") != "final"
        ):
            reasons[mode] = "receipt_not_final"
            continue
        documents[mode] = (path, document)
    return documents, reasons


def _rank(values: list[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    position = 0
    while position < len(order):
        end = position
        while end + 1 < len(order) and values[order[end + 1]] == values[order[position]]:
            end += 1
        average = (position + end) / 2 + 1
        for offset in range(position, end + 1):
            ranks[order[offset]] = average
        position = end + 1
    return ranks


def _wilcoxon_signed_rank(differences: list[float]) -> dict[str, Any]:
    """Two-sided signed-rank test with average-tie ranks; zero deltas dropped."""
    nonzero = [value for value in differences if value != 0]
    n = len(nonzero)
    if n == 0:
        return {"n_pairs": len(differences), "n_nonzero": 0, "statistic": None, "p_value": None,
                "method": "wilcoxon_signed_rank", "reason": "all_differences_zero",
                "effect_size": None, "effect_size_name": "matched_pairs_rank_biserial",
                "zero_differences": "dropped"}
    ranks = _rank([abs(value) for value in nonzero])
    doubled = [int(round(rank * 2)) for rank in ranks]
    positive = sum(rank for rank, value in zip(doubled, nonzero) if value > 0)
    negative = sum(rank for rank, value in zip(doubled, nonzero) if value < 0)
    total = positive + negative
    if n <= 25:
        counts = [0] * (sum(doubled) + 1)
        counts[0] = 1
        for weight in doubled:
            for value in range(len(counts) - 1, weight - 1, -1):
                counts[value] += counts[value - weight]
        denominator = 2 ** n
        lower = sum(counts[: positive + 1]) / denominator
        upper = sum(counts[positive:]) / denominator
        p_value = min(1.0, 2 * min(lower, upper))
        method = "exact"
    else:
        mean = total / 2
        variance = sum(weight * weight for weight in doubled) / 4
        if variance == 0:
            p_value, method = None, "unavailable_zero_variance"
        else:
            z = (positive - mean - 0.5) / math.sqrt(variance)
            p_value = min(1.0, math.erfc(abs(z) / math.sqrt(2)))
            method = "normal_approximation"
    effect = (positive - negative) / total if total else None
    return {
        "n_pairs": len(differences), "n_nonzero": n,
        "statistic": positive / 2, "p_value": p_value, "method": method,
        "effect_size": effect, "effect_size_name": "matched_pairs_rank_biserial",
        "zero_differences": "dropped",
    }


def _bootstrap_median_ci(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"estimate": None, "low": None, "high": None, "method": "bootstrap_percentile",
                "resamples": 0, "seed": BOOTSTRAP_SEED, "reason": "no_pairs"}
    rng = random.Random(BOOTSTRAP_SEED)
    estimates = sorted(
        median([values[rng.randrange(len(values))] for _ in values])
        for _ in range(BOOTSTRAP_RESAMPLES)
    )
    return {
        "estimate": round(median(values), 4),
        "low": round(estimates[int(0.025 * (len(estimates) - 1))], 4),
        "high": round(estimates[int(0.975 * (len(estimates) - 1))], 4),
        "method": "bootstrap_percentile", "resamples": BOOTSTRAP_RESAMPLES,
        "seed": BOOTSTRAP_SEED,
    }


def _holm(
    p_values: list[float | None], *, family_size: int | None = None,
) -> list[float | None]:
    """Holm-Bonferroni step-down within the declared family.

    Missing p-values keep a null adjusted value.  They never shrink the family:
    the default family size is the number of declared slots in ``p_values``,
    and callers with an explicit six-outcome declaration pass that size.  An
    unavailable hypothesis therefore cannot receive adjusted significance.
    """
    indexed = [(value, index) for index, value in enumerate(p_values) if value is not None]
    adjusted: list[float | None] = [None] * len(p_values)
    if not indexed:
        return adjusted
    total = len(p_values) if family_size is None else int(family_size)
    if total < len(indexed):
        raise ValueError(
            f'Holm family size {total} is smaller than the {len(indexed)} available p-values'
        )
    indexed.sort()
    running = 0.0
    for position, (value, index) in enumerate(indexed):
        candidate = min(1.0, value * (total - position))
        running = max(running, candidate)
        adjusted[index] = running
    return adjusted


def _mann_whitney_exploratory(
    left: list[float],
    right: list[float],
    *,
    reason: str = "declared exploratory comparison; independence is not established",
) -> dict[str, Any]:
    """Two-sided, tie-corrected rank sum; never assume independent repeats.

    Continuity correction moves the absolute distance *towards* the null mean,
    so exchanging groups preserves p while reversing the signed effect size.
    The normal approximation is explicitly exploratory at limited sample sizes.
    """
    result: dict[str, Any] = {
        "status": "unavailable", "independent": False, "reason": "empty_group",
        "n_left": len(left), "n_right": len(right), "u": None, "p_value": None,
        "effect_size": None, "effect_size_name": "rank_biserial_exploratory",
        "method": "normal_approximation_tie_corrected",
        "continuity_correction": 0.5,
        "left": _outcome_distribution(left), "right": _outcome_distribution(right),
        "limitations": (
            "Shared fixture, model and grader can induce dependence; equal repeat "
            "indices do not establish independence. Small-repeat asymptotic p-values "
            "are exploratory, not confirmatory evidence of model ranking."
        ),
    }
    if not left or not right:
        return result
    combined = left + right
    ranks = _rank(combined)
    n1, n2 = len(left), len(right)
    u_value = sum(ranks[:n1]) - n1 * (n1 + 1) / 2
    total = n1 + n2
    ties = Counter(combined)
    tie_term = sum(count ** 3 - count for count in ties.values())
    variance = n1 * n2 / 12 * (total + 1 - tie_term / (total * (total - 1)))
    distance = max(0.0, abs(u_value - n1 * n2 / 2) - 0.5)
    # All observations tied: U equals its null mean, with no rank separation.
    p_value = math.erfc(distance / math.sqrt(2 * variance)) if variance > 0 else 1.0
    result.update(
        status="exploratory", reason=reason, u=u_value, p_value=min(1.0, p_value),
        effect_size=round(2 * u_value / (n1 * n2) - 1, 4),
        tie_correction_term=tie_term, null_variance=variance,
    )
    return result


def _unavailable_distribution(reason: str, *, n: int = 0) -> dict[str, Any]:
    """Return an explicit unavailable descriptive summary, never a zero fill."""
    return {
        "n": n, "mean": None, "median": None, "minimum": None, "maximum": None,
        "range": None, "stdev": None, "variance": None, "iqr": None,
        "all_equal": None,
        "spread_available": False, "spread_reason": reason,
        "availability": False, "unavailable_reason": reason,
        "method": "descriptive",
    }


def _outcome_distribution(values: Iterable[float]) -> dict[str, Any]:
    """Describe one outcome distribution across independently planned repeats.

    Spread statistics use the observed final values only. A single final repeat
    still has an observed value but no sample variance; that distinction is
    reported instead of materialising a zero.
    """
    ordered = sorted(float(value) for value in values)
    n = len(ordered)
    if n == 0:
        return _unavailable_distribution("no_final_receipts")
    summary: dict[str, Any] = {
        "n": n,
        "mean": round(statistics.mean(ordered), 4),
        "median": round(median(ordered), 4),
        "minimum": round(ordered[0], 4),
        "maximum": round(ordered[-1], 4),
        "range": round(ordered[-1] - ordered[0], 4),
        "stdev": None,
        "variance": None,
        "iqr": None,
        "all_equal": ordered[0] == ordered[-1] if n >= 2 else None,
        "spread_available": n >= 2,
        "spread_reason": None if n >= 2 else "fewer_than_two_final_repeats",
        "availability": True,
        "unavailable_reason": None,
        "method": "descriptive; sample variance/stdev (n-1), inclusive-quartile IQR",
    }
    if n >= 2:
        quartiles = statistics.quantiles(ordered, n=4, method="inclusive")
        summary["stdev"] = round(statistics.stdev(ordered), 4)
        summary["variance"] = round(statistics.variance(ordered), 4)
        summary["iqr"] = round(quartiles[2] - quartiles[0], 4)
    return summary


def _receipt_values(document: Mapping[str, Any]) -> dict[str, float | None]:
    """Read the six graded outcomes from one final receipt without imputation."""
    raw_components = document.get("components")
    components: Mapping[str, Any] = raw_components if isinstance(raw_components, Mapping) else {}
    values: dict[str, float | None] = {}
    for name in COMPONENT_NAMES:
        raw = document.get("Srun_final") if name == "Srun_final" else components.get(name)
        values[name] = (
            float(raw)
            if isinstance(raw, (int, float)) and not isinstance(raw, bool) and math.isfinite(float(raw))
            else None
        )
    return values


def _final_receipt_complete(document: Mapping[str, Any]) -> bool:
    """A final receipt must carry all five components and a finite composite."""
    components = document.get("components")
    if not isinstance(components, Mapping):
        return False
    for name in COMPONENT_NAMES[:-1]:
        value = components.get(name)
        if not isinstance(value, (int, float)) or isinstance(value, bool) \
                or not math.isfinite(float(value)) or not 0 <= float(value) <= 4:
            return False
    srun = document.get("Srun_final")
    return (
        isinstance(srun, (int, float)) and not isinstance(srun, bool)
        and math.isfinite(float(srun)) and 0 <= float(srun) <= 4
    )


def _cell_identity(coordinate: Mapping[str, Any]) -> dict[str, Any]:
    return {name: coordinate.get(name) for name in SPREAD_AXES}


def _receipt_graders(
    document: Mapping[str, Any],
) -> tuple[tuple[tuple[str, str], ...] | None, str | None]:
    """Return the recorded ``(reviewer_id, review_version)`` identities.

    ``compare_receipts`` groups repeats by the latest decision per candidate,
    so the same rule is used here: a superseded decision never contributes a
    stale grader. A missing, empty or malformed ``review_history`` yields no
    identity and an explicit reason; it is never inferred from the scoring mode
    or treated as compatible with another receipt that lacks an identity.
    """
    history = document.get("review_history")
    if history is None:
        return None, "review_history_missing"
    if not isinstance(history, list):
        return None, "review_history_invalid"
    latest: dict[Any, Mapping[str, Any]] = {}
    for decision in history:
        if not isinstance(decision, Mapping):
            return None, "review_decision_invalid"
        candidate = decision.get("candidate_id")
        if not isinstance(candidate, str) or not candidate:
            return None, "review_candidate_identity_missing"
        latest[candidate] = decision
    graders: set[tuple[str, str]] = set()
    for decision in latest.values():
        reviewer = decision.get("reviewer_id")
        version = decision.get("review_version")
        if not (isinstance(reviewer, str) and reviewer.strip()):
            return None, "reviewer_id_missing"
        if not (isinstance(version, str) and version.strip()):
            return None, "review_version_missing"
        graders.add((reviewer, version))
    if not graders:
        return None, "review_history_empty"
    return tuple(sorted(graders)), None


def _grader_rows(graders: Iterable[tuple[str, str]]) -> list[dict[str, str]]:
    return [
        {"reviewer_id": reviewer, "review_version": version}
        for reviewer, version in graders
    ]


def _grader_problems(documents: Iterable[Mapping[str, Any]]) -> list[str]:
    problems: set[str] = set()
    for document in documents:
        problem = _receipt_graders(document)[1]
        if problem:
            problems.add(problem)
    return sorted(problems)


def _grader_unavailable_reason(problems: Iterable[str]) -> str:
    return "receipt_grader_identity_unavailable:" + ";".join(problems)


def _grader_report(documents: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Describe the recorded grader identities behind a set of receipts."""
    materialized = list(documents)
    graders: set[tuple[str, str]] = set()
    reasons: set[str] = set()
    for document in materialized:
        values, problem = _receipt_graders(document)
        if problem:
            reasons.add(problem)
        elif values is None:
            # Explicit failure path: assertion removal under ``python -O`` must
            # not make a malformed grader identity look compatible.
            reasons.add('grader_identity_unavailable')
        else:
            graders.update(values)
    if not materialized:
        status = "no_final_receipts"
    elif reasons:
        status = "unavailable"
    else:
        status = "recorded"
    report: dict[str, Any] = {"status": status, "graders": _grader_rows(sorted(graders))}
    if reasons:
        report["reasons"] = sorted(reasons)
    return report


def _grader_component_difference(
    left_graders: tuple[tuple[str, str], ...],
    right_graders: tuple[tuple[str, str], ...],
) -> list[str]:
    if left_graders == right_graders:
        return []
    left_ids = {reviewer for reviewer, _version in left_graders}
    right_ids = {reviewer for reviewer, _version in right_graders}
    left_versions = {version for _reviewer, version in left_graders}
    right_versions = {version for _reviewer, version in right_graders}
    different: list[str] = []
    if left_ids != right_ids:
        different.append("reviewer_id")
    if left_versions != right_versions:
        different.append("review_version")
    return different or ["graders"]


def _grader_difference(left: Mapping[str, Any], right: Mapping[str, Any]) -> list[str]:
    """Return the grader components that make two receipts incompatible."""
    left_graders, left_problem = _receipt_graders(left)
    right_graders, right_problem = _receipt_graders(right)
    if left_problem or right_problem or left_graders is None or right_graders is None:
        return ["grader_identity"]
    return _grader_component_difference(left_graders, right_graders)


def _grader_identity_problem(left: Mapping[str, Any], right: Mapping[str, Any]) -> str | None:
    """Return why two receipts cannot share one grader identity boundary."""
    left_graders, left_problem = _receipt_graders(left)
    right_graders, right_problem = _receipt_graders(right)
    problems = sorted({problem for problem in (left_problem, right_problem) if problem})
    if problems:
        return _grader_unavailable_reason(problems)
    if left_graders is None or right_graders is None:
        # Explicit failure path, equivalent to the removed assertion but visible
        # under optimised execution.
        return _grader_unavailable_reason(['grader_identity_unavailable'])
    different = _grader_component_difference(left_graders, right_graders)
    if not different:
        return None
    if different == ["reviewer_id"]:
        return "receipt_reviewer_id_mismatch"
    if different == ["review_version"]:
        return "receipt_review_version_mismatch"
    return "receipt_graders_mismatch"


def _receipt_compatibility_key(document: Mapping[str, Any]) -> str:
    """Scorer pair identity plus the recorded grader identity/version."""
    graders, problem = _receipt_graders(document)
    evidence: Any = problem if problem else graders
    return (
        f"{pair_compatibility_key(document)}|graders:"
        + json.dumps(evidence, sort_keys=True, default=str, separators=(",", ":"))
    )


def _receipt_compatibility_mismatches(
    left: Mapping[str, Any], right: Mapping[str, Any]
) -> list[str]:
    return sorted(
        set(pair_compatibility_mismatches(left, right))
        | set(_grader_difference(left, right))
    )


def _mode_spread(mode: str, planned_pairs: list[tuple[Mapping[str, Any], Mapping[str, Any]]]) -> dict[str, Any]:
    """Describe one grader mode within one planned coordinate cell."""
    repeat_rows: list[dict[str, Any]] = []
    documents: list[Mapping[str, Any]] = []
    for coordinate, observation in planned_pairs:
        repeat_index = coordinate.get("repeat_index")
        state = str(observation.get("state"))
        execution_id = (observation.get("identity") or {}).get("execution_id")
        if state != "final":
            repeat_rows.append({
                "repeat_index": repeat_index, "state": state,
                "reason": observation.get("reason") or state,
                "execution_id": execution_id, "values": None,
                "ready": observation.get("ready"),
                "readiness_reason": observation.get("readiness_reason"),
            })
            continue
        binding = (observation.get("documents") or {}).get(mode)
        if binding is None:
            repeat_rows.append({
                "repeat_index": repeat_index, "state": "final",
                "reason": "grader_mode_missing", "execution_id": execution_id,
                "values": None,
                "ready": observation.get("ready"),
                "readiness_reason": observation.get("readiness_reason"),
            })
            continue
        _path, document = binding
        values = _receipt_values(document)
        repeat_rows.append({
            "repeat_index": repeat_index, "state": "final", "reason": None,
            "execution_id": execution_id, "values": values,
            "missing_components": [name for name, value in values.items() if value is None],
            "ready": observation.get("ready"),
            "readiness_reason": observation.get("readiness_reason"),
        })
        documents.append(document)

    compatibility_keys = sorted({_receipt_compatibility_key(document) for document in documents})
    grader_problems = _grader_problems(documents)
    compatible = len(compatibility_keys) <= 1 and not grader_problems
    mismatches: list[str] = []
    if not compatible:
        if grader_problems:
            mismatches = sorted({"grader_identity", *grader_problems})
        else:
            reference = documents[0]
            mismatches = sorted({
                component
                for document in documents[1:]
                for component in _receipt_compatibility_mismatches(reference, document)
            })
    grader_only = {"reviewer_id", "review_version", "graders", "grader_identity"}
    if not compatible:
        if grader_problems:
            incompatible_reason = _grader_unavailable_reason(grader_problems)
        elif mismatches and set(mismatches) <= grader_only:
            incompatible_reason = "receipt_grader_identity_mismatch"
        else:
            incompatible_reason = "receipt_compatibility_mismatch"
    else:
        incompatible_reason = "receipt_compatibility_mismatch"
    metrics: dict[str, dict[str, Any]] = {}
    for name in COMPONENT_NAMES:
        values = [
            row["values"][name]
            for row in repeat_rows
            if isinstance(row.get("values"), Mapping) and row["values"].get(name) is not None
        ]
        metrics[name] = (
            _outcome_distribution(values) if compatible and values
            else _unavailable_distribution(
                incompatible_reason if not compatible
                else "no_final_receipts" if not documents
                else "component_unavailable",
                n=len(values),
            )
        )
    return {
        "scoring_mode": mode,
        "status": "final" if compatible else "incompatible",
        "reason": None if compatible else incompatible_reason,
        "grader_identity": _grader_report(documents),
        "n_planned": len(planned_pairs),
        "n_final": len(documents),
        "n_ready_final": sum(
            1 for row in repeat_rows
            if row["state"] == "final" and row.get("reason") is None
            and row.get("ready") is True
        ),
        "n_with_values": sum(
            1 for row in repeat_rows
            if isinstance(row.get("values"), Mapping)
            and any(value is not None for value in row["values"].values())
        ),
        "compatibility_keys": compatibility_keys,
        "receipt_compatibility_mismatches": mismatches,
        "metrics": metrics,
        "repeats": repeat_rows,
    }


def _spread_summary(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Count assessed and degenerate cell/mode rows per graded outcome."""
    materialized = list(rows)
    by_metric: dict[str, dict[str, Any]] = {}
    for name in COMPONENT_NAMES:
        by_metric[name] = {
            "n_cells_planned": len(materialized), "n_cell_modes": 0,
            "n_zero_variance": 0, "n_nonzero_variance": 0,
            "n_spread_unavailable": 0, "unavailable_reasons": Counter(),
        }
    for row in materialized:
        for mode_row in (row.get("modes") or {}).values():
            for name, distribution in (mode_row.get("metrics") or {}).items():
                bucket = by_metric.setdefault(name, {
                    "n_cells_planned": len(materialized), "n_cell_modes": 0,
                    "n_zero_variance": 0, "n_nonzero_variance": 0,
                    "n_spread_unavailable": 0, "unavailable_reasons": Counter(),
                })
                bucket["n_cell_modes"] += 1
                if distribution.get("spread_available"):
                    if distribution.get("all_equal") is True:
                        bucket["n_zero_variance"] += 1
                    else:
                        bucket["n_nonzero_variance"] += 1
                else:
                    bucket["n_spread_unavailable"] += 1
                    reason = str(distribution.get("spread_reason") or "unknown")
                    bucket["unavailable_reasons"][reason] += 1
    return {
        "definition": (
            "Zero-variance cells are rubric-saturation or task-difficulty findings; "
            "they are not repaired by dropping repeats or changing caps."
        ),
        "n_cells_planned": len(materialized),
        "n_cells_without_final": sum(
            1 for row in materialized if row.get("n_final_repeats") == 0
        ),
        "n_cells_without_modes": sum(1 for row in materialized if not row.get("modes")),
        "by_metric": {
            name: {**bucket, "unavailable_reasons": dict(sorted(bucket["unavailable_reasons"].items()))}
            for name, bucket in by_metric.items()
        },
    }


def _outcome_spread(
    planned: list[dict[str, Any]],
    observations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Report all planned cells and repeats with descriptive outcome spread."""
    cells: dict[tuple[str, ...], dict[str, Any]] = {}
    for index, coordinate in enumerate(planned):
        identity = _cell_identity(coordinate)
        key = tuple(repr(identity[name]) for name in SPREAD_AXES)
        cells.setdefault(key, {"coordinate": identity, "pairs": []})["pairs"].append(
            (coordinate, observations[index])
        )
    rows: list[dict[str, Any]] = []
    for key in sorted(cells):
        cell = cells[key]
        planned_pairs = sorted(
            cell["pairs"], key=lambda pair: str(pair[0].get("repeat_index"))
        )
        repeat_indices = [coordinate.get("repeat_index") for coordinate, _ in planned_pairs]
        duplicate_repeat = len({str(index) for index in repeat_indices}) != len(repeat_indices)
        observation_states = Counter(str(observation.get("state")) for _, observation in planned_pairs)
        unavailable_reasons = Counter(
            str(observation.get("reason") or observation.get("state"))
            for _, observation in planned_pairs
            if observation.get("state") != "final"
        )
        final_repeats = observation_states.get("final", 0)
        ready_final_repeats = sum(
            1 for _, observation in planned_pairs
            if observation.get("state") == "final" and observation.get("ready") is True
        )
        modes = sorted({
            str(mode)
            for _, observation in planned_pairs
            for mode in (observation.get("documents") or {})
        })
        row: dict[str, Any] = {
            "coordinate": cell["coordinate"],
            "planned_repeats": len(planned_pairs),
            "planned_repeat_indices": repeat_indices,
            "n_final_repeats": final_repeats,
            "n_ready_final_repeats": ready_final_repeats,
            "n_unavailable_repeats": len(planned_pairs) - final_repeats,
            "repeat_coverage": (
                "complete" if final_repeats == len(planned_pairs)
                else "partial" if final_repeats else "none"
            ),
            "observation_states": dict(sorted(observation_states.items())),
            "unavailable_reasons": dict(sorted(unavailable_reasons.items())),
            "status": "incompatible" if duplicate_repeat else "assessed",
            "reason": "duplicate_repeat_index" if duplicate_repeat else (
                None if modes else "no_final_receipts"
            ),
            "modes": {},
        }
        if not duplicate_repeat:
            for mode in modes:
                row["modes"][mode] = _mode_spread(mode, planned_pairs)
        rows.append(row)
    return {
        "definition": (
            "One row per planned frozen-cell identity (block, policy epoch, fixture, "
            "protocol, budget, provider, model, surface, security level, condition, "
            "method, payload mode, guardrail). Every planned repeat index is listed; "
            "final receipts are distributed per grader mode; missing, failed, pending, "
            "and unavailable repeats remain explicit and are never zero-filled."
        ),
        "repeat_unit": "one independently planned repeat index",
        "spread_statistic": "sample variance/stdev across observed final repeats; descriptive only",
        "cells": rows,
        "summary": _spread_summary(rows),
    }


def _planned_coordinates(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    planned: list[dict[str, Any]] = []
    for block, coordinates in (plan.get("blocks") or {}).items():
        for coordinate in coordinates:
            planned.append({**coordinate, "block": block})
    return planned


def _coordinate_identity_problems(
    coordinate: Mapping[str, Any],
    identity: Mapping[str, Any],
    constraints: Mapping[str, Any],
    plan_source_hashes_sha256: str | None = None,
) -> str | None:
    """Return the first reason a matched artifact cannot represent the coordinate."""
    if identity.get("experiment_block") != coordinate["block"]:
        return "block_mismatch"
    if identity.get("target_method") != coordinate["target_method"]:
        return "target_method_mismatch"
    if identity.get("repeat_index") != coordinate["repeat_index"]:
        return "repeat_mismatch"
    if identity.get("payload_mode") != coordinate["payload_mode"]:
        return "payload_mode_mismatch"
    if identity.get("experiment_condition") != coordinate["experiment_condition"]:
        return "condition_mismatch"
    if identity.get("surface") != coordinate["surface"]:
        return "surface_mismatch"
    if identity.get("security_level") != coordinate["security_level"]:
        return "security_level_mismatch"
    if identity.get("provider") != coordinate["provider"]:
        return "provider_mismatch"
    if not identity.get("policy_epoch_id"):
        return "missing_policy_epoch"
    if identity["policy_epoch_id"] != coordinate["policy_epoch_id"]:
        return "epoch_mismatch"
    if not identity.get("fixture_id") or not identity.get("protocol_version"):
        return "missing_fixture_identity"
    if identity["fixture_id"] != constraints.get("fixture_id"):
        return "fixture_mismatch"
    if identity["protocol_version"] != constraints.get("protocol_version"):
        return "protocol_mismatch"
    if identity.get("candidate_budget") != constraints.get("candidate_budget"):
        return "candidate_budget_mismatch"
    if constraints.get("scoring_profile_sha256") and identity.get("scoring_profile_sha256") != constraints["scoring_profile_sha256"]:
        return "scoring_profile_mismatch"
    if plan_source_hashes_sha256:
        if not identity.get("policy_source_hashes_sha256"):
            return "missing_source_identity"
        if identity["policy_source_hashes_sha256"] != plan_source_hashes_sha256:
            return REASON_SOURCE_HASH_MISMATCH
    expected_guardrail = (
        coordinate.get("guardrail_retry_enabled"), coordinate.get("guardrail_handling"),
    )
    observed_guardrail = (
        identity.get("guardrail_retry_enabled"), identity.get("guardrail_handling"),
    )
    if any(value is not None for value in expected_guardrail) and observed_guardrail != expected_guardrail:
        return REASON_GUARDRAIL_MISMATCH
    if constraints.get("payload_policy_snapshot_sha256"):
        if not identity.get("payload_policy_snapshot_sha256"):
            return "missing_payload_policy_snapshot"
        if identity["payload_policy_snapshot_sha256"] != constraints["payload_policy_snapshot_sha256"]:
            return "payload_policy_snapshot_mismatch"
    if constraints.get("token_price_schedule_sha256"):
        if not identity.get("token_price_schedule_sha256"):
            # A frozen plan price identity with an artifact that records none is
            # unavailable, never a match by omission.
            return "missing_token_price_schedule"
        if identity["token_price_schedule_sha256"] != constraints["token_price_schedule_sha256"]:
            return REASON_TOKEN_PRICE_MISMATCH
    return None


def _match_entries(
    planned: list[dict[str, Any]],
    entries: list[Any],
    constraints: Mapping[str, Any],
    plan_source_hashes_sha256: str | None,
) -> tuple[dict[int, Any], dict[int, str], dict[int, list[str]], set[int]]:
    """Match each planned coordinate to exactly one fully compatible artifact.

    The match predicate covers the complete study identity (block, model,
    provider, surface, level, condition, target, mode, repeat, policy epoch,
    fixture, protocol, budget, guardrail handling, price schedule, source
    hash).  Incompatible artifacts never consume the slot of a valid one, and a
    coordinate with more than one fully compatible artifact is ambiguous and is
    not assessed.
    """
    matched: dict[int, Any] = {}
    reasons: dict[int, str] = {}
    ambiguous: dict[int, list[str]] = {}
    used: set[int] = set()
    axis_names = (
        "provider", "surface", "security_level", "experiment_condition",
        "payload_mode", "repeat_index", "policy_epoch_id", "fixture_id",
        "protocol_version", "candidate_budget", "target_method",
        # Guardrail policy is a hard matching axis: an artifact produced under a
        # different retry/handling policy never represents this coordinate.
        "guardrail_retry_enabled", "guardrail_handling",
    )

    def axis_matches(coordinate: Mapping[str, Any], identity: Mapping[str, Any]) -> bool:
        if identity.get("experiment_block") != coordinate.get("block"):
            return False
        return all(identity.get(axis) == coordinate.get(axis) for axis in axis_names)

    for index, coordinate in enumerate(planned):
        eligible: list[tuple[int, Any]] = []
        problems: list[str] = []
        for entry_index, entry in enumerate(entries):
            if entry_index in used:
                continue
            identity = _identity(entry)
            if not axis_matches(coordinate, identity):
                continue
            problem = _coordinate_identity_problems(
                coordinate, identity, constraints, plan_source_hashes_sha256
            )
            if problem:
                problems.append(problem)
                continue
            eligible.append((entry_index, entry))
        if not eligible:
            reasons[index] = problems[0] if problems else "no_execution_artifact"
            continue
        if len(eligible) > 1:
            ambiguous[index] = [
                str(_identity(entry).get("execution_id")) for _index, entry in eligible
            ]
            continue
        entry_index, entry = eligible[0]
        used.add(entry_index)
        matched[index] = entry
    return matched, reasons, ambiguous, used


def _receipt_metric_summary(document: Mapping[str, Any]) -> dict[str, Any]:
    """Project one final receipt's metrics bundle into an availability summary.

    Final review receipts are the only document that carries the sanctioned
    ``research-metrics.v2`` bundle.  Execution artifacts only carry provisional
    runtime availability, so reading them here would silently report every
    research metric as unavailable.
    """
    metrics = document.get("metrics")
    if not isinstance(metrics, Mapping):
        return {
            "metric_availability": {},
            "metric_unavailable_reason": {"bundle": "metrics_bundle_missing"},
        }
    raw_values = metrics.get("values")
    raw_availability = metrics.get("availability")
    raw_reasons = metrics.get("unavailable_reason")
    values: Mapping[str, Any] = raw_values if isinstance(raw_values, Mapping) else {}
    availability: Mapping[str, Any] = raw_availability if isinstance(raw_availability, Mapping) else {}
    reasons: Mapping[str, Any] = raw_reasons if isinstance(raw_reasons, Mapping) else {}
    summary: dict[str, Any] = {
        str(name): values.get(name) for name in RESEARCH_METRIC_NAMES
    }
    summary["metric_availability"] = {
        str(name): bool(availability.get(name)) for name in RESEARCH_METRIC_NAMES
    }
    summary["metric_unavailable_reason"] = {
        str(name): reasons.get(name) for name in RESEARCH_METRIC_NAMES
        if reasons.get(name)
    }
    summary["metrics_epoch"] = metrics.get("metrics_epoch")
    return summary


def _research_metric_summary(documents: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate final-receipt research metrics without zero fill.

    Callers pass only the receipts belonging to one compatible comparison group
    and grader mode, so neither conditions nor grader modes are pooled.
    """
    summaries = [_receipt_metric_summary(document) for document in documents]
    return aggregate_research_metrics(summaries)


MODEL_CONTRAST_REASON = (
    "model executions are separate runs; repeat indices are design-aligned only, "
    "so this is an exploratory rank-sum, not a matched-pair test"
)


def _coverage(n_final: int, n_planned: int) -> str:
    if n_final >= n_planned and n_planned:
        return "complete"
    return "partial" if n_final else "none"


def _model_stratum(coordinate: Mapping[str, Any]) -> dict[str, Any]:
    return {name: coordinate.get(name) for name in MODEL_STRATUM_AXES}


def _model_stratum_key(coordinate: Mapping[str, Any]) -> tuple[str, ...]:
    stratum = _model_stratum(coordinate)
    return tuple(repr(stratum[name]) for name in MODEL_STRATUM_AXES) + (
        repr(coordinate.get("experiment_condition")),
    )


def _side_compatibility_problem(
    documents: list[Mapping[str, Any]], constraints: Mapping[str, Any]
) -> str | None:
    """Check that repeats on one side of a model contrast are comparable."""
    epoch_problem = _epoch_population_problem(documents)
    if epoch_problem:
        return epoch_problem
    if len(documents) < 2:
        return None
    grader_problems = _grader_problems(documents)
    if grader_problems:
        return _grader_unavailable_reason(grader_problems)
    if len({_receipt_compatibility_key(document) for document in documents}) > 1:
        grader_fields = {
            field
            for document in documents[1:]
            for field in _grader_difference(documents[0], document)
        }
        return (
            "receipt_grader_identity_mismatch"
            if grader_fields
            else "receipt_compatibility_mismatch"
        )
    reference = documents[0]
    for document in documents[1:]:
        problem = _receipt_common_problem(reference, document, constraints)
        if problem:
            return problem
    return None


def _model_contrast_row(
    model_a: tuple[str, str],
    model_b: tuple[str, str],
    key: tuple[str, ...],
    stratum: Mapping[str, Any],
    mode: str | None,
    final_documents: Mapping[tuple[tuple[str, str], tuple[str, ...], str], list[tuple[Any, Mapping[str, Any]]]],
    unready_documents: Mapping[tuple[tuple[str, str], tuple[str, ...], str], list[tuple[Any, Mapping[str, Any]]]],
    observation_states: Mapping[tuple[tuple[str, str], tuple[str, ...]], Counter[str]],
    planned_counts: Mapping[tuple[tuple[str, str], tuple[str, ...]], int],
    modes_by_model_key: Mapping[tuple[tuple[str, str], tuple[str, ...]], set[str]],
    unready_modes_by_model_key: Mapping[tuple[tuple[str, str], tuple[str, ...]], set[str]],
    constraints: Mapping[str, Any],
    declaration: Mapping[str, Any],
) -> dict[str, Any]:
    """Build one model-pair contrast row; never pair or pool silently."""
    left = list(final_documents.get((model_a, key, mode), [])) if mode is not None else []
    right = list(final_documents.get((model_b, key, mode), [])) if mode is not None else []
    left_unready = list(unready_documents.get((model_a, key, mode), [])) if mode is not None else []
    right_unready = list(unready_documents.get((model_b, key, mode), [])) if mode is not None else []
    row: dict[str, Any] = {
        "model_a": {"provider": model_a[0], "model": model_a[1]},
        "model_b": {"provider": model_b[0], "model": model_b[1]},
        "coordinate": dict(stratum["coordinate"]),
        "scoring_mode": mode,
        "direction": f"{model_a[0]}/{model_a[1]} minus {model_b[0]}/{model_b[1]}",
        "paired": False,
        "pairing": "model/provider are not pairing axes; repeat indices are design-aligned only",
        "status": "unsupported",
        "reason": None,
        "n_planned_model_a": planned_counts.get((model_a, key), 0),
        "n_planned_model_b": planned_counts.get((model_b, key), 0),
        "n_final_model_a": len(left),
        "n_final_model_b": len(right),
        "n_unready_final_model_a": len(left_unready),
        "n_unready_final_model_b": len(right_unready),
        "n_observed_final_model_a": len(left) + len(left_unready),
        "n_observed_final_model_b": len(right) + len(right_unready),
        "coverage_model_a": _coverage(len(left), planned_counts.get((model_a, key), 0)),
        "coverage_model_b": _coverage(len(right), planned_counts.get((model_b, key), 0)),
        "observed_coverage_model_a": _coverage(
            len(left) + len(left_unready), planned_counts.get((model_a, key), 0)
        ),
        "observed_coverage_model_b": _coverage(
            len(right) + len(right_unready), planned_counts.get((model_b, key), 0)
        ),
        "observation_states_model_a": dict(sorted(observation_states.get((model_a, key), Counter()).items())),
        "observation_states_model_b": dict(sorted(observation_states.get((model_b, key), Counter()).items())),
        "metrics": {},
    }
    row["partial"] = (
        row["coverage_model_a"] != "complete"
        or row["coverage_model_b"] != "complete"
        or row["n_unready_final_model_a"] > 0
        or row["n_unready_final_model_b"] > 0
    )
    if mode is None:
        row["reason"] = "no_final_receipts"
        return row
    left_modes = modes_by_model_key.get((model_a, key), set())
    right_modes = modes_by_model_key.get((model_b, key), set())
    left_unready_modes = unready_modes_by_model_key.get((model_a, key), set())
    right_unready_modes = unready_modes_by_model_key.get((model_b, key), set())
    if not left and not right:
        if (left_unready or left_unready_modes) and (right_unready or right_unready_modes):
            row["reason"] = "both_models_readiness_not_satisfied"
        elif left_unready or left_unready_modes:
            row["reason"] = "model_a_readiness_not_satisfied"
        elif right_unready or right_unready_modes:
            row["reason"] = "model_b_readiness_not_satisfied"
        else:
            row["reason"] = "no_final_receipts"
        return row
    if not left:
        if left_unready or left_unready_modes:
            row["reason"] = "model_a_readiness_not_satisfied"
        else:
            row["reason"] = (
                "model_a_no_final_receipts" if not left_modes else "model_a_grader_mode_missing"
            )
        return row
    if not right:
        if right_unready or right_unready_modes:
            row["reason"] = "model_b_readiness_not_satisfied"
        else:
            row["reason"] = (
                "model_b_no_final_receipts" if not right_modes else "model_b_grader_mode_missing"
            )
        return row

    left_documents = [document for _observation, document in left]
    right_documents = [document for _observation, document in right]
    row["grader_identity_model_a"] = _grader_report(left_documents)
    row["grader_identity_model_b"] = _grader_report(right_documents)
    left_problem = _side_compatibility_problem(left_documents, constraints)
    if left_problem:
        row["reason"] = f"model_a_{left_problem}"
        return row
    right_problem = _side_compatibility_problem(right_documents, constraints)
    if right_problem:
        row["reason"] = f"model_b_{right_problem}"
        return row
    contrast_problem = _receipt_common_problem(
        left_documents[0], right_documents[0], constraints
    )
    if contrast_problem:
        row["reason"] = f"model_contrast_{contrast_problem}"
        return row

    left_values = [_receipt_values(document) for document in left_documents]
    right_values = [_receipt_values(document) for document in right_documents]
    metrics: dict[str, dict[str, Any]] = {}
    names = list(COMPONENT_NAMES)
    tests: list[dict[str, Any]] = []
    for name in names:
        left_metric: list[float] = []
        for values in left_values:
            metric_value = values.get(name)
            if metric_value is not None:
                left_metric.append(metric_value)
        right_metric: list[float] = []
        for values in right_values:
            metric_value = values.get(name)
            if metric_value is not None:
                right_metric.append(metric_value)
        if not left_metric or not right_metric:
            test: dict[str, Any] = {
                "status": "unavailable", "reason": "empty_group", "independent": False,
            }
        else:
            test = _mann_whitney_exploratory(
                left_metric, right_metric, reason=MODEL_CONTRAST_REASON
            )
        tests.append(test)
        metrics[name] = {
            **test,
            "model_a": (
                _outcome_distribution(left_metric) if left_metric
                else _unavailable_distribution(
                    "no_final_receipts" if not left_documents else "component_unavailable"
                )
            ),
            "model_b": (
                _outcome_distribution(right_metric) if right_metric
                else _unavailable_distribution(
                    "no_final_receipts" if not right_documents else "component_unavailable"
                )
            ),
        }
    declared_family = _family_record(declaration)
    adjusted = _holm(
        [test.get("p_value") for test in tests],
        family_size=declared_family["family_size"],
    )
    for index, name in enumerate(names):
        metrics[name]["holm_adjusted_p"] = adjusted[index]
        metrics[name]["p_value_holm"] = adjusted[index]
        metrics[name]["p_value_raw"] = metrics[name].get("p_value")
        metrics[name]["signed_rank_biserial"] = metrics[name].get("effect_size")
        left_distribution = metrics[name].get("model_a") or {}
        right_distribution = metrics[name].get("model_b") or {}
        metrics[name].update({
            "outcome": name,
            "n_left": left_distribution.get("n"),
            "n_right": right_distribution.get("n"),
            "median_left": left_distribution.get("median"),
            "median_right": right_distribution.get("median"),
            "iqr_left": left_distribution.get("iqr"),
            "iqr_right": right_distribution.get("iqr"),
        })
    row["family"] = {
        **declared_family,
        "unit": "one model-pair × stratum × condition × grader-mode contrast row",
    }
    row["status"] = "analyzed"
    row["metrics"] = metrics
    return row


def _model_contrasts(
    planned: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    constraints: Mapping[str, Any],
    declaration: Mapping[str, Any],
) -> dict[str, Any]:
    """Contrast model pairs per frozen stratum, condition and grader mode."""
    models: dict[tuple[str, str], dict[str, Any]] = {}
    planned_counts: Counter[tuple[tuple[str, str], tuple[str, ...]]] = Counter()
    strata: dict[tuple[str, ...], dict[str, Any]] = {}
    missing_identity: list[dict[str, Any]] = []
    for coordinate in planned:
        provider, model = coordinate.get("provider"), coordinate.get("model")
        if not provider or not model:
            missing_identity.append({
                "coordinate_index": coordinate.get("coordinate_index"),
                "block": coordinate.get("block"),
                "reason": "missing_model_identity",
            })
            continue
        model_key = (str(provider), str(model))
        models.setdefault(model_key, {"provider": provider, "model": model})
        key = _model_stratum_key(coordinate)
        strata.setdefault(key, {
            "coordinate": {
                **_model_stratum(coordinate),
                "experiment_condition": coordinate.get("experiment_condition"),
            },
        })
        planned_counts[(model_key, key)] += 1

    final_documents: dict[
        tuple[tuple[str, str], tuple[str, ...], str], list[tuple[Any, Mapping[str, Any]]]
    ] = defaultdict(list)
    unready_documents: dict[
        tuple[tuple[str, str], tuple[str, ...], str], list[tuple[Any, Mapping[str, Any]]]
    ] = defaultdict(list)
    observation_states: dict[tuple[tuple[str, str], tuple[str, ...]], Counter[str]] = defaultdict(Counter)
    modes_by_model_key: dict[tuple[tuple[str, str], tuple[str, ...]], set[str]] = defaultdict(set)
    unready_modes_by_model_key: dict[tuple[tuple[str, str], tuple[str, ...]], set[str]] = defaultdict(set)
    for index, coordinate in enumerate(planned):
        provider, model = coordinate.get("provider"), coordinate.get("model")
        if not provider or not model:
            continue
        model_key = (str(provider), str(model))
        key = _model_stratum_key(coordinate)
        observation = observations[index]
        observation_states[(model_key, key)][str(observation.get("state"))] += 1
        if observation.get("state") != "final":
            continue
        ready = observation.get("ready") is True
        for mode, binding in (observation.get("documents") or {}).items():
            if ready:
                final_documents[(model_key, key, str(mode))].append((observation, binding[1]))
                modes_by_model_key[(model_key, key)].add(str(mode))
            else:
                unready_documents[(model_key, key, str(mode))].append((observation, binding[1]))
                unready_modes_by_model_key[(model_key, key)].add(str(mode))

    model_keys = sorted(models)
    results: list[dict[str, Any]] = []
    for model_a, model_b in combinations(model_keys, 2):
        for key in sorted(strata):
            if not planned_counts.get((model_a, key)) and not planned_counts.get((model_b, key)):
                continue
            modes = sorted(
                modes_by_model_key.get((model_a, key), set())
                | modes_by_model_key.get((model_b, key), set())
                | unready_modes_by_model_key.get((model_a, key), set())
                | unready_modes_by_model_key.get((model_b, key), set())
            )
            for mode in (modes or [None]):
                results.append(_model_contrast_row(
                    model_a, model_b, key, strata[key], mode, final_documents,
                    unready_documents, observation_states, planned_counts,
                    modes_by_model_key, unready_modes_by_model_key, constraints,
                    declaration,
                ))
    status_counts = Counter(row["status"] for row in results)
    unsupported_reasons = Counter(
        str(row.get("reason")) for row in results
        if row["status"] == "unsupported" and row.get("reason")
    )
    summary: dict[str, Any] = {
        "definition": (
            "One row per planned model pair × frozen stratum (block, policy epoch, "
            "fixture, protocol, budget, surface, level, method, payload mode, "
            "guardrail) × condition × grader mode. All planned repeats contribute "
            "to the descriptive distributions; no repeat is selected, pooled across "
            "models as a pair, or zero-filled."
        ),
        "test": (
            "exploratory two-sided Mann-Whitney U rank-sum with rank-biserial effect "
            "size; normal approximation, p-values are exploratory only"
        ),
        "pairing": "not paired; model/provider are not pairing axes",
        "independent": False,
        "multiple_comparisons": (
            "Holm-Bonferroni across the six outcomes within each "
            "stratum/condition/grader-mode row"
        ),
        "family_declaration": {
            **_family_record(declaration),
            "unit": "model-pair × stratum × condition × grader-mode contrast row",
        },
        "models": [models[model_key] for model_key in model_keys],
        "n_models": len(model_keys),
        "missing_model_identity": missing_identity,
        "n_contrast_rows": len(results),
        "status_counts": {
            state: status_counts.get(state, 0) for state in ("analyzed", "unsupported")
        },
        "unsupported_reasons": dict(sorted(unsupported_reasons.items())),
        "supported": len(model_keys) >= 2,
        "reason": None if len(model_keys) >= 2 else "fewer_than_two_planned_models",
        "results": results,
    }
    return summary


def _condition_contrasts(
    observations: list[dict[str, Any]], constraints: Mapping[str, Any],
    declaration: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Declared rank sums over compatible conditions, not complete pairs only.

    Every planned coordinate remains in a stratum's coverage ledger. Final,
    ready receipts contribute once even if the other condition's same-index
    repeat is unavailable. Different models, epochs, fixtures and graders are
    never pooled. Matched-pair statistics are reported separately.
    """
    if declaration is None:
        declaration = {
            'status': 'historical_unverified',
            'declared_before_analysis': False,
            'role': 'historical_recomputation_diagnostic',
            'family': _implemented_family(),
            'source': {},
            'chronology': {},
            'problems': ['caller_supplied_no_declaration'],
            'reason': 'no source-bound preselection family declaration was available',
        }
    declared_family = _family_record(declaration)
    axes = tuple(name for name in SPREAD_AXES if name != "experiment_condition")
    strata: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        coordinate = observation["coordinate"]
        strata[tuple(repr(coordinate.get(name)) for name in axes)].append(observation)
    results = []
    for key in sorted(strata):
        population = strata[key]
        modes = sorted({
            str(mode) for observation in population
            for mode in (observation.get("documents") or {})
        })
        for mode in modes or [None]:
            sides = {
                condition: [observation for observation in population
                            if observation["coordinate"].get("experiment_condition") == condition]
                for condition in PRIMARY_CONDITIONS
            }
            documents: dict[str, list[Mapping[str, Any]]] = {}
            coverage = {}
            for condition, rows in sides.items():
                included = [row for row in rows if row.get("state") == "final"
                            and row.get("ready") is True and mode in row.get("documents", {})]
                documents[condition] = [row["documents"][mode][1] for row in included]
                coverage[condition] = {
                    "n_planned": len(rows), "n_final_ready": len(included),
                    "states": dict(sorted(Counter(str(row.get("state")) for row in rows).items())),
                    "n_unready_final": sum(row.get("state") == "final" and row.get("ready") is not True
                                           for row in rows),
                    "repeat_indices": [row["coordinate"].get("repeat_index") for row in rows],
                    "included_repeat_indices": [row["coordinate"].get("repeat_index") for row in included],
                    "receipts": [str(row["documents"][mode][0]) for row in included],
                }
            row = {
                "coordinate": {name: population[0]["coordinate"].get(name) for name in axes},
                "scoring_mode": mode, "conditions": list(PRIMARY_CONDITIONS),
                "direction": DIFFERENCE_DIRECTION, "coverage": coverage,
                "status": "unsupported", "reason": None, "metrics": {},
            }
            repeats = [report["repeat_indices"] for report in coverage.values()]
            if any(len(indices) != len(set(indices)) for indices in repeats):
                row["reason"] = "duplicate_repeat_index"
            else:
                for condition in PRIMARY_CONDITIONS:
                    if not documents[condition]:
                        row["reason"] = f"{condition}:no_ready_final_receipts"
                        break
                    if any(not _final_receipt_complete(document)
                           for document in documents[condition]):
                        row["reason"] = f"{condition}:partial_final_receipt"
                        break
                    problem = _side_compatibility_problem(documents[condition], constraints)
                    if problem:
                        row["reason"] = f"{condition}:{problem}"
                        break
                if row["reason"] is None:
                    # Conditions and derived method choices may differ, but the
                    # scorer's other matched-identity gates still apply.
                    row["reason"] = _receipt_pair_problem(
                        documents[PRIMARY_CONDITIONS[0]][0],
                        documents[PRIMARY_CONDITIONS[1]][0], constraints,
                    )
            if row["reason"] is None:
                vectors = {
                    condition: [_receipt_values(document) for document in group]
                    for condition, group in documents.items()
                }
                metrics = {}
                for name in COMPONENT_NAMES:
                    values = {
                        condition: [vector[name] for vector in group if vector[name] is not None]
                        for condition, group in vectors.items()
                    }
                    metric = _mann_whitney_exploratory(
                        values[PRIMARY_CONDITIONS[0]], values[PRIMARY_CONDITIONS[1]],
                    )
                    left = metric.get("left") or {}
                    right = metric.get("right") or {}
                    metric.update({
                        "outcome": OUTCOME_LABELS[name],
                        "p_value_raw": metric.get("p_value"),
                        "n_left": left.get("n", metric.get("n_left")),
                        "n_right": right.get("n", metric.get("n_right")),
                        "median_left": left.get("median"),
                        "median_right": right.get("median"),
                        "iqr_left": left.get("iqr"),
                        "iqr_right": right.get("iqr"),
                        "signed_rank_biserial": metric.get("effect_size"),
                    })
                    metrics[name] = metric
                adjusted = _holm(
                    [metric.get("p_value") for metric in metrics.values()],
                    family_size=declared_family["family_size"],
                )
                for metric, p_value in zip(metrics.values(), adjusted):
                    metric["holm_adjusted_p"] = p_value
                    metric["p_value_holm"] = p_value
                row.update(status="analyzed", metrics=metrics)
                row["family"] = {
                    **declared_family,
                    "unit": "one model × surface × security-level condition contrast row",
                }
            results.append(row)
    return {
        "role": "declared_exploratory_analysis", "test": "two-sided Mann-Whitney U",
        "pairing": "not restricted to complete pairs; every eligible final repeat contributes",
        "independent": False,
        "limitations": "Shared fixtures, models and graders may induce dependence; three repeats limit inference.",
        "multiple_comparisons": "Holm-Bonferroni across six outcomes within each stratum/grader row",
        "family_declaration": {
            **_family_record(declaration),
            "unit": "model × surface × security-level condition-contrast row",
            "supplementary_families": (
                "paired Wilcoxon and bootstrap intervals are separate supplementary "
                "families and never replace the declared rank-sum result"
            ),
        },
        "reporting": {
            "effect_size": "signed rank-biserial exploratory",
            "n": "actual final ready receipts per side; planned n remains in coverage",
            "central_tendency": "median per side",
            "spread": "inclusive-quartile IQR per side",
        },
        "n_contrast_rows": len(results),
        "status_counts": dict(sorted(Counter(row["status"] for row in results).items())),
        "results": results,
    }


def analyze_plan(
    plan: Mapping[str, Any],
    *,
    source_roots: Mapping[str, str | Path],
    review_roots: Mapping[str, str | Path],
) -> dict[str, Any]:
    """Group final receipts, run declared rank sums and supplementary paired tests."""
    if plan.get("artifact_type") != "chapter3_research_plan":
        raise ValueError("analysis requires a declared Chapter 3 research plan")
    if not read_contract(plan.get("plan_version"), SUPPORTED_PLAN_VERSIONS[0]):
        raise ValueError(f"unsupported research plan version: {plan.get('plan_version')!r}")
    if not plan.get("source_hashes_sha256"):
        # A plan without a frozen source identity cannot reject stale artifacts;
        # refuse instead of matching by omission.
        raise ValueError("research plan is missing its frozen source_hashes_sha256")
    preliminary = _analysis_declaration(plan, ())
    if preliminary.get('status') == 'invalid':
        blocking = [
            problem for problem in preliminary.get('problems') or []
            if problem != 'earliest_final_receipt_generated_at_missing_or_invalid'
        ]
        if blocking:
            raise ValueError(
                'prospective plan analysis declaration is not source-bound: '
                + ';'.join(blocking)
            )
    catalog = ArtifactCatalog(source_roots, review_roots)
    catalog.scan()
    planned = _planned_coordinates(plan)
    constraints = plan.get("constraints") or {}
    plan_source_hashes_sha256 = plan.get("source_hashes_sha256")
    entries = list(catalog.runs)
    matched, match_reasons, ambiguous, used = _match_entries(
        planned, entries, constraints, plan_source_hashes_sha256
    )
    observations: list[dict[str, Any]] = []

    for index, coordinate in enumerate(planned):
        if index in ambiguous:
            observations.append({
                "coordinate": coordinate, "state": "ambiguous_match",
                "reason": REASON_AMBIGUOUS_MATCH,
                "candidate_execution_ids": ambiguous[index],
                "ready": False, "readiness_reason": REASON_AMBIGUOUS_MATCH,
            })
            continue
        entry = matched.get(index)
        if entry is None:
            missing_reason = match_reasons.get(index, "no_execution_artifact")
            state = "missing" if missing_reason == "no_execution_artifact" else "identity_incomplete"
            observations.append({
                "coordinate": coordinate, "state": state,
                "reason": missing_reason,
                "ready": False, "readiness_reason": missing_reason,
            })
            continue
        identity = _identity(entry)
        problem = _coordinate_identity_problems(
            coordinate, identity, constraints, plan_source_hashes_sha256
        )
        if problem:
            observations.append({
                "coordinate": coordinate, "state": "epoch_mismatch" if problem == "epoch_mismatch" else "identity_incomplete",
                "reason": problem, "ready": False, "readiness_reason": problem,
                "identity": identity,
            })
            continue
        ready, readiness_reason = _readiness_ok(entry.record)
        status = str(entry.record.get("execution_status") or entry.record.get("status") or "")
        reviews = discover_reviews(catalog, entry)
        documents, review_reasons = _final_receipts(catalog, reviews)
        epoch_binding = {}
        epoch_problem = None
        for mode, (_path, document) in documents.items():
            problem, info = _receipt_epoch_problem(document, plan, entry, constraints)
            epoch_binding[mode] = info
            if problem:
                epoch_problem = problem
                break
        if epoch_problem:
            observations.append({
                "coordinate": coordinate, "state": "epoch_mismatch",
                "reason": epoch_problem, "ready": False,
                "readiness_reason": epoch_problem, "identity": identity,
                "documents": documents, "reviews": reviews, "entry": entry,
                "epoch_binding": epoch_binding,
            })
            continue
        if status == "failed":
            state = "error"
            reason = (entry.record.get("execution_reason") or {}).get("code") or "execution_failed"
        elif status == "interrupted":
            state, reason = "interrupted", "interrupted"
        elif documents:
            state, reason = "final", None
        elif any(str(workflow.get("status")) == "pending" for workflow in reviews.values()):
            state = "pending_review"
            reason = "; ".join(sorted({value for value in review_reasons.values() if value})) or "review_pending"
        else:
            state = "unassessable"
            reason = "; ".join(sorted({value for value in review_reasons.values() if value})) or "no_review_workflow"
        observations.append({
            "coordinate": coordinate, "state": state, "reason": reason,
            "ready": ready, "readiness_reason": readiness_reason,
            "identity": identity, "documents": documents, "reviews": reviews, "entry": entry,
            "epoch_binding": epoch_binding,
        })

    analysis_declaration = _analysis_declaration(plan, observations)
    if analysis_declaration.get('status') == 'invalid':
        raise ValueError(
            'prospective plan analysis declaration is not source-bound: '
            + ';'.join(analysis_declaration.get('problems') or [])
        )

    # Authoritative per-group summaries come from the scorer. Never reimplement
    # repeat grouping, stability, or component arithmetic here.
    partitions: dict[tuple[Any, ...], dict[str, Any]] = {}
    for observation in observations:
        if observation["state"] != "final":
            continue
        identity = observation["identity"]
        partition_key = (
            identity.get("experiment_block"), identity.get("policy_epoch_id"),
            identity.get("fixture_id"), identity.get("protocol_version"),
            identity.get("provider"), identity.get("model"),
            identity.get("guardrail_retry_enabled"), identity.get("guardrail_handling"),
            identity.get("token_price_schedule_sha256"),
        )
        partition = partitions.setdefault(
            partition_key,
            {"paths": [], "entries": [], "modes": set(), "documents": []},
        )
        if observation["entry"] not in partition["entries"]:
            partition["entries"].append(observation["entry"])
        for mode, (path, document) in observation["documents"].items():
            if path in partition["paths"]:
                continue
            partition["paths"].append(path)
            partition["modes"].add(mode)
            partition["documents"].append((str(path), mode, document))

    repeats = int(constraints.get("repeats") or plan.get("constraints", {}).get("repeats") or 0)
    groups: list[dict[str, Any]] = []
    selection_groups: list[dict[str, Any]] = []
    group_exclusions: list[dict[str, Any]] = []
    for partition_key, partition in partitions.items():
        if not partition["paths"]:
            continue
        try:
            comparison = compare_receipts(partition["paths"], planned_repeats=repeats or None)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            # The scorer refuses mixed rubric/profile/rule receipts or duplicate
            # sources. Keep the refusal visible instead of pooling or aborting.
            group_exclusions.append({
                "block": partition_key[0],
                "policy_epoch_id": partition_key[1],
                "fixture_id": partition_key[2],
                "protocol_version": partition_key[3],
                "provider": partition_key[4],
                "model": partition_key[5],
                "guardrail_retry_enabled": partition_key[6],
                "guardrail_handling": partition_key[7],
                "reason": f"receipt_comparison_refused:{type(exc).__name__}",
                "detail": str(exc),
                "n_receipts": len(partition["paths"]),
            })
            continue
        selection_groups.extend(comparison.get("selection_groups", []))
        for row in comparison.get("groups", []):
            mode = row.get("scoring_mode")
            sources = {str(source) for source in (row.get("sources") or [])}
            group_documents = [] if row.get("n_final") == 0 else [
                document for path, document_mode, document in partition["documents"]
                if (mode is None or document_mode == mode)
                and (
                    not sources
                    or path in sources
                    or str(document.get("source_sha256")) in sources
                )
            ]
            groups.append({
                **row,
                "block": partition_key[0],
                "policy_epoch_id": partition_key[1],
                "fixture_id": partition_key[2],
                "protocol_version": partition_key[3],
                "guardrail_retry_enabled": partition_key[6],
                "guardrail_handling": partition_key[7],
                "token_price_schedule_sha256": partition_key[8],
                "planned_repeats": repeats or None,
                "research_metrics_receipts": len(group_documents),
                "research_metrics": _research_metric_summary(group_documents),
            })

    paired = _paired_analysis(observations, constraints)
    outcome_spread = _outcome_spread(planned, observations)
    model_contrasts = _model_contrasts(
        planned, observations, constraints, analysis_declaration
    )
    condition_contrasts = _condition_contrasts(
        observations, constraints, analysis_declaration
    )
    exclusions = Counter(
        str(observation.get("reason") or observation["state"])
        for observation in observations
        if observation["state"] != "final"
    )
    status_counts = Counter(observation["state"] for observation in observations)
    return {
        "artifact_type": "chapter3_research_analysis",
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "study_design_version": STUDY_DESIGN_VERSION,
        "plan_version": plan.get("plan_version"),
        "plan_sha256": plan.get("plan_sha256"),
        "epoch_id": plan.get("epoch_id"),
        "epoch_contract": {
            "receipt_epoch_binding_required": plan_requires_receipt_epoch_binding(plan),
            "mode": (
                "prospective_bound"
                if plan_requires_receipt_epoch_binding(plan)
                else "historical_read_only"
            ),
            "read_only": not plan_requires_receipt_epoch_binding(plan),
            "plan_sha256": plan.get("plan_sha256"),
            "required_receipt_fields": list(EPOCH_BINDING_REQUIRED),
            "note": (
                "A historical plan without the prospective binding marker remains readable "
                "for its recorded epoch only; it cannot satisfy a current plan or be pooled "
                "with another epoch."
            ),
        },
        "study": {
            "primary_conditions": list(PRIMARY_CONDITIONS),
            "payload_mode": constraints.get("payload_mode"),
            "repeats": constraints.get("repeats"),
            "fixture_id": constraints.get("fixture_id"),
            "protocol_version": constraints.get("protocol_version"),
            "candidate_budget": constraints.get("candidate_budget"),
            "scoring_rubric_version": constraints.get("scoring_rubric_version"),
            "policy_versions": dict(plan.get("policy_versions") or {}),
        },
        "prerequisites": list(plan.get("prerequisites") or []),
        "planned": len(planned),
        "planned_by_block": {
            block: sum(1 for coordinate in planned if coordinate["block"] == block)
            for block in sorted(set(plan.get("blocks") or {}) | {coordinate["block"] for coordinate in planned})
        },
        "matched_artifacts": len(matched),
        "unmatched_artifacts": max(0, len(entries) - len(used)),
        "status_counts": {state: status_counts.get(state, 0) for state in OBSERVATION_STATES},
        "exclusions": dict(sorted(exclusions.items())),
        "observations": [
            {
                "coordinate": observation["coordinate"],
                "state": observation["state"],
                "reason": observation["reason"],
                "readiness": observation["ready"],
                "readiness_reason": observation["readiness_reason"],
                "execution_id": (observation.get("identity") or {}).get("execution_id"),
                "receipt_modes": sorted(observation.get("documents", {})),
                "epoch_binding_status": sorted({
                    info.get("status")
                    for info in (observation.get("epoch_binding") or {}).values()
                }),
            }
            for observation in observations
        ],
        "groups": groups,
        "selection_groups": selection_groups,
        "group_exclusions": group_exclusions,
        "outcome_spread": outcome_spread,
        "analysis_declaration": analysis_declaration,
        "model_contrasts": model_contrasts,
        "condition_contrasts": condition_contrasts,
        "paired": {"role": "supplementary", **paired},
        "epoch_binding": {
            "interface": {
                "receipt_key": EPOCH_BINDING_KEY,
                "required": list(EPOCH_BINDING_REQUIRED),
                "optional": list(EPOCH_BINDING_OPTIONAL),
                "historical_policy": (
                    "unbound receipts stay readable for their recorded epoch; a row "
                    "with mixed bound/unbound receipts or differing explicit bindings "
                    "is refused rather than pooled"
                ),
            },
            "receipt_status_counts": dict(sorted(Counter(
                info.get("status")
                for observation in observations
                for info in (observation.get("epoch_binding") or {}).values()
            ).items())),
            "refused_observations": dict(sorted(Counter(
                str(observation.get("reason"))
                for observation in observations
                if observation["state"] == "epoch_mismatch"
            ).items())),
        },
        "score_epoch": {
            "runtime_provisional": "runtime-scoring",
            "thesis_final": constraints.get("scoring_rubric_version"),
            "final_status": "review_receipts_only",
            "policy_epoch": dict(plan.get("policy_epoch") or {}),
        },
        "statistics_policy": {
            "primary": "declared exploratory Mann-Whitney U on compatible ready condition/model groups; not restricted to complete pairs",
            "supplementary": "matched-pair Wilcoxon and bootstrap intervals, never replacements for the declared rank-sum analysis",
            "pairing_axes": list(PAIR_AXES),
            "receipt_axes": list(RECEIPT_AXES),
            "contrast_axes": ["experiment_condition", "derived_method_choice", "model"],
            "direction": DIFFERENCE_DIRECTION,
            "paired_test": "two-sided Wilcoxon signed-rank; exact for n<=25, normal approximation above",
            "effect_size": "rank-biserial correlation; matched-pairs rank-biserial only for supplementary paired results",
            "uncertainty": "supplementary bootstrap percentile CI of median paired difference",
            "multiple_comparisons": "Holm-Bonferroni across six outcomes within each declared contrast row; supplementary adjustment within paired families",
            "rank_sum": "declared exploratory two-sided Mann-Whitney U with average-tie ranks, tie-corrected null variance and continuity correction towards the null; independence is not established",
            "outcome_spread": "descriptive mean/median/sample variance/stdev/inclusive-quartile IQR per planned cell and grader mode; all repeats retained",
            "model_contrast": "separate exploratory Mann-Whitney U per stratum/condition/grader mode; model/provider are not pairing axes and repeats are not paired across models",
            "grader_identity": "reviewer_id/review_version from the latest review decision per candidate; receipts with different recorded graders or versions are incompatible, and a missing/empty/invalid review_history is unavailable rather than pooled",
            "no_imputation": "missing, pending, failed, and unassessable coordinates stay counted and null",
        },
    }


def _paired_analysis(
    observations: Iterable[Mapping[str, Any]], constraints: Mapping[str, Any]
) -> dict[str, Any]:
    """Build matched pairs and run the declared paired statistics."""
    finals: dict[tuple[Any, ...], dict[str, dict[str, dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    unmatched: list[dict[str, Any]] = []
    for observation in observations:
        if observation["state"] != "final":
            continue
        coordinate = observation["coordinate"]
        identity = observation["identity"]
        for mode, (_path, document) in observation["documents"].items():
            base = (
                coordinate["block"], identity.get("provider"), identity.get("model"),
                coordinate["surface"], coordinate["security_level"],
                coordinate["target_method"], coordinate["payload_mode"],
                coordinate["repeat_index"], identity.get("fixture_id"),
                identity.get("protocol_version"), identity.get("policy_epoch_id"),
            )
            finals[base][coordinate["experiment_condition"]][mode] = {
                "document": document, "observation": observation,
            }
    comparisons: list[dict[str, Any]] = []
    for base, conditions in finals.items():
        if not all(condition in conditions for condition in PRIMARY_CONDITIONS):
            unmatched.append({"pair": list(base), "reason": "condition_missing"})
            continue
        shared_modes = sorted(
            set(conditions[PRIMARY_CONDITIONS[0]]) & set(conditions[PRIMARY_CONDITIONS[1]])
        )
        if not shared_modes:
            unmatched.append({"pair": list(base), "reason": "grader_mode_missing"})
            continue
        for mode in shared_modes:
            left = conditions[PRIMARY_CONDITIONS[0]][mode]
            right = conditions[PRIMARY_CONDITIONS[1]][mode]
            left_observation, right_observation = left["observation"], right["observation"]
            if not (left_observation["ready"] and right_observation["ready"]):
                unmatched.append({
                    "pair": list(base), "mode": mode,
                    "reason": left_observation.get("readiness_reason")
                    or right_observation.get("readiness_reason"),
                })
                continue
            left_document, right_document = left["document"], right["document"]
            mismatch = _receipt_pair_problem(left_document, right_document, constraints)
            if mismatch:
                unmatched.append({"pair": list(base), "mode": mode, "reason": mismatch})
                continue
            metrics = {}
            left_vector = left_document["components"]
            right_vector = right_document["components"]
            for name in COMPONENT_NAMES:
                left_value = left_document["Srun_final"] if name == "Srun_final" else left_vector[name]
                right_value = right_document["Srun_final"] if name == "Srun_final" else right_vector[name]
                metrics[name] = {
                    "difference": float(left_value) - float(right_value),
                    "left": float(left_value),
                    "right": float(right_value),
                }
            comparisons.append({
                "pair": list(base),
                "mode": mode,
                "conditions": list(PRIMARY_CONDITIONS),
                "grader_identity": _grader_report([left_document, right_document]),
                "shared_compatibility_key": pair_compatibility_key(left_document)
                == pair_compatibility_key(right_document),
                "metrics": metrics,
            })

    # Pool repeat units within one comparison identity; repeat identity is a
    # pairing axis and must not leak into the pooled group key.  Recorded grader
    # identity/version is also a pooling boundary: repeats graded by different
    # reviewers (or versions) are separate analyses, never one sample.
    pooled: dict[tuple[Any, ...], dict[str, dict[str, list[float]]]] = defaultdict(
        lambda: defaultdict(lambda: {"differences": [], "left": [], "right": []})
    )
    pooled_graders: dict[tuple[Any, ...], dict[str, Any]] = {}
    for comparison in comparisons:
        pair = tuple(comparison["pair"])
        # Repeat is a pairing axis and is pooled; grader mode is NOT pooled —
        # 3 repeats under human + AI receipts are two analyses of n=3, not n=6.
        grader_key = json.dumps(
            comparison["grader_identity"], sort_keys=True, separators=(",", ":")
        )
        base = pair[:7] + pair[8:] + (comparison["mode"], grader_key)
        pooled_graders.setdefault(base, comparison["grader_identity"])
        for name, row in comparison["metrics"].items():
            pooled[base][name]["differences"].append(row["difference"])
            pooled[base][name]["left"].append(row["left"])
            pooled[base][name]["right"].append(row["right"])
    results = []
    for base, metrics in pooled.items():
        names = [name for name in COMPONENT_NAMES if metrics.get(name)]
        tests = [_wilcoxon_signed_rank(metrics[name]["differences"]) for name in names]
        adjusted = _holm(
            [test.get("p_value") for test in tests],
            family_size=len(COMPONENT_NAMES),
        )
        n_pairs = len(metrics[names[0]]["differences"]) if names else 0
        results.append({
            "comparison": list(base[:-2]),
            "scoring_mode": base[-2],
            "grader_identity": pooled_graders[base],
            "conditions": list(PRIMARY_CONDITIONS),
            "direction": DIFFERENCE_DIRECTION,
            "n_pairs": n_pairs,
            "metrics": {
                name: {
                    **test,
                    "median_difference": _bootstrap_median_ci(metrics[name]["differences"]),
                    "holm_adjusted_p": adjusted[index],
                    "exploratory_rank_sum": _mann_whitney_exploratory(
                        metrics[name]["left"], metrics[name]["right"]
                    ),
                }
                for index, (name, test) in enumerate(zip(names, tests))
            },
        })
    return {
        "results": results,
        "unmatched": unmatched,
        "family": {
            "role": "supplementary",
            "outcomes": list(FAMILY_OUTCOMES),
            "family_size": len(COMPONENT_NAMES),
            "adjustment": "Holm-Bonferroni step-down",
            "missing_outcome_policy": (
                "A missing p-value stays null; it never reduces the declared family "
                "size and can never receive adjusted significance."
            ),
            "declared_before_analysis": False,
            "replaces_declared_rank_sum": False,
        },
        "n_pair_units": sum(
            len(next(iter(metrics.values()))["differences"])
            for metrics in pooled.values()
            if metrics
        ),
        "n_eligible_pairs": len(comparisons),
        "repeat_unit": "one eligible pair per repeat index; pooled across repeats for the test",
        "pairing_axes": list(PAIR_AXES),
        "receipt_axes": list(RECEIPT_AXES),
        "grader_mode_axis": "scoring_mode",
        "grader_mode_pooling": "separate analyses per grader mode; never pooled into one sample",
        "grader_identity_pooling": "reviewer_id/review_version from the latest review decision per candidate; different recorded grader identities are separate analyses, and missing/empty/invalid identity is unavailable rather than pooled as a repeat",
        "direction": DIFFERENCE_DIRECTION,
        "planner_contract": {
            "planned_repeats": constraints.get("repeats"),
            "fixture_id": constraints.get("fixture_id"),
            "protocol_version": constraints.get("protocol_version"),
        },
    }


def _receipt_identity_problem(
    left: Mapping[str, Any], right: Mapping[str, Any]
) -> str | None:
    """Check rubric, scoring rule, grader mode, epoch binding and metrics epoch."""
    for field in ("rubric_version", "scoring_rule_sha256", "scoring_mode"):
        if left.get(field) != right.get(field) or not left.get(field):
            return f"receipt_{field}_mismatch"
    epoch_problem = _epoch_population_problem((left, right))
    if epoch_problem:
        return epoch_problem
    left_metrics_epoch = left.get("metrics_epoch")
    right_metrics_epoch = right.get("metrics_epoch")
    if left_metrics_epoch != right_metrics_epoch or not left_metrics_epoch:
        return "metrics_epoch_mismatch"
    return None


def _receipt_common_problem(
    left: Mapping[str, Any], right: Mapping[str, Any], constraints: Mapping[str, Any]
) -> str | None:
    """Return a receipt-level or frozen-config reason two outcomes cannot compare.

    Model contrasts legitimately differ in provider/model, so this check leaves
    the scorer-owned pair identity to ``_receipt_pair_problem``. Everything
    else that the plan freezes (rubric, rule, metrics epoch, fixture, protocol,
    budget, guardrail, price schedule) must still agree.
    """
    problem = _receipt_identity_problem(left, right)
    if problem:
        return problem
    problem = _grader_identity_problem(left, right)
    if problem:
        return problem
    raw_left_policy = left.get("scoring_policy")
    raw_right_policy = right.get("scoring_policy")
    left_policy: Mapping[str, Any] = raw_left_policy if isinstance(raw_left_policy, Mapping) else {}
    right_policy: Mapping[str, Any] = raw_right_policy if isinstance(raw_right_policy, Mapping) else {}
    for field in ("policy_version", "metrics_epoch", "rate_definition_version", "source_hashes"):
        if left_policy.get(field) != right_policy.get(field):
            return f"receipt_scoring_policy_{field}_mismatch"
    if (left.get("prompt_identities") or []) != (right.get("prompt_identities") or []):
        return "prompt_identities_mismatch"
    return _receipt_config_problem(left, right, constraints)


def _receipt_pair_problem(
    left: Mapping[str, Any], right: Mapping[str, Any], constraints: Mapping[str, Any]
) -> str | None:
    """Return the first reason two receipts are not a compatible matched pair."""
    problem = _receipt_identity_problem(left, right)
    if problem:
        return problem
    problem = _grader_identity_problem(left, right)
    if problem:
        return problem
    if pair_compatibility_key(left) != pair_compatibility_key(right):
        # The scorer owns the matched-pair identity: it excludes only the
        # contrasted condition, the derived method choice, and repeat identity.
        mismatches = pair_compatibility_mismatches(left, right)
        return "pair_incompatible:" + ";".join(mismatches) if mismatches else "receipt_compatibility_mismatch"
    return _receipt_config_problem(left, right, constraints)


def _receipt_config_problem(
    left: Mapping[str, Any], right: Mapping[str, Any], constraints: Mapping[str, Any]
) -> str | None:
    """Check each receipt against the plan's frozen configuration constraints."""
    expected_snapshot = constraints.get("payload_policy_snapshot_sha256")
    if expected_snapshot:
        for document, label in ((left, "left"), (right, "right")):
            observed = _recorded_snapshot_sha(document)
            if not observed:
                return f"{label}_payload_policy_snapshot_missing"
            if observed != expected_snapshot:
                return "payload_policy_snapshot_mismatch"
    for document, label in ((left, "left"), (right, "right")):
        config = document.get("config") or {}
        if constraints.get("fixture_id") and config.get("fixture_id") != constraints["fixture_id"]:
            return f"{label}_fixture_mismatch"
        if constraints.get("protocol_version") and config.get("protocol_version") != constraints["protocol_version"]:
            return f"{label}_protocol_mismatch"
        if constraints.get("candidate_budget") is not None and config.get("candidate_budget") != constraints["candidate_budget"]:
            return f"{label}_candidate_budget_mismatch"
        if constraints.get("scoring_profile_sha256"):
            profile = config.get("scoring_profile")
            if not isinstance(profile, dict) or profile.get("sha256") != constraints["scoring_profile_sha256"]:
                return f"{label}_scoring_profile_mismatch"
        schedule = config.get("token_price_schedule")
        if constraints.get("token_price_schedule_sha256"):
            if not isinstance(schedule, dict):
                # A frozen price identity with no recorded schedule is
                # unavailable, never a match by omission.
                return f"{label}_missing_token_price_schedule"
            if evidence_hash(schedule) != constraints["token_price_schedule_sha256"]:
                return REASON_TOKEN_PRICE_MISMATCH
        observed_guardrail = (
            config.get("guardrail_retry_enabled")
            if config.get("guardrail_retry_enabled") is not None
            else config.get("evasion_enabled"),
            config.get("guardrail_handling")
            if config.get("guardrail_handling") is not None
            else config.get("evasion_mode"),
        )
        expected_guardrail = (
            constraints.get("guardrail_retry_enabled"),
            constraints.get("guardrail_handling"),
        )
        if any(value is not None for value in expected_guardrail) and observed_guardrail != expected_guardrail:
            return REASON_GUARDRAIL_MISMATCH
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate final Chapter 3 receipts without pooling epochs")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--source-root", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--review-root", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    def roots(values: list[str]) -> dict[str, str]:
        parsed = {}
        for value in values:
            name, _, path = value.partition("=")
            if not name or not path:
                parser.error("roots must be NAME=PATH")
            parsed[name] = path
        return parsed

    try:
        plan = json.loads(args.plan.read_bytes())
        result = analyze_plan(
            plan,
            source_roots=roots(args.source_root),
            review_roots=roots(args.review_root),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({
            "status": "analyzed",
            "planned": result["planned"],
            "status_counts": result["status_counts"],
            "groups": len(result["groups"]),
            "outcome_spread_cells": len(result["outcome_spread"]["cells"]),
            "model_contrast_rows": result["model_contrasts"]["n_contrast_rows"],
            "paired_comparisons": len(result["paired"]["results"]),
            "output": str(args.output),
        }, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Research analysis failed: {type(exc).__name__}: {exc}\n")


__all__ = [
    "ANALYSIS_SCHEMA_VERSION",
    "BOOTSTRAP_RESAMPLES",
    "BOOTSTRAP_SEED",
    "DIFFERENCE_DIRECTION",
    "EPOCH_BINDING_KEY",
    "EPOCH_BINDING_REQUIRED",
    "EPOCH_BINDING_OPTIONAL",
    "FAMILY_OUTCOMES",
    "OUTCOME_LABELS",
    "OBSERVATION_STATES",
    "PAIR_AXES",
    "PRIMARY_CONDITIONS",
    "RECEIPT_AXES",
    "STUDY_DESIGN_VERSION",
    "SUPPORTED_PLAN_VERSIONS",
    "analyze_plan",
    "main",
    "refuse_epoch_pooling",
]


if __name__ == "__main__":
    raise SystemExit(main())
