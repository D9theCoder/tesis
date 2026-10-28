"""Final-receipt-backed Chapter 3 summaries and matched paired analysis.

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
receipts share rubric, scoring-rule hash, metrics epoch and grader mode.
Unmatched or pending coordinates are counted with reasons, never dropped.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
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
    compare_receipts,
    pair_compatibility_key,
    pair_compatibility_mismatches,
)
from tesis.artifact_catalog import ArtifactCatalog

ANALYSIS_SCHEMA_VERSION = "chapter3-analysis.v3"
SUPPORTED_PLAN_VERSIONS = ("chapter3-research-plan.v2",)
PRIMARY_CONDITIONS: tuple[str, ...] = ("linear_hybrid", "akg_guided_hybrid")
COMPONENT_NAMES = ("Smethod", "Spayload", "Sexploit", "Schain", "Soutput", "Srun_final")
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 20261028
DIFFERENCE_DIRECTION = "linear_hybrid_minus_akg_guided_hybrid"
STUDY_DESIGN_VERSION = "chapter3-study-design.v1"

# Axes that must agree for a coordinate pair to be compared. Repeat is a
# pairing axis (paired by repeat) and is dropped only when pooling pairs.
PAIR_AXES = (
    "experiment_block", "provider", "model", "surface", "security_level",
    "target_method", "payload_mode", "repeat_index", "fixture_id",
    "protocol_version", "policy_epoch_id", "guardrail_retry_enabled",
    "guardrail_handling", "token_price_schedule_sha256",
)
RECEIPT_AXES = ("scoring_mode", "rubric_version", "scoring_rule_sha256", "metrics_epoch")

OBSERVATION_STATES = (
    "final", "pending_review", "unassessable", "error", "interrupted", "missing",
    "epoch_mismatch", "identity_incomplete", "ambiguous_match",
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


def _holm(p_values: list[float | None]) -> list[float | None]:
    """Holm-Bonferroni step-down adjustment within one declared metric family."""
    indexed = [(value, index) for index, value in enumerate(p_values) if value is not None]
    adjusted: list[float | None] = [None] * len(p_values)
    if not indexed:
        return adjusted
    indexed.sort()
    running = 0.0
    total = len(indexed)
    for position, (value, index) in enumerate(indexed):
        candidate = min(1.0, value * (total - position))
        running = max(running, candidate)
        adjusted[index] = running
    return adjusted


def _mann_whitney_exploratory(left: list[float], right: list[float]) -> dict[str, Any]:
    """Exploratory rank-sum comparison; paired data does not establish independence."""
    if not left or not right:
        return {"status": "unavailable", "reason": "empty_group", "independent": False}
    combined = [(value, 0) for value in left] + [(value, 1) for value in right]
    ranks = _rank([value for value, _ in combined])
    rank_sum = sum(rank for rank, (_, group) in zip(ranks, combined) if group == 0)
    n1, n2 = len(left), len(right)
    u_value = rank_sum - n1 * (n1 + 1) / 2
    mean = n1 * n2 / 2
    variance = n1 * n2 * (n1 + n2 + 1) / 12
    p_value = min(1.0, math.erfc(abs((u_value - mean - 0.5) / math.sqrt(variance)) / math.sqrt(2))) if variance else None
    return {
        "status": "exploratory", "independent": False,
        "reason": "paired coordinates survive; rank-sum is supplementary only",
        "n_left": n1, "n_right": n2, "u": u_value, "p_value": p_value,
        "effect_size": round(2 * u_value / (n1 * n2) - 1, 4) if n1 and n2 else None,
        "effect_size_name": "rank_biserial_exploratory",
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


def analyze_plan(
    plan: Mapping[str, Any],
    *,
    source_roots: Mapping[str, str | Path],
    review_roots: Mapping[str, str | Path],
) -> dict[str, Any]:
    """Group compatible final receipts and run matched paired comparisons."""
    if plan.get("artifact_type") != "chapter3_research_plan":
        raise ValueError("analysis requires a declared Chapter 3 research plan")
    if plan.get("plan_version") not in SUPPORTED_PLAN_VERSIONS:
        raise ValueError(f"unsupported research plan version: {plan.get('plan_version')!r}")
    if not plan.get("source_hashes_sha256"):
        # A plan without a frozen source identity cannot reject stale artifacts;
        # refuse instead of matching by omission.
        raise ValueError("research plan is missing its frozen source_hashes_sha256")
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
        })

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
            }
            for observation in observations
        ],
        "groups": groups,
        "selection_groups": selection_groups,
        "group_exclusions": group_exclusions,
        "paired": paired,
        "score_epoch": {
            "runtime_provisional": "scoring.v2",
            "thesis_final": constraints.get("scoring_rubric_version"),
            "final_status": "review_receipts_only",
            "policy_epoch": dict(plan.get("policy_epoch") or {}),
        },
        "statistics_policy": {
            "primary": "matched pairs only after readiness and fixture-equivalence evidence",
            "pairing_axes": list(PAIR_AXES),
            "receipt_axes": list(RECEIPT_AXES),
            "contrast_axes": ["experiment_condition", "derived_method_choice"],
            "direction": DIFFERENCE_DIRECTION,
            "paired_test": "two-sided Wilcoxon signed-rank; exact for n<=25, normal approximation above",
            "effect_size": "matched-pairs rank-biserial correlation",
            "uncertainty": "bootstrap percentile CI of median paired difference",
            "multiple_comparisons": "Holm-Bonferroni within the paired metric family",
            "rank_sum": "Mann-Whitney U reported only as exploratory; independence is not established",
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
                "shared_compatibility_key": pair_compatibility_key(left_document)
                == pair_compatibility_key(right_document),
                "metrics": metrics,
            })

    # Pool repeat units within one comparison identity; repeat identity is a
    # pairing axis and must not leak into the pooled group key.
    pooled: dict[tuple[Any, ...], dict[str, dict[str, list[float]]]] = defaultdict(
        lambda: defaultdict(lambda: {"differences": [], "left": [], "right": []})
    )
    for comparison in comparisons:
        pair = tuple(comparison["pair"])
        # Repeat is a pairing axis and is pooled; grader mode is NOT pooled —
        # 3 repeats under human + AI receipts are two analyses of n=3, not n=6.
        base = pair[:7] + pair[8:] + (comparison["mode"],)
        for name, row in comparison["metrics"].items():
            pooled[base][name]["differences"].append(row["difference"])
            pooled[base][name]["left"].append(row["left"])
            pooled[base][name]["right"].append(row["right"])
    results = []
    for base, metrics in pooled.items():
        names = [name for name in COMPONENT_NAMES if metrics.get(name)]
        tests = [_wilcoxon_signed_rank(metrics[name]["differences"]) for name in names]
        adjusted = _holm([test.get("p_value") for test in tests])
        n_pairs = len(metrics[names[0]]["differences"]) if names else 0
        results.append({
            "comparison": list(base[:-1]),
            "scoring_mode": base[-1],
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
        "direction": DIFFERENCE_DIRECTION,
        "planner_contract": {
            "planned_repeats": constraints.get("repeats"),
            "fixture_id": constraints.get("fixture_id"),
            "protocol_version": constraints.get("protocol_version"),
        },
    }


def _receipt_pair_problem(
    left: Mapping[str, Any], right: Mapping[str, Any], constraints: Mapping[str, Any]
) -> str | None:
    """Return the first reason two receipts are not a compatible matched pair."""
    for field in ("rubric_version", "scoring_rule_sha256", "scoring_mode"):
        if left.get(field) != right.get(field) or not left.get(field):
            return f"receipt_{field}_mismatch"
    left_metrics_epoch = left.get("metrics_epoch")
    right_metrics_epoch = right.get("metrics_epoch")
    if left_metrics_epoch != right_metrics_epoch or not left_metrics_epoch:
        return "metrics_epoch_mismatch"
    if pair_compatibility_key(left) != pair_compatibility_key(right):
        # The scorer owns the matched-pair identity: it excludes only the
        # contrasted condition, the derived method choice, and repeat identity.
        mismatches = pair_compatibility_mismatches(left, right)
        return "pair_incompatible:" + ";".join(mismatches) if mismatches else "receipt_compatibility_mismatch"
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
    "OBSERVATION_STATES",
    "PAIR_AXES",
    "PRIMARY_CONDITIONS",
    "RECEIPT_AXES",
    "STUDY_DESIGN_VERSION",
    "SUPPORTED_PLAN_VERSIONS",
    "analyze_plan",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
