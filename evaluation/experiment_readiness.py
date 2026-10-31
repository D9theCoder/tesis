"""Offline-only readiness validator for the owner-requested 108-run matrix.

This module validates a *draft* study contract.  It never imports or invokes the
experiment runner, never freezes an epoch, never writes beneath
``results/runs`` and never contacts DVWA or a model provider.  It reads local
configuration, source identity, the draft contract, the declared study contract
as JSON data (never as an import), and the tesis-web discovery source
(read-only), then emits a readiness report plus the planned-coordinate manifest
into an evidence directory chosen by the caller.

The declared study contract supports selection-only plan build/verify, but the
current planner refuses selection-only execution.  The draft contract is
deliberately not an executable planner config and no matrix launch is claimed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections.abc import Mapping
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

DRAFT_VERSION = "autoresearch-primary-readiness.v1"
REPORT_VERSION = "autoresearch-readiness.v1"
PLANNED_MANIFEST_VERSION = "autoresearch-planned-manifest.v1"
DRAFT_STATUS = "draft_unapproved_unfrozen"
APPROVED_DRAFT_STATUS = "approved_frozen_ready"
DRAFT_STATUSES = frozenset({DRAFT_STATUS, APPROVED_DRAFT_STATUS})
EXPECTED_TOTAL = 108
REQUIRED_REASONING = "max"
OUTPUT_PARENT = "results/runs"
MAX_LEVELS = ("low", "medium", "high")
MAX_BLOCKS = ("selection",)
SAFE_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
GIT_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")

REQUIRED_MODELS: tuple[dict[str, str], ...] = (
    {
        "key": "deepseek-v4.1-flash-1017",
        "display_name": "DeepSeek V4.1 Flash 1017",
        "model_name": "deepseek-ai/DeepSeek-V4.1-Flash-1017",
        "configured_profile_id": "river-ai__deepseek-ai-deepseek-v4-1-flash-1017_15efb2abf693",
        "api_provider_id": "river-ai",
        "provider_protocol": "openai_compatible",
        "reasoning_effort": REQUIRED_REASONING,
    },
    {
        "key": "gpt-6-luna",
        "display_name": "GPT-6 Luna",
        "model_name": "gpt-6-luna",
        "configured_profile_id": "openai_codex_auth",
        "api_provider_id": "openai_codex_auth",
        "provider_protocol": "openai_codex_auth",
        "reasoning_effort": REQUIRED_REASONING,
    },
)

DESIGN_KEYS = frozenset({
    "blocks", "target_method", "conditions", "payload_mode", "surfaces",
    "levels", "repeats", "expected_coordinates", "models",
})
MODEL_KEYS = frozenset({
    "key", "display_name", "model_name", "configured_profile_id",
    "api_provider_id", "provider_protocol", "reasoning_effort",
})
COORDINATE_FIELDS = frozenset({
    "coordinate_index", "coordinate_id", "block", "model_key", "provider",
    "model_profile", "model_name", "model", "api_provider_id", "surface",
    "security_level", "payload_mode", "experiment_condition", "target_method",
    "repeat_index", "status", "policy_epoch_id", "fixture_id",
    "protocol_version", "candidate_budget",
})
SCORE_FIELDS = frozenset({
    "score", "srun", "srun_final", "components", "metrics", "Smethod",
    "Spayload", "Sexploit", "Schain", "Soutput",
})
FALSE_CLAIM_KEYS = frozenset({
    "approved", "frozen", "execution_authorized", "historical_preregistered",
})
DRAFT_KEYS = frozenset({
    "draft_version", "status", "created_at", "purpose", "intended_epoch",
    "design", "policy", "cost", "scope", "provider_inputs", "approval",
    "traceability", "declared_blockers", "coordinates",
})
DRAFT_EPOCH_KEYS = frozenset({
    "epoch_id", "output_root", "output_root_created", "execution_date",
})
DRAFT_POLICY_KEYS = frozenset({
    "rubric_version", "scoring_profile", "scoring_oracles",
    "scoring_policy_epoch", "ranking_profile", "oracle_preregistration",
    "candidate_order", "historical_smethod",
})
DRAFT_COST_KEYS = frozenset({
    "status", "token_price_schedule", "sources", "effective_at_basis",
    "price_key_routes", "measurement", "notes",
})
DRAFT_SCOPE_KEYS = frozenset({
    "target_url", "fixture_id", "protocol_version", "candidate_budget",
    "surface_level_scope", "containment", "live_target_access_performed",
    "provider_access_performed",
})
TRACEABILITY_KEYS = frozenset({
    "output_root", "web_discovery_contract", "required_run_fields",
    "manifest_emission", "coordinate_identity",
})
SUMMARY_FIELDS = (
    "provider", "model", "surface", "security_level", "payload_mode",
    "experiment_condition", "target_method", "repeat_index",
)

DISCOVERY_FILES = {
    "fs_util": "lib/server/fs-util.ts",
    "resolve_run": "lib/server/resolve-run.ts",
    "schemas": "lib/schemas.ts",
}
DISCOVERY_CHECKS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("default_runs_root", "discovery defaults to <repo>/results/runs", "fs_util",
     ('path.join(tesisRoot(), "results", "runs")',)),
    ("manifest_discriminator", "experiment manifests are recognized", "resolve_run",
     ('artifact_type === "experiment_manifest"', 'schema_version === "artifact-manifest.v1"')),
    ("primary_discriminators", "matrix and child primary artifacts are recognized",
     "resolve_run",
     ('schema_version === "tui.v1"', 'schema_version === "stage8.v1"',
      'artifact_type === "matrix_aggregate"')),
    ("manifest_members", "manifest children bind by execution_id and one-based index",
     "resolve_run", ("manifest.raw.runs", "coordinateIndex", "m.index")),
    ("embedded_children", "aggregate-embedded children bind by exact execution ID",
     "resolve_run", ("embedded_child_source", "matrixExecutionId")),
    ("summary_axes", "summaries expose the planned coordinate axes", "resolve_run",
     ("securityLevel: text(m.security_level)",
      "experimentCondition: text(m.experiment_condition)",
      "targetMethod: text(m.target_method)",
      "repeatIndex: finite(m.repeat_index)")),
    ("artifact_execution_id", "primary artifact schema requires execution_id", "schemas",
     ("execution_id: z.string()", "runs: z.array(z.record(z.unknown())).optional()")),
)
GIT_SOURCE_SCOPE = (
    "agents", "core", "evaluation", "foundation", "llm", "tesis",
    "config.yaml", "pyproject.toml", "uv.lock",
)

# The declared study contract is read as data only.  It is never imported,
# executed or treated as an approval.  Linking the draft is not registration.
STUDY_CONTRACT_VERSION = "chapter3-research-config.v1"
STUDY_CONTRACT_PATH = "config/research/autoresearch-primary-study-2026-10-31.json"
STUDY_SCORING_RUNTIME_PROVISIONAL = "scoring.v2"
STUDY_SCORING_FINAL_SOURCE = "thesis_score_receipt only"
STUDY_FROZEN_INPUTS = frozenset({
    "scoring_profile", "scoring_oracles", "scoring_policy_epoch",
    "token_price_schedule", "fixture_id", "protocol_version", "candidate_budget",
})
ORACLE_PREREGISTRATION_DRAFT_PATH = (
    "config/research/autoresearch-oracle-preregistration-draft-2026-10-31.json"
)
ORACLE_PREREGISTRATION_DOC_PATH = (
    "docs/active/HANDOFF_AUTORESEARCH_LOOP_2026-10-30.md"
)
PLANNER_PATH = "evaluation/research_plan.py"
PLANNER_SELECTION_EXECUTION_REFUSAL = "selection-only plan execution is not supported"

# tesis-web renders target_method through z.string().nullable() and its summary
# type is string | null.  A selection coordinate therefore records null as the
# valid model-selected value; the key must still be present.  No null is
# rewritten to a string.
MODEL_SELECTED_NULL_SUMMARY_FIELDS = frozenset({"target_method"})


def _issue(code: str, detail: str, path: str | None = None) -> dict[str, Any]:
    return {"code": code, "detail": detail, "path": path}


def _blocker(code: str, category: str, detail: str, *, severity: str = "blocker",
             evidence: Any = None) -> dict[str, Any]:
    return {"id": code, "category": category, "severity": severity,
            "detail": detail, "evidence": evidence}


def _canonical_hash(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _file_hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def load_draft(path: str | Path) -> dict[str, Any]:
    """Load the draft study contract; it is never executed or frozen."""
    document = json.loads(Path(path).read_bytes())
    if not isinstance(document, dict):
        raise ValueError("readiness draft must be a JSON object")
    return document


def _coordinate_id(row: Mapping[str, Any]) -> str:
    axes = (
        "model_key", "surface", "security_level", "payload_mode",
        "experiment_condition", "target_method", "repeat_index", "block",
        "policy_epoch_id",
    )
    return _canonical_hash({axis: row.get(axis) for axis in axes})[:16]


def expand_coordinates(draft: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Expand the declared Cartesian product; never drops or zero-fills axes."""
    design = draft["design"]
    epoch_id = draft["intended_epoch"]["epoch_id"]
    scope = draft["scope"]
    rows: list[dict[str, Any]] = []
    index = 0
    for model in design["models"]:
        for surface in design["surfaces"]:
            for level in design["levels"]:
                for condition in design["conditions"]:
                    for repeat_index in range(design["repeats"]):
                        row = {
                            "coordinate_index": index,
                            "coordinate_id": None,
                            "block": "selection",
                            "model_key": model["key"],
                            "provider": model["configured_profile_id"],
                            "model_profile": model["configured_profile_id"],
                            "model_name": model["model_name"],
                            "model": model["model_name"],
                            "api_provider_id": model["api_provider_id"],
                            "surface": surface,
                            "security_level": level,
                            "payload_mode": design["payload_mode"],
                            "experiment_condition": condition,
                            "target_method": None,
                            "repeat_index": repeat_index,
                            "status": "planned",
                            "policy_epoch_id": epoch_id,
                            "fixture_id": scope["fixture_id"],
                            "protocol_version": scope["protocol_version"],
                            "candidate_budget": scope["candidate_budget"],
                        }
                        row["coordinate_id"] = _coordinate_id(row)
                        rows.append(row)
                        index += 1
    return rows


def _walk_claims(value: Any, path: str = "") -> list[tuple[str, str, Any]]:
    found: list[tuple[str, str, Any]] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            found.append((child_path, str(key), child))
            found.extend(_walk_claims(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_walk_claims(child, f"{path}[{index}]"))
    return found


def _price_like(value: Any) -> list[str]:
    hits: list[str] = []
    for path, key, child in _walk_claims(value):
        if key in {"input_per_million", "output_per_million", "cache_read_per_million",
                   "cache_write_per_million"} and isinstance(child, (int, float)) and not isinstance(child, bool):
            hits.append(path)
        if key == "prices" and isinstance(child, Mapping) and child:
            hits.append(path)
    return hits


def validate_design(draft: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Validate exact axes, models and non-executable draft status."""
    issues: list[dict[str, Any]] = []
    unknown = sorted(set(draft) - DRAFT_KEYS)
    if unknown:
        issues.append(_issue("draft_unknown_fields", f"unknown draft fields: {unknown}"))
    if draft.get("draft_version") != DRAFT_VERSION:
        issues.append(_issue("draft_version_invalid", f"expected {DRAFT_VERSION}", "draft_version"))
    if draft.get("status") not in DRAFT_STATUSES:
        issues.append(_issue("draft_status_invalid", f"expected one of {sorted(DRAFT_STATUSES)}", "status"))
    epoch = draft.get("intended_epoch")
    epoch_map = epoch if isinstance(epoch, Mapping) else {}
    if not isinstance(epoch, Mapping):
        issues.append(_issue("intended_epoch_missing", "intended_epoch must be a mapping"))
    else:
        unknown = sorted(set(epoch) - DRAFT_EPOCH_KEYS)
        if unknown:
            issues.append(_issue("intended_epoch_unknown_fields", f"unknown fields: {unknown}"))
        epoch_id = epoch.get("epoch_id")
        if not isinstance(epoch_id, str) or not SAFE_SEGMENT.fullmatch(epoch_id):
            issues.append(_issue("epoch_id_invalid", "epoch_id must be one safe path segment", "intended_epoch.epoch_id"))
        elif epoch.get("output_root") != f"{OUTPUT_PARENT}/{epoch_id}":
            issues.append(_issue(
                "output_root_invalid",
                f"output_root must be {OUTPUT_PARENT}/<epoch_id>",
                "intended_epoch.output_root",
            ))
        if epoch.get("output_root_created") is not False:
            issues.append(_issue("output_root_claim_invalid", "the draft must not claim to have created the run root"))
    design = draft.get("design")
    if not isinstance(design, Mapping):
        issues.append(_issue("design_missing", "design must be a mapping"))
        return issues
    unknown = sorted(set(design) - DESIGN_KEYS)
    if unknown:
        issues.append(_issue("design_unknown_fields", f"unknown design fields: {unknown}"))
    blocks = design.get("blocks")
    if blocks != list(MAX_BLOCKS):
        issues.append(_issue("forced_block_present", "the primary matrix must declare only the selection block"))
    if design.get("target_method") is not None:
        issues.append(_issue("target_method_forced", "target_method must be null for model-selected runs"))
    if design.get("payload_mode") != "hybrid":
        issues.append(_issue("payload_mode_invalid", "payload_mode must be hybrid"))
    if design.get("repeats") != 3:
        issues.append(_issue("repeats_invalid", "exactly three repetitions are required"))
    if design.get("surfaces") != ["sqli", "access_control", "brute_force"]:
        issues.append(_issue("surfaces_invalid", "surfaces must be exactly the three registered surfaces in order"))
    if design.get("levels") != list(MAX_LEVELS):
        issues.append(_issue("levels_invalid", "levels must be exactly low, medium, high"))
    if design.get("conditions") != ["linear_hybrid", "akg_guided_hybrid"]:
        issues.append(_issue("conditions_invalid", "both named conditions are required in order"))
    models = design.get("models")
    if not isinstance(models, list) or len(models) != len(REQUIRED_MODELS):
        issues.append(_issue("models_invalid", "exactly the two requested models are required"))
    else:
        expected = {spec["key"]: spec for spec in REQUIRED_MODELS}
        seen: set[str] = set()
        for index, model in enumerate(models):
            if not isinstance(model, Mapping):
                issues.append(_issue("model_not_object", "model entry must be an object", f"design.models[{index}]"))
                continue
            unknown = sorted(set(model) - MODEL_KEYS)
            if unknown:
                issues.append(_issue("model_unknown_fields", f"unknown model fields: {unknown}", f"design.models[{index}]"))
            key = model.get("key")
            if not isinstance(key, str) or key not in expected:
                issues.append(_issue("model_unexpected", f"unexpected model key {key!r}", f"design.models[{index}].key"))
                continue
            if key in seen:
                issues.append(_issue("model_duplicate", f"duplicate model {key!r}", f"design.models[{index}]"))
                continue
            seen.add(key)
            spec = expected[key]
            for field in ("display_name", "model_name", "configured_profile_id",
                          "api_provider_id", "provider_protocol", "reasoning_effort"):
                if model.get(field) != spec[field]:
                    issues.append(_issue(
                        "model_field_mismatch",
                        f"{key}.{field} must be {spec[field]!r}",
                        f"design.models[{index}].{field}",
                    ))
            if model.get("reasoning_effort") != REQUIRED_REASONING:
                issues.append(_issue("model_reasoning_not_max", f"{key} must request max reasoning"))
        missing = sorted(set(expected) - seen)
        if missing:
            issues.append(_issue("model_missing", f"missing models: {missing}"))
    models_value = design.get("models")
    surfaces_value = design.get("surfaces")
    levels_value = design.get("levels")
    conditions_value = design.get("conditions")
    repeats_value = design.get("repeats")
    total = 0
    if isinstance(models_value, list) and isinstance(surfaces_value, list) \
            and isinstance(levels_value, list) and isinstance(conditions_value, list) \
            and isinstance(repeats_value, int) and not isinstance(repeats_value, bool):
        total = len(models_value) * len(surfaces_value) * len(levels_value) * len(conditions_value) * repeats_value
    if design.get("expected_coordinates") != EXPECTED_TOTAL:
        issues.append(_issue("expected_coordinates_invalid", f"expected_coordinates must be {EXPECTED_TOTAL}"))
    if total != EXPECTED_TOTAL:
        issues.append(_issue("coordinate_product_invalid", f"declared axes expand to {total}, not {EXPECTED_TOTAL}"))
    policy = draft.get("policy")
    if not isinstance(policy, Mapping):
        issues.append(_issue("policy_missing", "policy must be a mapping"))
    else:
        unknown = sorted(set(policy) - DRAFT_POLICY_KEYS)
        if unknown:
            issues.append(_issue("policy_unknown_fields", f"unknown policy fields: {unknown}"))
        if policy.get("rubric_version") != "scoring.v4":
            issues.append(_issue("rubric_version_invalid", "rubric_version must be scoring.v4"))
        declared_policy_epoch = policy.get("scoring_policy_epoch")
        intended_epoch_id = declared_policy_epoch.get("intended_epoch_id") \
            if isinstance(declared_policy_epoch, Mapping) else None
        if intended_epoch_id and intended_epoch_id != epoch_map.get("epoch_id"):
            issues.append(_issue("policy_epoch_intent_mismatch", "policy epoch intent must match intended_epoch"))
    cost = draft.get("cost")
    if not isinstance(cost, Mapping):
        issues.append(_issue("cost_missing", "cost must be a mapping"))
    else:
        unknown = sorted(set(cost) - DRAFT_COST_KEYS)
        if unknown:
            issues.append(_issue("cost_unknown_fields", f"unknown cost fields: {unknown}"))
        schedule = cost.get("token_price_schedule")
        if schedule:
            try:
                from evaluation.research_metrics import validate_token_price_schedule

                if not isinstance(schedule, Mapping):
                    raise ValueError("token_price_schedule must be a mapping")
                validate_token_price_schedule(dict(schedule))
            except (TypeError, ValueError) as exc:
                issues.append(_issue("price_schedule_invalid", str(exc), "cost.token_price_schedule"))
            if isinstance(schedule, Mapping) and schedule.get("epoch_id") not in (None, epoch_map.get("epoch_id")):
                issues.append(_issue("price_schedule_epoch_mismatch", "price schedule epoch must match intended_epoch"))
        elif _price_like(draft):
            issues.append(_issue(
                "unsourced_prices_present",
                "price-like values are present without a validated token_price_schedule",
            ))
    scope = draft.get("scope")
    if not isinstance(scope, Mapping):
        issues.append(_issue("scope_missing", "scope must be a mapping"))
    else:
        unknown = sorted(set(scope) - DRAFT_SCOPE_KEYS)
        if unknown:
            issues.append(_issue("scope_unknown_fields", f"unknown scope fields: {unknown}"))
        for field in ("fixture_id", "protocol_version"):
            value = scope.get(field)
            if not isinstance(value, str) or not value.strip():
                issues.append(_issue("scope_field_missing", f"scope requires {field}", f"scope.{field}"))
        if scope.get("live_target_access_performed") is not False or \
                scope.get("provider_access_performed") is not False:
            issues.append(_issue("network_claim_invalid", "offline draft must record no target/provider access"))
    traceability = draft.get("traceability")
    if not isinstance(traceability, Mapping):
        issues.append(_issue("traceability_missing", "traceability must be a mapping"))
    else:
        unknown = sorted(set(traceability) - TRACEABILITY_KEYS)
        if unknown:
            issues.append(_issue("traceability_unknown_fields", f"unknown traceability fields: {unknown}"))
        if traceability.get("output_root") != epoch_map.get("output_root"):
            issues.append(_issue("traceability_output_mismatch", "traceability output_root must match intended_epoch"))
        required_value = traceability.get("required_run_fields")
        required = set(required_value) if isinstance(required_value, (list, tuple, set, frozenset)) else set()
        missing = sorted(set(SUMMARY_FIELDS) - required)
        if missing:
            issues.append(_issue("traceability_fields_missing", f"missing run fields: {missing}"))
    approval = draft.get("approval")
    if draft.get("status") == APPROVED_DRAFT_STATUS:
        if not isinstance(approval, Mapping) or approval.get("recorded") is not True:
            issues.append(_issue("approval_record_missing", "an approved draft must record approval"))
        else:
            for field in ("source", "approved_by", "signature", "recorded_at"):
                value = approval.get(field)
                if not isinstance(value, str) or not value.strip():
                    issues.append(_issue(
                        "approval_field_missing", f"approval requires {field}", f"approval.{field}",
                    ))
            try:
                recorded_at = datetime.fromisoformat(str(approval.get("recorded_at")))
                if recorded_at.tzinfo is None:
                    raise ValueError("naive timestamp")
            except ValueError:
                issues.append(_issue(
                    "approval_timestamp_invalid",
                    "approval.recorded_at must be an ISO timestamp with timezone",
                    "approval.recorded_at",
                ))
    elif not isinstance(approval, Mapping) or approval.get("recorded") is not False:
        issues.append(_issue("false_approval_claim", "the unapproved draft must record approval as not recorded"))
    for path, key, child in _walk_claims(draft):
        if key in FALSE_CLAIM_KEYS and child is True:
            issues.append(_issue("false_freeze_or_approval_claim", f"{path} must not be true", path))
    return issues


def validate_coordinates(draft: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Preserve and audit all declared coordinates; report duplicate/missing axes."""
    issues: list[dict[str, Any]] = []
    declared = draft.get("coordinates")
    stats: dict[str, Any] = {
        "expected_count": EXPECTED_TOTAL,
        "declared_count": len(declared) if isinstance(declared, list) else 0,
        "unique_coordinate_ids": 0,
        "unique_axis_tuples": 0,
        "duplicate_coordinate_ids": [],
        "duplicate_axis_tuples": [],
        "missing_axis_tuples": [],
        "extra_axis_tuples": [],
        "status_counts": {},
        "indices_contiguous": False,
        "zero_fills": [],
    }
    if not isinstance(declared, list):
        issues.append(_issue("coordinates_not_list", "coordinates must be a list"))
        return issues, stats
    try:
        expected = expand_coordinates(draft)
    except (KeyError, TypeError, ValueError) as exc:
        issues.append(_issue("coordinate_expansion_failed", f"cannot expand axes: {exc}"))
        expected = []
    expected_tuples = {
        (row["model_key"], row["surface"], row["security_level"],
         row["experiment_condition"], row["repeat_index"]) for row in expected
    }
    actual_tuples: dict[tuple[Any, ...], int] = {}
    ids: dict[str, int] = {}
    indices: list[int] = []
    status_counts: dict[str, int] = {}
    zero_fills: list[str] = []
    design_value = draft.get("design")
    scope_value = draft.get("scope")
    epoch_value = draft.get("intended_epoch")
    scope_map = scope_value if isinstance(scope_value, Mapping) else {}
    epoch_map = epoch_value if isinstance(epoch_value, Mapping) else {}
    model_specs: dict[str, Mapping[str, Any]] = {}
    if isinstance(design_value, Mapping):
        models_value = design_value.get("models")
        if isinstance(models_value, list):
            model_specs = {
                model["key"]: model for model in models_value
                if isinstance(model, Mapping) and isinstance(model.get("key"), str)
            }
    for position, row in enumerate(declared):
        path = f"coordinates[{position}]"
        if not isinstance(row, Mapping):
            issues.append(_issue("coordinate_not_object", "coordinate must be an object", path))
            continue
        unknown = sorted(set(row) - COORDINATE_FIELDS)
        if unknown:
            issues.append(_issue("coordinate_unknown_fields", f"unknown fields: {unknown}", path))
        missing = sorted(COORDINATE_FIELDS - set(row))
        if missing:
            issues.append(_issue("coordinate_fields_missing", f"missing fields: {missing}", path))
        score_fields = sorted(set(row) & SCORE_FIELDS)
        if score_fields:
            zero_fills.append(f"{path}:{score_fields}")
        if row.get("block") != "selection":
            issues.append(_issue("coordinate_forced_block", "only selection coordinates are allowed", path))
        if row.get("target_method") is not None:
            issues.append(_issue("coordinate_forced_method", "target_method must be null", path))
        if row.get("payload_mode") != "hybrid":
            issues.append(_issue("coordinate_payload_mode", "payload_mode must be hybrid", path))
        for field, expected_value in (
            ("policy_epoch_id", epoch_map.get("epoch_id")),
            ("fixture_id", scope_map.get("fixture_id")),
            ("protocol_version", scope_map.get("protocol_version")),
            ("candidate_budget", scope_map.get("candidate_budget")),
        ):
            if expected_value is not None and row.get(field) != expected_value:
                issues.append(_issue("coordinate_scope_mismatch", f"{field} must be {expected_value!r}", path))
        if row.get("status") is not None:
            status_counts[str(row.get("status"))] = status_counts.get(str(row.get("status")), 0) + 1
        index = row.get("coordinate_index")
        if isinstance(index, int) and not isinstance(index, bool):
            indices.append(index)
        else:
            issues.append(_issue("coordinate_index_invalid", "coordinate_index must be an integer", path))
        repeat_index = row.get("repeat_index")
        if not isinstance(repeat_index, int) or isinstance(repeat_index, bool) or not 0 <= repeat_index < 3:
            issues.append(_issue("repeat_index_invalid", "repeat_index must be 0..2", path))
        tuple_key = (
            row.get("model_key"), row.get("surface"), row.get("security_level"),
            row.get("experiment_condition"), row.get("repeat_index"),
        )
        actual_tuples[tuple_key] = actual_tuples.get(tuple_key, 0) + 1
        coordinate_id = row.get("coordinate_id")
        if isinstance(coordinate_id, str):
            ids[coordinate_id] = ids.get(coordinate_id, 0) + 1
        else:
            issues.append(_issue("coordinate_id_invalid", "coordinate_id must be a string", path))
        spec = model_specs.get(row.get("model_key")) if isinstance(row.get("model_key"), str) else None
        if spec is None:
            issues.append(_issue("coordinate_model_unknown", "model_key is not declared", path))
        else:
            expected_values = (
                ("provider", spec.get("configured_profile_id")),
                ("model_profile", spec.get("configured_profile_id")),
                ("model_name", spec.get("model_name")),
                ("model", spec.get("model_name")),
                ("api_provider_id", spec.get("api_provider_id")),
            )
            if any(value is None for _field, value in expected_values):
                issues.append(_issue("coordinate_model_spec_incomplete", "declared model spec is incomplete", path))
            else:
                for field, expected_value in expected_values:
                    if row.get(field) != expected_value:
                        issues.append(_issue("coordinate_model_mismatch", f"{field} must be {expected_value!r}", path))
    stats["unique_coordinate_ids"] = len(ids)
    stats["unique_axis_tuples"] = len(actual_tuples)
    stats["duplicate_coordinate_ids"] = sorted(key for key, count in ids.items() if count > 1)
    stats["duplicate_axis_tuples"] = [
        list(key) for key, count in sorted(actual_tuples.items(), key=lambda item: str(item[0]))
        if count > 1
    ]
    stats["missing_axis_tuples"] = [
        list(key) for key in sorted(expected_tuples - set(actual_tuples), key=str)
    ]
    stats["extra_axis_tuples"] = [
        list(key) for key in sorted(set(actual_tuples) - expected_tuples, key=str)
    ]
    stats["status_counts"] = dict(sorted(status_counts.items()))
    stats["indices_contiguous"] = (
        sorted(indices) == list(range(len(declared))) and len(indices) == len(declared)
    )
    stats["zero_fills"] = zero_fills
    if len(declared) != EXPECTED_TOTAL:
        issues.append(_issue("coordinate_count_mismatch", f"declared {len(declared)} coordinates, expected {EXPECTED_TOTAL}"))
    if stats["duplicate_coordinate_ids"]:
        issues.append(_issue("coordinate_id_duplicate", f"duplicate IDs: {stats['duplicate_coordinate_ids']}"))
    if stats["duplicate_axis_tuples"]:
        issues.append(_issue("coordinate_axis_duplicate", f"duplicate axes: {stats['duplicate_axis_tuples']}"))
    if stats["missing_axis_tuples"]:
        issues.append(_issue("coordinate_axis_missing", f"missing axes: {stats['missing_axis_tuples']}"))
    if stats["extra_axis_tuples"]:
        issues.append(_issue("coordinate_axis_extra", f"extra axes: {stats['extra_axis_tuples']}"))
    if not stats["indices_contiguous"]:
        issues.append(_issue("coordinate_index_not_contiguous", "coordinate_index must be 0..107 without gaps"))
    if zero_fills:
        issues.append(_issue("zero_fill_present", f"score fields must not be zero-filled: {zero_fills[:5]}"))
    return issues, stats


def load_configured(config_path: str | Path) -> dict[str, Any]:
    """Resolve local configuration without network access or secret export."""
    path = Path(config_path)
    result: dict[str, Any] = {"available": False, "path": str(path), "error": None}
    try:
        from tesis.config_loader import load_and_resolve_config, load_yaml_config

        config = load_and_resolve_config(config_path=str(path), cli_args={})
        raw = load_yaml_config(str(path))
        models: dict[str, Any] = {}
        for name, model in config.models.items():
            models[name] = {
                "provider": model.provider,
                "model_name": model.model_name,
                "reasoning_effort": model.reasoning_effort,
                "temperature": model.temperature,
                "max_tokens": model.max_tokens,
                "timeout": model.timeout,
            }
        from evaluation.scoring_evidence import evidence_hash, validate_evidence_config

        profile = dict(config.scoring_profile or {})
        oracles = list(config.scoring_oracles or [])
        oracle_validation: dict[str, Any] = {"valid": None, "reason": None}
        try:
            validate_evidence_config(config.scoring_rubric_version, profile, oracles)
            oracle_validation = {"valid": True, "reason": None}
        except (TypeError, ValueError) as exc:
            oracle_validation = {"valid": False, "reason": str(exc)}
        roles = {
            role: {"reasoning_effort": settings.reasoning_effort,
                   "model_profile": settings.model_profile}
            for role, settings in (config.llm_runtime.roles or {}).items()
        }
        restoration = config.fixture_restoration_evidence or {}
        by_level = restoration.get("by_level") if isinstance(restoration, Mapping) else {}
        restoration_summary = {
            "present": bool(restoration),
            "levels": sorted(by_level) if isinstance(by_level, Mapping) else [],
            "epoch_ids": sorted({
                str(document.get("epoch_id"))
                for document in (by_level or {}).values()
                if isinstance(document, Mapping) and document.get("epoch_id")
            }) if isinstance(by_level, Mapping) else [],
            "source_hashes_sha256": sorted({
                str(document.get("source_hashes_sha256"))
                for document in (by_level or {}).values()
                if isinstance(document, Mapping) and document.get("source_hashes_sha256")
            }) if isinstance(by_level, Mapping) else [],
        }
        result.update({
            "available": True,
            "target_url": config.target_url,
            "default_provider": config.provider,
            "providers": list(config.providers or []),
            "models": models,
            "levels": list(config.levels or []),
            "surfaces": list(config.surfaces or []),
            "payload_mode": config.payload_mode,
            "repeats": config.repeats,
            "experiment_condition": config.experiment_condition,
            "candidate_budget": config.candidate_budget,
            "fixture_id": config.fixture_id,
            "protocol_version": config.protocol_version,
            "output_dir": config.output_dir,
            "scoring_mode": config.scoring_mode,
            "scoring_rubric_version": config.scoring_rubric_version,
            "scoring_profile": profile,
            "scoring_profile_sha256": evidence_hash(profile) if profile else None,
            "scoring_oracles": oracles,
            "scoring_oracles_sha256": evidence_hash(oracles) if oracles else None,
            "scoring_oracle_source_ids": sorted({
                str(source.get("source_id")) for source in oracles
                if isinstance(source, Mapping) and source.get("source_id")
            }),
            "scoring_oracle_validation": oracle_validation,
            "scoring_policy_epoch": dict(config.scoring_policy_epoch or {}),
            "token_price_schedule": dict(config.token_price_schedule or {}),
            "fixture_restoration": restoration_summary,
            "roles": roles,
            "reasoning_catalog": dict((raw or {}).get("reasoning_catalog") or {}),
        })
    except Exception as exc:  # noqa: BLE001 - readiness must report an unavailable config
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _model_candidates(provider: str, model_name: str, profile_id: str) -> list[str]:
    return [f"{provider}/{model_name}", f"{provider}/{profile_id}", model_name]


def analyse_models(draft: Mapping[str, Any], configured: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve configured model/profile/reasoning identity and catalog claims."""
    entries: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    if not configured.get("available"):
        blockers.append(_blocker(
            "configured_config_unavailable", "configuration",
            f"config could not be resolved offline: {configured.get('error')}",
        ))
        return entries, blockers, warnings
    for spec in draft["design"]["models"]:
        declared = spec["configured_profile_id"]
        models = configured.get("models") or {}
        model = models.get(declared)
        by_name = [name for name, item in models.items() if item.get("model_name") == spec["model_name"]]
        entry = {
            "key": spec["key"],
            "display_name": spec["display_name"],
            "declared_profile_id": declared,
            "resolved_by_name": by_name,
            "model_name_expected": spec["model_name"],
            "reasoning_required": REQUIRED_REASONING,
            "configured": model is not None,
            "external_catalog_truth": "unverified_no_provider_request",
            "authenticated_account_ready": "unverified_no_provider_request",
        }
        if model is None:
            blockers.append(_blocker(
                "configured_profile_missing", "models",
                f"{spec['key']}: declared profile {declared!r} is not configured; "
                f"profiles with model {spec['model_name']!r}: {by_name or 'none'}",
            ))
            entry["actual_reasoning_effort"] = None
            entries.append(entry)
            continue
        entry.update({
            "actual_provider_adapter": model.get("provider"),
            "actual_model_name": model.get("model_name"),
            "actual_reasoning_effort": model.get("reasoning_effort"),
            "profile_in_configured_providers": declared in (configured.get("providers") or []),
        })
        if model.get("model_name") != spec["model_name"]:
            blockers.append(_blocker(
                "configured_model_name_mismatch", "models",
                f"{spec['key']}: configured model {model.get('model_name')!r} "
                f"!= requested {spec['model_name']!r}",
            ))
        if model.get("reasoning_effort") != REQUIRED_REASONING:
            blockers.append(_blocker(
                "configured_reasoning_effort_not_max", "models",
                f"{spec['key']}: configured reasoning_effort is "
                f"{model.get('reasoning_effort')!r}, not {REQUIRED_REASONING!r}; "
                "an explicit max pin is required before execution",
            ))
        advertised = (configured.get("reasoning_catalog") or {}).get(spec["model_name"])
        entry["catalog_efforts"] = advertised
        if advertised is None:
            warnings.append(_blocker(
                "reasoning_catalog_unverified", "models",
                f"{spec['key']}: no local reasoning catalog entry; external truth not verified",
                severity="warning",
            ))
        elif REQUIRED_REASONING not in advertised:
            blockers.append(_blocker(
                "reasoning_max_not_advertised", "models",
                f"{spec['key']}: local reasoning catalog does not advertise max: {advertised}",
            ))
        if declared not in (configured.get("providers") or []):
            blockers.append(_blocker(
                "profile_not_in_configured_providers", "models",
                f"{spec['key']}: profile {declared!r} is not in config.providers; "
                "the matrix selector would omit it",
            ))
        overrides = {
            role: settings.get("reasoning_effort")
            for role, settings in (configured.get("roles") or {}).items()
            if settings.get("reasoning_effort") not in (None, REQUIRED_REASONING)
        }
        if overrides:
            blockers.append(_blocker(
                "role_reasoning_effort_not_max", "models",
                f"explicit role reasoning overrides are not max: {overrides}",
            ))
        entries.append(entry)
    return entries, blockers, warnings


def analyse_policy(draft: Mapping[str, Any], configured: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    policy = draft["policy"]
    profile = configured.get("scoring_profile") or {}
    epoch = configured.get("scoring_policy_epoch") or {}
    oracles = configured.get("scoring_oracles") or []
    oracle_validation = configured.get("scoring_oracle_validation") or {}
    if not profile:
        blockers.append(_blocker(
            "scoring_profile_missing", "policy",
            "config.scoring_profile is empty; a frozen ranking/scoring profile is required before selection",
        ))
    if not epoch.get("epoch_id"):
        blockers.append(_blocker(
            "scoring_policy_epoch_missing", "policy",
            "config.scoring_policy_epoch has no epoch_id; the draft epoch is not frozen",
        ))
    if not oracles:
        blockers.append(_blocker("scoring_oracles_missing", "policy", "config.scoring_oracles is empty"))
    elif oracle_validation.get("valid") is not True:
        blockers.append(_blocker(
            "scoring_oracles_invalid", "policy",
            f"configured scoring oracle sources failed validation: {oracle_validation.get('reason')}",
        ))
    declared_oracles = policy.get("scoring_oracles") or {}
    if declared_oracles.get("sha256") and \
            declared_oracles.get("sha256") != configured.get("scoring_oracles_sha256"):
        blockers.append(_blocker(
            "scoring_oracle_hash_drift", "policy",
            "the draft scoring-oracle hash no longer matches the configured operator sources",
        ))
    declared_ids = sorted(declared_oracles.get("source_ids") or [])
    if declared_ids and declared_ids != sorted(configured.get("scoring_oracle_source_ids") or []):
        blockers.append(_blocker(
            "scoring_oracle_sources_drift", "policy",
            "the draft scoring-oracle source IDs no longer match the configured operator sources",
        ))
    ranking = policy.get("ranking_profile") or {}
    if profile and profile.get("frozen_at") and profile.get("sha256"):
        ranking = {
            **ranking,
            "status": "present_frozen_before_selection",
            "sha256": profile.get("sha256"),
            "profile_id": profile.get("profile_id"),
        }
    if ranking.get("status") != "present_frozen_before_selection":
        blockers.append(_blocker(
            "ranking_profile_missing", "policy",
            "no owner-approved, frozen 27-entry ranking profile exists before selection",
        ))
    preregistration = policy.get("oracle_preregistration") or {}
    if preregistration.get("status") not in {"present", "preregistered"}:
        blockers.append(_blocker(
            "oracle_preregistration_missing", "policy",
            "independent oracle evidence preregistration is not recorded; configured scoring "
            "oracle sources are configuration, not preregistered independent evidence",
        ))
    candidate_order = dict(policy.get("candidate_order") or {})
    try:
        from core.payload_policy import (
            CANDIDATE_ORDER_POLICY,
            CANDIDATE_ORDER_POLICY_VERSION,
            CANDIDATE_ORDER_TRIGGER,
        )

        candidate_order.update({
            "status": "IMPLEMENTED_AND_FROZEN",
            "policy_version": CANDIDATE_ORDER_POLICY_VERSION,
            "candidate_order_policy": CANDIDATE_ORDER_POLICY,
            "fallback_trigger": CANDIDATE_ORDER_TRIGGER,
        })
    except ImportError:
        pass
    if candidate_order.get("status") != "IMPLEMENTED_AND_FROZEN":
        blockers.append(_blocker(
            "candidate_order_unimplemented_unfrozen", "policy",
            "generated-first/static-fallback is owner direction only; the fallback trigger "
            "is not frozen and runtime ordering is unchanged",
        ))
    return {
        "rubric_version": policy.get("rubric_version"),
        "configured_scoring_mode": configured.get("scoring_mode"),
        "configured_rubric_version": configured.get("scoring_rubric_version"),
        "scoring_profile_present": bool(profile),
        "scoring_profile_sha256": configured.get("scoring_profile_sha256"),
        "scoring_policy_epoch": epoch or None,
        "scoring_oracles_present": bool(oracles),
        "scoring_oracles_count": len(oracles),
        "scoring_oracles_sha256": configured.get("scoring_oracles_sha256"),
        "scoring_oracle_validation": oracle_validation,
        "ranking_profile": ranking,
        "oracle_preregistration": preregistration,
        "candidate_order": candidate_order,
        "historical_smethod": policy.get("historical_smethod"),
    }, blockers


def _schedule_sources_valid(cost: Mapping[str, Any]) -> tuple[bool, str | None]:
    sources = cost.get("sources")
    if not isinstance(sources, list) or not sources:
        return False, "token price schedule requires independently sourced URLs"
    for source in sources:
        url = source.get("url") if isinstance(source, Mapping) else None
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            return False, "each price source requires an absolute http(s) URL"
    if not isinstance(cost.get("effective_at_basis"), str) or not cost["effective_at_basis"].strip():
        return False, "price schedule requires an explicit effective_at basis"
    return True, None


def analyse_cost(draft: Mapping[str, Any], configured: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    cost = draft["cost"]
    schedule = cost.get("token_price_schedule")
    configured_schedule = configured.get("token_price_schedule") or {}
    result: dict[str, Any] = {
        "status": "unavailable",
        "token_price_schedule": schedule,
        "schedule_sha256": _canonical_hash(schedule) if schedule else None,
        "configured_schedule_present": bool(configured_schedule),
        "configured_schedule_sha256": _canonical_hash(configured_schedule) if configured_schedule else None,
        "currency": (schedule or {}).get("currency"),
        "effective_at": (schedule or {}).get("effective_at"),
        "effective_at_basis": cost.get("effective_at_basis"),
        "applicable_models": {},
        "direct_route_prices": {},
        "measurement": {
            "token_cost": "null_with_reason_when_usage_or_price_is_unavailable",
            "token_cost_per_success": "null_with_reason_when_usage_or_price_is_unavailable",
            "zero_fill": "forbidden",
        },
    }
    if not isinstance(schedule, Mapping) or not schedule:
        blockers.append(_blocker(
            "token_price_schedule_missing", "cost",
            "the draft has no validated token price schedule; token cost remains null with a reason, never zero",
        ))
        if not configured_schedule:
            blockers.append(_blocker(
                "configured_token_price_schedule_missing", "cost",
                "config.token_price_schedule is empty; the executable plan freeze would reject the epoch",
            ))
        return result, blockers, warnings
    try:
        from evaluation.research_metrics import validate_token_price_schedule

        validate_token_price_schedule(dict(schedule))
    except (TypeError, ValueError) as exc:
        blockers.append(_blocker("token_price_schedule_invalid", "cost", str(exc)))
        return result, blockers, warnings
    if not configured_schedule:
        blockers.append(_blocker(
            "configured_token_price_schedule_missing", "cost",
            "config.token_price_schedule is empty; the draft schedule is not yet an executable "
            "epoch-local config and the plan freeze would reject the epoch",
        ))
    elif _canonical_hash(configured_schedule) != _canonical_hash(schedule):
        blockers.append(_blocker(
            "configured_token_price_schedule_mismatch", "cost",
            "config.token_price_schedule differs from the draft schedule; cost identity would drift",
        ))
    sources_ok, source_reason = _schedule_sources_valid(cost)
    if not sources_ok:
        blockers.append(_blocker("token_price_sources_missing", "cost", source_reason or "invalid sources"))
    prices_value = schedule.get("prices")
    prices = dict(prices_value) if isinstance(prices_value, Mapping) else {}
    configured_models = configured.get("models") or {}
    for spec in draft["design"]["models"]:
        model = configured_models.get(spec["configured_profile_id"]) or {}
        adapter = model.get("provider")
        candidates = _model_candidates(
            str(adapter or spec["provider_protocol"]),
            spec["model_name"],
            spec["configured_profile_id"],
        ) if adapter else []
        match = next((key for key in candidates if key in prices), None)
        result["applicable_models"][spec["key"]] = {
            "configured_profile_id": spec["configured_profile_id"],
            "runtime_candidates": candidates,
            "matched_price_key": match,
            "applicable": match is not None,
        }
        if match is None:
            detail = (
                f"{spec['key']}: no price key matches the configured runtime identity "
                f"({adapter}/{spec['model_name']} or {adapter}/{spec['configured_profile_id']}); "
            )
            if spec.get("api_provider_id") != spec["configured_profile_id"]:
                detail += (
                    "the public direct-route rate is not applicable to this configured "
                    "subscription/OAuth profile"
                )
            else:
                detail += "cost metrics stay null with a reason"
            blockers.append(_blocker("token_price_unavailable_for_configured_model", "cost", detail))
        direct = f"openai/{spec['model_name']}" if spec["model_name"] == "gpt-6-luna" else None
        if direct and direct in prices:
            result["direct_route_prices"][spec["key"]] = {
                "price_key": direct,
                "applicable_to_configured_profile": match == direct,
            }
            warnings.append(_blocker(
                "price_tier_multipliers_not_modeled", "cost",
                "Direct GPT-6 Luna Standard base rates do not encode the documented >272K "
                "input, Fast/Flex/Batch or regional multipliers; any such call needs separate "
                "accounting rather than a silently under-counted cost.",
                severity="warning",
            ))
    applicable = sum(1 for item in result["applicable_models"].values() if item["applicable"])
    total = len(result["applicable_models"])
    result["status"] = "available" if applicable == total else ("partial" if applicable else "unavailable")
    return result, blockers, warnings


def analyse_live_readiness(
    draft: Mapping[str, Any], configured: Mapping[str, Any], *, repo_root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate recorded live target/provider probe evidence for this epoch."""
    blockers: list[dict[str, Any]] = []
    epoch = draft.get("intended_epoch") or {}
    epoch_id = str(epoch.get("epoch_id") or "")
    path = repo_root / "results" / "epochs" / epoch_id / "live-readiness.json"
    result: dict[str, Any] = {
        "path": str(path.relative_to(repo_root)) if path.is_file() else None,
        "present": path.is_file(),
        "checks": {},
        "missing": [],
        "detail": "No recorded live target/provider readiness evidence exists for this epoch.",
    }
    if not path.is_file():
        blockers.append(_blocker(
            "live_readiness_unverified", "readiness",
            "offline validation cannot prove DVWA authentication, requested level, endpoint "
            "availability or provider reachability; a recorded live probe is required",
            severity="gate",
        ))
        blockers.append(_blocker(
            "containment_unverified_live", "readiness",
            "containment policy is present in source but live containment behavior has not "
            "been verified by a recorded probe",
            severity="gate",
        ))
        return result, blockers
    try:
        document = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        blockers.append(_blocker(
            "live_readiness_unreadable", "readiness", f"{type(exc).__name__}: {exc}",
        ))
        return result, blockers
    source = configured.get("_source_tree_sha256")
    expected_target = str(configured.get("target_url") or "")
    issues: list[str] = []
    if document.get("artifact_type") != "autoresearch_live_readiness":
        issues.append("artifact_type")
    if document.get("epoch_id") != epoch_id:
        issues.append("epoch_id")
    if str(document.get("target_url") or "") != expected_target:
        issues.append("target_url")
    if document.get("source_hashes_sha256") != source:
        issues.append("source_tree_hash")
    try:
        generated_at = datetime.fromisoformat(str(document.get("generated_at")))
        if generated_at.tzinfo is None:
            raise ValueError("naive")
    except ValueError:
        issues.append("generated_at")
    profile_ids = {
        str(spec.get("configured_profile_id")) for spec in draft["design"]["models"]
    }
    checks = {
        str(check.get("id")): check
        for check in document.get("checks") or []
        if isinstance(check, Mapping)
    }
    required = {
        "containment.http",
        "live.dvwa.authentication",
        "live.dvwa.levels",
        "live.dvwa.surfaces",
        *{f"live.model.{profile_id}" for profile_id in profile_ids},
    }
    missing = sorted(required - set(checks))
    failed = sorted(
        check_id for check_id, check in checks.items()
        if check_id in required and check.get("status") != "passed"
    )
    result.update({
        "present": True,
        "checks": {
            check_id: {
                "status": checks[check_id].get("status"),
                "target": checks[check_id].get("target"),
                "detail": checks[check_id].get("detail"),
            }
            for check_id in sorted(required & set(checks))
        },
        "missing": missing,
        "failed": failed,
        "generated_at": document.get("generated_at"),
        "issues": sorted(set(issues)),
        "detail": (
            "Recorded live probes cover DVWA authentication/levels/surfaces, containment "
            "and both evaluated models for this source epoch."
            if not issues and not missing and not failed else
            "Recorded live readiness evidence is incomplete or stale."
        ),
    })
    if issues:
        blockers.append(_blocker(
            "live_readiness_identity_mismatch", "readiness",
            f"live readiness evidence does not match the current epoch: {sorted(set(issues))}",
            severity="gate",
        ))
    if missing:
        blockers.append(_blocker(
            "live_readiness_checks_missing", "readiness",
            f"live readiness is missing required checks: {missing}", severity="gate",
        ))
    if failed:
        blockers.append(_blocker(
            "live_readiness_checks_failed", "readiness",
            f"live readiness checks failed: {failed}", severity="gate",
        ))
    return result, blockers


def analyse_scope(draft: Mapping[str, Any], configured: Mapping[str, Any], *,
                  repo_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    scope = draft["scope"]
    design = draft["design"]
    result: dict[str, Any] = {
        "target_url": configured.get("target_url"),
        "fixture_id": configured.get("fixture_id"),
        "protocol_version": configured.get("protocol_version"),
        "candidate_budget": configured.get("candidate_budget"),
        "configured_payload_mode": configured.get("payload_mode"),
        "configured_repeats": configured.get("repeats"),
        "configured_levels": configured.get("levels"),
        "configured_surfaces": configured.get("surfaces"),
        "live_target_access_performed": False,
        "provider_access_performed": False,
    }
    if not configured.get("available"):
        blockers.append(_blocker("configured_scope_unavailable", "scope",
                                 "configured scope cannot be read offline"))
        return result, blockers
    comparisons = {
        "target_url": scope.get("target_url"),
        "fixture_id": scope.get("fixture_id"),
        "protocol_version": scope.get("protocol_version"),
        "candidate_budget": scope.get("candidate_budget"),
    }
    for field, expected in comparisons.items():
        if configured.get(field) != expected:
            blockers.append(_blocker(
                "scope_mismatch", "scope",
                f"configured {field}={configured.get(field)!r} does not match draft {expected!r}",
            ))
    if configured.get("payload_mode") != design["payload_mode"]:
        blockers.append(_blocker(
            "configured_payload_mode_not_hybrid", "scope",
            f"config.payload_mode is {configured.get('payload_mode')!r}; the primary matrix requires hybrid",
        ))
    if (configured.get("repeats") or 0) < design["repeats"]:
        blockers.append(_blocker(
            "configured_repeats_below_required", "scope",
            f"config.repeats is {configured.get('repeats')!r}; at least {design['repeats']} are required",
        ))
    if list(configured.get("levels") or []) != list(design["levels"]):
        blockers.append(_blocker("configured_levels_mismatch", "scope", "configured levels differ from the draft"))
    if list(configured.get("surfaces") or []) != list(design["surfaces"]):
        blockers.append(_blocker("configured_surfaces_mismatch", "scope", "configured surfaces differ from the draft"))
    restoration = configured.get("fixture_restoration") or {}
    expected_levels = set(design["levels"])
    provided_levels = set(restoration.get("levels") or [])
    missing_levels = sorted(expected_levels - provided_levels)
    if missing_levels:
        blockers.append(_blocker(
            "fixture_restoration_missing_levels", "readiness",
            f"fixture restoration evidence is missing levels: {missing_levels}",
        ))
    source_hash = configured.get("_source_tree_sha256")
    hashes = set(restoration.get("source_hashes_sha256") or [])
    if restoration.get("present") and source_hash and source_hash not in hashes:
        blockers.append(_blocker(
            "fixture_restoration_bound_to_other_source_tree", "readiness",
            "configured fixture-restoration evidence is bound to a different source tree; "
            "a new operator attestation is required for the current epoch",
        ))
    live, live_blockers = analyse_live_readiness(draft, configured, repo_root=repo_root)
    result["live_readiness"] = live
    result["live_target_access_performed"] = bool(live.get("present"))
    result["provider_access_performed"] = bool(live.get("present"))
    blockers.extend(live_blockers)
    return result, blockers


def _study_contract_issues(document: Mapping[str, Any], draft: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Compare the declared study contract with the draft without importing it."""
    issues: list[dict[str, Any]] = []
    design = draft["design"]
    epoch = draft["intended_epoch"]
    policy = draft["policy"]

    if document.get("research_config_version") != STUDY_CONTRACT_VERSION:
        issues.append(_issue(
            "study_contract_version_invalid",
            f"expected {STUDY_CONTRACT_VERSION}",
            "research_config_version",
        ))
    if document.get("epoch_id") != epoch.get("epoch_id"):
        issues.append(_issue(
            "study_contract_epoch_mismatch",
            f"expected {epoch.get('epoch_id')!r}",
            "epoch_id",
        ))
    blocks = document.get("blocks")
    block_names = list(blocks) if isinstance(blocks, Mapping) else []
    if not isinstance(blocks, Mapping) or block_names != ["selection"]:
        issues.append(_issue(
            "study_contract_blocks_not_selection_only",
            f"declared blocks are {block_names!r}; only ['selection'] is compatible",
            "blocks",
        ))
    else:
        selection = blocks.get("selection")
        if not isinstance(selection, Mapping) or selection.get("target_method") is not None:
            issues.append(_issue(
                "study_contract_selection_forces_method",
                "the selection block must declare target_method as null (model-selected)",
                "blocks.selection.target_method",
            ))
    if document.get("payload_mode") != design.get("payload_mode"):
        issues.append(_issue(
            "study_contract_payload_mode_mismatch",
            f"expected {design.get('payload_mode')!r}",
            "payload_mode",
        ))
    if document.get("repeats") != design.get("repeats"):
        issues.append(_issue(
            "study_contract_repeats_mismatch",
            f"expected {design.get('repeats')!r}",
            "repeats",
        ))
    if document.get("primary_conditions") != design.get("conditions"):
        issues.append(_issue(
            "study_contract_conditions_mismatch",
            f"expected {design.get('conditions')!r}",
            "primary_conditions",
        ))
    if document.get("levels") != design.get("levels"):
        issues.append(_issue(
            "study_contract_levels_mismatch",
            f"expected {design.get('levels')!r}",
            "levels",
        ))
    if document.get("surfaces") != design.get("surfaces"):
        issues.append(_issue(
            "study_contract_surfaces_mismatch",
            f"expected {design.get('surfaces')!r}",
            "surfaces",
        ))
    if document.get("output_root") != epoch.get("output_root"):
        issues.append(_issue(
            "study_contract_output_root_mismatch",
            f"expected {epoch.get('output_root')!r}",
            "output_root",
        ))
    study_design = document.get("design")
    expected_coordinates = (
        study_design.get("expected_coordinates") if isinstance(study_design, Mapping) else None
    )
    if expected_coordinates != design.get("expected_coordinates"):
        issues.append(_issue(
            "study_contract_coordinate_count_mismatch",
            f"expected {design.get('expected_coordinates')!r}",
            "design.expected_coordinates",
        ))
    for key in ("pairing", "multiple_comparisons"):
        if not isinstance(study_design, Mapping) or not study_design.get(key):
            issues.append(_issue(
                "study_contract_analysis_policy_missing",
                f"study design must declare {key}",
                f"design.{key}",
            ))

    expected_models = {
        spec["configured_profile_id"]: spec for spec in design.get("models", [])
    }
    profiles = document.get("model_profiles")
    if not isinstance(profiles, list) or len(profiles) != len(expected_models):
        issues.append(_issue(
            "study_contract_model_count_mismatch",
            f"expected {len(expected_models)} declared model profiles",
            "model_profiles",
        ))
    else:
        by_profile: dict[str, Mapping[str, Any]] = {}
        for profile in profiles:
            if not isinstance(profile, Mapping):
                issues.append(_issue("study_contract_model_invalid", "profile must be a mapping", "model_profiles"))
                continue
            profile_id = profile.get("profile_id")
            if not isinstance(profile_id, str) or profile_id not in expected_models:
                issues.append(_issue(
                    "study_contract_model_unknown",
                    f"profile {profile_id!r} is not in the draft design",
                    "model_profiles",
                ))
                continue
            if profile_id in by_profile:
                issues.append(_issue(
                    "study_contract_model_duplicate",
                    f"profile {profile_id!r} is declared more than once",
                    "model_profiles",
                ))
            by_profile[profile_id] = profile
        for profile_id, spec in expected_models.items():
            profile = by_profile.get(profile_id)
            if profile is None:
                issues.append(_issue(
                    "study_contract_model_missing",
                    f"draft profile {profile_id!r} is absent",
                    "model_profiles",
                ))
                continue
            if profile.get("model_name") != spec.get("model_name"):
                issues.append(_issue(
                    "study_contract_model_name_mismatch",
                    f"{profile_id}: expected {spec.get('model_name')!r}",
                    "model_profiles",
                ))
            if profile.get("provider") != spec.get("provider_protocol"):
                issues.append(_issue(
                    "study_contract_model_provider_mismatch",
                    f"{profile_id}: expected {spec.get('provider_protocol')!r}",
                    "model_profiles",
                ))
            if profile.get("reasoning_effort") != REQUIRED_REASONING:
                issues.append(_issue(
                    "study_contract_model_reasoning_not_max",
                    f"{profile_id}: expected {REQUIRED_REASONING!r}",
                    "model_profiles",
                ))

    scoring = document.get("scoring")
    if not isinstance(scoring, Mapping):
        issues.append(_issue("study_contract_scoring_missing", "scoring must be a mapping", "scoring"))
    else:
        if scoring.get("rubric_version") != policy.get("rubric_version"):
            issues.append(_issue(
                "study_contract_rubric_mismatch",
                f"expected {policy.get('rubric_version')!r}",
                "scoring.rubric_version",
            ))
        if scoring.get("runtime_provisional") != STUDY_SCORING_RUNTIME_PROVISIONAL:
            issues.append(_issue(
                "study_contract_runtime_provisional_mismatch",
                f"expected {STUDY_SCORING_RUNTIME_PROVISIONAL!r}",
                "scoring.runtime_provisional",
            ))
        if scoring.get("final_source") != STUDY_SCORING_FINAL_SOURCE:
            issues.append(_issue(
                "study_contract_final_source_mismatch",
                f"expected {STUDY_SCORING_FINAL_SOURCE!r}",
                "scoring.final_source",
            ))
    declared_inputs = document.get("frozen_inputs_required")
    declared_set = set(declared_inputs) if isinstance(declared_inputs, list) else set()
    if declared_set != set(STUDY_FROZEN_INPUTS):
        issues.append(_issue(
            "study_contract_frozen_inputs_mismatch",
            f"expected {sorted(STUDY_FROZEN_INPUTS)}",
            "frozen_inputs_required",
        ))
    for path, key, child in _walk_claims(document):
        if key in FALSE_CLAIM_KEYS and child is True:
            issues.append(_issue(
                "study_contract_false_freeze_or_approval_claim",
                f"{path} must not be true",
                path,
            ))
    return issues


def analyse_study_contract(
    *,
    repo_root: str | Path,
    draft: Mapping[str, Any],
    study_path: str | Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read the declared study contract as data; never import or execute it."""
    root = Path(repo_root).resolve()
    relative = STUDY_CONTRACT_PATH if study_path is None else str(study_path)
    path = Path(relative)
    if not path.is_absolute():
        path = root / path
    result: dict[str, Any] = {
        "path": str(path),
        "declared_path": relative,
        "present": path.is_file(),
        "sha256": None,
        "contract_version": None,
        "status": "missing",
        "compatible": False,
        "issues": [],
        "declared": None,
        "scoring": None,
        "fixture_restoration": None,
        "note": (
            "Read as a data contract only. No planner module is imported, no approval "
            "or freeze is inferred, and compatibility is not matrix-launch readiness."
        ),
    }
    if not result["present"]:
        return result, [_blocker(
            "study_contract_missing", "planning",
            f"declared study contract is absent: {relative}; selection-only plan build cannot be checked",
        )]
    result["sha256"] = _file_hash(path)
    try:
        document = json.loads(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        result["status"] = "unreadable"
        result["issues"] = [_issue("study_contract_unreadable", str(exc))]
        return result, [_blocker(
            "study_contract_unreadable", "planning",
            f"declared study contract could not be read as JSON: {type(exc).__name__}: {exc}",
        )]
    if not isinstance(document, dict):
        result["status"] = "invalid"
        result["issues"] = [_issue("study_contract_not_object", "contract must be a JSON object")]
        return result, [_blocker(
            "study_contract_invalid", "planning",
            "declared study contract must be a JSON object",
        )]
    issues = _study_contract_issues(document, draft)
    blocks = document.get("blocks")
    scoring = document.get("scoring")
    profiles = document.get("model_profiles")
    result.update({
        "contract_version": document.get("research_config_version"),
        "status": "compatible" if not issues else "incompatible",
        "compatible": not issues,
        "issues": issues,
        "declared": {
            "epoch_id": document.get("epoch_id"),
            "blocks": list(blocks) if isinstance(blocks, Mapping) else None,
            "payload_mode": document.get("payload_mode"),
            "repeats": document.get("repeats"),
            "levels": document.get("levels"),
            "surfaces": document.get("surfaces"),
            "output_root": document.get("output_root"),
            "expected_coordinates": (
                document.get("design", {}).get("expected_coordinates")
                if isinstance(document.get("design"), Mapping) else None
            ),
            "model_profiles": [
                {
                    "profile_id": profile.get("profile_id"),
                    "provider": profile.get("provider"),
                    "model_name": profile.get("model_name"),
                    "reasoning_effort": profile.get("reasoning_effort"),
                }
                for profile in profiles if isinstance(profile, Mapping)
            ] if isinstance(profiles, list) else None,
        },
        "scoring": {
            "rubric_version": scoring.get("rubric_version") if isinstance(scoring, Mapping) else None,
            "runtime_provisional": (
                scoring.get("runtime_provisional") if isinstance(scoring, Mapping) else None
            ),
            "final_source": scoring.get("final_source") if isinstance(scoring, Mapping) else None,
            "final_scoring_available": False,
            "detail": (
                "scoring.v4 remains the final rubric; scoring.v2 is runtime-provisional; "
                "only thesis_score_receipt can supply final v4 components. No frozen "
                "scoring profile or policy epoch exists in the configured inputs."
            ),
        },
        "fixture_restoration": {
            "declared": document.get("fixture_restoration"),
            "status": (
                "missing_external_input"
                if document.get("fixture_restoration") is None
                else "declared_but_unverified"
            ),
        },
    })
    if issues:
        return result, [_blocker(
            "study_contract_incompatible", "planning",
            "declared study contract is not compatible with the readiness draft: "
            f"{sorted({issue['code'] for issue in issues})}",
            evidence={"path": relative, "issues": issues},
        )]
    return result, []


def analyse_planner_status(
    *, repo_root: str | Path, study: Mapping[str, Any],
) -> dict[str, Any]:
    """Report planner build/verify and execution support from source text.

    The planner module is not imported: importing a changing executable planner
    during offline readiness would run its module-level work and couple this
    report to implementation timing.  Refusal is read from the explicit marker;
    absence of that marker never becomes a launch claim.
    """
    root = Path(repo_root).resolve()
    path = root / PLANNER_PATH
    result: dict[str, Any] = {
        "path": PLANNER_PATH,
        "sha256": None,
        "build_verify": "unverified",
        "execution": "unverified_not_authorized",
        "execution_rejection_stage": None,
        "study_contract_supported": False,
        "matrix_launch_ready": False,
        "owner_execution_hold": True,
        "detail": (
            "The matrix launch is on owner hold. This validator never authorizes or "
            "performs a run."
        ),
    }
    if not path.is_file():
        result["detail"] = f"{PLANNER_PATH} is absent; build/verify support cannot be read."
        return result
    text = path.read_text(encoding="utf-8")
    result["sha256"] = _file_hash(path)
    supports_build_verify = "--research-config" in text and "load_research_config" in text
    supports_selection_execution = (
        "_write_epoch_manifest" in text and "chapter3_coordinate_reconciliation" in text
    )
    refuses_selection_execution = PLANNER_SELECTION_EXECUTION_REFUSAL in text
    result["build_verify"] = (
        "supported_for_selection_only" if supports_build_verify else "unverified"
    )
    result["execution"] = (
        "blocked_by_planner" if refuses_selection_execution else
        "supported_for_selection_only" if supports_selection_execution else
        "unverified_not_authorized"
    )
    if refuses_selection_execution:
        result["execution_rejection_stage"] = "before_block_calls_or_output_creation"
    result["study_contract_supported"] = bool(supports_build_verify and study.get("compatible"))
    if supports_build_verify and supports_selection_execution and not refuses_selection_execution:
        result["matrix_launch_ready"] = bool(study.get("compatible"))
        result["owner_execution_hold"] = False
        result["detail"] = (
            "The planner builds/verifies the selection-only plan, executes exactly the "
            "declared blocks, reconciles observed runs to planned coordinates, and writes "
            "the epoch experiment.manifest.json. Launch readiness still depends on the "
            "remaining readiness blockers."
        )
    elif supports_build_verify and refuses_selection_execution:
        result["detail"] = (
            "The current planner accepts --research-config and can build/verify a "
            "selection-only plan, but run_research_plan rejects selection-only execution "
            "before any block call or output directory. Execution remains blocked."
        )
    elif supports_build_verify:
        result["detail"] = (
            "The planner accepts --research-config, but selection-only execution support or "
            "its refusal marker was not found. Execution remains unverified."
        )
    else:
        result["detail"] = (
            "The planner's --research-config selection-only support was not found; "
            "execution remains unverified."
        )
    return result


def _git(repo_root: Path, *args: str) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if completed.returncode != 0:
        return False, (completed.stderr or completed.stdout).strip()
    return True, completed.stdout.strip()


def git_identity(repo_root: str | Path) -> dict[str, Any]:
    """Read the named commit and source dirtiness without modifying git state."""
    root = Path(repo_root).resolve()
    ok, head = _git(root, "rev-parse", "HEAD")
    ok_status, status = _git(root, "status", "--porcelain", "--", *GIT_SOURCE_SCOPE)
    changed = [line[3:] for line in status.splitlines() if line.strip()] if ok_status else []
    return {
        "commit": head if ok and GIT_COMMIT.fullmatch(head) else None,
        "commit_available": bool(ok and GIT_COMMIT.fullmatch(head)),
        "source_tree_dirty": bool(ok_status and changed),
        "source_tree_status_available": ok_status,
        "changed_source_count": len(changed),
        "changed_source_sample": changed[:10],
        "status_error": None if ok_status else status,
    }


def source_snapshot(repo_root: str | Path, config_path: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    from evaluation.research_plan import source_identity

    identity = source_identity(config_path=config_path)
    git = git_identity(repo_root)
    tree_sha = identity["source_hashes_sha256"]
    result = {
        "repository_root": identity["repository_root"],
        "git_commit": git["commit"],
        "git_commit_available": git["commit_available"],
        "worktree_dirty": git["source_tree_dirty"],
        "changed_source_count": git["changed_source_count"],
        "changed_source_sample": git["changed_source_sample"],
        "tree_sha256": tree_sha,
        "config_path": identity["config_path"],
        "config_sha256": identity["config_sha256"],
        "source_file_count": len(identity["source_hashes"]),
        "commit_is_tree_hash": False,
        "tree_binding": (
            "unverified_status_unavailable" if not git["source_tree_status_available"]
            else "unbound_dirty_worktree" if git["source_tree_dirty"]
            else "commit_matches_worktree_at_check_time"
        ),
        "approval_recorded": False,
    }
    if not git["commit_available"]:
        blockers.append(_blocker(
            "source_commit_unavailable", "identity",
            f"a named git commit could not be read: {git.get('status_error') or 'git unavailable'}",
        ))
    if not git["source_tree_status_available"]:
        blockers.append(_blocker(
            "source_tree_status_unavailable", "identity",
            f"worktree cleanliness could not be read: {git.get('status_error') or 'git status unavailable'}",
        ))
    if git["source_tree_dirty"]:
        blockers.append(_blocker(
            "source_tree_not_commit_bound", "identity",
            f"{git['changed_source_count']} source/config files differ from HEAD; "
            "the tree hash is a content digest, not a commit, until the epoch source is committed "
            "or an approved amendment is recorded",
            evidence={"changed_source_sample": git["changed_source_sample"]},
        ))
    return result, blockers


def analyse_output_root(repo_root: str | Path, draft: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    epoch = draft["intended_epoch"]
    output_root = epoch["output_root"]
    parts = PurePosixPath(output_root).parts
    result = {
        "output_root": output_root,
        "exists": False,
        "non_empty": False,
        "created_by_validator": False,
        "writes_beneath_results_runs": False,
    }
    if len(parts) != 3 or parts[0] != "results" or parts[1] != "runs" or \
            parts[2] != epoch["epoch_id"] or not SAFE_SEGMENT.fullmatch(parts[2]):
        blockers.append(_blocker(
            "output_root_invalid", "output",
            f"intended output root must be results/runs/<safe epoch_id>; got {output_root!r}",
        ))
        return result, blockers
    target = Path(repo_root).resolve() / Path(*parts)
    result["exists"] = target.exists()
    if target.exists():
        try:
            entries = sorted(entry.name for entry in target.iterdir())
        except OSError as exc:
            entries = []
            result["error"] = str(exc)
        pre_execution = {"research-plan.json", "payload-policy-snapshot.json"}
        unexpected = [name for name in entries if name not in pre_execution]
        result["entries"] = entries
        result["pre_execution_only"] = bool(entries) and not unexpected
        result["non_empty"] = bool(unexpected)
    if result["non_empty"]:
        blockers.append(_blocker(
            "output_root_not_empty", "output",
            f"intended run root already has execution evidence at {output_root}; "
            "a new epoch must be allocated",
        ))
    return result, blockers


def _normalized(text: str) -> str:
    return " ".join(text.split())


def discovery_source_checks(files: Mapping[str, str]) -> list[dict[str, Any]]:
    """Check the read-only tesis-web contract against the source text."""
    normalized = {name: _normalized(text) for name, text in files.items()}
    checks: list[dict[str, Any]] = []
    for identifier, description, file_key, snippets in DISCOVERY_CHECKS:
        text = normalized.get(file_key, "")
        missing = [snippet for snippet in snippets if _normalized(snippet) not in text]
        checks.append({
            "id": identifier,
            "description": description,
            "source": DISCOVERY_FILES[file_key],
            "passed": bool(text) and not missing,
            "missing_snippets": missing,
        })
    return checks


def summary_traceability(coordinates: Any) -> dict[str, Any]:
    """Report summary-axis defects without rewriting declared null values.

    ``target_method: null`` is the valid model-selected coordinate value in the
    selection block; the field must be explicitly present in the row.  A missing
    key, a null in any other summary field, or a null target_method outside the
    selection block remains a traceability defect.  Values are never converted
    to strings or filled in.
    """
    rows = list(coordinates) if isinstance(coordinates, (list, tuple)) else []
    missing: set[str] = set()
    model_selected_nulls = 0
    for row in rows:
        if not isinstance(row, Mapping):
            missing.update(SUMMARY_FIELDS)
            continue
        for field in SUMMARY_FIELDS:
            if field not in row:
                missing.add(field)
                continue
            if row.get(field) is not None:
                continue
            if field in MODEL_SELECTED_NULL_SUMMARY_FIELDS and row.get("block") == "selection":
                model_selected_nulls += 1
            else:
                missing.add(field)
    return {
        "required": list(SUMMARY_FIELDS),
        "model_selected_null_allowed": sorted(MODEL_SELECTED_NULL_SUMMARY_FIELDS),
        "present_null_model_selected": model_selected_nulls,
        "missing": sorted(missing),
        "passed": not missing,
    }


def check_discovery(
    *,
    repo_root: str | Path,
    web_root: str | Path | None,
    draft: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate planned traceability against tesis-web discovery, read-only."""
    blockers: list[dict[str, Any]] = []
    root = Path(web_root).resolve() if web_root else None
    result: dict[str, Any] = {
        "web_root": str(root) if root else None,
        "status": "unverified",
        "source_hashes": {},
        "checks": [],
        "planned_summary_fields": {},
        "manifest_emission": None,
    }
    if root is None or not root.is_dir():
        blockers.append(_blocker(
            "web_discovery_contract_unverified", "discovery",
            "tesis-web checkout was not found; discovery compatibility cannot be checked",
        ))
        return result, blockers
    files: dict[str, str] = {}
    for key, relative in DISCOVERY_FILES.items():
        path = root / relative
        if not path.is_file():
            result["source_hashes"][relative] = None
            continue
        result["source_hashes"][relative] = _file_hash(path)
        files[key] = path.read_text(encoding="utf-8")
    checks = discovery_source_checks(files)
    result["checks"] = checks
    failed = [check["id"] for check in checks if not check["passed"]]
    if failed:
        blockers.append(_blocker(
            "web_discovery_contract_changed", "discovery",
            f"tesis-web discovery source no longer matches the expected contract: {failed}",
        ))
    coordinates = draft.get("coordinates") or []
    summary = summary_traceability(coordinates)
    summary["coordinate_count"] = len(coordinates) if isinstance(coordinates, (list, tuple)) else 0
    summary["expected_count"] = EXPECTED_TOTAL
    summary["passed"] = summary["passed"] and summary["coordinate_count"] == EXPECTED_TOTAL
    result["planned_summary_fields"] = summary
    missing_fields = summary["missing"]
    if missing_fields:
        blockers.append(_blocker(
            "web_traceability_fields_missing", "discovery",
            f"planned coordinates lack tesis-web summary fields: {missing_fields}",
        ))
    research_plan = Path(repo_root).resolve() / "evaluation" / "research_plan.py"
    planner_text = research_plan.read_text(encoding="utf-8") if research_plan.is_file() else ""
    emitted = "ExperimentArtifactLayout" in planner_text or "write_manifest" in planner_text
    result["manifest_emission"] = {
        "expected_file": "experiment.manifest.json",
        "implemented_in_research_plan": emitted,
        "aggregate_membership_fallback_supported": any(
            check["id"] == "embedded_children" and check["passed"] for check in checks
        ),
    }
    if not emitted:
        blockers.append(_blocker(
            "epoch_manifest_not_emitted", "discovery",
            "the current research-plan path does not write experiment.manifest.json; tesis-web can "
            "fall back to aggregate/embedded membership, but explicit one-based coordinate indexes "
            "and manifest metadata are not proven for the new epoch",
            severity="gate",
        ))
    result["status"] = "contract_satisfied" if not failed and not missing_fields and emitted else \
        ("contract_satisfied_with_manifest_gap" if not failed and not missing_fields else "contract_mismatch")
    return result, blockers


def _authorization_gate(draft: Mapping[str, Any]) -> dict[str, Any]:
    approval_value = draft.get("approval")
    approval: Mapping[str, Any] = approval_value if isinstance(approval_value, Mapping) else {}
    policy_value = draft.get("policy")
    policy: Mapping[str, Any] = policy_value if isinstance(policy_value, Mapping) else {}
    profile_value = policy.get("scoring_profile")
    profile: Mapping[str, Any] = profile_value if isinstance(profile_value, Mapping) else {}
    epoch_value = policy.get("scoring_policy_epoch")
    epoch: Mapping[str, Any] = epoch_value if isinstance(epoch_value, Mapping) else {}
    approved = draft.get("status") == APPROVED_DRAFT_STATUS and approval.get("recorded") is True
    frozen = (
        str(profile.get("status")) == "present_frozen_before_selection"
        and bool(epoch.get("epoch_id"))
        and bool(profile.get("sha256"))
    )
    return {
        "draft_status": draft.get("status"),
        "owner_approval_recorded": approved,
        "matrix_frozen": frozen,
        "matrix_launch_ready": bool(approved and frozen),
        "e2e_authorized": bool(approved),
        "execution_authorized": bool(approved and frozen),
        "detail": (
            "Owner approval and the frozen profile/policy epoch are recorded. Execution "
            "authorization remains bounded by the readiness blockers and containment rules."
            if approved and frozen else
            "Owner approval and/or the frozen profile/policy epoch are not recorded; no "
            "matrix launch, provider call or target traffic is authorized by this artifact."
        ),
    }


def _oracle_preregistration(draft: Mapping[str, Any], *, root: Path) -> dict[str, Any]:
    """Read the pinned preregistration artifact without treating proof as present."""
    policy_value = draft.get("policy")
    policy: Mapping[str, Any] = policy_value if isinstance(policy_value, Mapping) else {}
    declared_value = policy.get("oracle_preregistration")
    declared: Mapping[str, Any] = declared_value if isinstance(declared_value, Mapping) else {}
    path = root / ORACLE_PREREGISTRATION_DRAFT_PATH
    result: dict[str, Any] = {
        "status": "missing_not_registered",
        "draft_declared_status": declared.get("status"),
        "registered": False,
        "evidence_imported": False,
        "draft_path": ORACLE_PREREGISTRATION_DRAFT_PATH,
        "documentation_path": ORACLE_PREREGISTRATION_DOC_PATH,
        "commitment": None,
        "proof": None,
        "detail": (
            "The preregistration artifact is missing or invalid. Configured scoring oracle "
            "sources are configuration, not preregistered independent evidence."
        ),
    }
    if not path.is_file():
        return result
    try:
        from evaluation import oracle_preregistration

        report = oracle_preregistration.assess_draft(
            oracle_preregistration.load_draft(path), root=root,
        )
    except (OSError, ValueError) as exc:
        result.update({"status": "invalid", "detail": f"{type(exc).__name__}: {exc}"})
        return result
    commitment = report["readiness"]["commitment"]
    result.update({
        "status": (
            "preregistered" if commitment["preregistered"] else "not_preregistered"
        ),
        "registered": bool(commitment["preregistered"]),
        "evidence_imported": True,
        "draft_sha256": report.get("source_record", {}).get("file_sha256"),
        "commitment": commitment,
        "proof": report["readiness"]["proof"],
        "coverage": report.get("coverage"),
        "approval": report.get("preregistration"),
        "detail": (
            "The commitment and owner approval are recorded prospectively. Per-run "
            "attestations remain separate proof and are graded only from recorded controls."
        ),
    })
    return result


def build_readiness_report(
    *,
    draft_path: str | Path,
    config_path: str | Path,
    repo_root: str | Path,
    web_root: str | Path | None = None,
    study_path: str | Path | None = None,
) -> dict[str, Any]:
    """Build the complete offline report; never executes or freezes anything."""
    draft = load_draft(draft_path)
    issues = validate_design(draft)
    coordinate_issues, coordinate_stats = validate_coordinates(draft)
    configured = load_configured(config_path)
    source, source_blockers = source_snapshot(repo_root, config_path)
    configured["_source_tree_sha256"] = source["tree_sha256"]
    models, model_blockers, warnings = analyse_models(draft, configured)
    policy, policy_blockers = analyse_policy(draft, configured)
    cost, cost_blockers, cost_warnings = analyse_cost(draft, configured)
    warnings.extend(cost_warnings)
    scope, scope_blockers = analyse_scope(
        draft, configured, repo_root=Path(repo_root).resolve()
    )
    study, study_blockers = analyse_study_contract(
        repo_root=repo_root, draft=draft, study_path=study_path,
    )
    planner = analyse_planner_status(repo_root=repo_root, study=study)
    output, output_blockers = analyse_output_root(repo_root, draft)
    discovery, discovery_blockers = check_discovery(
        repo_root=repo_root, web_root=web_root, draft=draft,
    )
    blockers = []
    for issue in [*issues, *coordinate_issues]:
        blockers.append(_blocker(
            f"draft_{issue['code']}", "draft", issue["detail"], evidence={"path": issue.get("path")},
        ))
    blockers.extend(model_blockers)
    blockers.extend(policy_blockers)
    blockers.extend(cost_blockers)
    blockers.extend(scope_blockers)
    blockers.extend(study_blockers)
    blockers.extend(source_blockers)
    blockers.extend(output_blockers)
    blockers.extend(discovery_blockers)
    authorization = _authorization_gate(draft)
    launch_ready = bool(
        not blockers
        and planner["matrix_launch_ready"]
        and authorization["execution_authorized"]
    )
    report = {
        "artifact_type": "autoresearch_readiness_report",
        "report_version": REPORT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": (
            "ready_for_execution" if launch_ready else
            "ready_for_owner_approval_review" if not blockers else "blocked"
        ),
        "execution_authorized": launch_ready,
        "evidence_class": "offline_plan_validation_not_experiment_result",
        "draft": {
            "path": str(Path(draft_path).resolve()),
            "sha256": _file_hash(Path(draft_path)),
            "draft_version": draft.get("draft_version"),
            "status": draft.get("status"),
        },
        "epoch": draft.get("intended_epoch"),
        "design": {
            "models": draft["design"]["models"],
            "surfaces": draft["design"]["surfaces"],
            "levels": draft["design"]["levels"],
            "conditions": draft["design"]["conditions"],
            "payload_mode": draft["design"]["payload_mode"],
            "repeats": draft["design"]["repeats"],
            "target_method": draft["design"]["target_method"],
            "blocks": draft["design"]["blocks"],
            "expected_coordinates": draft["design"]["expected_coordinates"],
        },
        "coordinates": coordinate_stats,
        "models": models,
        "policy": policy,
        "scoring": study.get("scoring"),
        "cost": cost,
        "scope": scope,
        "study_contract": study,
        "planner": planner,
        "oracle_preregistration": _oracle_preregistration(
            draft, root=Path(repo_root).resolve()
        ),
        "source_identity": source,
        "output_intent": output,
        "discovery": discovery,
        "blockers": blockers,
        "warnings": warnings,
        "authorization": authorization,
        "launch_gate": {
            "matrix_launch_ready": launch_ready,
            "owner_execution_hold": not authorization["owner_approval_recorded"],
            "planner_build_verify": planner["build_verify"],
            "planner_execution": planner["execution"],
            "detail": (
                "The frozen plan, approval and recorded artifacts satisfy the readiness "
                "checks; execution remains bound by containment and the declared coordinates."
                if launch_ready else
                "Execution is not ready: resolve the recorded blockers and authorization "
                "state. Compatibility alone is not launch readiness."
            ),
        },
        "notes": [
            "Synthetic/offline checks demonstrate mechanics only; they are not experiment results.",
            "The declared study is executed by run_research_plan only after the frozen plan, "
            "epoch config, ranking profile, policy and price schedule verify.",
            "Oracle preregistration separates the prospective commitment/approval from "
            "per-run collected control proof.",
            "API-equivalent cost estimates are never reported as verified billed charges.",
        ],
    }
    return report


def planned_manifest(draft: Mapping[str, Any], report: Mapping[str, Any]) -> dict[str, Any]:
    """Return the planned-coordinate manifest for evidence storage (not a run)."""
    return {
        "artifact_type": "autoresearch_planned_matrix_manifest",
        "schema_version": PLANNED_MANIFEST_VERSION,
        "epoch_id": draft["intended_epoch"]["epoch_id"],
        "status": "planned_not_executed",
        "output_root_intent": draft["intended_epoch"]["output_root"],
        "coordinate_count": len(draft.get("coordinates") or []),
        "coordinates": draft.get("coordinates") or [],
        "traceability": draft.get("traceability"),
        "readiness_report_sha256": _canonical_hash(report),
        "notes": [
            "Planned coordinates only; no execution identity exists yet.",
            "This file is stored under results/validation, never results/runs.",
            "Synthetic/offline planning evidence is not an experiment result.",
        ],
    }


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _resolve_evidence_dir(repo_root: Path, output_dir: str | Path) -> Path:
    candidate = Path(output_dir)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    resolved = candidate.resolve()
    runs = (repo_root / OUTPUT_PARENT).resolve()
    if resolved == runs or runs in resolved.parents:
        raise ValueError("readiness evidence must not be written beneath results/runs")
    return resolved


def write_evidence(
    *,
    report: Mapping[str, Any],
    manifest: Mapping[str, Any],
    output_dir: str | Path,
    repo_root: str | Path,
) -> dict[str, str]:
    """Write readiness evidence outside results/runs, atomically."""
    root = _resolve_evidence_dir(Path(repo_root).resolve(), output_dir)
    report_path = root / "readiness-report.json"
    manifest_path = root / "planned-coordinate-manifest.json"
    _atomic_json(report_path, report)
    _atomic_json(manifest_path, manifest)
    return {"readiness_report": str(report_path), "planned_manifest": str(manifest_path)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline-only readiness validator for the draft 108-coordinate matrix; "
                    "never executes a run.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="validate the draft matrix and optionally write evidence")
    check.add_argument("--draft", default="config/research/autoresearch-primary-draft-2026-10-31.json")
    check.add_argument("--config", default="config.yaml")
    check.add_argument("--study", default=STUDY_CONTRACT_PATH)
    check.add_argument("--repo-root", default=".")
    check.add_argument("--web-root", default=None)
    check.add_argument("--output-dir", default=None)
    check.add_argument("--fail-on-blockers", action="store_true")
    args = parser.parse_args(argv)
    try:
        repo_root = Path(args.repo_root).resolve()
        draft_path = Path(args.draft)
        if not draft_path.is_absolute():
            draft_path = repo_root / draft_path
        config_path = Path(args.config)
        if not config_path.is_absolute():
            config_path = repo_root / config_path
        web_root = args.web_root
        if web_root is None:
            web_root = os.environ.get("TESIS_WEB_ROOT") or str(repo_root.parent / "tesis-web")
        report = build_readiness_report(
            draft_path=draft_path,
            config_path=config_path,
            repo_root=repo_root,
            web_root=web_root,
            study_path=args.study,
        )
        draft = load_draft(draft_path)
        manifest = planned_manifest(draft, report)
        paths = None
        if args.output_dir:
            paths = write_evidence(
                report=report, manifest=manifest,
                output_dir=args.output_dir, repo_root=repo_root,
            )
        summary = {
            "status": report["status"],
            "execution_authorized": report["execution_authorized"],
            "matrix_launch_ready": report["launch_gate"]["matrix_launch_ready"],
            "study_contract": report["study_contract"]["status"],
            "planner_build_verify": report["planner"]["build_verify"],
            "planner_execution": report["planner"]["execution"],
            "oracle_preregistration": report["oracle_preregistration"]["status"],
            "coordinates": report["coordinates"]["declared_count"],
            "blockers": len(report["blockers"]),
            "blocker_ids": sorted({item["id"] for item in report["blockers"]}),
            "paths": paths,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
        if args.fail_on_blockers and report["blockers"]:
            return 3
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        parser.exit(1, f"Readiness check failed: {type(exc).__name__}: {exc}\n")


__all__ = [
    "DRAFT_VERSION",
    "EXPECTED_TOTAL",
    "ORACLE_PREREGISTRATION_DOC_PATH",
    "ORACLE_PREREGISTRATION_DRAFT_PATH",
    "PLANNED_MANIFEST_VERSION",
    "REPORT_VERSION",
    "STUDY_CONTRACT_PATH",
    "STUDY_CONTRACT_VERSION",
    "analyse_cost",
    "analyse_models",
    "analyse_output_root",
    "analyse_planner_status",
    "analyse_study_contract",
    "build_readiness_report",
    "check_discovery",
    "discovery_source_checks",
    "expand_coordinates",
    "git_identity",
    "load_configured",
    "load_draft",
    "planned_manifest",
    "source_snapshot",
    "summary_traceability",
    "validate_coordinates",
    "validate_design",
    "write_evidence",
]


if __name__ == "__main__":
    raise SystemExit(main())
