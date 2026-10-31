"""Declared Chapter 3 research plan: declared blocks, frozen inputs, no pooling.

The frozen ``evaluation/scoring_v4_matrix.py`` remains untouched. This module
declares the *new* primary study described by the Chapter 3 handoff:

* ``selection``: ``target_method=None`` so the model chooses a method;
* ``forced``: every registered method is forced for payload/agent coverage.

A study may declare the ``selection`` block alone (the owner-requested primary
matrix) or both blocks; a forced-only or empty declaration is rejected. Both
blocks keep the two primary hybrid conditions and at least three repeats. A plan
freezes config/profile/oracle/policy/source identities before execution and
refuses to run when they drift. Runtime aggregates remain provisional; final
summaries come from review receipts in ``evaluation.research_analysis``.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from core.payload_policy import (
    BUDGET_POLICY_VERSION,
    CONTROL_POLICY_VERSION,
    EXPERIMENT_POLICY_VERSION,
    PAYLOAD_POLICY_VERSION,
    REASON_ATTESTATION_MISSING,
)
from core.state import METHODS_BY_SURFACE, SECURITY_LEVELS, SURFACES
from evaluation.scoring_evidence import evidence_hash, validate_evidence_config, validate_profile
from foundation.payload_snapshot import payload_policy_snapshot, verify_payload_policy_snapshot
from tesis.config_loader import (
    dump_yaml_config,
    load_and_resolve_config,
    load_yaml_config,
    validate_provider,
)

RESEARCH_PLAN_VERSION = "chapter3-research-plan.v2"
RESEARCH_CONFIG_VERSION = "chapter3-research-config.v1"
MIN_REPEATS = 3
PRIMARY_CONDITIONS: tuple[str, ...] = ("linear_hybrid", "akg_guided_hybrid")
PRIMARY_PAYLOAD_MODE = "hybrid"
BLOCKS: tuple[str, ...] = ("selection", "forced")
SELECTION_TARGET = None
FORCED_TARGET = "per_method"
PRIMARY_REASONING_EFFORT = "max"
OUTPUT_ROOT_PARENT = ("results", "runs")
SOURCE_ROOTS = ("agents", "core", "evaluation", "foundation", "llm", "tesis")
TOP_LEVEL_SOURCES = ("config.yaml", "pyproject.toml", "uv.lock")
SOURCE_SUFFIXES = {".py", ".yaml", ".yml", ".json"}
RESEARCH_CONFIG_KEYS = frozenset({
    "research_config_version", "epoch_id", "primary_conditions", "payload_mode",
    "blocks", "repeats", "levels", "surfaces", "design", "scoring",
    "frozen_inputs_required", "fixture_restoration", "model_profiles", "output_root",
})
OPTIONAL_RESEARCH_CONFIG_KEYS = frozenset({
    "fixture_restoration", "model_profiles", "output_root",
})
MODEL_PROFILE_KEYS = frozenset({"profile_id", "provider", "model_name", "reasoning_effort"})
BLOCK_SPEC_KEYS = frozenset({"target_method", "unit"})
REQUIRED_FROZEN_INPUTS = (
    "scoring_profile", "scoring_oracles", "scoring_policy_epoch",
    "token_price_schedule", "fixture_id", "protocol_version", "candidate_budget",
)
PRICE_SCHEDULE_REQUIRED = "token_price_schedule_required"
FREEZE_PREGEN_ALLOWED = frozenset({
    "census-before.json",
    "census-after.json",
    "no-mutation-check.json",
    "fixture-restoration-evidence.json",
    "fixture-restoration-low.json",
    "fixture-restoration-medium.json",
    "fixture-restoration-high.json",
    "live-readiness.json",
    "config.frozen.yaml",
    "freeze-receipt.json",
    "payload-policy-snapshot.json",
    "policy-epoch.json",
    "ranking-profile.frozen.json",
})


def require_frozen_token_price_schedule(config: Any) -> dict[str, Any]:
    """Reject an absent, empty, or malformed frozen price schedule.

    The schedule is an operator input: planning never invents prices, and an
    epoch that cannot price its own calls cannot freeze a cost-bearing research
    plan.  The global config loader still accepts ``{}`` for offline readers and
    shipped defaults; only these new-epoch boundaries are strict.
    """
    schedule = getattr(config, "token_price_schedule", None)
    if not schedule:
        raise ValueError(
            f"{PRICE_SCHEDULE_REQUIRED}: the frozen epoch requires a non-empty "
            "operator-supplied token_price_schedule; prices are never guessed"
        )
    try:
        from evaluation.research_metrics import validate_token_price_schedule

        return dict(validate_token_price_schedule(dict(schedule)))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{PRICE_SCHEDULE_REQUIRED}: token_price_schedule invalid: {exc}"
        ) from exc


def _ordered_block_names(declared: Mapping[str, Any], *, source: str) -> tuple[str, ...]:
    """Return declared blocks in the canonical deterministic execution order.

    A study may declare the model-selected ``selection`` block alone, or both
    blocks.  A forced-only or empty declaration is never a valid study: forcing
    every method without the model-selected comparison changes the estimand and
    bypasses the selection/forced pairing.
    """
    if not isinstance(declared, Mapping) or not declared:
        raise ValueError(f"{source} must declare at least one execution block")
    unknown = sorted(set(declared) - set(BLOCKS))
    if unknown:
        raise ValueError(f"{source} declares unknown execution blocks: {unknown}")
    if "selection" not in declared:
        raise ValueError(
            f"{source} must declare the selection block; forced-only plans are not supported"
        )
    return tuple(block for block in BLOCKS if block in declared)


def _validate_declared_blocks(declared: Any, *, source: str) -> tuple[str, ...]:
    """Validate the study declaration's block mapping and target semantics."""
    names = _ordered_block_names(declared, source=source)
    for block in names:
        spec = declared[block]
        if not isinstance(spec, Mapping):
            raise ValueError(f"{source} block {block!r} must be a mapping")
        unknown = sorted(set(spec) - BLOCK_SPEC_KEYS)
        if unknown:
            raise ValueError(f"{source} block {block!r} has unknown fields: {unknown}")
        if "target_method" not in spec:
            raise ValueError(f"{source} block {block!r} must declare target_method")
        expected = SELECTION_TARGET if block == "selection" else FORCED_TARGET
        if spec["target_method"] != expected:
            raise ValueError(
                f"{source} block {block!r} must declare target_method={expected!r}"
            )
    return names


def _validate_model_profiles(document: Mapping[str, Any]) -> list[dict[str, Any]] | None:
    """Validate the optional exact model-profile selection of a study."""
    profiles = document.get("model_profiles")
    if profiles is None:
        return None
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("research config model_profiles must be a non-empty list")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, profile in enumerate(profiles):
        if not isinstance(profile, Mapping):
            raise ValueError(f"research config model_profiles[{index}] must be a mapping")
        unknown = sorted(set(profile) - MODEL_PROFILE_KEYS)
        if unknown:
            raise ValueError(
                f"research config model_profiles[{index}] has unknown fields: {unknown}"
            )
        missing = sorted(MODEL_PROFILE_KEYS - set(profile))
        if missing:
            raise ValueError(
                f"research config model_profiles[{index}] is missing fields: {missing}"
            )
        for key in MODEL_PROFILE_KEYS:
            value = profile[key]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"research config model_profiles[{index}].{key} must be a non-empty string"
                )
        profile_id = str(profile["profile_id"]).strip()
        if profile_id in seen:
            raise ValueError(f"research config declares duplicate model profile {profile_id!r}")
        seen.add(profile_id)
        if str(profile["reasoning_effort"]).strip().lower() != PRIMARY_REASONING_EFFORT:
            raise ValueError(
                f"research config model profile {profile_id!r} must request "
                f"reasoning_effort={PRIMARY_REASONING_EFFORT!r}"
            )
        result.append({
            "profile_id": profile_id,
            "provider": str(profile["provider"]).strip(),
            "model_name": str(profile["model_name"]).strip(),
            "reasoning_effort": str(profile["reasoning_effort"]).strip().lower(),
        })
    return result


def _validate_output_root(document: Mapping[str, Any]) -> str | None:
    """Validate the declared run root used by tesis-web discovery."""
    value = document.get("output_root")
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("research config output_root must be a non-empty relative path")
    path = PurePosixPath(value.strip())
    if path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise ValueError("research config output_root must be a safe relative path")
    if path.parts[:len(OUTPUT_ROOT_PARENT)] != OUTPUT_ROOT_PARENT or len(path.parts) <= len(OUTPUT_ROOT_PARENT):
        raise ValueError(
            "research config output_root must be results/runs/<epoch> so run discovery stays bounded"
        )
    return path.as_posix()


def _contained_run_root(
    repository_root: Path,
    output_root: str,
    output_epoch: str | Path,
    *,
    source: str,
) -> Path:
    """Resolve a declared run root and refuse any escape from the repository.

    A lexically safe ``results/runs/<epoch>`` can still be redirected outside the
    repository by a symlinked ``results``, ``results/runs``, or epoch directory.
    Both the declared path and the caller's epoch path are resolved, required to
    stay strictly beneath the repository root, and required to name the same
    directory.  Checking equality alone is insufficient because two paths can
    resolve to the same outside target.
    """
    repository = Path(repository_root).resolve()
    declared = (repository / output_root).resolve()
    candidate = Path(output_epoch).resolve()
    for label, resolved in (("declared run root", declared), ("output epoch", candidate)):
        if resolved == repository or not resolved.is_relative_to(repository):
            raise ValueError(
                f"{source}: {label} resolves outside the repository root "
                f"({repository}); symlinked or traversing run roots are rejected"
            )
    if candidate != declared:
        raise ValueError(
            f"{source}: output epoch must equal the declared run root {output_root!r}"
        )
    return candidate


def load_research_config(path: str | Path) -> dict[str, Any]:
    """Load and validate a declared Chapter 3 study contract.

    The contract declares only study axes (blocks, conditions, mode, repeats,
    levels, surfaces) and the analysis policy.  Every value that can alter a
    score stays in the frozen epoch config produced by ``freeze-profile``; this
    loader never invents a profile, oracle, budget, or epoch.
    """
    document = json.loads(Path(path).read_bytes())
    if not isinstance(document, dict):
        raise ValueError("research config must be a JSON object")
    if document.get("research_config_version") != RESEARCH_CONFIG_VERSION:
        raise ValueError("unsupported research config version")
    unknown = sorted(set(document) - RESEARCH_CONFIG_KEYS)
    if unknown:
        raise ValueError(f"research config has unknown keys: {unknown}")
    missing = sorted(
        RESEARCH_CONFIG_KEYS - {"frozen_inputs_required"} - OPTIONAL_RESEARCH_CONFIG_KEYS - set(document)
    )
    if missing:
        raise ValueError(f"research config is missing keys: {missing}")
    restoration = document.get("fixture_restoration")
    if restoration is not None and not isinstance(restoration, (str, dict, list)):
        raise ValueError("research config fixture_restoration must be a path, object, or list")
    conditions = document.get("primary_conditions")
    if (
        not isinstance(conditions, list)
        or any(not isinstance(condition, str) for condition in conditions)
        or sorted(set(conditions)) != sorted(PRIMARY_CONDITIONS)
        or len(conditions) != len(set(conditions))
    ):
        raise ValueError("research config must declare exactly both primary conditions")
    if document.get("payload_mode") != PRIMARY_PAYLOAD_MODE:
        raise ValueError("research config must declare the hybrid primary payload mode")
    if type(document.get("epoch_id")) is not str or not document["epoch_id"].strip():
        raise ValueError("research config requires an explicit epoch_id")
    if type(document.get("repeats")) is not int or document["repeats"] < MIN_REPEATS:
        raise ValueError(f"research config requires at least {MIN_REPEATS} repeats")
    blocks = document.get("blocks")
    _validate_declared_blocks(blocks, source="research config")
    _validate_model_profiles(document)
    _validate_output_root(document)
    levels = document.get("levels")
    if (
        not isinstance(levels, list)
        or not levels
        or any(not isinstance(level, str) for level in levels)
        or len(set(levels)) != len(levels)
        or any(level not in SECURITY_LEVELS for level in levels)
    ):
        raise ValueError("research config levels must be unique known security levels")
    surfaces = document.get("surfaces")
    if (
        not isinstance(surfaces, list)
        or not surfaces
        or any(not isinstance(surface, str) for surface in surfaces)
        or len(set(surfaces)) != len(surfaces)
        or any(surface not in SURFACES for surface in surfaces)
    ):
        raise ValueError("research config surfaces must be unique known surfaces")
    declared_inputs = document.get("frozen_inputs_required")
    if not isinstance(declared_inputs, list) or sorted(declared_inputs) != sorted(REQUIRED_FROZEN_INPUTS):
        raise ValueError("research config must list the frozen epoch inputs it depends on")
    design = document.get("design")
    if not isinstance(design, dict) or not design.get("pairing") or not design.get("multiple_comparisons"):
        raise ValueError("research config must predeclare pairing and multiple-comparison policy")
    return document


def _repository_root(config_path: Path) -> Path:
    """Find the source repository root, including for an epoch-local config."""
    for parent in [config_path.resolve().parent, *config_path.resolve().parents]:
        if (parent / "core" / "payload_policy.py").is_file() and (parent / "pyproject.toml").is_file():
            return parent
    raise ValueError("cannot locate the repository root for source hashing")


def _file_hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def source_tree_hashes(repository_root: Path) -> dict[str, str]:
    """Hash every runtime/config source that defines this experiment epoch."""
    paths: set[Path] = set()
    for name in SOURCE_ROOTS:
        directory = repository_root / name
        if directory.exists():
            paths.update(
                path for path in directory.rglob("*")
                if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
                and "__pycache__" not in path.parts
            )
    for name in TOP_LEVEL_SOURCES:
        path = repository_root / name
        if path.is_file():
            paths.add(path)
    result: dict[str, str] = {}
    for path in sorted(paths):
        relative = path.resolve().relative_to(repository_root.resolve()).as_posix()
        result[relative] = (_config_epoch_hash(path) if relative == "config.yaml"
                           else _file_hash(path))
    return result


# Operator inputs that describe the fixture rather than the experiment's code or
# frozen settings.  An attestation has to carry the source-hash epoch it is bound
# to (fixture-restoration.v1), so hashing the attestation into that same epoch
# would be circular: writing the attestation would change the value it must equal.
CONFIG_EPOCH_EXCLUDED_KEYS = ("fixture_restoration_evidence",)


def _config_epoch_hash(path: Path) -> str:
    """Hash the experiment-relevant part of the config for the source epoch."""
    try:
        from tesis.config_loader import load_yaml_config
        document = load_yaml_config(path)
    except Exception:
        return _file_hash(path)
    if not isinstance(document, dict):
        return _file_hash(path)
    projected = {key: value for key, value in document.items()
                 if key not in CONFIG_EPOCH_EXCLUDED_KEYS}
    return _json_hash(projected)


def _json_hash(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


SOURCE_IDENTITY_VERSION = "chapter3-source-identity.v1"
FIXTURE_RESTORATION_POLICY_VERSION = "fixture-restoration.v1"
FIXTURE_RESTORATION_KINDS: tuple[str, ...] = ("operator_attestation",)
FIXTURE_RESTORATION_STATES: tuple[str, ...] = ("reset", "isolated_equivalent")
FIXTURE_RESTORATION_REQUIRED_KEYS = (
    "policy_version", "evidence_id", "kind", "fixture_id", "protocol_version",
    "security_level", "epoch_id", "source_hashes_sha256", "restoration",
    "authorized_protocol", "evidence_refs", "evidence_sha256", "observed_at", "operator",
)
_HEX64 = set("0123456789abcdef")


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX64


def source_identity(
    *,
    repository_root: str | Path | None = None,
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return the one source/config hash identity shared by runs and study plans.

    ``repository_root`` wins when supplied; otherwise the root is derived from
    ``config_path``.  Runner/headless/CLI artifacts must use this helper instead
    of computing a second hash contract.
    """
    if repository_root is not None:
        root = Path(repository_root).resolve()
    elif config_path is not None:
        root = _repository_root(Path(config_path))
    else:
        raise ValueError("source_identity requires repository_root or config_path")
    hashes = source_tree_hashes(root)
    resolved_config = Path(config_path).resolve() if config_path is not None else None
    return {
        "identity_version": SOURCE_IDENTITY_VERSION,
        "repository_root": str(root),
        "config_path": str(resolved_config) if resolved_config else None,
        "config_sha256": _file_hash(resolved_config) if resolved_config and resolved_config.is_file() else None,
        "source_hashes": hashes,
        "source_hashes_sha256": _json_hash(hashes),
    }


def verify_fixture_restoration(document: Any) -> list[dict[str, Any]]:
    """Validate one operator fixture-restoration document (B's approved schema).

    The document is the single input consumed by both the study plan freeze and
    readiness (`fixture_restoration_evidence`).  Nothing here invokes a reset
    endpoint or synthesizes restoration.
    """
    if not isinstance(document, Mapping):
        return [{"valid": False, "reason": "fixture_restoration_not_an_object"}]
    issues: list[dict[str, Any]] = []
    extra = sorted(set(document) - set(FIXTURE_RESTORATION_REQUIRED_KEYS))
    if extra:
        return [{"valid": False, "reason": "fixture_restoration_unknown_fields", "detail": extra}]
    missing = [
        key for key in FIXTURE_RESTORATION_REQUIRED_KEYS
        if key not in document or document.get(key) in (None, "", [])
    ]
    if missing:
        return [{"valid": False, "reason": "fixture_restoration_missing_fields", "detail": missing}]
    if document.get("policy_version") != FIXTURE_RESTORATION_POLICY_VERSION:
        issues.append({"valid": False, "reason": "fixture_restoration_policy_version_invalid"})
    if document.get("kind") not in FIXTURE_RESTORATION_KINDS:
        issues.append({"valid": False, "reason": "fixture_restoration_kind_invalid"})
    for key in ("evidence_id", "fixture_id", "protocol_version", "epoch_id", "authorized_protocol", "operator"):
        value = document.get(key)
        if not isinstance(value, str) or not value.strip():
            issues.append({"valid": False, "reason": f"fixture_restoration_{key}_invalid"})
    if document.get("security_level") not in {"low", "medium", "high"}:
        issues.append({"valid": False, "reason": "fixture_restoration_security_level_invalid"})
    if document.get("restoration") not in FIXTURE_RESTORATION_STATES:
        issues.append({"valid": False, "reason": "fixture_restoration_state_invalid"})
    if not _is_hex64(document.get("source_hashes_sha256")):
        issues.append({"valid": False, "reason": "fixture_restoration_source_hash_invalid"})
    if not _is_hex64(document.get("evidence_sha256")):
        issues.append({"valid": False, "reason": "fixture_restoration_evidence_hash_invalid"})
    refs = document.get("evidence_refs")
    if not isinstance(refs, list) or not refs or any(
        not isinstance(ref, str) or not ref.strip() for ref in refs
    ):
        issues.append({"valid": False, "reason": "fixture_restoration_refs_invalid"})
    try:
        stamp = datetime.fromisoformat(str(document["observed_at"]).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("naive")
    except ValueError:
        issues.append({"valid": False, "reason": "fixture_restoration_timestamp_invalid"})
    return issues


def _canonical_fixture_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact validated operator document, unchanged.

    The 14 documented fields are the whole scientific input.  Freeze-time
    provenance (source path, file digest, identity digest) is kept separate so
    the document can be forwarded verbatim to the runner/readiness validator.
    """
    issues = verify_fixture_restoration(document)
    if issues:
        raise ValueError(
            "fixture_restoration is not a valid authorized evidence document: "
            + ", ".join(sorted({str(issue["reason"]) for issue in issues}))
        )
    return {key: document[key] for key in FIXTURE_RESTORATION_REQUIRED_KEYS}


def _fixture_provenance(document: Mapping[str, Any], *, source_path: str | None = None,
                        file_sha256: str | None = None) -> dict[str, Any]:
    """Return freeze-time provenance for one canonical fixture document."""
    return {
        "identity_sha256": _json_hash(dict(document)),
        "source_path": source_path,
        "sha256": file_sha256,
    }


def load_fixture_restoration(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load one operator restoration document plus its freeze provenance.

    Returns ``(document, provenance)`` where ``document`` is the exact validated
    operator document (safe to pass to the runner) and ``provenance`` is plan
    metadata that must never be forwarded as evidence.
    """
    source = Path(path).resolve()
    raw = json.loads(source.read_bytes())
    document = _canonical_fixture_document(raw)
    return document, _fixture_provenance(
        document, source_path=str(source), file_sha256=_file_hash(source)
    )


_COORDINATE_ID_AXES = (
    "block", "provider", "surface", "security_level", "payload_mode",
    "experiment_condition", "target_method", "repeat_index", "fixture_id",
    "protocol_version", "policy_epoch_id",
)


def _coordinate_id(coordinate: Mapping[str, Any]) -> str:
    """Return the stable identity of one planned coordinate."""
    return _json_hash({axis: coordinate.get(axis) for axis in _COORDINATE_ID_AXES})[:16]


def _block_coordinate_rows(
    block: str,
    *,
    profiles: list[dict[str, Any]],
    surfaces: list[str],
    levels: list[str],
    conditions: list[str],
    repeats: int,
    candidate_budget: int,
    fixture_id: str,
    protocol_version: str,
    policy_epoch_id: str,
    guardrail_retry_enabled: bool,
    guardrail_handling: str,
) -> list[dict[str, Any]]:
    """Instantiate one block's declared coordinate grid deterministically.

    The builder and plan verifier share this factory so a verified plan cannot
    silently omit, duplicate, or reorder the coordinates its declaration implies.
    """
    rows: list[dict[str, Any]] = []
    index = 0
    for profile in sorted(profiles, key=lambda item: item["profile_id"]):
        for surface in sorted(surfaces):
            methods = [None] if block == "selection" else list(METHODS_BY_SURFACE[surface])
            for level in sorted(levels):
                for condition in sorted(conditions):
                    for method in methods:
                        for repeat_index in range(repeats):
                            coordinate = {
                                "coordinate_index": index,
                                "block": block,
                                "provider": profile["profile_id"],
                                "model": profile["model_name"],
                                "reasoning_effort": profile["reasoning_effort"],
                                "surface": surface,
                                "security_level": level,
                                "payload_mode": PRIMARY_PAYLOAD_MODE,
                                "experiment_condition": condition,
                                "target_method": method,
                                "repeat_index": repeat_index,
                                "candidate_budget": candidate_budget,
                                "guardrail_retry_enabled": guardrail_retry_enabled,
                                "guardrail_handling": guardrail_handling,
                                "fixture_id": fixture_id,
                                "protocol_version": protocol_version,
                                "policy_epoch_id": policy_epoch_id,
                                "status": "planned",
                            }
                            coordinate["coordinate_id"] = _coordinate_id(coordinate)
                            rows.append(coordinate)
                            index += 1
    return rows


def planned_coordinates(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return the plan's declared coordinates with block and planned status."""
    rows: list[dict[str, Any]] = []
    for block, coordinates in (plan.get("blocks") or {}).items():
        for coordinate in coordinates:
            rows.append({**coordinate, "block": block, "status": coordinate.get("status", "planned")})
    return rows


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _freeze_model_settings(
    raw: dict[str, Any], *, providers: list[str] | None, config: Any,
) -> None:
    """Pin every selected model and role to the declared max reasoning.

    The frozen config is the epoch's authority: a later config edit must fail
    verification rather than silently lowering reasoning effort or dropping one
    model from the matrix.  Generated provider profiles are pinned through
    ``api_providers.*.model_options`` because their profile IDs are derived.
    """
    if not providers:
        return
    from tesis.provider_registry import model_profile_id

    raw["providers"] = list(providers)
    raw_models = raw.setdefault("models", {})
    if not isinstance(raw_models, dict):
        raise ValueError("config models must be a mapping before freeze")
    api_providers = raw.get("api_providers") or {}
    for profile_id in providers:
        model = config.models.get(profile_id)
        if model is None:
            raise ValueError(f"frozen model profile {profile_id!r} is not configured")
        if profile_id in raw_models:
            section = raw_models[profile_id]
            if not isinstance(section, dict):
                raise ValueError(f"config models.{profile_id} must be a mapping")
            section["reasoning_effort"] = PRIMARY_REASONING_EFFORT
            continue
        matches = [
            (provider_id, entry) for provider_id, entry in api_providers.items()
            if isinstance(entry, dict) and any(
                model_profile_id(provider_id, model_name) == profile_id
                for model_name in (entry.get("models") or [])
            )
        ]
        if len(matches) != 1:
            raise ValueError(
                f"cannot locate one api_providers entry for frozen profile {profile_id!r}"
            )
        provider_id, entry = matches[0]
        options = entry.setdefault("model_options", {})
        if not isinstance(options, dict):
            raise ValueError(f"api_providers.{provider_id}.model_options must be a mapping")
        model_options = options.setdefault(model.model_name, {})
        if not isinstance(model_options, dict):
            raise ValueError(
                f"api_providers.{provider_id}.model_options.{model.model_name} must be a mapping"
            )
        model_options["reasoning_effort"] = PRIMARY_REASONING_EFFORT
    runtime = raw.get("llm_runtime")
    if isinstance(runtime, dict):
        roles = runtime.get("roles")
        if isinstance(roles, dict):
            for role_name, settings in roles.items():
                if isinstance(settings, dict) and settings.get("reasoning_effort") not in (
                    None, PRIMARY_REASONING_EFFORT,
                ):
                    settings["reasoning_effort"] = PRIMARY_REASONING_EFFORT


def freeze_ranking_profile(
    *,
    config_path: str,
    candidate_profile_path: str,
    output_epoch: str,
    epoch_id: str,
    repeats: int = MIN_REPEATS,
    providers: list[str] | None = None,
    fixture_restoration_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Re-freeze a pilot-derived profile for a new, explicitly declared epoch.

    Content (fit predicates, request counts, protocol references) is preserved;
    only identity/timestamps and the lineage hash change. The source profile's
    fixture, protocol, and candidate budget must match the current config.
    """
    if repeats < MIN_REPEATS:
        raise ValueError(f"Chapter 3 requires at least {MIN_REPEATS} repeats")
    config = load_and_resolve_config(config_path=config_path, cli_args={})
    token_price_schedule = require_frozen_token_price_schedule(config)
    candidate_path = Path(candidate_profile_path)
    candidate = json.loads(candidate_path.read_bytes())
    validate_profile(candidate)
    if not config.scoring_oracles:
        raise ValueError("config must include hash-pinned scoring oracles before freezing")
    validate_evidence_config(config.scoring_rubric_version, candidate, config.scoring_oracles)
    if candidate["fixture_id"] != config.fixture_id or candidate["protocol_version"] != config.protocol_version:
        raise ValueError("candidate ranking profile must match the configured fixture/protocol")
    if candidate["candidate_budget"] != config.candidate_budget:
        raise ValueError("candidate ranking profile must match the configured candidate budget")
    if any(source.get("origin") != "operator_fixture" for source in candidate["sources"]):
        raise ValueError("a current-epoch profile requires operator_fixture evidence sources")
    epoch_root = Path(output_epoch)
    run_root = _repository_root(Path(config_path)) / "results" / "runs" / epoch_id
    if run_root.exists() and any(run_root.iterdir()):
        raise ValueError(
            f"epoch {epoch_id!r} already has run artifacts under {run_root}; a new epoch "
            "is required instead of re-freezing retained evidence"
        )
    if epoch_root.exists() and any(epoch_root.iterdir()):
        unexpected = sorted(
            entry.name for entry in epoch_root.iterdir()
            if entry.name not in FREEZE_PREGEN_ALLOWED
        )
        if unexpected:
            raise ValueError(
                "output epoch must be new, empty, or contain only pre-freeze evidence; "
                f"unexpected entries: {unexpected}"
            )
    epoch_root.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat()
    frozen = dict(candidate)
    frozen["parent_profile_sha256"] = candidate["sha256"]
    frozen["profile_id"] = f"{candidate['profile_id']}+{epoch_id}"
    frozen["version"] = f"{candidate['version']}+{epoch_id}"
    frozen["frozen_at"] = now
    frozen["freeze_epoch"] = {
        "epoch_id": epoch_id,
        "policy_version": EXPERIMENT_POLICY_VERSION,
        "payload_policy_version": PAYLOAD_POLICY_VERSION,
        "frozen_at": now,
    }
    frozen["sha256"] = evidence_hash({k: v for k, v in frozen.items() if k != "sha256"})
    profile_path = epoch_root / "ranking-profile.frozen.json"
    _atomic_json(profile_path, frozen)

    policy_snapshot = payload_policy_snapshot()
    _atomic_json(epoch_root / "payload-policy-snapshot.json", policy_snapshot)
    policy_epoch = {
        "epoch_id": epoch_id,
        "policy_version": EXPERIMENT_POLICY_VERSION,
        "payload_policy_version": PAYLOAD_POLICY_VERSION,
        "control_policy_version": CONTROL_POLICY_VERSION,
        "budget_policy_version": BUDGET_POLICY_VERSION,
        "frozen_at": now,
        "parent_profile_sha256": candidate["sha256"],
        "ranking_profile_sha256": frozen["sha256"],
        "payload_policy_snapshot_sha256": policy_snapshot["snapshot_sha256"],
        # Full immutable policy/template/prompt identity, persisted with the
        # epoch so run artifacts carry what produced their candidates.
        "payload_policy_snapshot": policy_snapshot,
        "source_hashes": source_tree_hashes(_repository_root(Path(config_path))),
    }
    _atomic_json(epoch_root / "policy-epoch.json", policy_epoch)

    raw = load_yaml_config(config_path)
    raw["scoring_profile"] = profile_path.name
    raw["scoring_oracles"] = config.scoring_oracles
    raw["scoring_policy_epoch"] = policy_epoch
    # Persist the resolved, validated mapping rather than a source-relative path:
    # the frozen config lives in a different epoch directory and must remain
    # price-complete without the original file.
    raw["token_price_schedule"] = token_price_schedule
    raw["fixture_id"] = config.fixture_id
    raw["protocol_version"] = config.protocol_version
    raw["candidate_budget"] = config.candidate_budget
    raw["repeats"] = repeats
    raw["matrix"] = True
    raw["levels"] = list(SECURITY_LEVELS)
    raw["surfaces"] = list(SURFACES)
    raw["payload_mode"] = PRIMARY_PAYLOAD_MODE
    raw["payload_modes"] = [PRIMARY_PAYLOAD_MODE]
    if fixture_restoration_paths:
        by_level: dict[str, dict[str, Any]] = {}
        for path in fixture_restoration_paths:
            document, _provenance = load_fixture_restoration(path)
            if document["epoch_id"] != epoch_id:
                raise ValueError(
                    f"fixture restoration {path!r} is bound to epoch {document['epoch_id']!r}, "
                    f"not {epoch_id!r}"
                )
            level = str(document["security_level"])
            if level in by_level:
                raise ValueError(f"duplicate fixture restoration for level {level!r}")
            by_level[level] = document
        raw["fixture_restoration_evidence"] = {
            "by_level": by_level,
            "levels": sorted(by_level),
        }
    _freeze_model_settings(raw, providers=providers, config=config)
    frozen_config = epoch_root / "config.frozen.yaml"
    frozen_config.write_text(dump_yaml_config(raw), encoding="utf-8")
    receipt = {
        "artifact_type": "chapter3_profile_freeze_receipt",
        "epoch_id": epoch_id,
        "config_path": str(frozen_config),
        "config_sha256": _file_hash(frozen_config),
        "source_profile": str(candidate_path),
        "source_profile_sha256": _file_hash(candidate_path),
        "frozen_profile": str(profile_path),
        "frozen_profile_sha256": _file_hash(profile_path),
        "policy_epoch": policy_epoch,
        "note": (
            "Profile content is pilot-derived; this receipt re-freezes it for the declared "
            "epoch and records lineage. It does not invent new pilot observations."
        ),
    }
    _atomic_json(epoch_root / "freeze-receipt.json", receipt)
    return receipt


def _canonical_profile_sha(profile: Mapping[str, Any] | None) -> str | None:
    """Return the validated ranking-profile digest (excludes its own sha field)."""
    if not isinstance(profile, Mapping) or not profile:
        return None
    return evidence_hash({key: value for key, value in profile.items() if key != "sha256"})


def _selected_model_profiles(
    config: Any,
    *,
    declared_profiles: list[dict[str, Any]] | None,
    providers: list[str] | None,
    raw_config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Resolve the exact evaluated model profiles and reject config mismatch.

    A declaration pins profile ID, provider adapter, model name and ``max``
    reasoning.  The resolved config is the authority for the adapter/model, so a
    stale or differently configured profile fails here, before any plan freeze.
    """
    declared_by_id: dict[str, dict[str, Any]] = {}
    if declared_profiles is not None:
        declared_by_id = {profile["profile_id"]: profile for profile in declared_profiles}
        declared_ids = sorted(declared_by_id)
        if providers is not None and sorted(set(providers)) != declared_ids:
            raise ValueError(
                "providers must match the exact model profiles declared by the research config"
            )
        chosen = declared_ids
    else:
        chosen = list(providers or config.providers or [config.provider])
    if not chosen:
        raise ValueError("a research plan requires at least one model profile")
    if len(set(chosen)) != len(chosen):
        raise ValueError("a research plan cannot declare duplicate model profiles")
    from llm.reasoning import model_efforts

    selected: list[dict[str, Any]] = []
    for profile_id in sorted(chosen):
        validate_provider(profile_id, config.models)
        model = config.models[profile_id]
        expected = declared_by_id.get(profile_id)
        if expected is not None:
            if model.provider != expected["provider"]:
                raise ValueError(
                    f"model profile {profile_id!r} is configured with provider "
                    f"{model.provider!r}, but the study declares {expected['provider']!r}"
                )
            if model.model_name != expected["model_name"]:
                raise ValueError(
                    f"model profile {profile_id!r} is configured with model "
                    f"{model.model_name!r}, but the study declares {expected['model_name']!r}"
                )
            configured_effort = (model.reasoning_effort or "").strip().lower() or None
            if configured_effort != expected["reasoning_effort"]:
                raise ValueError(
                    f"model profile {profile_id!r} is configured with reasoning_effort="
                    f"{configured_effort!r}; the study requires "
                    f"{expected['reasoning_effort']!r}"
                )
            advertised = model_efforts(dict(raw_config), expected["model_name"])
            if advertised is not None and expected["reasoning_effort"] not in advertised:
                raise ValueError(
                    f"model {expected['model_name']!r} does not advertise "
                    f"reasoning_effort={expected['reasoning_effort']!r} "
                    f"(advertised: {advertised})"
                )
        selected.append({
            "profile_id": profile_id,
            "provider": model.provider,
            "model_name": model.model_name,
            "reasoning_effort": model.reasoning_effort,
        })
    return selected


def build_research_plan(
    *,
    config_path: str,
    output_epoch: str,
    epoch_id: str,
    repeats: int = MIN_REPEATS,
    providers: list[str] | None = None,
    conditions: list[str] | None = None,
    research_config_path: str | None = None,
) -> dict[str, Any]:
    """Build and freeze the declared-block plan without executing anything."""
    resolved_config = Path(config_path).resolve()
    declaration: dict[str, Any] | None = None
    declared_block_names: tuple[str, ...] = BLOCKS
    declared_profiles: list[dict[str, Any]] | None = None
    declared_output_root: str | None = None
    if research_config_path:
        declaration = load_research_config(research_config_path)
        if declaration["epoch_id"] != epoch_id:
            raise ValueError("--epoch-id must match the declared research config epoch")
        declared_block_names = _validate_declared_blocks(
            declaration["blocks"], source="research config",
        )
        declared_profiles = _validate_model_profiles(declaration)
        declared_output_root = _validate_output_root(declaration)
        repeats = declaration["repeats"]
        conditions = list(declaration["primary_conditions"])
        if declaration["payload_mode"] != PRIMARY_PAYLOAD_MODE:
            raise ValueError("the declared research config payload mode is not supported")
    config = load_and_resolve_config(config_path=str(resolved_config), cli_args={})
    require_frozen_token_price_schedule(config)
    if repeats < MIN_REPEATS:
        raise ValueError(f"Chapter 3 requires at least {MIN_REPEATS} repeats per coordinate")
    if config.payload_mode != PRIMARY_PAYLOAD_MODE:
        raise ValueError("the primary study requires the hybrid payload mode")
    chosen_conditions = sorted(set(conditions or PRIMARY_CONDITIONS))
    if chosen_conditions != sorted(PRIMARY_CONDITIONS):
        raise ValueError("the primary study compares both linear_hybrid and akg_guided_hybrid")
    if not config.scoring_profile or not config.scoring_oracles:
        raise ValueError(
            "a final-scoring plan requires a frozen scoring_profile and operator oracles; "
            "run freeze-profile first (empty config values are never filled from history)"
        )
    validate_evidence_config(config.scoring_rubric_version, config.scoring_profile, config.scoring_oracles)
    profile = config.scoring_profile
    if profile.get("fixture_id") != config.fixture_id or profile.get("protocol_version") != config.protocol_version:
        raise ValueError("ranking profile must match the configured fixture/protocol")
    if profile.get("candidate_budget") != config.candidate_budget:
        raise ValueError("ranking profile must match the configured candidate budget")
    if any(source.get("origin") != "operator_fixture" for source in profile.get("sources", [])):
        raise ValueError("live primary study requires operator_fixture profile sources")
    if not config.scoring_policy_epoch.get("epoch_id"):
        raise ValueError("config requires an explicitly frozen scoring_policy_epoch")
    if config.scoring_policy_epoch["epoch_id"] != epoch_id:
        raise ValueError("--epoch-id must match the frozen config scoring_policy_epoch")
    raw_config = load_yaml_config(resolved_config)
    selected_profiles = _selected_model_profiles(
        config,
        declared_profiles=declared_profiles,
        providers=providers,
        raw_config=raw_config,
    )
    chosen_levels = list(declaration["levels"] if declaration else config.levels or SECURITY_LEVELS)
    chosen_surfaces = list(declaration["surfaces"] if declaration else config.surfaces or SURFACES)
    for axis, values, known in (
        ("levels", chosen_levels, SECURITY_LEVELS),
        ("surfaces", chosen_surfaces, SURFACES),
    ):
        if (
            not values
            or any(not isinstance(value, str) for value in values)
            or len(set(values)) != len(values)
            or any(value not in known for value in values)
        ):
            raise ValueError(f"research plan {axis} must be unique known values")
    if declared_output_root is not None:
        _contained_run_root(
            _repository_root(resolved_config),
            declared_output_root,
            output_epoch,
            source="research plan build",
        )
    guardrails = [(config.evasion_enabled, config.evasion_mode)]
    blocks: dict[str, list[dict[str, Any]]] = {}
    for block in declared_block_names:
        blocks[block] = _block_coordinate_rows(
            block,
            profiles=selected_profiles,
            surfaces=chosen_surfaces,
            levels=chosen_levels,
            conditions=chosen_conditions,
            repeats=repeats,
            candidate_budget=config.candidate_budget,
            fixture_id=str(config.fixture_id),
            protocol_version=str(config.protocol_version),
            policy_epoch_id=epoch_id,
            guardrail_retry_enabled=guardrails[0][0],
            guardrail_handling=guardrails[0][1],
        )
    if declaration is not None:
        expected_coordinates = (declaration.get("design") or {}).get("expected_coordinates")
        if expected_coordinates is not None:
            total = sum(len(rows) for rows in blocks.values())
            if type(expected_coordinates) is not int or total != expected_coordinates:
                raise ValueError(
                    "research config declared expected_coordinates="
                    f"{expected_coordinates!r}, but the frozen grid has {total} coordinates"
                )
    research_config_resolved = (
        Path(str(research_config_path)).resolve() if declaration is not None else None
    )
    source_info = source_identity(config_path=resolved_config)
    restoration_input = declaration.get("fixture_restoration") if declaration else None
    restoration_items: list[Any] = []
    if isinstance(restoration_input, list):
        restoration_items = list(restoration_input)
    elif restoration_input:
        restoration_items = [restoration_input]
    restoration_by_level: dict[str, dict[str, Any]] = {}
    restoration_provenance: dict[str, dict[str, Any]] = {}
    for item in restoration_items:
        if isinstance(item, str):
            restoration_path = Path(item)
            if not restoration_path.is_absolute() and research_config_resolved is not None:
                restoration_path = research_config_resolved.parent / restoration_path
            document, provenance = load_fixture_restoration(restoration_path)
        else:
            document = _canonical_fixture_document(item)
            provenance = _fixture_provenance(document)
        if document["fixture_id"] != config.fixture_id or \
                document["protocol_version"] != config.protocol_version:
            raise ValueError("fixture restoration must match the configured fixture/protocol")
        if document["epoch_id"] != epoch_id:
            raise ValueError("fixture restoration epoch_id must match the declared study epoch")
        if document["source_hashes_sha256"] != source_info["source_hashes_sha256"]:
            raise ValueError("fixture restoration source_hashes_sha256 must match this code/config epoch")
        level = str(document["security_level"])
        if level in restoration_by_level:
            raise ValueError(f"duplicate fixture restoration for level {level!r}")
        restoration_by_level[level] = document
        restoration_provenance[level] = provenance
    missing_levels = sorted(set(chosen_levels) - set(restoration_by_level))
    fixture_restoration = {
        # Exact operator documents: the only value forwarded to the runner.
        "by_level": restoration_by_level,
        # Freeze provenance: never forwarded as scientific evidence.
        "provenance": restoration_provenance,
        "levels": sorted(restoration_by_level),
        "missing_levels": missing_levels,
    } if restoration_by_level else None
    prerequisites = [{
        "name": "fixture_restoration_attestation",
        "status": (
            "frozen" if fixture_restoration and not missing_levels
            else "partial_external_input" if fixture_restoration
            else "missing_external_input"
        ),
        "reason": (
            None if fixture_restoration and not missing_levels
            else "fixture_restoration_attestation_incomplete" if fixture_restoration
            else REASON_ATTESTATION_MISSING
        ),
        "detail": (
            "Operator-supplied fixture-restoration documents are frozen in the plan."
            if fixture_restoration and not missing_levels else
            f"Authorized fixture restoration is missing for levels: {', '.join(missing_levels)}; "
            "paired analysis stays unassessable for those coordinates (no synthesis)."
            if fixture_restoration else
            "No authorized fixture-restoration document was supplied; paired analysis stays "
            "unassessable until an operator provides one (no synthesis)."
        ),
        "missing_levels": missing_levels,
    }]
    source_hashes = source_info["source_hashes"]
    policy_epoch = dict(config.scoring_policy_epoch)
    policy_snapshot = payload_policy_snapshot()
    plan = {
        "artifact_type": "chapter3_research_plan",
        "plan_version": RESEARCH_PLAN_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "epoch_id": epoch_id,
        "config_path": str(resolved_config),
        "config_sha256": _file_hash(resolved_config),
        "research_config": (
            {
                "path": str(research_config_resolved),
                "sha256": _file_hash(research_config_resolved),
                "declaration": declaration,
            }
            if research_config_resolved is not None
            else None
        ),
        "policy_epoch": policy_epoch,
        "payload_policy_snapshot": policy_snapshot,
        "source_identity_version": source_info["identity_version"],
        "prerequisites": prerequisites,
        "policy_versions": {
            "experiment": EXPERIMENT_POLICY_VERSION,
            "payload": PAYLOAD_POLICY_VERSION,
            "control": CONTROL_POLICY_VERSION,
            "budget": BUDGET_POLICY_VERSION,
        },
        "constraints": {
            "primary_conditions": list(PRIMARY_CONDITIONS),
            "payload_mode": PRIMARY_PAYLOAD_MODE,
            "repeats": repeats,
            "fixture_id": config.fixture_id,
            "protocol_version": config.protocol_version,
            "candidate_budget": config.candidate_budget,
            "scoring_rubric_version": config.scoring_rubric_version,
            "scoring_mode": config.scoring_mode,
            "scoring_profile_sha256": _canonical_profile_sha(profile),
            "payload_policy_snapshot_sha256": policy_snapshot["snapshot_sha256"],
            "scoring_oracles_sha256": evidence_hash(config.scoring_oracles),
            "token_price_schedule_sha256": evidence_hash(config.token_price_schedule),
            "guardrail_retry_enabled": guardrails[0][0],
            "guardrail_handling": guardrails[0][1],
            "model_profiles": selected_profiles,
            "declared_axes": {
                "blocks": {
                    block: (
                        SELECTION_TARGET if block == "selection" else FORCED_TARGET
                    )
                    for block in declared_block_names
                },
                "providers": sorted(profile["profile_id"] for profile in selected_profiles),
                "surfaces": sorted(chosen_surfaces),
                "levels": sorted(chosen_levels),
                "conditions": sorted(chosen_conditions),
                "repeats": repeats,
            },
            "fixture_restoration": fixture_restoration,
            "fixture_restoration_sha256": (
                _json_hash({
                    "by_level": fixture_restoration["by_level"],
                    "provenance": fixture_restoration["provenance"],
                }) if fixture_restoration else None
            ),
        },
        "source_hashes": source_hashes,
        "source_hashes_sha256": source_info["source_hashes_sha256"],
        "blocks": blocks,
        "output_root": declared_output_root,
        "web_manifest": {
            "status": "emitted_at_run",
            "artifact_type": "experiment_manifest",
            "schema_version": "artifact-manifest.v1",
            "default_root": "results/runs",
            "expected_path": (
                f"{declared_output_root}/experiment.manifest.json"
                if declared_output_root else None
            ),
            "required_run_fields": [
                "execution_id",
                "matrix_execution_id",
                "coordinate_index",
                "provider",
                "model",
                "surface",
                "security_level",
                "payload_mode",
                "experiment_condition",
                "target_method",
                "repeat_index",
            ],
            "note": (
                "run_research_plan writes experiment.manifest.json at the epoch root and "
                "binds each run to its planned coordinate_index; planning itself writes no "
                "execution claim."
            ),
        },
        "planned_counts": {
            **{block: len(rows) for block, rows in blocks.items()},
            "total": sum(len(rows) for rows in blocks.values()),
        },
    }
    plan["plan_sha256"] = _json_hash(plan)
    epoch_root = Path(output_epoch)
    if epoch_root.exists() and any(epoch_root.iterdir()):
        raise ValueError("output epoch must be new or empty")
    _atomic_json(epoch_root / "payload-policy-snapshot.json", policy_snapshot)
    _atomic_json(epoch_root / "research-plan.json", plan)
    return plan


def _plan_block_names(plan: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the plan's declared execution blocks in canonical order."""
    blocks = plan.get("blocks")
    if not isinstance(blocks, Mapping):
        raise ValueError("research plan must declare a block mapping")
    return _ordered_block_names(blocks, source="research plan")


def _plan_model_profiles(
    plan: Mapping[str, Any], constraints: Mapping[str, Any], axes: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Validate the plan's exact model-profile recording against its axes."""
    profiles = constraints.get("model_profiles")
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("research plan declared axes require model_profiles")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, profile in enumerate(profiles):
        if not isinstance(profile, Mapping) or set(profile) != MODEL_PROFILE_KEYS:
            raise ValueError(f"research plan model_profiles[{index}] is malformed")
        profile_id = str(profile["profile_id"])
        if not profile_id or profile_id in seen:
            raise ValueError(f"research plan model_profiles[{index}] has an invalid profile_id")
        seen.add(profile_id)
        for key in ("provider", "model_name"):
            value = profile[key]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"research plan model_profiles[{index}].{key} is invalid")
        effort = profile["reasoning_effort"]
        if effort is not None and not isinstance(effort, str):
            raise ValueError(f"research plan model_profiles[{index}].reasoning_effort is invalid")
        result.append({
            "profile_id": profile_id,
            "provider": profile["provider"],
            "model_name": profile["model_name"],
            "reasoning_effort": effort,
        })
    if sorted(seen) != list(axes["providers"]):
        raise ValueError("research plan model profiles do not match the declared providers")
    return result


def _verify_plan_blocks(plan: Mapping[str, Any], constraints: Mapping[str, Any]) -> None:
    """Reject missing, duplicated, or drifted coordinates in a frozen plan."""
    output_root = plan.get("output_root")
    if output_root is not None:
        _validate_output_root({"output_root": output_root})
        manifest = plan.get("web_manifest")
        if not isinstance(manifest, Mapping) or \
                manifest.get("expected_path") != f"{output_root}/experiment.manifest.json":
            raise ValueError("research plan web manifest metadata disagrees with output_root")
    block_names = _plan_block_names(plan)
    blocks = plan["blocks"]
    counts = plan.get("planned_counts")
    if not isinstance(counts, Mapping) or set(counts) != set(block_names) | {"total"}:
        raise ValueError(
            "research plan planned_counts must declare exactly "
            f"{sorted(set(block_names) | {'total'})}"
        )
    repeats = constraints.get("repeats")
    if type(repeats) is not int or repeats < MIN_REPEATS:
        raise ValueError("research plan constraints declare invalid repeats")
    total = 0
    for block in block_names:
        rows = blocks[block]
        if not isinstance(rows, list) or not rows:
            raise ValueError(f"research plan block {block!r} has no planned coordinates")
        if counts[block] != len(rows):
            raise ValueError(f"research plan planned_counts[{block!r}] does not match its block")
        seen_ids: set[str] = set()
        indexes: list[int] = []
        for coordinate in rows:
            if not isinstance(coordinate, Mapping):
                raise ValueError(f"research plan block {block!r} has a malformed coordinate")
            if coordinate.get("block") != block:
                raise ValueError(f"research plan block {block!r} has a coordinate from another block")
            if coordinate.get("status") != "planned":
                raise ValueError(f"research plan block {block!r} has a non-planned coordinate")
            coordinate_id = coordinate.get("coordinate_id")
            if not isinstance(coordinate_id, str) or coordinate_id != _coordinate_id(coordinate):
                raise ValueError(f"research plan block {block!r} has a drifted coordinate_id")
            if coordinate_id in seen_ids:
                raise ValueError(f"research plan block {block!r} duplicates a coordinate")
            seen_ids.add(coordinate_id)
            index = coordinate.get("coordinate_index")
            if type(index) is not int:
                raise ValueError(f"research plan block {block!r} has an invalid coordinate_index")
            indexes.append(index)
            for key in ("fixture_id", "protocol_version", "candidate_budget", "payload_mode"):
                if coordinate.get(key) != constraints.get(key):
                    raise ValueError(
                        f"research plan block {block!r} coordinate disagrees with constraints.{key}"
                    )
            if coordinate.get("policy_epoch_id") != plan.get("epoch_id"):
                raise ValueError(f"research plan block {block!r} coordinate has a foreign epoch")
            condition = coordinate.get("experiment_condition")
            if condition not in PRIMARY_CONDITIONS:
                raise ValueError(f"research plan block {block!r} has an undeclared condition")
            repeat_index = coordinate.get("repeat_index")
            if type(repeat_index) is not int or not 0 <= repeat_index < repeats:
                raise ValueError(f"research plan block {block!r} has an invalid repeat_index")
            if block == "selection":
                if coordinate.get("target_method") is not None:
                    raise ValueError("the selection block must keep target_method=None")
            else:
                surface = str(coordinate.get("surface") or "")
                method = coordinate.get("target_method")
                if method not in METHODS_BY_SURFACE.get(surface, []):
                    raise ValueError(
                        f"the forced block coordinate has an invalid target for surface {surface!r}"
                    )
        if sorted(indexes) != list(range(len(rows))):
            raise ValueError(f"research plan block {block!r} has missing or duplicate coordinate indexes")
        total += len(rows)
    if counts["total"] != total:
        raise ValueError("research plan planned total does not match its blocks")

    axes = constraints.get("declared_axes")
    if axes is None:
        return
    if not isinstance(axes, Mapping) or set(axes) != {
        "blocks", "providers", "surfaces", "levels", "conditions", "repeats",
    }:
        raise ValueError("research plan declared_axes are malformed")
    axis_map: Mapping[str, Any] = axes
    axis_blocks = axis_map["blocks"]
    if not isinstance(axis_blocks, Mapping) or _ordered_block_names(
        axis_blocks, source="research plan declared_axes",
    ) != block_names:
        raise ValueError("research plan declared_axes blocks disagree with its blocks")
    for block, target in axis_blocks.items():
        expected = SELECTION_TARGET if block == "selection" else FORCED_TARGET
        if target != expected:
            raise ValueError(f"research plan declared_axes block {block!r} has an invalid target")
    for axis, known in (
        ("providers", None), ("surfaces", SURFACES), ("levels", SECURITY_LEVELS),
        ("conditions", PRIMARY_CONDITIONS),
    ):
        values = axis_map[axis]
        if not isinstance(values, list) or not values or len(values) != len(set(values)):
            raise ValueError(f"research plan declared_axes.{axis} must be a non-empty unique list")
        if known is not None and any(value not in known for value in values):
            raise ValueError(f"research plan declared_axes.{axis} contains an unknown value")
    if axis_map["repeats"] != repeats:
        raise ValueError("research plan declared_axes.repeats disagrees with constraints.repeats")
    profiles = _plan_model_profiles(plan, constraints, axis_map)
    for block in block_names:
        expected_rows = _block_coordinate_rows(
            block,
            profiles=profiles,
            surfaces=list(axis_map["surfaces"]),
            levels=list(axis_map["levels"]),
            conditions=list(axis_map["conditions"]),
            repeats=repeats,
            candidate_budget=int(constraints["candidate_budget"]),
            fixture_id=str(constraints["fixture_id"]),
            protocol_version=str(constraints["protocol_version"]),
            policy_epoch_id=str(plan["epoch_id"]),
            guardrail_retry_enabled=bool(constraints["guardrail_retry_enabled"]),
            guardrail_handling=str(constraints["guardrail_handling"]),
        )
        if blocks[block] != expected_rows:
            raise ValueError(
                f"research plan block {block!r} coordinates do not match the declared axes"
            )


def verify_plan(plan_path: str | Path) -> dict[str, Any]:
    """Re-hash a plan's frozen inputs; refuse execution after drift."""
    path = Path(plan_path)
    plan = json.loads(path.read_bytes())
    if plan.get("artifact_type") != "chapter3_research_plan" or plan.get("plan_version") != RESEARCH_PLAN_VERSION:
        raise ValueError("not a supported Chapter 3 research plan")
    expected = {k: v for k, v in plan.items() if k != "plan_sha256"}
    if plan.get("plan_sha256") != _json_hash(expected):
        raise ValueError("research plan content hash mismatch")
    config_path = Path(plan["config_path"])
    if _file_hash(config_path) != plan["config_sha256"]:
        raise ValueError("config.yaml changed after the plan was frozen")
    if source_tree_hashes(_repository_root(config_path)) != plan["source_hashes"]:
        raise ValueError("runtime source tree changed after the plan was frozen")
    config = load_and_resolve_config(config_path=str(config_path), cli_args={})
    require_frozen_token_price_schedule(config)
    validate_evidence_config(config.scoring_rubric_version, config.scoring_profile, config.scoring_oracles)
    constraints = plan["constraints"]
    research_config = plan.get("research_config")
    if research_config:
        declaration_path = Path(research_config["path"])
        if not declaration_path.is_file() or _file_hash(declaration_path) != research_config["sha256"]:
            raise ValueError("research config declaration changed after the plan was frozen")
        reloaded = load_research_config(declaration_path)
        if reloaded != research_config.get("declaration"):
            raise ValueError("research config declaration content changed after the plan was frozen")
        declared_names = _validate_declared_blocks(
            reloaded["blocks"], source="research config",
        )
        if declared_names != _plan_block_names(plan):
            raise ValueError("research plan blocks disagree with the declared study")
        declared_profiles = _validate_model_profiles(reloaded)
        if declared_profiles is not None:
            recorded_profiles = constraints.get("model_profiles")
            if not isinstance(recorded_profiles, list) or sorted(
                (
                    str(profile.get("profile_id")),
                    str(profile.get("provider")),
                    str(profile.get("model_name")),
                    str(profile.get("reasoning_effort")),
                )
                for profile in recorded_profiles
                if isinstance(profile, Mapping)
            ) != sorted(
                (
                    profile["profile_id"],
                    profile["provider"],
                    profile["model_name"],
                    profile["reasoning_effort"],
                )
                for profile in declared_profiles
            ):
                raise ValueError(
                    "research plan model profiles disagree with the declared study"
                )
    if _json_hash(dict(config.scoring_policy_epoch)) != _json_hash(dict(plan["policy_epoch"])):
        raise ValueError("config scoring policy epoch changed after the plan was frozen")
    restoration = constraints.get("fixture_restoration")
    if isinstance(restoration, Mapping):
        documents = restoration.get("by_level") or {}
        provenance = restoration.get("provenance") or {}
        if not isinstance(documents, Mapping) or not isinstance(provenance, Mapping):
            raise ValueError("frozen fixture restoration is malformed")
        if set(documents) != set(provenance):
            raise ValueError("frozen fixture restoration provenance is incomplete")
        for level, document in documents.items():
            if not isinstance(document, Mapping):
                raise ValueError("frozen fixture restoration entry is malformed")
            document = dict(document)
            issues = verify_fixture_restoration(document)
            if issues:
                raise ValueError(
                    "frozen fixture restoration is no longer valid: "
                    + ", ".join(sorted({str(issue["reason"]) for issue in issues}))
                )
            record = provenance.get(level) or {}
            source_path = str(record.get("source_path") or "")
            if source_path:
                if not Path(source_path).is_file():
                    raise ValueError("fixture restoration evidence is unavailable after the plan was frozen")
                reloaded_document, reloaded_provenance = load_fixture_restoration(source_path)
                if reloaded_document != document or \
                        reloaded_provenance.get("identity_sha256") != record.get("identity_sha256") or \
                        reloaded_provenance.get("sha256") != record.get("sha256"):
                    raise ValueError("fixture restoration changed after the plan was frozen")
            if document.get("fixture_id") != config.fixture_id or \
                    document.get("protocol_version") != config.protocol_version:
                raise ValueError("fixture restoration no longer matches the configured fixture/protocol")
            if document.get("epoch_id") != plan["epoch_id"]:
                raise ValueError("fixture restoration epoch changed after the plan was frozen")
            if document.get("source_hashes_sha256") != plan["source_hashes_sha256"]:
                raise ValueError("fixture restoration source hash no longer matches the plan")
    frozen_snapshot = plan.get("payload_policy_snapshot")
    snapshot_issues = verify_payload_policy_snapshot(frozen_snapshot)
    if snapshot_issues:
        raise ValueError(
            "frozen payload policy/template snapshot is invalid: "
            + ", ".join(sorted({str(issue["reason"]) for issue in snapshot_issues}))
        )
    if constraints.get("payload_policy_snapshot_sha256") != frozen_snapshot.get("snapshot_sha256"):
        raise ValueError("frozen payload policy/template snapshot identity mismatch")
    if payload_policy_snapshot()["snapshot_sha256"] != frozen_snapshot["snapshot_sha256"]:
        raise ValueError("payload policy/template identity changed after the plan was frozen")
    if _canonical_profile_sha(config.scoring_profile) != constraints["scoring_profile_sha256"]:
        raise ValueError("scoring profile changed after the plan was frozen")
    if evidence_hash(config.scoring_oracles) != constraints["scoring_oracles_sha256"]:
        raise ValueError("scoring oracles changed after the plan was frozen")
    if evidence_hash(config.token_price_schedule) != constraints["token_price_schedule_sha256"]:
        raise ValueError("token price schedule changed after the plan was frozen")
    for key in ("fixture_id", "protocol_version"):
        if config.fixture_id != constraints["fixture_id"] or config.protocol_version != constraints["protocol_version"]:
            raise ValueError(f"configured {key} changed after the plan was frozen")
    if config.candidate_budget != constraints["candidate_budget"]:
        raise ValueError("candidate budget changed after the plan was frozen")
    _verify_plan_blocks(plan, constraints)
    return plan


def _run_block(plan: dict[str, Any], block: str, *, output_epoch: Path
               ) -> tuple[dict[str, Any], list[dict[str, Any]], list[str], dict[str, Any] | None]:
    """Execute one declared block and always record a truthful receipt."""
    if block not in BLOCKS:
        raise ValueError(f"unknown experiment block {block!r}; expected one of {BLOCKS}")
    declared = plan.get("blocks")
    if not isinstance(declared, Mapping) or block not in declared:
        raise ValueError(f"block {block!r} is not declared by the frozen plan")
    coordinates = declared[block]
    if not isinstance(coordinates, list) or not coordinates:
        raise ValueError(f"block {block!r} has no planned coordinates")

    from dataclasses import asdict

    from evaluation.multi_llm_runner import run_provider_matrix

    config = load_and_resolve_config(config_path=plan["config_path"], cli_args={})
    first = coordinates[0]
    block_root = output_epoch / block
    if block_root.exists() and any(block_root.iterdir()):
        raise ValueError(
            f"block {block!r} already has an attempt under {block_root}; start a new attempt/epoch "
            "instead of overwriting retained evidence"
        )
    block_root.mkdir(parents=True, exist_ok=True)
    counter = {"n": 0}
    attempt_directories: list[str] = []

    def child_directory(_coordinate: dict[str, Any], _index: int) -> Path:
        counter["n"] += 1
        child = block_root / f"run-{counter['n']:03d}"
        child.mkdir(parents=True, exist_ok=False)
        attempt_directories.append(str(child))
        return child

    models = {name: asdict(value) for name, value in config.models.items()}
    receipt: dict[str, Any] = {
        "artifact_type": "chapter3_block_run",
        "block": block,
        "planned": len(coordinates),
        "observed": 0,
        "status": "running",
        "aggregate_path": None,
        "aggregate_sha256": None,
        "execution_id": None,
        "attempted_runs": 0,
        "run_directories": attempt_directories,
        "error": None,
    }
    try:
        artifacts, aggregate = run_provider_matrix(
            target_url=config.target_url,
            providers=sorted({item["provider"] for item in coordinates}),
            security_levels=sorted({item["security_level"] for item in coordinates}),
            surfaces=sorted({item["surface"] for item in coordinates}),
            payload_modes=[PRIMARY_PAYLOAD_MODE],
            repeats=plan["constraints"]["repeats"],
            max_iterations=config.iterations,
            candidate_budget=config.candidate_budget,
            stop_policy=config.stop_policy,
            coverage_target=config.coverage_target,
            enriched_reporting=config.enriched_reporting,
            diagnose=config.diagnose,
            output_dir=str(block_root),
            include_aggregate=True,
            evasion_enabled=first["guardrail_retry_enabled"],
            evasion_mode=first["guardrail_handling"],
            evasion_max_retries=config.evasion_max_retries,
            evasion_cooldown_threshold=config.evasion_cooldown_threshold,
            model_configs=models,
            execution_id=f"{plan['epoch_id']}-{block}",
            experiment_conditions=list(PRIMARY_CONDITIONS),
            method_level_matrix=block == "forced",
            target_method=None,
            experiment_block=block,
            guardrail_configurations=[(first["guardrail_retry_enabled"], first["guardrail_handling"])],
            run_output_dir_factory=child_directory,
            llm_max_concurrency=config.llm_max_concurrency,
            llm_runtime_config=asdict(config.llm_runtime),
            llm_cache_enabled=config.llm_cache,
            llm_role_configs={role: asdict(settings) for role, settings in config.llm_runtime.roles.items()},
            scoring_mode=config.scoring_mode,
            scoring_evaluator=config.scoring_evaluator,
            scoring_rubric_version=config.scoring_rubric_version,
            scoring_profile=config.scoring_profile,
            scoring_oracles=config.scoring_oracles,
            scoring_policy_epoch=config.scoring_policy_epoch,
            token_price_schedule=config.token_price_schedule,
            source_hashes_sha256=plan["source_hashes_sha256"],
            payload_policy_snapshot=plan.get("payload_policy_snapshot"),
            fixture_id=config.fixture_id,
            protocol_version=config.protocol_version,
            # Only the exact validated operator documents are evidence; plan
            # provenance (source path/digests) stays outside this envelope.
            fixture_restoration_evidence={
                str(level): dict(document)
                for level, document in (
                    (plan["constraints"].get("fixture_restoration") or {}).get("by_level") or {}
                ).items()
            },
        )
    except Exception as exc:  # noqa: BLE001 - attempt failure must be retained truthfully
        receipt.update({
            "status": "failed",
            "observed": 0,
            "attempted_runs": counter["n"],
            "error": f"{type(exc).__name__}: {exc}",
        })
        _atomic_json(block_root / "block-run-receipt.json", receipt)
        raise
    if not isinstance(artifacts, list) or not isinstance(aggregate, Mapping):
        raise ValueError("matrix runner did not return artifacts and an aggregate")
    aggregate_path = block_root / f"{aggregate['execution_id']}.matrix.json"
    if not aggregate_path.is_file():
        receipt.update({
            "status": "failed",
            "observed": len(artifacts),
            "attempted_runs": counter["n"],
            "execution_id": aggregate.get("execution_id"),
            "error": "aggregate_missing_after_matrix_run",
        })
        _atomic_json(block_root / "block-run-receipt.json", receipt)
        raise ValueError(f"block {block!r} produced no aggregate at {aggregate_path}")
    reconciliation = _reconcile_coordinates(coordinates, artifacts)
    receipt.update({
        "status": "completed",
        "observed": len(artifacts),
        "attempted_runs": counter["n"],
        "aggregate_path": str(aggregate_path),
        "aggregate_sha256": _file_hash(aggregate_path),
        "execution_id": aggregate.get("execution_id"),
        "coordinate_reconciliation": {
            key: reconciliation[key]
            for key in ("planned", "observed", "matched", "missing", "extra")
        },
        "coordinate_reconciliation_path": str(block_root / "coordinate-reconciliation.json"),
    })
    _atomic_json(block_root / "coordinate-reconciliation.json", reconciliation)
    _atomic_json(block_root / "block-run-receipt.json", receipt)
    return receipt, artifacts, attempt_directories, aggregate


def _coordinate_axes(row: Mapping[str, Any]) -> tuple[Any, ...]:
    """Return the exact plan/run identity axes used for reconciliation."""
    return (
        row.get("provider"),
        row.get("surface"),
        row.get("security_level"),
        row.get("payload_mode"),
        row.get("experiment_condition"),
        row.get("target_method"),
        row.get("repeat_index"),
    )


def _reconcile_coordinates(
    planned: list[dict[str, Any]], artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Map observed run artifacts to the plan's exact coordinates.

    Every planned coordinate must be observed exactly once.  Missing, extra or
    duplicate runs stay visible; they are never replaced, zero-filled, or
    collapsed into the planned count.
    """
    by_axes: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in planned:
        by_axes.setdefault(_coordinate_axes(row), []).append(row)
    observed: list[dict[str, Any]] = []
    matched: set[str] = set()
    duplicates: list[str] = []
    extra: list[dict[str, Any]] = []
    for artifact in artifacts:
        axes = _coordinate_axes(artifact)
        candidates = [row for row in by_axes.get(axes, [])
                      if row.get("coordinate_id") not in matched]
        if not candidates:
            known = by_axes.get(axes, [])
            if known and len(known) == 1:
                duplicates.append(str(known[0].get("coordinate_id")))
            extra.append({
                "axes": list(axes),
                "execution_id": artifact.get("execution_id"),
                "run_id": artifact.get("run_id"),
            })
            continue
        coordinate = candidates[0]
        matched.add(str(coordinate.get("coordinate_id")))
        observed.append({
            "coordinate_id": coordinate.get("coordinate_id"),
            "coordinate_index": coordinate.get("coordinate_index"),
            "execution_id": artifact.get("execution_id"),
            "run_id": artifact.get("run_id"),
            "status": artifact.get("status"),
            "axes": list(axes),
        })
    missing = [
        {
            "coordinate_id": row.get("coordinate_id"),
            "coordinate_index": row.get("coordinate_index"),
            "axes": list(_coordinate_axes(row)),
        }
        for row in planned if str(row.get("coordinate_id")) not in matched
    ]
    return {
        "artifact_type": "chapter3_coordinate_reconciliation",
        "planned": len(planned),
        "observed": len(artifacts),
        "matched": len(matched),
        "missing": missing,
        "extra": extra,
        "duplicates": sorted(set(duplicates)),
        "coordinates": observed,
    }


def run_research_plan(plan_path: str | Path, *, output_epoch: str | None = None) -> dict[str, Any]:
    """Verify the frozen plan and execute its declared blocks in canonical order.

    A study may declare only the model-selected ``selection`` block (the
    owner-requested primary matrix) or both blocks.  Execution never adds a
    block: exactly the declared coordinates run, under the frozen config,
    profile, policy and price schedule.  Every planned coordinate is
    reconciled against the observed artifacts, and the epoch writes an
    ``experiment.manifest.json`` for tesis-web discovery.
    """
    plan = verify_plan(plan_path)
    declared_blocks = plan.get("blocks")
    if not isinstance(declared_blocks, Mapping) or "selection" not in declared_blocks:
        raise ValueError("a research plan must declare the selection block")
    block_names = _plan_block_names(plan)
    epoch_root = Path(output_epoch or Path(plan_path).parent)
    declared_output_root = plan.get("output_root")
    if declared_output_root is not None:
        _contained_run_root(
            _repository_root(Path(plan["config_path"])),
            declared_output_root,
            epoch_root,
            source="research plan run",
        )
    receipts: dict[str, Any] = {}
    artifacts: list[dict[str, Any]] = []
    children: list[str] = []
    aggregates: dict[str, Any] = {}
    reconciliations: dict[str, Any] = {}
    summary: dict[str, Any] = {
        "artifact_type": "chapter3_research_run_summary",
        "epoch_id": plan["epoch_id"],
        "planned_counts": plan["planned_counts"],
        "observed_counts": {},
        "blocks": receipts,
        "status": "running",
        "error": None,
        "manifest": None,
        "coordinate_reconciliation": reconciliations,
        "score_epoch": {
            "runtime_provisional": "scoring.v2",
            "thesis_final": plan["constraints"]["scoring_rubric_version"],
            "final_status": "pending_review",
        },
    }
    try:
        for block in block_names:
            receipt, block_artifacts, block_children, aggregate = _run_block(
                plan, block, output_epoch=epoch_root
            )
            receipts[block] = receipt
            summary["observed_counts"][block] = receipt["observed"]
            artifacts.extend(block_artifacts)
            children.extend(block_children)
            if aggregate is not None:
                aggregates[block] = aggregate
            reconciliation_path = Path(receipt["coordinate_reconciliation_path"])
            reconciliations[block] = json.loads(reconciliation_path.read_bytes())
        expected = int(plan["planned_counts"]["total"])
        missing = sum(len(row["missing"]) for row in reconciliations.values())
        extra = sum(len(row["extra"]) for row in reconciliations.values())
        duplicates = sorted({value for row in reconciliations.values()
                             for value in row.get("duplicates") or []})
        summary["coordinate_reconciliation"] = reconciliations
        summary["coordinate_summary"] = {
            "planned": expected,
            "observed": len(artifacts),
            "missing": missing,
            "extra": extra,
            "duplicates": duplicates,
        }
        manifest_path = _write_epoch_manifest(
            epoch_root, plan=plan,
            artifacts=_manifest_artifacts(artifacts, reconciliations),
            children=children,
            aggregate=aggregates.get(block_names[0]),
            status="completed" if not missing and not extra and not duplicates else "incomplete",
        )
        summary["manifest"] = {
            "path": str(manifest_path),
            "sha256": _file_hash(manifest_path),
        }
        if missing or extra or duplicates:
            summary["status"] = "incomplete"
            summary["error"] = (
                f"coordinate reconciliation failed: missing={missing} extra={extra} "
                f"duplicates={duplicates}"
            )
        else:
            summary["status"] = "completed"
    except Exception as exc:  # noqa: BLE001 - retain the failed attempt, never roll back
        summary.update({"status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        _atomic_json(epoch_root / "research-run-summary.json", summary)
        raise
    _atomic_json(epoch_root / "research-run-summary.json", summary)
    return summary


def _manifest_artifacts(
    artifacts: list[dict[str, Any]], reconciliations: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Attach each run's planned coordinate index for tesis-web binding."""
    by_execution: dict[str, int] = {}
    for reconciliation in reconciliations.values():
        for row in reconciliation.get("coordinates") or []:
            if row.get("execution_id") is not None and row.get("coordinate_index") is not None:
                by_execution[str(row["execution_id"])] = int(row["coordinate_index"])
    projected: list[dict[str, Any]] = []
    for artifact in artifacts:
        execution_id = artifact.get("execution_id")
        index = by_execution.get(str(execution_id)) if execution_id is not None else None
        projected.append(
            {**artifact, "coordinate_index": index} if index is not None else artifact
        )
    return projected


def _write_epoch_manifest(
    epoch_root: Path,
    *,
    plan: Mapping[str, Any],
    artifacts: list[dict[str, Any]],
    children: list[str],
    aggregate: Mapping[str, Any] | None,
    status: str,
) -> Path:
    """Write the epoch-level manifest tesis-web uses for discovery."""
    from tesis.artifact_layout import ExperimentArtifactLayout

    layout = ExperimentArtifactLayout(
        root=epoch_root.resolve(),
        mode="matrix",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    layout.register_children(children)
    return layout.write_manifest(
        config={
            "epoch_id": plan["epoch_id"],
            "plan_sha256": plan.get("plan_sha256"),
            "source_hashes_sha256": plan.get("source_hashes_sha256"),
            "scoring_profile_sha256": (plan.get("constraints") or {}).get(
                "scoring_profile_sha256"
            ),
            "policy_epoch_id": (plan.get("policy_epoch") or {}).get("epoch_id"),
            "payload_mode": (plan.get("constraints") or {}).get("payload_mode"),
            "repeats": (plan.get("constraints") or {}).get("repeats"),
            "target_url": None,
            "scoring_mode": (plan.get("constraints") or {}).get("scoring_mode"),
        },
        artifacts=artifacts,
        aggregate=aggregate,
        status=status,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze or run the Chapter 3 declared-block research plan")
    subparsers = parser.add_subparsers(dest="command", required=True)
    freeze = subparsers.add_parser("freeze-profile", help="re-freeze a pilot profile for a new declared epoch")
    freeze.add_argument("--config", default="config.yaml")
    freeze.add_argument("--candidate-profile", required=True)
    freeze.add_argument("--output-epoch", required=True)
    freeze.add_argument("--epoch-id", required=True)
    freeze.add_argument("--repeats", type=int, default=MIN_REPEATS)
    freeze.add_argument("--providers", nargs="*")
    freeze.add_argument("--fixture-restoration", action="append", default=None)
    plan_parser = subparsers.add_parser("plan", help="write and freeze the declared-block plan")
    plan_parser.add_argument("--config", required=True)
    plan_parser.add_argument("--output-epoch", required=True)
    plan_parser.add_argument("--epoch-id", required=True)
    plan_parser.add_argument("--repeats", type=int, default=MIN_REPEATS)
    plan_parser.add_argument("--providers", nargs="*")
    plan_parser.add_argument(
        "--research-config",
        help=(
            "declared study contract (for example "
            "config/research/autoresearch-primary-study-2026-10-31.json); "
            "selection-only contracts execute one block"
        ),
    )
    run_parser = subparsers.add_parser("run", help="verify and execute a frozen plan (live DVWA/provider)")
    run_parser.add_argument("--manifest", required=True)
    run_parser.add_argument("--output-epoch")
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze-profile":
            result = freeze_ranking_profile(
                config_path=args.config,
                candidate_profile_path=args.candidate_profile,
                output_epoch=args.output_epoch,
                epoch_id=args.epoch_id,
                repeats=args.repeats,
                providers=args.providers,
                fixture_restoration_paths=args.fixture_restoration,
            )
            print(json.dumps({"status": "frozen", **{k: result[k] for k in (
                "epoch_id", "config_path", "frozen_profile", "frozen_profile_sha256")}}, sort_keys=True))
            return 0
        if args.command == "plan":
            result = build_research_plan(
                config_path=args.config,
                output_epoch=args.output_epoch,
                epoch_id=args.epoch_id,
                repeats=args.repeats,
                providers=args.providers,
                research_config_path=args.research_config,
            )
            print(json.dumps({
                "status": "planned",
                "plan": str(Path(args.output_epoch) / "research-plan.json"),
                "plan_sha256": result["plan_sha256"],
                "planned_counts": result["planned_counts"],
            }, sort_keys=True))
            return 0
        result = run_research_plan(args.manifest, output_epoch=args.output_epoch)
        print(json.dumps({
            "status": "completed",
            "epoch_id": result["epoch_id"],
            "observed_counts": result["observed_counts"],
        }, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Research plan {args.command} failed: {type(exc).__name__}: {exc}\n")


__all__ = [
    "BLOCKS",
    "FIXTURE_RESTORATION_KINDS",
    "FIXTURE_RESTORATION_POLICY_VERSION",
    "FIXTURE_RESTORATION_REQUIRED_KEYS",
    "FIXTURE_RESTORATION_STATES",
    "FORCED_TARGET",
    "MIN_REPEATS",
    "PRIMARY_CONDITIONS",
    "PRIMARY_PAYLOAD_MODE",
    "PRIMARY_REASONING_EFFORT",
    "REQUIRED_FROZEN_INPUTS",
    "RESEARCH_CONFIG_VERSION",
    "RESEARCH_PLAN_VERSION",
    "SELECTION_TARGET",
    "SOURCE_IDENTITY_VERSION",
    "build_research_plan",
    "freeze_ranking_profile",
    "load_fixture_restoration",
    "load_research_config",
    "planned_coordinates",
    "run_research_plan",
    "source_identity",
    "source_tree_hashes",
    "verify_fixture_restoration",
    "verify_plan",
]


if __name__ == "__main__":
    raise SystemExit(main())
