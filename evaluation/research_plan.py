"""Declared Chapter 3 research plan: two blocks, frozen inputs, no silent pooling.

The frozen ``evaluation/scoring_v4_matrix.py`` remains untouched. This module
declares the *new* primary study described by the Chapter 3 handoff:

* ``selection``: ``target_method=None`` so the model chooses a method;
* ``forced``: every registered method is forced for payload/agent coverage.

Both blocks keep the two primary hybrid conditions and at least three repeats.
A plan freezes config/profile/oracle/policy/source identities before execution
and refuses to run when they drift. Runtime aggregates remain provisional; final
summaries come from review receipts in ``evaluation.research_analysis``.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
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
from tesis.config_loader import dump_yaml_config, load_yaml_config, load_and_resolve_config

RESEARCH_PLAN_VERSION = "chapter3-research-plan.v2"
RESEARCH_CONFIG_VERSION = "chapter3-research-config.v1"
MIN_REPEATS = 3
PRIMARY_CONDITIONS: tuple[str, ...] = ("linear_hybrid", "akg_guided_hybrid")
PRIMARY_PAYLOAD_MODE = "hybrid"
BLOCKS: tuple[str, ...] = ("selection", "forced")
SELECTION_TARGET = None
FORCED_TARGET = "per_method"
SOURCE_ROOTS = ("agents", "core", "evaluation", "foundation", "llm", "tesis")
TOP_LEVEL_SOURCES = ("config.yaml", "pyproject.toml", "uv.lock")
SOURCE_SUFFIXES = {".py", ".yaml", ".yml", ".json"}
RESEARCH_CONFIG_KEYS = frozenset({
    "research_config_version", "epoch_id", "primary_conditions", "payload_mode",
    "blocks", "repeats", "levels", "surfaces", "design", "scoring",
    "frozen_inputs_required", "fixture_restoration",
})
OPTIONAL_RESEARCH_CONFIG_KEYS = frozenset({"fixture_restoration"})
REQUIRED_FROZEN_INPUTS = (
    "scoring_profile", "scoring_oracles", "scoring_policy_epoch",
    "token_price_schedule", "fixture_id", "protocol_version", "candidate_budget",
)


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
    if not isinstance(conditions, list) or sorted(set(conditions)) != sorted(PRIMARY_CONDITIONS) or len(conditions) != len(set(conditions)):
        raise ValueError("research config must declare exactly both primary conditions")
    if document.get("payload_mode") != PRIMARY_PAYLOAD_MODE:
        raise ValueError("research config must declare the hybrid primary payload mode")
    if type(document.get("epoch_id")) is not str or not document["epoch_id"].strip():
        raise ValueError("research config requires an explicit epoch_id")
    if type(document.get("repeats")) is not int or document["repeats"] < MIN_REPEATS:
        raise ValueError(f"research config requires at least {MIN_REPEATS} repeats")
    blocks = document.get("blocks")
    if not isinstance(blocks, dict) or sorted(blocks) != sorted(BLOCKS):
        raise ValueError("research config must declare exactly the selection and forced blocks")
    if blocks["selection"].get("target_method") is not None:
        raise ValueError("the selection block must declare target_method=None")
    if blocks["forced"].get("target_method") != FORCED_TARGET:
        raise ValueError("the forced block must declare per-method targets")
    levels = document.get("levels")
    if not isinstance(levels, list) or not levels or any(level not in SECURITY_LEVELS for level in levels):
        raise ValueError("research config levels must be known security levels")
    surfaces = document.get("surfaces")
    if not isinstance(surfaces, list) or not surfaces or any(surface not in SURFACES for surface in surfaces):
        raise ValueError("research config surfaces must be known surfaces")
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
        result[path.resolve().relative_to(repository_root.resolve()).as_posix()] = _file_hash(path)
    return result


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


def freeze_ranking_profile(
    *,
    config_path: str,
    candidate_profile_path: str,
    output_epoch: str,
    epoch_id: str,
    repeats: int = MIN_REPEATS,
    providers: list[str] | None = None,
) -> dict[str, Any]:
    """Re-freeze a pilot-derived profile for a new, explicitly declared epoch.

    Content (fit predicates, request counts, protocol references) is preserved;
    only identity/timestamps and the lineage hash change. The source profile's
    fixture, protocol, and candidate budget must match the current config.
    """
    if repeats < MIN_REPEATS:
        raise ValueError(f"Chapter 3 requires at least {MIN_REPEATS} repeats")
    config = load_and_resolve_config(config_path=config_path, cli_args={})
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
    if epoch_root.exists() and any(epoch_root.iterdir()):
        raise ValueError("output epoch must be new or empty")
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
    raw["fixture_id"] = config.fixture_id
    raw["protocol_version"] = config.protocol_version
    raw["candidate_budget"] = config.candidate_budget
    raw["repeats"] = repeats
    raw["payload_mode"] = PRIMARY_PAYLOAD_MODE
    raw["payload_modes"] = [PRIMARY_PAYLOAD_MODE]
    if providers:
        raw["providers"] = list(providers)
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
    """Build and freeze the two-block plan without executing anything."""
    resolved_config = Path(config_path).resolve()
    declaration: dict[str, Any] | None = None
    if research_config_path:
        declaration = load_research_config(research_config_path)
        if declaration["epoch_id"] != epoch_id:
            raise ValueError("--epoch-id must match the declared research config epoch")
        repeats = declaration["repeats"]
        conditions = list(declaration["primary_conditions"])
        if declaration["payload_mode"] != PRIMARY_PAYLOAD_MODE:
            raise ValueError("the declared research config payload mode is not supported")
    config = load_and_resolve_config(config_path=str(resolved_config), cli_args={})
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
    chosen_providers = list(providers or config.providers or [config.provider])
    chosen_levels = list(declaration["levels"] if declaration else config.levels or SECURITY_LEVELS)
    chosen_surfaces = list(declaration["surfaces"] if declaration else config.surfaces or SURFACES)
    if not chosen_providers:
        raise ValueError("a research plan requires at least one model profile")
    guardrails = [(config.evasion_enabled, config.evasion_mode)]
    blocks: dict[str, list[dict[str, Any]]] = {"selection": [], "forced": []}
    for block in BLOCKS:
        index = 0
        for provider in sorted(chosen_providers):
            for surface in sorted(chosen_surfaces):
                methods = [None] if block == "selection" else list(METHODS_BY_SURFACE[surface])
                for level in sorted(chosen_levels):
                    for condition in sorted(chosen_conditions):
                        for method in methods:
                            for repeat_index in range(repeats):
                                coordinate = {
                                    "coordinate_index": index,
                                    "block": block,
                                    "provider": provider,
                                    "surface": surface,
                                    "security_level": level,
                                    "payload_mode": PRIMARY_PAYLOAD_MODE,
                                    "experiment_condition": condition,
                                    "target_method": method,
                                    "repeat_index": repeat_index,
                                    "candidate_budget": config.candidate_budget,
                                    "guardrail_retry_enabled": guardrails[0][0],
                                    "guardrail_handling": guardrails[0][1],
                                    "fixture_id": config.fixture_id,
                                    "protocol_version": config.protocol_version,
                                    "policy_epoch_id": epoch_id,
                                    "status": "planned",
                                }
                                coordinate["coordinate_id"] = _coordinate_id(coordinate)
                                blocks[block].append(coordinate)
                                index += 1
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
            "scoring_profile_sha256": _canonical_profile_sha(profile),
            "payload_policy_snapshot_sha256": policy_snapshot["snapshot_sha256"],
            "scoring_oracles_sha256": evidence_hash(config.scoring_oracles),
            "token_price_schedule_sha256": evidence_hash(config.token_price_schedule),
            "guardrail_retry_enabled": guardrails[0][0],
            "guardrail_handling": guardrails[0][1],
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
        "planned_counts": {
            "selection": len(blocks["selection"]),
            "forced": len(blocks["forced"]),
            "total": len(blocks["selection"]) + len(blocks["forced"]),
        },
    }
    plan["plan_sha256"] = _json_hash(plan)
    epoch_root = Path(output_epoch)
    if epoch_root.exists() and any(epoch_root.iterdir()):
        raise ValueError("output epoch must be new or empty")
    _atomic_json(epoch_root / "payload-policy-snapshot.json", policy_snapshot)
    _atomic_json(epoch_root / "research-plan.json", plan)
    return plan


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
    return plan


def _run_block(plan: dict[str, Any], block: str, *, output_epoch: Path) -> dict[str, Any]:
    """Execute one declared block and always record a truthful receipt."""
    from dataclasses import asdict

    from evaluation.multi_llm_runner import run_provider_matrix

    config = load_and_resolve_config(config_path=plan["config_path"], cli_args={})
    coordinates = plan["blocks"][block]
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
    receipt = {
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
    receipt.update({
        "status": "completed",
        "observed": len(artifacts),
        "attempted_runs": counter["n"],
        "aggregate_path": str(aggregate_path),
        "aggregate_sha256": _file_hash(aggregate_path),
        "execution_id": aggregate.get("execution_id"),
    })
    _atomic_json(block_root / "block-run-receipt.json", receipt)
    return receipt


def run_research_plan(plan_path: str | Path, *, output_epoch: str | None = None) -> dict[str, Any]:
    """Verify the frozen plan, execute both blocks, and write run receipts."""
    plan = verify_plan(plan_path)
    epoch_root = Path(output_epoch or Path(plan_path).parent)
    receipts: dict[str, Any] = {}
    summary: dict[str, Any] = {
        "artifact_type": "chapter3_research_run_summary",
        "epoch_id": plan["epoch_id"],
        "planned_counts": plan["planned_counts"],
        "observed_counts": {},
        "blocks": receipts,
        "status": "running",
        "error": None,
        "score_epoch": {
            "runtime_provisional": "scoring.v2",
            "thesis_final": plan["constraints"]["scoring_rubric_version"],
            "final_status": "pending_review",
        },
    }
    try:
        for block in BLOCKS:
            receipts[block] = _run_block(plan, block, output_epoch=epoch_root)
            summary["observed_counts"][block] = receipts[block]["observed"]
    except Exception as exc:  # noqa: BLE001 - retain the failed attempt, never roll back
        summary.update({"status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        _atomic_json(epoch_root / "research-run-summary.json", summary)
        raise
    summary["status"] = "completed"
    _atomic_json(epoch_root / "research-run-summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze or run the Chapter 3 two-block research plan")
    subparsers = parser.add_subparsers(dest="command", required=True)
    freeze = subparsers.add_parser("freeze-profile", help="re-freeze a pilot profile for a new declared epoch")
    freeze.add_argument("--config", default="config.yaml")
    freeze.add_argument("--candidate-profile", required=True)
    freeze.add_argument("--output-epoch", required=True)
    freeze.add_argument("--epoch-id", required=True)
    freeze.add_argument("--repeats", type=int, default=MIN_REPEATS)
    freeze.add_argument("--providers", nargs="*")
    plan_parser = subparsers.add_parser("plan", help="write and freeze the two-block plan")
    plan_parser.add_argument("--config", required=True)
    plan_parser.add_argument("--output-epoch", required=True)
    plan_parser.add_argument("--epoch-id", required=True)
    plan_parser.add_argument("--repeats", type=int, default=MIN_REPEATS)
    plan_parser.add_argument("--providers", nargs="*")
    plan_parser.add_argument(
        "--research-config",
        help="declared study contract (config/research/chapter3_study.json)",
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
