"""Frozen plan and explicit launcher for the scoring.v4 fresh matrix.

Planning is offline. The separate ``run`` command verifies the frozen inputs
again before delegating the fixed 108-coordinate design to multi_llm_runner.
"""
from __future__ import annotations

from core.run_status import terminal_status, STATUS_FIELDS

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from core.state import METHODS_BY_SURFACE
from evaluation.reporter import write_json_report
from evaluation.scoring_evidence import evidence_hash, validate_evidence_config
from tesis.artifact_repository import new_execution_id
from tesis.config_loader import load_and_resolve_config, load_yaml_config
from tesis.runtime_events import redact_secrets


SCHEMA_VERSION = "scoring-v4-fresh-matrix-plan.v1"
PROVIDER = "openai_compatible"
CONDITIONS = ("akg_guided_hybrid", "linear_hybrid")
SURFACES = ("access_control", "brute_force", "sqli")
LEVELS = ("high", "low", "medium")
PAYLOAD_MODES = ("hybrid", "llm_mutation_only")
OUTPUT_PREFIX = "scoring-v4-remediation-"
SOURCE_ROOTS = ("agents", "core", "evaluation", "foundation", "llm", "tesis")
SOURCE_SUFFIXES = {".py", ".yaml", ".yml", ".json", ".txt", ".toml", ".md"}
TOP_LEVEL_SOURCES = ("pyproject.toml", "uv.lock")


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(encoded.encode("utf-8")).hexdigest()


def _file_hash(path: Path) -> str:
    try:
        return sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ValueError(f"Cannot hash pinned input: {path}") from exc


def _fixture_policy_pin(path: Path, *, fixture_id: str, protocol_version: str,
                        target_url: str) -> dict:
    path = path.resolve(strict=True)
    try:
        evidence = json.loads(path.read_bytes())
        binding = evidence["deployed_source_binding"]
        source_path = Path(binding["readable_mount"]).resolve(strict=True)
        helper_path = Path(binding["auth_helper_path"]).resolve(strict=True)
        source_hash = binding["locally_verified_worktree_sha256"]
        helper_hash = binding["auth_helper_worktree_sha256"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Cannot read deployed fixture policy evidence") from exc
    if (evidence.get("fixture_id") != fixture_id or
            evidence.get("protocol_version") != protocol_version or
            evidence.get("target_url") != target_url):
        raise ValueError("Deployed fixture policy does not match the matrix configuration")
    if (not binding.get("hash_match") or
            binding.get("operator_supplied_sha256") != source_hash or
            _file_hash(source_path) != source_hash or
            _file_hash(helper_path) != helper_hash):
        raise ValueError("Deployed fixture source changed or its hash is unverified")
    if not isinstance(evidence.get("permission_matrix"), list) or not evidence["permission_matrix"]:
        raise ValueError("Deployed fixture policy has no permission matrix")
    return {
        "path": str(path), "sha256": _file_hash(path),
        "security_php_path": str(source_path), "security_php_sha256": source_hash,
        "auth_helper_path": str(helper_path), "auth_helper_sha256": helper_hash,
        "dvwa_git_head": binding.get("dvwa_git_head"),
    }


def _source_hashes(repository_root: Path) -> dict[str, str]:
    paths = set()
    for source_root in SOURCE_ROOTS:
        directory = repository_root / source_root
        if directory.exists():
            paths.update(
                path for path in directory.rglob("*")
                if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
                and "__pycache__" not in path.parts
            )
    paths.update(repository_root / name for name in TOP_LEVEL_SOURCES
        if (repository_root / name).is_file())
    paths.add(Path(__file__).resolve())
    result = {}
    for path in sorted(paths):
        try:
            relative = path.resolve().relative_to(repository_root.resolve()).as_posix()
        except ValueError as exc:
            raise ValueError("Runtime sources must remain inside the repository") from exc
        result[relative] = _file_hash(path)
    return result


def _config_input_hashes(config_path: Path, raw_config: dict, config) -> dict:
    inputs = {
        "config": {"path": str(config_path), "sha256": _file_hash(config_path)},
        "scoring_profile": {"content_sha256": evidence_hash(config.scoring_profile)},
        "scoring_oracles": {"content_sha256": evidence_hash(config.scoring_oracles)},
        "external_files": [],
    }
    for key in ("scoring_profile", "scoring_oracles"):
        value = raw_config.get(key)
        if isinstance(value, str):
            path = Path(value)
            if not path.is_absolute():
                path = config_path.parent / path
            path = path.resolve(strict=True)
            inputs["external_files"].append({"kind": key, "path": str(path), "sha256": _file_hash(path)})
    inputs["external_files"].sort(key=lambda item: (item["kind"], item["path"]))
    return inputs


def _target_pin(target_url: str) -> dict:
    parsed = urlsplit(target_url)
    host = (parsed.hostname or "").strip().lower()
    if parsed.scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
        raise ValueError("Target must be an HTTP(S) DVWA URL without embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Target URL must not contain query or fragment data")
    try:
        address = ipaddress.ip_address(host)
        allowed_host = address.is_private or address.is_loopback
    except ValueError:
        allowed_host = host == "localhost" or host.endswith((".local", ".test", ".internal"))
    if not allowed_host:
        raise ValueError("Fresh-matrix target must resolve to a local or private DVWA host")
    port = f":{parsed.port}" if parsed.port else ""
    safe_url = urlunsplit((parsed.scheme, f"{host}{port}", parsed.path.rstrip("/"), "", ""))
    return {"url": safe_url, "host": host, "path": parsed.path.rstrip("/")}


def _planned_coordinates(*, guardrail_enabled: bool, guardrail_mode: str) -> list[dict]:
    coordinates = []
    for surface in SURFACES:
        for level in LEVELS:
            for payload_mode in PAYLOAD_MODES:
                for condition in CONDITIONS:
                    for method in METHODS_BY_SURFACE[surface]:
                        identity = {
                            "provider": PROVIDER,
                            "experiment_condition": condition,
                            "surface": surface,
                            "target_method": method,
                            "security_level": level,
                            "payload_mode": payload_mode,
                            "repeat_index": 0,
                            "guardrail_retry_enabled": guardrail_enabled,
                            "guardrail_handling": guardrail_mode,
                        }
                        coordinates.append({
                            "coordinate_index": len(coordinates) + 1,
                            "coordinate_id": "coord-" + _canonical_hash(identity)[:16],
                            **identity,
                        })
    ids = [row["coordinate_id"] for row in coordinates]
    if len(coordinates) != 108 or len(set(ids)) != 108:
        raise ValueError("The frozen fresh-matrix design must contain 108 unique coordinates")
    return coordinates


def _source_records(sources: list[dict], *, fixture_id: str, protocol_version: str) -> list[dict]:
    return [{
        "source_id": source["source_id"],
        "origin": source["origin"],
        "sha256": source["sha256"],
        "fixture_id": source["document"].get("fixture_id"),
        "protocol_version": source["document"].get("protocol_version"),
        "matches_fixture": source["document"].get("fixture_id") == fixture_id,
        "matches_protocol": source["document"].get("protocol_version") == protocol_version,
    } for source in sources]


def _validate_config(config) -> dict:
    expected_levels = set(LEVELS)
    if config.provider != PROVIDER or set(config.providers) != {PROVIDER} or len(config.providers) != 1:
        raise ValueError("The frozen matrix must use only the openai_compatible provider")
    if set(config.levels) != expected_levels or set(config.surfaces) != set(SURFACES):
        raise ValueError("Config must explicitly freeze all three levels and supported DVWA surfaces")
    if set(config.payload_modes) != set(PAYLOAD_MODES) or config.repeats != 1:
        raise ValueError("Config must freeze hybrid and llm_mutation_only with one repeat")
    if config.target_method:
        raise ValueError("Config target_method must be unset for the nine-method matrix")
    if not config.matrix:
        raise ValueError("Config must explicitly select matrix mode")
    if config.scoring_mode != "ai" or config.scoring_rubric_version != "scoring.v4":
        raise ValueError("Fresh matrix requires AI review with the scoring.v4 rubric")
    if not config.fixture_id or not config.protocol_version:
        raise ValueError("Config must pin fixture_id and protocol_version")

    profile = config.scoring_profile
    oracles = config.scoring_oracles
    validate_evidence_config(config.scoring_rubric_version, profile, oracles)
    if not profile or not oracles:
        raise ValueError("Config must include a hash-validated ranking profile and scoring oracle sources")
    if profile.get("fixture_id") != config.fixture_id or profile.get("protocol_version") != config.protocol_version:
        raise ValueError("Config fixture/protocol pins must match the ranking profile")
    if profile.get("candidate_budget") != config.candidate_budget:
        raise ValueError("Config candidate budget must match the frozen ranking profile")
    all_sources = [*profile.get("sources", []), *oracles]
    if any(source.get("origin") != "operator_fixture" for source in all_sources):
        raise ValueError("Live matrix profile and oracle pins must use operator_fixture sources")
    if not any(source["document"].get("fixture_id") == config.fixture_id for source in all_sources):
        raise ValueError("Pinned evidence sources do not bind the configured fixture")
    if not any(source["document"].get("protocol_version") == config.protocol_version for source in all_sources):
        raise ValueError("Pinned evidence sources do not bind the configured protocol")

    required_scenarios = {f"{surface}:{level}" for surface in SURFACES for level in LEVELS}
    if set(profile.get("scenarios", {})) != required_scenarios:
        raise ValueError("Ranking profile must cover all nine surface/security-level scenarios")

    model = config.models.get(PROVIDER)
    if model is None or model.provider != PROVIDER or not model.model_name:
        raise ValueError("Config must pin an openai_compatible model profile")
    if config.model_profile not in (None, PROVIDER):
        raise ValueError("Global model profile must not select another provider")
    if any(role.model_profile not in (None, PROVIDER) for role in config.llm_runtime.roles.values()):
        raise ValueError("LLM role profiles must follow openai_compatible")
    evaluator = config.scoring_evaluator
    if evaluator.get("provider") != PROVIDER or evaluator.get("model") != model.model_name:
        raise ValueError("AI evaluator must use the pinned openai_compatible model")

    pending_references = [
        {"scenario": scenario, "method": method, "reason": entry.get("reference_reason")}
        for scenario, entries in profile["scenarios"].items()
        for method, entry in entries.items()
        if entry.get("reference_status") == "pending"
    ]
    return {
        "target": _target_pin(config.target_url),
        "profile": {
            "profile_id": profile["profile_id"], "version": profile["version"],
            "sha256": profile["sha256"], "content_sha256": evidence_hash(profile),
            "candidate_budget": profile["candidate_budget"],
        },
        "oracle_sources": _source_records(oracles, fixture_id=config.fixture_id,
            protocol_version=config.protocol_version),
        "profile_sources": _source_records(profile["sources"], fixture_id=config.fixture_id,
            protocol_version=config.protocol_version),
        "fixture_id": config.fixture_id,
        "protocol_version": config.protocol_version,
        "model": {"provider": PROVIDER, "name": model.model_name,
            "base_url": _target_pin(model.base_url)["url"] if model.base_url and urlsplit(model.base_url).hostname in {
                "localhost", "127.0.0.1", "::1"} else None},
        "evaluator": {"provider": evaluator["provider"], "model": evaluator["model"],
            "max_attempts": evaluator["max_attempts"], "max_tokens": evaluator["max_tokens"],
            "timeout": evaluator["timeout"]},
        "pending_ranking_references": pending_references,
        "cache_scope": config.llm_runtime.cache_scope,
        "llm_max_concurrency": config.llm_runtime.max_concurrency,
    }


def _apply_evaluator_budget(config, requested_max_tokens: int | None) -> dict:
    source_max_tokens = config.scoring_evaluator.get("max_tokens")
    if requested_max_tokens is not None:
        if (type(requested_max_tokens) is not int or
                type(source_max_tokens) is not int or
                not source_max_tokens < requested_max_tokens <= 8192):
            raise ValueError("Evaluator token budget must exceed the source budget and be at most 8192")
        config.scoring_evaluator = {
            **config.scoring_evaluator, "max_tokens": requested_max_tokens,
        }
    return {
        "source_max_tokens": source_max_tokens,
        "requested_max_tokens": config.scoring_evaluator.get("max_tokens"),
        "override_reason": "observed_length_truncation" if requested_max_tokens is not None else None,
    }


def _load_snapshot(config_path: Path, repository_root: Path,
                   *, evaluator_max_tokens_override: int | None = None) -> tuple[object, dict]:
    config_path = config_path.resolve(strict=True)
    try:
        config_path.relative_to(repository_root.resolve())
    except ValueError as exc:
        raise ValueError("Config must be inside the repository") from exc
    raw_config = load_yaml_config(config_path)
    config = load_and_resolve_config(config_path=str(config_path), cli_args={})
    evaluator_budget = _apply_evaluator_budget(config, evaluator_max_tokens_override)
    pins = _validate_config(config)
    pins["evaluator_budget"] = evaluator_budget
    input_hashes = _config_input_hashes(config_path, raw_config, config)
    resolved_settings = redact_secrets(asdict(config))
    return config, {"pins": pins, "input_hashes": input_hashes,
        "resolved_execution_settings": resolved_settings,
        "source_hashes": _source_hashes(repository_root),
        "config_fingerprint": _canonical_hash({
            "target": pins["target"], "profile": pins["profile"],
            "oracle_sources": pins["oracle_sources"], "fixture_id": pins["fixture_id"],
            "protocol_version": pins["protocol_version"], "evaluator": pins["evaluator"],
            "resolved_execution_settings": resolved_settings,
        })}


def _validate_output_epoch(path: Path, repository_root: Path, *, must_not_exist: bool) -> Path:
    path = path.resolve()
    validation_root = (repository_root / "results" / "validation").resolve()
    try:
        relative = path.relative_to(validation_root)
    except ValueError as exc:
        raise ValueError("Output epoch must be under results/validation") from exc
    if not relative.parts or not relative.parts[0].startswith(OUTPUT_PREFIX):
        raise ValueError("Output epoch must use a new scoring-v4-remediation-* root")
    if must_not_exist and path.exists():
        raise ValueError("Output epoch already exists; choose a new epoch to preserve prior artifacts")
    return path


def create_plan(config_path: Path, output_epoch: Path,
                *, fixture_policy_evidence: Path,
                evaluator_max_tokens_override: int | None = None) -> dict:
    repository_root = Path(__file__).resolve().parents[1]
    output_epoch = _validate_output_epoch(output_epoch, repository_root, must_not_exist=True)
    config_path = config_path.resolve(strict=True)
    config, snapshot = _load_snapshot(config_path, repository_root,
        evaluator_max_tokens_override=evaluator_max_tokens_override)
    fixture_policy = _fixture_policy_pin(fixture_policy_evidence,
        fixture_id=config.fixture_id, protocol_version=config.protocol_version,
        target_url=config.target_url)
    coordinates = _planned_coordinates(
        guardrail_enabled=config.evasion_enabled,
        guardrail_mode=config.evasion_mode,
    )
    plan = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "scoring_v4_fresh_matrix_pre_run_manifest",
        "status": "planned",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "repository_root": str(repository_root),
        "output_epoch": str(output_epoch),
        "matrix_execution_id": new_execution_id(),
        "matrix_design": {
            "provider": PROVIDER, "conditions": list(CONDITIONS),
            "surfaces": list(SURFACES), "methods_by_surface": {
                surface: list(METHODS_BY_SURFACE[surface]) for surface in SURFACES},
            "security_levels": list(LEVELS), "payload_modes": list(PAYLOAD_MODES),
            "repeat_indices": [0], "guardrail_retry_enabled": config.evasion_enabled,
            "guardrail_handling": config.evasion_mode,
            "coordinate_count": len(coordinates),
        },
        "pins": snapshot["pins"],
        "resolved_execution_settings": snapshot["resolved_execution_settings"],
        "fixture_policy_evidence": fixture_policy,
        "input_hashes": snapshot["input_hashes"],
        "source_hashes": snapshot["source_hashes"],
        "config_fingerprint": snapshot["config_fingerprint"],
        "execution_policy": {"resume": False, "checkpointing": False,
            "provider_scope": [PROVIDER], "cache_scope": config.llm_runtime.cache_scope,
            "evaluator_max_tokens_override": evaluator_max_tokens_override},
        "planned_identities": coordinates,
    }
    plan["plan_sha256"] = _canonical_hash({key: value for key, value in plan.items()
        if key != "plan_sha256"})
    output_epoch.mkdir(parents=True, exist_ok=False)
    write_json_report(output_epoch / "pre-run-manifest.json", plan)
    return plan


def _verify_plan(manifest_path: Path) -> tuple[dict, object, Path]:
    manifest_path = manifest_path.resolve(strict=True)
    try:
        plan = json.loads(manifest_path.read_bytes())
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError("Cannot read frozen pre-run manifest") from exc
    if not isinstance(plan, dict) or plan.get("schema_version") != SCHEMA_VERSION or plan.get("status") != "planned":
        raise ValueError("Manifest is not an unused scoring.v4 fresh-matrix plan")
    root = Path(plan.get("repository_root", "")).resolve()
    output_epoch = _validate_output_epoch(Path(plan.get("output_epoch", "")), root, must_not_exist=False)
    if manifest_path != output_epoch / "pre-run-manifest.json":
        raise ValueError("Manifest must remain in its planned output epoch")
    if manifest_path.parent != output_epoch:
        raise ValueError("Invalid output epoch manifest location")
    if (output_epoch / "matrix-run-start.json").exists():
        raise ValueError("This plan has already started; use a new output epoch")
    files = [item for item in output_epoch.iterdir()]
    if len(files) != 1 or files[0] != manifest_path:
        raise ValueError("Output epoch must contain only the pre-run manifest before launch")
    config_path = Path(plan["input_hashes"]["config"]["path"])
    config, current = _load_snapshot(config_path, root,
        evaluator_max_tokens_override=plan["execution_policy"].get("evaluator_max_tokens_override"))
    if current["resolved_execution_settings"] != plan.get("resolved_execution_settings"):
        raise ValueError("Resolved execution settings changed or were not frozen; create a new output epoch")
    if current["pins"] != plan["pins"] or current["input_hashes"] != plan["input_hashes"]:
        raise ValueError("Config, ranking profile, oracle, fixture, or protocol pins changed since planning")
    fixture_policy = _fixture_policy_pin(Path(plan["fixture_policy_evidence"]["path"]),
        fixture_id=config.fixture_id, protocol_version=config.protocol_version,
        target_url=config.target_url)
    if fixture_policy != plan["fixture_policy_evidence"]:
        raise ValueError("Deployed fixture source or permission matrix changed since planning")
    if current["source_hashes"] != plan["source_hashes"]:
        raise ValueError("Runtime source hashes changed since planning; create a new output epoch")
    expected_plan_hash = _canonical_hash({key: value for key, value in plan.items() if key != "plan_sha256"})
    if expected_plan_hash != plan.get("plan_sha256"):
        raise ValueError("Pre-run manifest hash mismatch")
    return plan, config, output_epoch


def _run_kwargs(config, plan: dict, layout) -> dict:
    model_config = asdict(config.models[PROVIDER])
    role_configs = {role: asdict(settings) for role, settings in config.llm_runtime.roles.items()}
    guardrails = [(config.evasion_enabled, config.evasion_mode)]
    return {
        "target_url": config.target_url,
        "providers": [PROVIDER],
        "security_levels": list(LEVELS),
        "surfaces": list(SURFACES),
        "payload_modes": list(PAYLOAD_MODES),
        "repeats": 1,
        "max_iterations": config.iterations,
        "candidate_budget": config.candidate_budget,
        "stop_policy": config.stop_policy,
        "coverage_target": config.coverage_target,
        "enriched_reporting": config.enriched_reporting,
        "diagnose": config.diagnose,
        "output_dir": str(layout.root),
        "include_aggregate": True,
        "evasion_enabled": config.evasion_enabled,
        "evasion_mode": config.evasion_mode,
        "evasion_max_retries": config.evasion_max_retries,
        "evasion_cooldown_threshold": config.evasion_cooldown_threshold,
        "guardrail_configurations": guardrails,
        "model_configs": {PROVIDER: model_config},
        "llm_role_configs": role_configs,
        "llm_max_concurrency": config.llm_runtime.max_concurrency,
        "llm_cache_enabled": config.llm_runtime.cache_enabled,
        "llm_cache_scope": config.llm_runtime.cache_scope,
        "resume": False,
        "checkpoint_dir": None,
        # experiment_id is a checkpoint opt-in in the runner. This plan's
        # identity is carried by execution_id and the frozen epoch manifest.
        "experiment_id": None,
        "execution_id": plan["matrix_execution_id"],
        "experiment_condition": CONDITIONS[0],
        "experiment_conditions": list(CONDITIONS),
        "target_method": None,
        "method_level_matrix": True,
        "scoring_mode": config.scoring_mode,
        "scoring_evaluator": dict(config.scoring_evaluator),
        "scoring_rubric_version": config.scoring_rubric_version,
        "scoring_profile": config.scoring_profile,
        "scoring_oracles": config.scoring_oracles,
        "fixture_id": config.fixture_id,
        "protocol_version": config.protocol_version,
        "run_output_dir_factory": layout.child_directory,
    }


def run_plan(manifest_path: Path) -> dict:
    plan, config, output_epoch = _verify_plan(manifest_path)
    from evaluation.multi_llm_runner import run_provider_matrix
    from tesis.artifact_layout import ExperimentArtifactLayout

    started_at = datetime.now(timezone.utc).isoformat()
    write_json_report(output_epoch / "matrix-run-start.json", {
        "artifact_type": "scoring_v4_matrix_start", "status": "started",
        "started_at": started_at, "matrix_execution_id": plan["matrix_execution_id"],
        "plan_sha256": plan["plan_sha256"], "planned_coordinates": 108,
        "fixture_policy_sha256": plan["fixture_policy_evidence"]["sha256"],
        "security_php_sha256": plan["fixture_policy_evidence"]["security_php_sha256"],
    })
    layout = ExperimentArtifactLayout(root=output_epoch, mode="matrix", created_at=started_at)
    run_summary = {"artifact_type": "scoring_v4_matrix_run_summary", "plan_sha256": plan["plan_sha256"]}
    try:
        artifacts, aggregate = run_provider_matrix(**_run_kwargs(config, plan, layout))
        layout.write_manifest(config={
            "provider": PROVIDER,
            "fixture_id": config.fixture_id,
            "protocol_version": config.protocol_version,
            "scoring_profile_sha256": config.scoring_profile["sha256"],
            "scoring_oracle_source_ids": [source["source_id"] for source in config.scoring_oracles],
            "planned_coordinates": 108,
            "plan_sha256": plan["plan_sha256"],
            "fixture_policy_sha256": plan["fixture_policy_evidence"]["sha256"],
        }, artifacts=artifacts, aggregate=aggregate, status=aggregate.get("status"))
        run_summary.update({
            "status": aggregate.get("status", "unknown"),
            **terminal_status(aggregate),
            "totals": aggregate.get("totals", {}),
            "matrix_execution_id": aggregate.get("execution_id"),
            "completed_artifacts": len(artifacts),
            "coordinates": [{
                "coordinate_id": planned["coordinate_id"],
                "execution_id": artifact.get("execution_id"),
                "run_id": artifact.get("run_id"),
                "status": artifact.get("status", "unknown"),
                **terminal_status(artifact),
            } for planned, artifact in zip(plan["planned_identities"], artifacts)],
        })
    except BaseException as exc:
        run_summary.update({"status": "error", "error_type": type(exc).__name__})
        write_json_report(output_epoch / "matrix-run-end.json", {
            "artifact_type": "scoring_v4_matrix_end", "status": "error",
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "matrix_execution_id": plan["matrix_execution_id"],
            "error_type": type(exc).__name__, "plan_sha256": plan["plan_sha256"],
        })
        write_json_report(output_epoch / "matrix-run-summary.json", run_summary)
        raise
    write_json_report(output_epoch / "matrix-run-summary.json", run_summary)
    write_json_report(output_epoch / "matrix-run-end.json", {
        "artifact_type": "scoring_v4_matrix_end", "status": run_summary["status"],
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "matrix_execution_id": plan["matrix_execution_id"],
        **{key: run_summary.get(key) for key in STATUS_FIELDS},
        "completed_artifacts": len(artifacts), "plan_sha256": plan["plan_sha256"],
    })
    return run_summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze or launch the scoring.v4 108-coordinate DVWA matrix")
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan", help="write an offline pre-run manifest")
    plan_parser.add_argument("--config", type=Path, required=True,
        help="explicit config containing the pinned profile, oracles, fixture, and protocol")
    plan_parser.add_argument("--output-epoch", type=Path, required=True,
        help="new results/validation/scoring-v4-remediation-* directory")
    plan_parser.add_argument("--fixture-policy-evidence", type=Path, required=True,
        help="source-hash-bound deployed security.php policy evidence")
    plan_parser.add_argument("--evaluator-max-tokens", type=int,
        help="freeze a larger evaluator response budget after observed length truncation")
    run_parser = subparsers.add_parser("run", help="verify the frozen manifest and call the live matrix API")
    run_parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            plan = create_plan(args.config, args.output_epoch,
                fixture_policy_evidence=args.fixture_policy_evidence,
                evaluator_max_tokens_override=args.evaluator_max_tokens)
            path = Path(plan["output_epoch"]) / "pre-run-manifest.json"
            print(json.dumps({"status": "planned", "manifest": str(path),
                "manifest_sha256": _file_hash(path), "plan_sha256": plan["plan_sha256"],
                "planned_coordinates": plan["matrix_design"]["coordinate_count"],
                "config_sha256": plan["input_hashes"]["config"]["sha256"],
                "source_file_count": len(plan["source_hashes"])}, sort_keys=True))
            return 0
        result = run_plan(args.manifest)
        print(json.dumps({key: result[key] for key in (
            "status", "matrix_execution_id", "completed_artifacts", "plan_sha256")}, sort_keys=True))
        return 0 if str(result.get("status", "error")).lower() in {"success", "cancelled"} else 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Matrix {args.command} failed: {type(exc).__name__}: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
