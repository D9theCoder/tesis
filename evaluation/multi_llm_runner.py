"""Stage 6 matrix runner across providers, surfaces, and security levels."""

from __future__ import annotations

from core.run_status import terminal_status, lifecycle_alias, EXECUTION_STATUSES, SECURITY_OUTCOMES, reason as status_reason, matrix_terminal_status

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from threading import Lock
from time import perf_counter
from typing import Any, Callable

from core.state import METHODS_BY_SURFACE, SECURITY_LEVELS
from core.payload_policy import (
    BUDGET_POLICY_VERSION,
    CONTROL_POLICY_VERSION,
    EXPERIMENT_POLICY_VERSION,
    PAYLOAD_POLICY_VERSION,
    is_supported_payload_mode,
    mode_display_label,
)
from evaluation.metrics import aggregate_runs
from evaluation.research_metrics import SCORING_POLICY_VERSION
from evaluation.scoring_evidence import evidence_hash
from evaluation.reporter import write_json_report
from foundation.http_client import HTTP_PHASES, HTTP_ROLES
from llm.cache_metrics import cache_performance_summary
from llm.provider import SUPPORTED_PROVIDERS, provider_capabilities
from llm.runtime import LLMRuntime, RoleSettings, provider_request_summary
from tesis.artifact_repository import config_fingerprint, new_execution_id
from tesis.config_fields import fixture_evidence_envelope
from tesis.runtime_events import CancellationToken, RunEvent, RuntimeEventSink, redact_secrets

from evaluation.runner import (
    default_source_hashes_sha256,
    default_source_identity,
    fixture_evidence_for_level,
    generation_opportunity_coverage,
    recorded_payload_policy_snapshot,
    run_single_engagement,
)


_EXPERIMENT_CONDITIONS = frozenset({"linear_hybrid", "akg_guided_hybrid"})
_GUARDRAIL_MODES = frozenset({"reactive", "proactive", "disabled"})


def _serialize_role_configs(
    role_configs: dict[str, RoleSettings | dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    """Return JSON-safe role settings for matrix and coordinate artifacts."""
    serialized: dict[str, dict[str, Any]] = {}
    for role, value in (role_configs or {}).items():
        if isinstance(value, RoleSettings):
            serialized[str(role)] = {
                "model_profile": value.model_profile,
                "model_name": value.model_name,
                "temperature": value.temperature,
                "max_tokens": value.max_tokens,
                "structured_output": value.structured_output,
                "reasoning_effort": value.reasoning_effort,
                "max_tokens_default": value.max_tokens_default,
            }
        elif isinstance(value, dict):
            serialized[str(role)] = dict(value)
    return serialized


def _llm_performance_summary_defaults() -> dict[str, Any]:
    """Return the empty telemetry shape used by non-started coordinates."""
    return {
        "calls": 0,
        **provider_request_summary([]),
        **cache_performance_summary([]),
        "invalid_outputs": 0,
        "invalid_output_rate": None,
        "invalid_output_rate_status": "no_calls",
        "peak_llm_concurrency": 0,
        "peak_dvwa_node_concurrency": 0,
        "by_role": {},
        "time_by_role_ms": {},
    }


def _count_event_values(value: Any) -> int:
    """Count an event collection or an already-materialized event count."""
    if value is None:
        return 0
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _artifact_audit_counts(artifact: dict[str, Any]) -> dict[str, int]:
    """Extract audit counters without dropping evidence from failed runs."""
    final_state = artifact.get("final_state")
    if not isinstance(final_state, dict):
        final_state = {}
    report_summary = artifact.get("report", {}).get("summary", {})
    if not isinstance(report_summary, dict):
        report_summary = {}
    performance_summary = artifact.get("llm_performance_summary", {})
    if not isinstance(performance_summary, dict):
        performance_summary = {}

    def first_present(*keys: str) -> int:
        for source in (artifact, final_state, report_summary, performance_summary):
            for key in keys:
                if key in source:
                    return _count_event_values(source.get(key))
        return 0

    containment_value = next(
        (
            source.get("containment_events")
            for source in (artifact, final_state, report_summary)
            if "containment_events" in source
        ),
        [],
    )
    containment_rows = containment_value if isinstance(containment_value, list) else []
    from evaluation.containment import containment_summary
    containment = containment_summary(containment_rows)
    containment_failures = containment["attack_relevant"]

    return {
        "invalid_json_events": first_present("invalid_json_events", "invalid_outputs"),
        "fallback_events": first_present("fallback_events"),
        "containment_events": first_present("containment_events"),
        # Attack-relevant violations only; navigation discards are reported on
        # their own line so the two are never added together (D11).
        "containment_failures": containment_failures,
        "containment_navigation_discards": containment["navigation_discards"],
        "containment_summary": containment,
        "guardrail_activations": first_present(
            "guardrail_activations", "guardrail_activation_count"
        ),
    }


def _run_single_with_payload_kwargs(kwargs: dict[str, Any]) -> dict:
    try:
        return run_single_engagement(**kwargs)
    except TypeError as exc:
        optional_compat = {
            "payload_mode",
            "candidate_budget",
            "event_sink",
            "cancellation_token",
            "execution_id",
            "experiment_condition",
            "experiment_block",
            "target_method",
            "scoring_policy_epoch",
            "token_price_schedule",
            "fixture_restoration_evidence",
            "payload_policy_snapshot",
            "source_hashes_sha256",
            "llm_runtime",
            "llm_role_configs",
            "model_profiles",
            "llm_cache_enabled",
            "resume",
            "checkpoint_dir",
            "experiment_id",
        }
        # Checkpoint opt-in must never be silently dropped: only default-valued
        # flags (resume=False, dir/id None) may be stripped for legacy
        # signatures. Explicit values re-raise instead of running uncheckpointed.
        default_valued_only = {"resume": False, "checkpoint_dir": None, "experiment_id": None}
        rejected = {key for key in optional_compat if key in kwargs and key in str(exc)}
        if not rejected:
            raise
        legacy_kwargs = dict(kwargs)
        for key in rejected:
            if key in default_valued_only and legacy_kwargs[key] != default_valued_only[key]:
                raise
            legacy_kwargs.pop(key, None)
        return _run_single_with_payload_kwargs(legacy_kwargs)


def _build_matrix_aggregate(
    artifacts: list[dict[str, Any]],
    *,
    matrix_max_llm_concurrency: int | None = None,
    payload_policy_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregate matrix children without pooling incompatible coordinates."""
    recorded_payload_policy = (
        payload_policy_snapshot
        if isinstance(payload_policy_snapshot, dict) and payload_policy_snapshot
        else recorded_payload_policy_snapshot()
    )
    derived_providers = sorted({
        str(artifact.get("config", {}).get("provider", "unknown"))
        for artifact in artifacts
    })
    derived_security_levels = sorted({
        str(artifact.get("config", {}).get("security_level", "unknown"))
        for artifact in artifacts
    })
    derived_surfaces = sorted({
        str(artifact.get("config", {}).get("surface", "unknown"))
        for artifact in artifacts
    })
    derived_payload_modes = sorted({
        str(artifact.get("config", {}).get("payload_mode", "static_only"))
        for artifact in artifacts
    })
    derived_conditions = sorted({
        str(artifact.get("config", {}).get("experiment_condition", "linear_hybrid"))
        for artifact in artifacts
    })
    derived_blocks = sorted({
        str(artifact.get("config", {}).get("experiment_block", "selection"))
        for artifact in artifacts
    })
    derived_policy_epochs = sorted({
        str((artifact.get("policy_epoch") or {}).get("epoch_id") or "unset")
        for artifact in artifacts
    })
    derived_repeats = max(
        (
            int(artifact.get("config", {}).get("repeat_index", 0) or 0)
            for artifact in artifacts
        ),
        default=-1,
    ) + 1
    by_provider_surface_level: dict[str, dict[str, dict[str, dict[str, Any]]]] = {}
    by_provider_level: dict[str, dict[str, dict[str, Any]]] = {}
    by_provider: dict[str, dict[str, Any]] = {}

    for artifact in artifacts:
        config = artifact.get("config", {})
        provider = str(config.get("provider", "unknown"))
        surface = str(config.get("surface", "unknown"))
        payload_mode = str(config.get("payload_mode", "static_only"))
        level = str(config.get("security_level", "unknown"))
        status_fields = terminal_status(artifact)
        status = "skipped" if artifact.get("status") == "skipped" else lifecycle_alias(status_fields["execution_status"])
        final_state = artifact.get("final_state", {})
        condition = str(config.get("experiment_condition", "linear_hybrid"))
        block = str(config.get("experiment_block", "selection"))
        target = str(config.get("target_method") or "model-selected")
        policy_epoch_data = artifact.get("policy_epoch") if isinstance(artifact.get("policy_epoch"), dict) else {}
        fallback_fingerprint = str(artifact.get("config_fingerprint") or config_fingerprint(config))
        policy_epoch = str(policy_epoch_data.get("epoch_id") or f"missing-epoch:{fallback_fingerprint}")
        model_identity = str(config.get("model") or config.get("model_profile") or "unknown-model")
        guardrail = f"{bool(config.get('evasion_enabled', False))}:{config.get('evasion_mode', 'reactive')}"
        source_identity = str(
            artifact.get("source_hashes_sha256")
            or config.get("source_hashes_sha256")
            or policy_epoch_data.get("source_hashes_sha256")
            or f"missing-source:{fallback_fingerprint}"
        )
        policy_versions = "/".join(str(value or f"missing-policy:{fallback_fingerprint}") for value in (
            config.get("payload_policy_version"),
            config.get("experiment_policy_version"),
            config.get("scoring_policy_version"),
        ))
        price_hash = evidence_hash(config.get("token_price_schedule") or {})
        group_key = (
            f"{surface}:{model_identity}:{level}:{payload_mode}:{condition}:{block}:{target}:"
            f"{guardrail}:{config.get('fixture_id') or 'no-fixture'}:"
            f"{config.get('protocol_version') or 'no-protocol'}:{policy_epoch}:"
            f"{source_identity}:{policy_versions}:{price_hash}"
        )

        provider_surface = by_provider_surface_level.setdefault(provider, {}).setdefault(
            surface,
            {},
        )
        provider_level = provider_surface.setdefault(
            group_key,
            {
                "runs": 0,
                "statuses": {"success": 0, "error": 0, "skipped": 0, "cancelled": 0},
                "execution_status_counts": dict.fromkeys(EXECUTION_STATUSES, 0),
                "security_outcome_counts": dict.fromkeys(SECURITY_OUTCOMES, 0),
                "total_score": 0,
                "chain_exploits": 0,
                "guardrail_activations": 0,
                "invalid_json_events": 0,
                "fallback_events": 0,
                "containment_events": 0,
                "containment_failures": 0,
                "highest_outcomes": [],
                "iterations": [],
            },
        )
        provider_level_agg = by_provider_level.setdefault(provider, {}).setdefault(
            group_key,
            {
                "runs": 0,
                "statuses": {"success": 0, "error": 0, "skipped": 0, "cancelled": 0},
                "execution_status_counts": dict.fromkeys(EXECUTION_STATUSES, 0),
                "security_outcome_counts": dict.fromkeys(SECURITY_OUTCOMES, 0),
                "total_score": 0,
                "chain_exploits": 0,
                "guardrail_activations": 0,
                "invalid_json_events": 0,
                "fallback_events": 0,
                "containment_events": 0,
                "containment_failures": 0,
                "highest_outcomes": [],
                "iterations": [],
            },
        )
        provider_level["runs"] += 1
        provider_level_agg["runs"] += 1
        repeat_index = config.get("repeat_index")
        if repeat_index is not None:
            if repeat_index not in provider_level.setdefault("repeat_indices", []):
                provider_level["repeat_indices"].append(repeat_index)
            if repeat_index not in provider_level_agg.setdefault("repeat_indices", []):
                provider_level_agg["repeat_indices"].append(repeat_index)
        if status in provider_level["statuses"]:
            provider_level["statuses"][status] += 1
        if status in provider_level_agg["statuses"]:
            provider_level_agg["statuses"][status] += 1

        provider_summary = by_provider.setdefault(
            provider,
            {
                "runs": 0,
                "statuses": {"success": 0, "error": 0, "skipped": 0, "cancelled": 0},
                "execution_status_counts": dict.fromkeys(EXECUTION_STATUSES, 0),
                "security_outcome_counts": dict.fromkeys(SECURITY_OUTCOMES, 0),
                "total_score": 0,
                "chain_exploits": 0,
                "guardrail_activations": 0,
                "invalid_json_events": 0,
                "fallback_events": 0,
                "containment_events": 0,
                "containment_failures": 0,
                "highest_outcomes": [],
                "iterations": [],
                "score_distribution": {bucket: 0 for bucket in range(5)},
            },
        )
        provider_summary["runs"] += 1
        if repeat_index is not None and repeat_index not in provider_summary.setdefault("repeat_indices", []):
            provider_summary["repeat_indices"].append(repeat_index)
        if status in provider_summary["statuses"]:
            provider_summary["statuses"][status] += 1

        report_summary = artifact.get("report", {}).get("summary", {})
        module_scores = artifact.get("report", {}).get("module_scores", {})
        audit_counts = _artifact_audit_counts(artifact)
        for summary in (provider_level, provider_level_agg, provider_summary):
            if status_fields["execution_status"]:
                summary["execution_status_counts"][status_fields["execution_status"]] += 1
                summary["security_outcome_counts"][status_fields["security_outcome"]] += 1
            for key, count in audit_counts.items():
                # Only scalar counts roll up; nested per-artifact summaries do not.
                if isinstance(count, int):
                    summary[key] = summary.get(key, 0) + count
        if status == "success":
            total_score = sum(int(item.get("score", 0)) for item in module_scores.values())
            chain_exploits = int(report_summary.get("chain_exploits_achieved", 0) or 0)

            highest_outcome = report_summary.get("highest_impact_outcome")
            iterations = int(report_summary.get("total_iterations_used", 0) or 0)
            distribution = report_summary.get("score_distribution", {})

            provider_level["total_score"] += total_score
            provider_level["chain_exploits"] += chain_exploits
            provider_level["iterations"].append(iterations)
            if highest_outcome:
                provider_level["highest_outcomes"].append(highest_outcome)
            provider_level_agg["total_score"] += total_score
            provider_level_agg["chain_exploits"] += chain_exploits
            provider_level_agg["iterations"].append(iterations)
            if highest_outcome:
                provider_level_agg["highest_outcomes"].append(highest_outcome)

            provider_summary["total_score"] += total_score
            provider_summary["chain_exploits"] += chain_exploits
            provider_summary["iterations"].append(iterations)
            if highest_outcome:
                provider_summary["highest_outcomes"].append(highest_outcome)

            for bucket, count in distribution.items():
                if str(bucket).isdigit():
                    provider_summary["score_distribution"][int(bucket)] += int(count)

    for provider_surfaces in by_provider_surface_level.values():
        for payload in provider_surfaces.values():
            for level_payload in payload.values():
                successes = level_payload["statuses"]["success"]
                level_payload["provisional_avg_score"] = round(level_payload["total_score"] / successes, 2) if successes else None
                level_payload["provisional_avg_iterations"] = round(mean(level_payload["iterations"]), 2) if level_payload["iterations"] else None
                level_payload["avg_score_reason"] = None if successes else "no_completed_runs"
                level_payload["score_epoch"] = "runtime_provisional_scoring.v2"

    for provider_levels in by_provider_level.values():
        for level_payload in provider_levels.values():
            successes = level_payload["statuses"]["success"]
            level_payload["provisional_avg_score"] = round(level_payload["total_score"] / successes, 2) if successes else None
            level_payload["provisional_avg_iterations"] = round(mean(level_payload["iterations"]), 2) if level_payload["iterations"] else None
            level_payload["avg_score_reason"] = None if successes else "no_completed_runs"
            level_payload["score_epoch"] = "runtime_provisional_scoring.v2"

    for payload in by_provider.values():
        # Provider-only rollups are operational counts. Provisional runtime
        # scores are not comparable across the omitted axes and are not exposed.
        payload.pop("total_score", None)
        payload.pop("avg_score", None)
        payload.pop("avg_iterations", None)
        payload.pop("guardrail_per_iteration", None)
        payload.pop("score_distribution", None)
        payload["score_aggregation"] = "not_computed_pooled_coordinates"
        payload["pooling_warning"] = (
            "by_provider is an operational count rollup across conditions/blocks/targets/"
            "guardrails/epochs; it must not be used for research score comparisons."
        )

    performance_rows = [
        row
        for artifact in artifacts
        for row in artifact.get("llm_performance", []) or []
        if isinstance(row, dict)
    ]
    performance_calls = len(performance_rows)
    invalid_outputs = sum(
        str(row.get("parse_status")) in {"invalid", "incomplete"}
        for row in performance_rows
    )
    time_by_role: dict[str, int] = {}
    for row in performance_rows:
        role = str(row.get("role", "unknown"))
        time_by_role[role] = time_by_role.get(role, 0) + int(row.get("call_duration_ms", 0) or 0)

    audit_totals = {
        key: sum(_artifact_audit_counts(artifact)[key] for artifact in artifacts)
        for key in (
            "invalid_json_events",
            "fallback_events",
            "containment_events",
            "containment_failures",
            "containment_navigation_discards",
            "guardrail_activations",
        )
    }
    totals = aggregate_runs(artifacts)
    # Pooled metric means across incompatible coordinates are not research
    # evidence; the matrix totals stay an operational count rollup.
    totals.pop("metrics", None)
    totals["score_aggregation"] = "not_computed_pooled_coordinates"
    totals["pooling_warning"] = (
        "Matrix totals are operational counts. No metric, score, or mean is averaged "
        "across conditions, blocks, targets, models, guardrails, fixtures, epochs, or graders."
    )
    totals.update(audit_totals)

    return {
        "schema_version": "stage8.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "recorded_payload_policy": recorded_payload_policy,
        "matrix": {
            "providers": derived_providers,
            "security_levels": derived_security_levels,
            "surfaces": derived_surfaces,
            "payload_modes": derived_payload_modes,
            "experiment_conditions": derived_conditions,
            "experiment_blocks": derived_blocks,
            "policy_epochs": derived_policy_epochs,
            "repeats": derived_repeats,
            "runs": len(artifacts),
            "grouping": [
                "provider", "model", "surface", "security_level", "payload_mode",
                "experiment_condition", "experiment_block", "target_method",
                "guardrail_retry_enabled", "guardrail_handling",
                "fixture_id", "protocol_version", "policy_epoch",
                "policy_versions", "source_hashes_sha256", "token_price_schedule_sha256",
            ],
            "pooling_note": (
                "Runtime groups never pool models, conditions, blocks, payload modes, targets, "
                "guardrail policies, fixtures, protocols, policy/source/price identities, or epochs; "
                "research summaries use final v4 receipts."
            ),
        },
        "totals": totals,
        "audit_totals": audit_totals,
        "diagnostics": {
            "runs_with_diagnostics": sum(
                1
                for artifact in artifacts
                if isinstance(artifact.get("report", {}).get("summary", {}).get("diagnostics"), dict)
            ),
            "audit_totals": audit_totals,
        },
        "llm_performance_summary": {
            "calls": performance_calls,
            **provider_request_summary(performance_rows),
            **cache_performance_summary(performance_rows),
            "invalid_outputs": invalid_outputs,
            "invalid_output_rate": round(invalid_outputs / performance_calls, 4) if performance_calls else None,
            "invalid_output_rate_status": "measured" if performance_calls else "no_calls",
            "invalid_output_rate_numerator": invalid_outputs,
            "invalid_output_rate_denominator": performance_calls,
            "time_by_role_ms": time_by_role,
            "summed_role_call_duration_ms": sum(time_by_role.values()),
            "per_run_peak_llm_concurrency": max(
                (int((artifact.get("llm_performance_summary") or {}).get("peak_llm_concurrency", 0) or 0)
                 for artifact in artifacts),
                default=0,
            ),
            "matrix_max_llm_concurrency": matrix_max_llm_concurrency,
            "concurrency_scope_note": (
                "matrix_max_llm_concurrency is matrix-wide; per_run_peak_llm_concurrency is "
                "the maximum simultaneous calls observed inside one coordinate."
            ),
            "peak_llm_concurrency": max(
                int((artifact.get("llm_performance_summary") or {}).get("peak_llm_concurrency", 0) or 0)
                for artifact in artifacts
            ) if artifacts else 0,
            "peak_dvwa_node_concurrency": max(
                int((artifact.get("llm_performance_summary") or {}).get("peak_dvwa_node_concurrency", 0) or 0)
                for artifact in artifacts
            ) if artifacts else 0,
        },
        "by_provider_level": by_provider_level,
        "by_provider_surface_level": by_provider_surface_level,
        "by_provider": by_provider,
        "runs": artifacts,
    }


def run_provider_matrix(
    *,
    target_url: str,
    providers: list[str] | None = None,
    security_levels: list[str] | None = None,
    surfaces: list[str] | None = None,
    payload_modes: list[str] | None = None,
    repeats: int = 1,
    max_iterations: int = 30,
    candidate_budget: int = 5,
    stop_policy: str = "impact",
    coverage_target: float = 0.70,
    enriched_reporting: bool = False,
    diagnose: bool = False,
    output_dir: str | None = None,
    include_aggregate: bool = False,
    evasion_enabled: bool = False,
    evasion_mode: str = "reactive",
    evasion_max_retries: int = 3,
    evasion_cooldown_threshold: int = 5,
    live_display: bool = False,
    model_configs: dict[str, dict[str, Any]] | None = None,
    event_sink: RuntimeEventSink | None = None,
    cancellation_token: CancellationToken | None = None,
    execution_id: str | None = None,
    experiment_condition: str = "linear_hybrid",
    target_method: str | None = None,
    experiment_block: str | None = None,
    experiment_conditions: list[str] | None = None,
    method_level_matrix: bool = False,
    guardrail_configurations: list[tuple[bool, str]] | None = None,
    run_output_dir_factory: Callable[[dict[str, Any], int], str | Path] | None = None,
    llm_max_concurrency: int = 1,
    llm_cache_enabled: bool = False,
    llm_role_configs: dict[str, RoleSettings | dict[str, Any]] | None = None,
    llm_runtime: LLMRuntime | None = None,
    llm_cache: bool | None = None,
    llm_cache_scope: str | None = None,
    role_configs: dict[str, RoleSettings | dict[str, Any]] | None = None,
    llm_runtime_config: dict[str, Any] | None = None,
    resume: bool = False,
    checkpoint_dir: str | None = None,
    experiment_id: str | None = None,
    scoring_mode: str = "human",
    scoring_evaluator: dict[str, Any] | None = None,
    scoring_rubric_version: str = "scoring.v3",
    scoring_profile: dict[str, Any] | None = None,
    scoring_oracles: list[dict[str, Any]] | None = None,
    scoring_policy_epoch: dict[str, Any] | None = None,
    token_price_schedule: dict[str, Any] | None = None,
    fixture_restoration_evidence: dict[str, Any] | None = None,
    payload_policy_snapshot: dict[str, Any] | None = None,
    source_hashes_sha256: str | None = None,
    fixture_id: str | None = None,
    protocol_version: str | None = None,
    dvwa_username: str = "admin",
    dvwa_password: str = "password",
) -> list[dict] | tuple[list[dict], dict[str, Any]]:
    """Run a deterministic matrix over all requested DVWA experiment axes.

    By default this preserves the historical provider × surface × level ×
    payload-mode matrix.  Set ``method_level_matrix=True`` to expand each
    surface to its supported static methods, and pass the two thesis conditions
    and guardrail configurations explicitly when executing the full experiment.
    Every coordinate is recorded in the individual artifact configuration.
    """
    if llm_role_configs is None:
        llm_role_configs = role_configs
    if llm_runtime_config:
        if not llm_role_configs and isinstance(llm_runtime_config.get("roles"), dict):
            llm_role_configs = llm_runtime_config["roles"]
        if llm_runtime_config.get("max_concurrency") is not None and llm_max_concurrency == 1:
            llm_max_concurrency = int(llm_runtime_config["max_concurrency"])
        if llm_cache_scope is None and llm_cache is None and llm_runtime_config.get("cache_scope") is not None:
            llm_cache_scope = str(llm_runtime_config["cache_scope"])
    if llm_cache is not None:
        llm_cache_enabled = bool(llm_cache)
    if llm_cache_scope is not None:
        llm_cache_enabled = str(llm_cache_scope).strip().lower() == "run"
    effective_cache_scope = (
        str(llm_cache_scope).strip().lower()
        if llm_cache_scope is not None
        else ("run" if llm_cache_enabled else "none")
    )

    chosen_providers = sorted(providers or [
        name for name in SUPPORTED_PROVIDERS
        if not provider_capabilities(name).requires_explicit_selection
    ])
    chosen_levels = sorted(security_levels or list(SECURITY_LEVELS))
    chosen_surfaces = sorted(surfaces or ["sqli", "access_control", "brute_force"])
    chosen_payload_modes = sorted(payload_modes or ["static_only", "hybrid"])
    unsupported_modes = [mode for mode in chosen_payload_modes if not is_supported_payload_mode(mode)]
    if unsupported_modes:
        raise ValueError(f"unsupported payload modes: {', '.join(unsupported_modes)}")
    chosen_conditions = sorted({
        str(condition).strip().lower()
        for condition in (experiment_conditions or [experiment_condition])
    })
    if not chosen_conditions or any(condition not in _EXPERIMENT_CONDITIONS for condition in chosen_conditions):
        raise ValueError(
            "experiment_conditions must contain only linear_hybrid or akg_guided_hybrid"
        )
    if not 1 <= int(llm_max_concurrency) <= 4:
        raise ValueError("llm_max_concurrency must be between 1 and 4")
    if target_method and method_level_matrix:
        raise ValueError("target_method and method_level_matrix cannot be used together")
    from tesis.model_config import EXPERIMENT_BLOCKS

    block = str(
        experiment_block or ("forced" if (target_method or method_level_matrix) else "selection")
    ).strip().lower()
    if block not in EXPERIMENT_BLOCKS:
        raise ValueError(f"experiment_block must be one of {EXPERIMENT_BLOCKS}")
    if block == "selection" and (target_method or method_level_matrix):
        raise ValueError("selection-block matrices must not force a target method or expand every method")
    if block == "forced" and not (target_method or method_level_matrix):
        raise ValueError("forced-block matrices require target_method or method_level_matrix")
    scoring_policy_epoch = dict(scoring_policy_epoch or {})
    token_price_schedule = dict(token_price_schedule or {})
    fixture_restoration_evidence = fixture_evidence_envelope(fixture_restoration_evidence)
    from evaluation.runner import resolve_recorded_payload_policy

    recorded_payload_policy = resolve_recorded_payload_policy(payload_policy_snapshot)
    recorded_policy_sha256 = (
        str(recorded_payload_policy.get("snapshot_sha256") or "")
        if isinstance(recorded_payload_policy, Mapping)
        else ""
    ) or evidence_hash(recorded_payload_policy)
    if source_hashes_sha256 is None:
        source_hashes_sha256 = default_source_hashes_sha256()
    if target_method and any(target_method not in METHODS_BY_SURFACE.get(surface, []) for surface in chosen_surfaces):
        raise ValueError("target_method must be valid for every selected surface")

    requested_guardrails = guardrail_configurations or [(evasion_enabled, evasion_mode)]
    chosen_guardrails = sorted({
        (bool(enabled), str(mode).strip().lower())
        for enabled, mode in requested_guardrails
    })
    if not chosen_guardrails or any(mode not in _GUARDRAIL_MODES for _, mode in chosen_guardrails):
        raise ValueError("guardrail configurations must use reactive, proactive, or disabled mode")

    coordinates: list[dict[str, Any]] = []
    for provider in chosen_providers:
        for surface in chosen_surfaces:
            methods = (
                list(METHODS_BY_SURFACE[surface])
                if method_level_matrix
                else [target_method]
            )
            for level in chosen_levels:
                for payload_mode in chosen_payload_modes:
                    for condition in chosen_conditions:
                        for method in methods:
                            for guardrail_enabled, guardrail_mode in chosen_guardrails:
                                for repeat_index in range(repeats):
                                    coordinates.append({
                                        "provider": provider,
                                        "surface": surface,
                                        "security_level": level,
                                        "payload_mode": payload_mode,
                                        "experiment_condition": condition,
                                        "experiment_block": block,
                                        "target_method": method,
                                        "guardrail_retry_enabled": guardrail_enabled,
                                        "guardrail_handling": guardrail_mode,
                                        "repeat_index": repeat_index,
                                        "experiment_policy_version": EXPERIMENT_POLICY_VERSION,
                                        "payload_policy_version": PAYLOAD_POLICY_VERSION,
                                        "policy_epoch_id": scoring_policy_epoch.get("epoch_id"),
                                    })

    cancellation_token = cancellation_token or CancellationToken()
    matrix_execution_id = execution_id or new_execution_id()
    total_runs = len(coordinates)

    event_lock = Lock()

    def emit(event_type: str, *, message: str, data: dict[str, Any]) -> None:
        if event_sink is not None:
            with event_lock:
                event_sink.emit(RunEvent(
                    event_type=event_type,
                    execution_id=matrix_execution_id,
                    message=message,
                    data=data,
                ))

    class _SerializedSink:
        def emit(self, event: RunEvent) -> None:
            if event_sink is not None:
                with event_lock:
                    event_sink.emit(event)

    child_event_sink = _SerializedSink() if event_sink is not None else None

    matrix_started_clock = perf_counter()
    emit("matrix.started", message="Experiment matrix started", data={"total": total_runs})

    serialized_role_configs = _serialize_role_configs(llm_role_configs)
    matrix_config = {
        "scoring_rubric_version": scoring_rubric_version,
        "scoring_profile": scoring_profile or {}, "scoring_oracles": scoring_oracles or [],
        "scoring_policy_epoch": scoring_policy_epoch, "token_price_schedule": token_price_schedule,
        "source_hashes_sha256": source_hashes_sha256,
        "source_identity_version": default_source_identity().get("identity_version"),
        "source_config_sha256": default_source_identity().get("config_sha256"),
        "fixture_restoration_evidence": fixture_restoration_evidence,
        "fixture_restoration_sha256": (
            evidence_hash(fixture_restoration_evidence) if fixture_restoration_evidence else None
        ),
        "fixture_id": fixture_id, "protocol_version": protocol_version,
        "experiment_block": block,
        "experiment_policy_version": EXPERIMENT_POLICY_VERSION,
        "payload_policy_version": PAYLOAD_POLICY_VERSION,
        "recorded_payload_policy_sha256": recorded_policy_sha256,
        "control_policy_version": CONTROL_POLICY_VERSION,
        "budget_policy_version": BUDGET_POLICY_VERSION,
        "scoring_mode": scoring_mode,
        "scoring_evaluator": redact_secrets(scoring_evaluator or {}),
        "target_url": target_url,
        "providers": chosen_providers,
        "security_levels": chosen_levels,
        "surfaces": chosen_surfaces,
        "payload_modes": chosen_payload_modes,
        "experiment_conditions": chosen_conditions,
        "method_level_matrix": method_level_matrix,
        "target_method": target_method,
        "guardrail_configurations": [
            {"enabled": enabled, "mode": mode}
            for enabled, mode in chosen_guardrails
        ],
        "repeats": repeats,
        "max_iterations": max_iterations,
        "candidate_budget": candidate_budget,
        "llm_max_concurrency": int(llm_max_concurrency),
        "llm_cache_enabled": bool(llm_cache_enabled),
        "llm_cache_scope": effective_cache_scope,
        "cache_scope": effective_cache_scope,
        "llm_role_configs": serialized_role_configs,
        "model_configs": redact_secrets(model_configs or {}),
        "model_profiles": redact_secrets(model_configs or {}),
    }

    runtime_service = llm_runtime or LLMRuntime(
        max_concurrency=int(llm_max_concurrency), rate_limit_config=llm_runtime_config,
    )
    owns_runtime = llm_runtime is None

    def finalize_aggregate(status: str) -> tuple[list[dict], dict[str, Any]]:
        aggregate = _build_matrix_aggregate(
            artifacts,
            matrix_max_llm_concurrency=int(runtime_service.max_concurrency),
            payload_policy_snapshot=recorded_payload_policy,
        )
        aggregate["llm_performance_summary"].update({
            "peak_llm_concurrency": runtime_service.peak_llm_concurrency,
            "peak_dvwa_node_concurrency": runtime_service.peak_http_concurrency,
        })
        # A cancelled matrix must remain cancelled even when a child returned
        # an error, while a completed matrix cannot be reported successful if
        # any child failed.  The TUI presents this aggregate status as the
        # matrix result, so derive it from the authoritative child artifacts.
        if cancellation_token.is_cancelled or status == "cancelled":
            status = "cancelled"
        elif any(terminal_status(artifact)["execution_status"] == "failed" for artifact in artifacts):
            status = "error"
        matrix_fields = matrix_terminal_status(artifacts, interrupted=status == "cancelled",
            interruption_reason=cancellation_token.reason or "")
        status = lifecycle_alias(matrix_fields["execution_status"])
        aggregate.update({
            "execution_id": matrix_execution_id,
            "run_id": "matrix-" + config_fingerprint(matrix_config).split(":", 1)[-1][:12],
            "status": status,
            "planned_runs": total_runs,
            "observed_runs": len(artifacts),
            "not_started_runs": max(0, total_runs - len(artifacts)),
            "matrix_wall_time_ms": int((perf_counter() - matrix_started_clock) * 1000),
            "score_epoch": {
                "runtime_provisional": "scoring.v2",
                "thesis_final": scoring_rubric_version,
                "final_status": "pending_review",
            },
            **matrix_fields,
            "config": matrix_config,
            "config_fingerprint": config_fingerprint(matrix_config),
        })
        aggregate["cancellation"] = {
            "requested": bool(cancellation_token.is_cancelled or status == "cancelled"),
            "reason": cancellation_token.reason if cancellation_token.is_cancelled else None,
            "completed_runs": len(artifacts),
            "total_runs": total_runs,
            "not_started_runs": max(0, total_runs - len(artifacts)),
        }
        if output_dir:
            write_json_report(Path(output_dir) / f"{matrix_execution_id}.matrix.json", aggregate)
        return artifacts, aggregate

    prepared: list[tuple[int, dict[str, Any], str | None, str]] = []
    for index, coordinate in enumerate(coordinates):
        coordinate_output_dir = output_dir
        if run_output_dir_factory is not None:
            coordinate_output_dir = str(run_output_dir_factory(coordinate, index))
        prepared.append((index, coordinate, coordinate_output_dir, new_execution_id()))

    ordered_artifacts: list[dict[str, Any] | None] = [None] * total_runs

    def empty_artifact(
        coordinate: dict[str, Any],
        run_execution_id: str,
        *,
        status: str,
        reason: str,
    ) -> dict[str, Any]:
        """Build a contract-complete artifact for a coordinate that did not run."""
        provider = str(coordinate["provider"])
        model_config = (model_configs or {}).get(provider) or {}
        model_name = (
            model_config.get("model_name")
            if isinstance(model_config, dict)
            else None
        )
        coordinate_evidence = fixture_evidence_for_level(
            fixture_restoration_evidence, str(coordinate["security_level"]),
        )
        artifact_config = {
            "scoring_rubric_version": scoring_rubric_version,
        "scoring_profile": scoring_profile or {}, "scoring_oracles": scoring_oracles or [],
        "scoring_policy_epoch": scoring_policy_epoch, "token_price_schedule": token_price_schedule,
        "source_hashes_sha256": source_hashes_sha256,
        "source_identity_version": default_source_identity().get("identity_version"),
        "source_config_sha256": default_source_identity().get("config_sha256"),
        "fixture_restoration_evidence": coordinate_evidence,
        "fixture_restoration_sha256": (
            evidence_hash(coordinate_evidence) if coordinate_evidence else None
        ),
        "fixture_id": fixture_id, "protocol_version": protocol_version,
        "scoring_mode": scoring_mode,
            "scoring_evaluator": redact_secrets(scoring_evaluator or {}),
            "target_url": target_url,
            "experiment_block": coordinate.get("experiment_block", block),
            "experiment_policy_version": EXPERIMENT_POLICY_VERSION,
            "payload_policy_version": PAYLOAD_POLICY_VERSION,
            "control_policy_version": CONTROL_POLICY_VERSION,
            "budget_policy_version": BUDGET_POLICY_VERSION,
            **coordinate,
            "provider": provider,
            "model": model_name,
            "model_config": redact_secrets(model_config if isinstance(model_config, dict) else {}),
            "model_profiles": redact_secrets(model_configs or {}),
            "llm_required": False,
            "llm_max_concurrency": int(llm_max_concurrency),
            "llm_cache_enabled": bool(llm_cache_enabled),
            "llm_cache": bool(llm_cache_enabled),
            "llm_cache_scope": effective_cache_scope,
            "cache_scope": effective_cache_scope,
            "llm_role_configs": serialized_role_configs,
            "max_iterations": max_iterations,
            "candidate_budget": candidate_budget,
            "evasion_enabled": coordinate["guardrail_retry_enabled"],
            "evasion_mode": coordinate["guardrail_handling"],
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
        }
        execution_log: list[dict[str, Any]] = []
        llm_activity = {"started": 0, "completed": 0, "failed": 0, "tokens": 0}
        llm_performance_summary = _llm_performance_summary_defaults()
        audit_lists = {
            "guardrail_activations": [],
            "payload_guardrail_activations": [],
            "invalid_json_events": [],
            "fallback_events": [],
            "containment_events": [],
        }
        state_lists = {
            "confirmed_vulns": [],
            "achieved_outcomes": [],
            "viable_methods": [],
            "akg_path": [],
            "response_evidence": [],
            "timing_evidence": [],
        }
        state_maps = {
            "payload_candidates": {},
            "generated_payloads": {},
            "payload_validation_results": {},
            "payload_provenance": {},
            "payload_scores": {},
            "method_scores": {},
            "exploitation_scores": {},
            "chain_scores": {},
            "output_scores": {},
            "composite_scores": {},
        }
        incomplete_reason = "CANCELLED" if status == "cancelled" else "SKIPPED"
        status_fields = terminal_status({}, execution_status="interrupted" if status == "cancelled" else None,
            execution_reason=status_reason("CANCELLED", reason) if status == "cancelled" else None)
        final_state = {
            "iteration_count": 0,
            **status_fields,
            "task_result": None,
            "incomplete_reason": incomplete_reason,
            "llm_activity": llm_activity,
            "llm_required": False,
            "llm_performance": [],
            "llm_performance_summary": llm_performance_summary,
            **state_lists,
            "selected_method": None,
            **state_maps,
            **audit_lists,
            "verifier_decision": None,
            "execution_log": execution_log,
        }
        run_id = (
            f"{provider}-{coordinate['surface']}-{coordinate['security_level']}-"
            f"{coordinate['payload_mode']}-{coordinate['experiment_condition']}-"
            f"{coordinate['target_method'] or 'surface'}-{coordinate['repeat_index']}"
        )
        report = {
            "summary": {
                "chain_exploits_achieved": 0,
                "guardrail_activations": 0,
                "total_iterations_used": 0,
                "score_distribution": {},
            },
            "module_scores": {},
        }
        artifact = {
            "schema_version": "tui.v1",
            "execution_id": run_execution_id,
            "run_id": run_id,
            "status": status,
            **status_fields,
            "experiment_condition": coordinate["experiment_condition"],
            "experiment_block": coordinate.get("experiment_block", block),
            "target_method": coordinate["target_method"],
            "policy_epoch": {
                "epoch_id": scoring_policy_epoch.get("epoch_id"),
                "policy_version": EXPERIMENT_POLICY_VERSION,
                "payload_policy_version": PAYLOAD_POLICY_VERSION,
                "control_policy_version": CONTROL_POLICY_VERSION,
                "budget_policy_version": BUDGET_POLICY_VERSION,
                "scoring_rubric_version": scoring_rubric_version,
                "source_hashes_sha256": source_hashes_sha256,
                "recorded_payload_policy_sha256": recorded_policy_sha256,
            },
            "readiness": None,
            "recorded_payload_policy": recorded_payload_policy,
            "fixture_restoration_evidence": coordinate_evidence,
            "fixture_restoration_sha256": (
                evidence_hash(coordinate_evidence) if coordinate_evidence else None
            ),
            "source_hashes_sha256": source_hashes_sha256,
            "source_identity": {
                key: default_source_identity().get(key)
                for key in ("identity_version", "source_hashes", "source_hashes_sha256", "config_sha256")
            },
            "http_request_counters": {
                "policy_version": "http-accounting.v1", "scope": "run",
                "total_requests": 0,
                "by_phase": {phase: 0 for phase in HTTP_PHASES},
                "by_role": {role: 0 for role in HTTP_ROLES},
                "per_method": {},
                "retries": 0, "redirect_hops": 0, "failed_requests": 0,
                "complete": False, "capture_status": "unavailable",
            },
            "candidate_lifecycle": [],
            "candidate_budget_receipts": [],
            "model_call_requirements": [],
            "chain_assessment": None,
            "selection_rejections": [],
            "control_events": [],
            "quarantined_visits": [],
            "payload_generation_opportunities": [],
            "payload_validation_opportunities": [],
            "payload_generation_opportunity_coverage": generation_opportunity_coverage({
                "payload_generation_opportunities": [],
                "payload_validation_opportunities": [],
                "config": {"payload_mode": coordinate["payload_mode"]},
            }),
            "payload_policy_version": PAYLOAD_POLICY_VERSION,
            "control_policy_version": CONTROL_POLICY_VERSION,
            "budget_policy_version": BUDGET_POLICY_VERSION,
            "experiment_policy_version": EXPERIMENT_POLICY_VERSION,
            "repeat_index": coordinate["repeat_index"],
            "provider": provider,
            "model": model_name,
            "surface": coordinate["surface"],
            "security_level": coordinate["security_level"],
            "payload_mode": coordinate["payload_mode"],
            "llm_required": False,
            "score_epoch": {
                "runtime_provisional": "scoring.v2",
                "thesis_final": scoring_rubric_version,
                "final_status": "pending_review",
                "scoring_policy_version": SCORING_POLICY_VERSION,
            },
            "scoring_policy": None,
            "composite_score_status": "runtime_provisional_scoring.v2",
            "thesis_scoring_status": "pending_review",
            "payload_mode_label": mode_display_label(coordinate["payload_mode"]),
            "llm_activity": llm_activity,
            "llm_performance": [],
            "llm_performance_summary": llm_performance_summary,
            "task_result": None,
            "incomplete_reason": incomplete_reason,
            "selected_method": None,
            **state_lists,
            "method_score": 0,
            "payload_scores": {},
            "exploitation_score": 0,
            "chain_score": 0,
            "payload_validity_rate": 0.0,
            "payload_execution_success_rate": 0.0,
            "payload_improvement_rate": 0.0,
            "consistency_score": None,
            "metric_availability": {"consistency_score": False, "token_cost": False, "token_cost_per_success": False},
            "metric_unavailable_reason": {"consistency_score": "not_computed", "token_cost": "not_computed", "token_cost_per_success": "not_computed"},
            **audit_lists,
            "payload_guardrail_activations": 0,
            "guardrail_activation_count": 0,
            "attempts_to_success": 0,
            "token_cost": None,
            "token_cost_per_success": None,
            "config": artifact_config,
            "timing": {},
            "final_state": final_state,
            **state_maps,
            "execution_log": execution_log,
            "verifier_decision": None,
            "output_score": 0,
            "composite_score": 0,
            "report": report,
            "error": reason,
        }
        if status == "cancelled":
            artifact["cancellation_reason"] = reason
        artifact["config_fingerprint"] = config_fingerprint(artifact_config)
        artifact["manual_scoring_evidence"] = []
        artifact["report"]["summary"].update(status_fields)
        return artifact

    def skipped_artifact(coordinate: dict[str, Any], run_execution_id: str) -> dict[str, Any]:
        provider = str(coordinate["provider"])
        return empty_artifact(
            coordinate,
            run_execution_id,
            status="skipped",
            reason=f"Unsupported provider: {provider}",
        )

    def cancelled_artifact(
        coordinate: dict[str, Any], run_execution_id: str, reason: str,
    ) -> dict[str, Any]:
        return empty_artifact(
            coordinate,
            run_execution_id,
            status="cancelled",
            reason=reason,
        )

    def execute_coordinate(
        coordinate: dict[str, Any], coordinate_output_dir: str | None, run_execution_id: str
    ) -> dict[str, Any]:
        provider = str(coordinate["provider"])
        run_kwargs = {
            "scoring_rubric_version": scoring_rubric_version,
        "scoring_profile": scoring_profile or {}, "scoring_oracles": scoring_oracles or [],
        "scoring_policy_epoch": scoring_policy_epoch, "token_price_schedule": token_price_schedule,
        "fixture_restoration_evidence": fixture_restoration_evidence,
        "payload_policy_snapshot": recorded_payload_policy,
        "source_hashes_sha256": source_hashes_sha256,
        "fixture_id": fixture_id, "protocol_version": protocol_version,
        "scoring_mode": scoring_mode,
            "scoring_evaluator": scoring_evaluator or {},
            "target_url": target_url,
            "dvwa_username": dvwa_username,
            "dvwa_password": dvwa_password,
            "security_level": coordinate["security_level"],
            "llm_provider": provider,
            "surface": coordinate["surface"],
            "payload_mode": coordinate["payload_mode"],
            "max_iterations": max_iterations,
            "candidate_budget": candidate_budget,
            "repeat_index": coordinate["repeat_index"],
            "stop_policy": stop_policy,
            "coverage_target": coverage_target,
            "enriched_reporting": enriched_reporting,
            "diagnose": diagnose,
            "evasion_enabled": coordinate["guardrail_retry_enabled"],
            "evasion_mode": coordinate["guardrail_handling"],
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
            "output_dir": coordinate_output_dir,
            "live_display": live_display,
            "model_config": (model_configs or {}).get(provider),
            "event_sink": child_event_sink,
            "cancellation_token": cancellation_token,
            "execution_id": run_execution_id,
            "experiment_condition": coordinate["experiment_condition"],
            "experiment_block": coordinate["experiment_block"],
            "target_method": coordinate["target_method"],
            "llm_runtime": runtime_service,
            "llm_role_configs": llm_role_configs or {},
            "model_profiles": model_configs or {},
            "llm_cache_enabled": llm_cache_enabled,
            "resume": resume,
            "checkpoint_dir": checkpoint_dir,
            "experiment_id": experiment_id,
        }
        return _run_single_with_payload_kwargs(run_kwargs)

    next_to_submit = 0
    futures: dict[Future[dict[str, Any]], tuple[int, dict[str, Any]]] = {}
    interrupted = False

    def record_future_result(
        future: Future[dict[str, Any]], index: int, coordinate: dict[str, Any],
    ) -> None:
        """Store one future result, preserving an auditable cancel artifact."""

        nonlocal interrupted
        try:
            artifact = future.result()
        except KeyboardInterrupt:
            interrupted = True
            cancellation_token.cancel("keyboard interrupt")
            artifact = cancelled_artifact(
                coordinate,
                prepared[index][3],
                cancellation_token.reason or "keyboard interrupt",
            )
        except BaseException as exc:
            if not cancellation_token.is_cancelled and not interrupted:
                raise
            artifact = cancelled_artifact(
                coordinate,
                prepared[index][3],
                f"{type(exc).__name__}: {exc}",
            )
        ordered_artifacts[index] = artifact
        completed = sum(item is not None for item in ordered_artifacts)
        failure = artifact.get("failure")
        failure_class = failure.get("failure_class") if isinstance(failure, dict) else None
        finished_data: dict[str, Any] = {
            **coordinate,
            "coordinate_index": index,
            "coordinate_execution_id": prepared[index][3],
            "run_id": artifact.get("run_id"),
            "selected_method": artifact.get("selected_method"),
            "confirmed_vulns": redact_secrets(list(artifact.get("confirmed_vulns") or [])),
            "achieved_outcomes": redact_secrets(list(artifact.get("achieved_outcomes") or [])),
            "task_result": artifact.get("task_result"),
            **terminal_status(artifact),
            "status": artifact.get("status", "unknown"),
            "completed": completed,
            "total": total_runs,
        }
        if failure_class:
            finished_data["failure_class"] = failure_class
        emit("matrix.run.finished", message="Matrix coordinate finished", data=finished_data)

    def shutdown_executor(executor: ThreadPoolExecutor) -> None:
        """Wait for safe worker boundaries even when Ctrl-C repeats."""

        nonlocal interrupted
        while True:
            try:
                executor.shutdown(wait=True)
                return
            except KeyboardInterrupt:
                interrupted = cancellation_token.cancel("keyboard interrupt") or interrupted

    executor = ThreadPoolExecutor(
        max_workers=int(llm_max_concurrency),
        thread_name_prefix="tesis-coordinate",
    )
    try:
        while next_to_submit < total_runs or futures:
            while (
                next_to_submit < total_runs
                and len(futures) < int(llm_max_concurrency)
                and not cancellation_token.is_cancelled
            ):
                index, coordinate, coordinate_output_dir, run_execution_id = prepared[next_to_submit]
                next_to_submit += 1
                provider = str(coordinate["provider"])
                adapter = str(((model_configs or {}).get(provider) or {}).get("provider", provider))
                if adapter not in SUPPORTED_PROVIDERS:
                    ordered_artifacts[index] = skipped_artifact(coordinate, run_execution_id)
                    continue
                completed = sum(item is not None for item in ordered_artifacts)
                emit("matrix.run.started", message="Starting matrix coordinate", data={
                    **coordinate,
                    "coordinate_index": index,
                    "coordinate_execution_id": run_execution_id,
                    "completed": completed, "total": total_runs,
                })
                future = executor.submit(
                    execute_coordinate, coordinate, coordinate_output_dir, run_execution_id
                )
                futures[future] = (index, coordinate)

            if not futures:
                break
            try:
                completed_futures, _ = wait(tuple(futures), return_when=FIRST_COMPLETED)
            except KeyboardInterrupt:
                interrupted = True
                cancellation_token.cancel("keyboard interrupt")
                break
            for future in sorted(completed_futures, key=lambda item: futures[item][0]):
                index, coordinate = futures.pop(future)
                record_future_result(future, index, coordinate)
                if interrupted:
                    break
            if interrupted:
                break
    except KeyboardInterrupt:
        interrupted = True
        cancellation_token.cancel("keyboard interrupt")
    finally:
        shutdown_executor(executor)

    # A KeyboardInterrupt can arrive while waiting or while consuming a
    # completed future.  The executor is now drained, so collect every active
    # future before writing the partial aggregate instead of losing it.
    if interrupted or cancellation_token.is_cancelled:
        for future, (index, coordinate) in sorted(
            futures.items(), key=lambda item: item[1][0]
        ):
            record_future_result(future, index, coordinate)
        futures.clear()

    artifacts = [artifact for artifact in ordered_artifacts if artifact is not None]
    if cancellation_token.is_cancelled:
        emit("matrix.cancelled", message="Matrix cancellation acknowledged", data={
            "completed": len(artifacts), "total": total_runs,
        })

    if include_aggregate:
        artifacts, aggregate = finalize_aggregate("cancelled" if cancellation_token.is_cancelled else "success")
        emit("matrix.finished", message="Experiment matrix finished", data={
            **aggregate.get("totals", {}),
            "status": aggregate["status"],
            "completed": len(artifacts), "total": total_runs,
            "cancellation": aggregate["cancellation"],
        })
        if owns_runtime:
            runtime_service.close()
        return artifacts, aggregate
    emit("matrix.finished", message="Experiment matrix finished", data={"completed": len(artifacts)})
    if owns_runtime:
        runtime_service.close()
    return artifacts
