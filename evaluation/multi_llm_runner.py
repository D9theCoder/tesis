"""Stage 6 matrix runner across providers, surfaces, and security levels."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from threading import Lock
from typing import Any, Callable

from core.state import METHODS_BY_SURFACE, SECURITY_LEVELS
from evaluation.metrics import aggregate_runs
from evaluation.reporter import write_json_report
from llm.provider import SUPPORTED_PROVIDERS
from llm.runtime import LLMRuntime, RoleSettings
from tesis.artifact_repository import config_fingerprint, new_execution_id
from tesis.runtime_events import CancellationToken, RunEvent, RuntimeEventSink, redact_secrets

from evaluation.runner import run_single_engagement


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
            }
        elif isinstance(value, dict):
            serialized[str(role)] = dict(value)
    return serialized


def _llm_performance_summary_defaults() -> dict[str, Any]:
    """Return the empty telemetry shape used by non-started coordinates."""
    return {
        "calls": 0,
        "cache_hits": 0,
        "cache_hit_rate": 0.0,
        "invalid_outputs": 0,
        "invalid_output_rate": 0.0,
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
    containment_failures = sum(
        1
        for event in containment_rows
        if isinstance(event, dict)
        and str(event.get("kind", "")).lower() in {"request", "redirect"}
    )

    return {
        "invalid_json_events": first_present("invalid_json_events", "invalid_outputs"),
        "fallback_events": first_present("fallback_events"),
        "containment_events": first_present("containment_events"),
        "containment_failures": containment_failures,
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
            "target_method",
            "llm_runtime",
            "llm_role_configs",
            "model_profiles",
            "llm_cache_enabled",
        }
        rejected = {key for key in optional_compat if key in str(exc)}
        if not rejected:
            raise
        legacy_kwargs = dict(kwargs)
        for key in rejected:
            legacy_kwargs.pop(key, None)
        return _run_single_with_payload_kwargs(legacy_kwargs)


def _build_matrix_aggregate(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    """Supports build matrix aggregate behavior for this module."""
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
        status = str(artifact.get("status", "unknown"))
        final_state = artifact.get("final_state", {})

        provider_surface = by_provider_surface_level.setdefault(provider, {}).setdefault(
            surface,
            {},
        )
        provider_level = provider_surface.setdefault(
            f"{level}:{payload_mode}",
            {
                "runs": 0,
                "statuses": {"success": 0, "error": 0, "skipped": 0, "cancelled": 0},
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
            f"{level}:{payload_mode}",
            {
                "runs": 0,
                "statuses": {"success": 0, "error": 0, "skipped": 0, "cancelled": 0},
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
        if status in provider_level["statuses"]:
            provider_level["statuses"][status] += 1
        if status in provider_level_agg["statuses"]:
            provider_level_agg["statuses"][status] += 1

        provider_summary = by_provider.setdefault(
            provider,
            {
                "runs": 0,
                "statuses": {"success": 0, "error": 0, "skipped": 0, "cancelled": 0},
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
        if status in provider_summary["statuses"]:
            provider_summary["statuses"][status] += 1

        report_summary = artifact.get("report", {}).get("summary", {})
        module_scores = artifact.get("report", {}).get("module_scores", {})
        audit_counts = _artifact_audit_counts(artifact)
        for summary in (provider_level, provider_level_agg, provider_summary):
            for key, count in audit_counts.items():
                summary[key] += count
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
                level_payload["avg_score"] = round(level_payload["total_score"] / successes, 2) if successes else 0.0
                level_payload["avg_iterations"] = round(mean(level_payload["iterations"]), 2) if level_payload["iterations"] else 0.0

    for provider_levels in by_provider_level.values():
        for level_payload in provider_levels.values():
            successes = level_payload["statuses"]["success"]
            level_payload["avg_score"] = round(level_payload["total_score"] / successes, 2) if successes else 0.0
            level_payload["avg_iterations"] = round(mean(level_payload["iterations"]), 2) if level_payload["iterations"] else 0.0

    for payload in by_provider.values():
        successful = payload["statuses"]["success"]
        payload["avg_score"] = round(payload["total_score"] / successful, 2) if successful else 0.0
        payload["avg_iterations"] = round(mean(payload["iterations"]), 2) if payload["iterations"] else 0.0
        total_calls_estimate = sum(payload["iterations"]) or 0
        # NOTE: denominator is total iterations used (LangGraph node transitions),
        # not LLM call count. This remains a coarse proxy until call counts are tracked.
        payload["guardrail_per_iteration"] = (
            round(payload["guardrail_activations"] / total_calls_estimate * 100, 2)
            if total_calls_estimate > 0
            else 0.0
        )

    performance_rows = [
        row
        for artifact in artifacts
        for row in artifact.get("llm_performance", []) or []
        if isinstance(row, dict)
    ]
    performance_calls = len(performance_rows)
    cache_hits = sum(bool(row.get("cache_hit")) for row in performance_rows)
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
            "guardrail_activations",
        )
    }
    totals = aggregate_runs(artifacts)
    totals.update(audit_totals)

    return {
        "schema_version": "stage8.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "matrix": {
            "providers": derived_providers,
            "security_levels": derived_security_levels,
            "surfaces": derived_surfaces,
            "payload_modes": derived_payload_modes,
            "repeats": derived_repeats,
            "runs": len(artifacts),
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
            "cache_hits": cache_hits,
            "cache_hit_rate": round(cache_hits / performance_calls, 4) if performance_calls else 0.0,
            "invalid_outputs": invalid_outputs,
            "invalid_output_rate": round(invalid_outputs / performance_calls, 4) if performance_calls else 0.0,
            "time_by_role_ms": time_by_role,
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
        if llm_cache_scope is None and llm_runtime_config.get("cache_scope") is not None:
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

    chosen_providers = sorted(providers or list(SUPPORTED_PROVIDERS))
    chosen_levels = sorted(security_levels or list(SECURITY_LEVELS))
    chosen_surfaces = sorted(surfaces or ["sqli", "access_control", "brute_force"])
    chosen_payload_modes = sorted(payload_modes or ["static_only", "hybrid"])
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
                                        "target_method": method,
                                        "guardrail_retry_enabled": guardrail_enabled,
                                        "guardrail_handling": guardrail_mode,
                                        "repeat_index": repeat_index,
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

    emit("matrix.started", message="Experiment matrix started", data={"total": total_runs})

    serialized_role_configs = _serialize_role_configs(llm_role_configs)
    matrix_config = {
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

    runtime_service = llm_runtime or LLMRuntime(max_concurrency=int(llm_max_concurrency))
    owns_runtime = llm_runtime is None

    def finalize_aggregate(status: str) -> tuple[list[dict], dict[str, Any]]:
        aggregate = _build_matrix_aggregate(artifacts)
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
        elif any(str(artifact.get("status", "")).lower() == "error" for artifact in artifacts):
            status = "error"
        aggregate.update({
            "execution_id": matrix_execution_id,
            "run_id": "matrix-" + config_fingerprint(matrix_config).split(":", 1)[-1][:12],
            "status": status,
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
        artifact_config = {
            "target_url": target_url,
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
        final_state = {
            "iteration_count": 0,
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
            "experiment_condition": coordinate["experiment_condition"],
            "target_method": coordinate["target_method"],
            "provider": provider,
            "model": model_name,
            "surface": coordinate["surface"],
            "security_level": coordinate["security_level"],
            "payload_mode": coordinate["payload_mode"],
            "llm_required": False,
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
            "consistency_score": 0.0,
            **audit_lists,
            "payload_guardrail_activations": 0,
            "guardrail_activation_count": 0,
            "attempts_to_success": 0,
            "token_cost": 0.0,
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
            "target_url": target_url,
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
            "target_method": coordinate["target_method"],
            "llm_runtime": runtime_service,
            "llm_role_configs": llm_role_configs or {},
            "model_profiles": model_configs or {},
            "llm_cache_enabled": llm_cache_enabled,
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
        emit("matrix.run.finished", message="Matrix coordinate finished", data={
            **coordinate,
            "status": artifact.get("status", "unknown"),
            "completed": completed,
            "total": total_runs,
        })

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
                if provider not in SUPPORTED_PROVIDERS:
                    ordered_artifacts[index] = skipped_artifact(coordinate, run_execution_id)
                    continue
                completed = sum(item is not None for item in ordered_artifacts)
                emit("matrix.run.started", message="Starting matrix coordinate", data={
                    **coordinate, "completed": completed, "total": total_runs,
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
        emit("matrix.finished", message="Experiment matrix finished", data=aggregate.get("totals", {}))
        if owns_runtime:
            runtime_service.close()
        return artifacts, aggregate
    emit("matrix.finished", message="Experiment matrix finished", data={"completed": len(artifacts)})
    if owns_runtime:
        runtime_service.close()
    return artifacts
