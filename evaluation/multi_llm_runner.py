"""Stage 6 matrix runner across providers, surfaces, and security levels."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Callable

from core.state import METHODS_BY_SURFACE, SECURITY_LEVELS
from evaluation.metrics import aggregate_runs
from evaluation.reporter import write_json_report
from llm.provider import SUPPORTED_PROVIDERS
from tesis.artifact_repository import config_fingerprint, new_execution_id
from tesis.runtime_events import CancellationToken, RunEvent, RuntimeEventSink, redact_secrets

from evaluation.runner import run_single_engagement


_EXPERIMENT_CONDITIONS = frozenset({"linear_hybrid", "akg_guided_hybrid"})
_GUARDRAIL_MODES = frozenset({"reactive", "proactive", "disabled"})


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
        if status == "success":
            total_score = sum(int(item.get("score", 0)) for item in module_scores.values())
            chain_exploits = int(report_summary.get("chain_exploits_achieved", 0) or 0)
            guardrails = int(report_summary.get("guardrail_activations", 0) or 0)

            highest_outcome = report_summary.get("highest_impact_outcome")
            iterations = int(report_summary.get("total_iterations_used", 0) or 0)
            distribution = report_summary.get("score_distribution", {})

            provider_level["total_score"] += total_score
            provider_level["chain_exploits"] += chain_exploits
            provider_level["guardrail_activations"] += guardrails
            provider_level["iterations"].append(iterations)
            if highest_outcome:
                provider_level["highest_outcomes"].append(highest_outcome)
            provider_level_agg["total_score"] += total_score
            provider_level_agg["chain_exploits"] += chain_exploits
            provider_level_agg["guardrail_activations"] += guardrails
            provider_level_agg["iterations"].append(iterations)
            if highest_outcome:
                provider_level_agg["highest_outcomes"].append(highest_outcome)

            provider_summary["total_score"] += total_score
            provider_summary["chain_exploits"] += chain_exploits
            provider_summary["guardrail_activations"] += guardrails
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
        "totals": aggregate_runs(artifacts),
        "diagnostics": {
            "runs_with_diagnostics": sum(
                1
                for artifact in artifacts
                if isinstance(artifact.get("report", {}).get("summary", {}).get("diagnostics"), dict)
            ),
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
) -> list[dict] | tuple[list[dict], dict[str, Any]]:
    """Run a deterministic matrix over all requested DVWA experiment axes.

    By default this preserves the historical provider × surface × level ×
    payload-mode matrix.  Set ``method_level_matrix=True`` to expand each
    surface to its supported static methods, and pass the two thesis conditions
    and guardrail configurations explicitly when executing the full experiment.
    Every coordinate is recorded in the individual artifact configuration.
    """
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

    def emit(event_type: str, *, message: str, data: dict[str, Any]) -> None:
        if event_sink is not None:
            event_sink.emit(RunEvent(
                event_type=event_type,
                execution_id=matrix_execution_id,
                message=message,
                data=data,
            ))

    emit("matrix.started", message="Experiment matrix started", data={"total": total_runs})

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
        "model_configs": redact_secrets(model_configs or {}),
    }

    def finalize_aggregate(status: str) -> tuple[list[dict], dict[str, Any]]:
        aggregate = _build_matrix_aggregate(artifacts)
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
        if output_dir:
            write_json_report(Path(output_dir) / f"{matrix_execution_id}.matrix.json", aggregate)
        return artifacts, aggregate

    artifacts: list[dict] = []
    for coordinate in coordinates:
        if cancellation_token.is_cancelled:
            emit("matrix.cancelled", message="Matrix cancellation acknowledged", data={
                "completed": len(artifacts), "total": total_runs,
            })
            if include_aggregate:
                return finalize_aggregate("cancelled")
            return artifacts
        provider = str(coordinate["provider"])
        coordinate_output_dir = output_dir
        if run_output_dir_factory is not None:
            coordinate_output_dir = str(run_output_dir_factory(coordinate, len(artifacts)))
        if provider not in SUPPORTED_PROVIDERS:
            skipped_config = {
                "target_url": target_url,
                **coordinate,
                "evasion_enabled": coordinate["guardrail_retry_enabled"],
                "evasion_mode": coordinate["guardrail_handling"],
                "max_iterations": max_iterations,
                "candidate_budget": candidate_budget,
            }
            artifacts.append({
                "schema_version": "tui.v1",
                "execution_id": new_execution_id(),
                "run_id": (
                    f"{provider}-{coordinate['surface']}-{coordinate['security_level']}-"
                    f"{coordinate['payload_mode']}-{coordinate['experiment_condition']}-"
                    f"{coordinate['target_method'] or 'surface'}-{coordinate['repeat_index']}"
                ),
                "status": "skipped",
                "config": skipped_config,
                "config_fingerprint": config_fingerprint(skipped_config),
                "timing": {},
                "final_state": {},
                "report": {},
                "error": f"Unsupported provider: {provider}",
            })
            continue

        emit("matrix.run.started", message="Starting matrix coordinate", data={
            **coordinate, "completed": len(artifacts), "total": total_runs,
        })
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
            "event_sink": event_sink,
            "cancellation_token": cancellation_token,
            "execution_id": new_execution_id(),
            "experiment_condition": coordinate["experiment_condition"],
            "target_method": coordinate["target_method"],
        }
        artifact = _run_single_with_payload_kwargs(run_kwargs)
        artifacts.append(artifact)
        emit("matrix.run.finished", message="Matrix coordinate finished", data={
            **coordinate,
            "status": artifact.get("status", "unknown"),
            "completed": len(artifacts),
            "total": total_runs,
        })

    if include_aggregate:
        artifacts, aggregate = finalize_aggregate("cancelled" if cancellation_token.is_cancelled else "success")
        emit("matrix.finished", message="Experiment matrix finished", data=aggregate.get("totals", {}))
        return artifacts, aggregate
    emit("matrix.finished", message="Experiment matrix finished", data={"completed": len(artifacts)})
    return artifacts
