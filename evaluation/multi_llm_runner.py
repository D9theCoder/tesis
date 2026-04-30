"""Stage 6 matrix runner across providers, surfaces, and security levels."""

from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean
from typing import Any

from core.state import SECURITY_LEVELS
from evaluation.metrics import aggregate_runs
from llm.provider import SUPPORTED_PROVIDERS

from evaluation.runner import run_single_engagement


def _build_matrix_aggregate(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    by_provider_surface_level: dict[str, dict[str, dict[str, dict[str, Any]]]] = {}
    by_provider: dict[str, dict[str, Any]] = {}

    for artifact in artifacts:
        config = artifact.get("config", {})
        provider = str(config.get("provider", "unknown"))
        surface = str(config.get("surface", "unknown"))
        level = str(config.get("security_level", "unknown"))
        status = str(artifact.get("status", "unknown"))
        final_state = artifact.get("final_state", {})

        provider_surface = by_provider_surface_level.setdefault(provider, {}).setdefault(
            surface,
            {},
        )
        provider_level = provider_surface.setdefault(
            level,
            {
                "runs": 0,
                "statuses": {"success": 0, "error": 0, "skipped": 0},
                "total_score": 0,
                "chain_exploits": 0,
                "guardrail_activations": 0,
                "highest_outcomes": [],
                "iterations": [],
            },
        )
        provider_level["runs"] += 1
        if status in provider_level["statuses"]:
            provider_level["statuses"][status] += 1

        provider_summary = by_provider.setdefault(
            provider,
            {
                "runs": 0,
                "statuses": {"success": 0, "error": 0, "skipped": 0},
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
                successful = max(level_payload["statuses"]["success"], 1)
                level_payload["avg_score"] = round(level_payload["total_score"] / successful, 2)
                level_payload["avg_iterations"] = round(mean(level_payload["iterations"]), 2) if level_payload["iterations"] else 0.0

    for payload in by_provider.values():
        successful = max(payload["statuses"]["success"], 1)
        payload["avg_score"] = round(payload["total_score"] / successful, 2)
        payload["avg_iterations"] = round(mean(payload["iterations"]), 2) if payload["iterations"] else 0.0
        total_calls_estimate = sum(payload["iterations"]) or 0
        payload["guardrail_rate"] = (
            round(payload["guardrail_activations"] / total_calls_estimate * 100, 2)
            if total_calls_estimate > 0
            else 0.0
        )

    return {
        "schema_version": "stage8.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": aggregate_runs(artifacts),
        "diagnostics": {
            "runs_with_diagnostics": sum(
                1
                for artifact in artifacts
                if isinstance(artifact.get("report", {}).get("summary", {}).get("diagnostics"), dict)
            ),
        },
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
    repeats: int = 1,
    max_iterations: int = 30,
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
) -> list[dict] | tuple[list[dict], dict[str, Any]]:
    chosen_providers = sorted(providers or list(SUPPORTED_PROVIDERS))
    chosen_levels = sorted(security_levels or list(SECURITY_LEVELS))
    chosen_surfaces = sorted(surfaces or ["sqli", "access_control", "brute_force"])

    artifacts: list[dict] = []
    for provider in chosen_providers:
        if provider not in SUPPORTED_PROVIDERS:
            for surface in chosen_surfaces:
                for level in chosen_levels:
                    for repeat_index in range(repeats):
                        artifacts.append(
                            {
                                "schema_version": "stage8.v1",
                                "run_id": f"{provider}-{surface}-{level}-{repeat_index}",
                                "status": "skipped",
                                "config": {
                                    "target_url": target_url,
                                    "provider": provider,
                                    "security_level": level,
                                    "surface": surface,
                                    "max_iterations": max_iterations,
                                    "repeat_index": repeat_index,
                                    "evasion_enabled": evasion_enabled,
                                    "evasion_mode": evasion_mode,
                                },
                                "timing": {},
                                "final_state": {},
                                "report": {},
                                "error": f"Unsupported provider: {provider}",
                            }
                        )
            continue

        for surface in chosen_surfaces:
            for level in chosen_levels:
                for repeat_index in range(repeats):
                    artifacts.append(
                        run_single_engagement(
                            target_url=target_url,
                            security_level=level,
                            llm_provider=provider,
                            surface=surface,
                            max_iterations=max_iterations,
                            repeat_index=repeat_index,
                            stop_policy=stop_policy,
                            coverage_target=coverage_target,
                            enriched_reporting=enriched_reporting,
                            diagnose=diagnose,
                            evasion_enabled=evasion_enabled,
                            evasion_mode=evasion_mode,
                            evasion_max_retries=evasion_max_retries,
                            evasion_cooldown_threshold=evasion_cooldown_threshold,
                            output_dir=output_dir,
                            live_display=live_display,
                            model_config=(model_configs or {}).get(provider),
                        )
                    )

    if include_aggregate:
        return artifacts, _build_matrix_aggregate(artifacts)
    return artifacts
