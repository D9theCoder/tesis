"""Stage 6 matrix runner across providers and security levels."""

from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean
from typing import Any

from core.state import SECURITY_LEVELS
from evaluation.metrics import aggregate_runs
from llm.provider import SUPPORTED_PROVIDERS

from evaluation.runner import run_single_engagement


def _build_matrix_aggregate(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    by_provider_level: dict[str, dict[str, dict[str, Any]]] = {}
    by_provider: dict[str, dict[str, Any]] = {}

    for artifact in artifacts:
        config = artifact.get("config", {})
        provider = str(config.get("provider", "unknown"))
        level = str(config.get("security_level", "unknown"))
        status = str(artifact.get("status", "unknown"))
        strategy = str(config.get("evasion_strategy", "pipeline"))
        final_state = artifact.get("final_state", {})

        provider_level = by_provider_level.setdefault(provider, {}).setdefault(
            level,
            {
                "runs": 0,
                "statuses": {"success": 0, "error": 0, "skipped": 0},
                "total_score": 0,
                "chain_exploits": 0,
                "guardrail_activations": 0,
                "highest_outcomes": [],
                "iterations": [],
                "evasion_attempts": 0,
                "successful_evasions": 0,
                "evasion_strategy": strategy,
                "evasion_enabled": bool(config.get("evasion_enabled", False)),
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
                "evasion_attempts": 0,
                "successful_evasions": 0,
                "evasion_strategy": strategy,
                "evasion_enabled": bool(config.get("evasion_enabled", False)),
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

        evasion_attempts = int(final_state.get("evasion_attempts", 0) or 0)
        successful_evasions = int(final_state.get("successful_evasions", 0) or 0)
        provider_level["evasion_attempts"] += evasion_attempts
        provider_level["successful_evasions"] += successful_evasions
        provider_summary["evasion_attempts"] += evasion_attempts
        provider_summary["successful_evasions"] += successful_evasions

    for provider_levels in by_provider_level.values():
        for payload in provider_levels.values():
            successful = max(payload["statuses"]["success"], 1)
            payload["avg_score"] = round(payload["total_score"] / successful, 2)
            payload["avg_iterations"] = round(mean(payload["iterations"]), 2) if payload["iterations"] else 0.0
            attempts = payload["evasion_attempts"]
            payload["evasion_success_rate"] = (
                round(payload["successful_evasions"] / attempts * 100, 2)
                if attempts > 0
                else None
            )

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
        attempts = payload["evasion_attempts"]
        payload["evasion_success_rate"] = (
            round(payload["successful_evasions"] / attempts * 100, 2)
            if attempts > 0
            else None
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
        "by_provider_level": by_provider_level,
        "by_provider": by_provider,
        "runs": artifacts,
    }


def run_provider_matrix(
    *,
    target_url: str,
    providers: list[str] | None = None,
    security_levels: list[str] | None = None,
    repeats: int = 1,
    max_iterations: int = 30,
    stop_policy: str = "impact",
    coverage_target: float = 0.70,
    enriched_reporting: bool = False,
    diagnose: bool = False,
    output_dir: str | None = None,
    include_aggregate: bool = False,
    evasion_enabled: bool = False,
    evasion_strategy: str = "pipeline",
) -> list[dict] | tuple[list[dict], dict[str, Any]]:
    chosen_providers = sorted(providers or list(SUPPORTED_PROVIDERS))
    chosen_levels = sorted(security_levels or list(SECURITY_LEVELS))

    artifacts: list[dict] = []
    for provider in chosen_providers:
        if provider not in SUPPORTED_PROVIDERS:
            for level in chosen_levels:
                for repeat_index in range(repeats):
                    artifacts.append(
                        {
                            "schema_version": "stage8.v1",
                            "run_id": f"{provider}-{level}-{repeat_index}",
                            "status": "skipped",
                            "config": {
                                "target_url": target_url,
                                "provider": provider,
                                "security_level": level,
                                "max_iterations": max_iterations,
                                "repeat_index": repeat_index,
                                "evasion_enabled": evasion_enabled,
                                "evasion_strategy": evasion_strategy,
                            },
                            "timing": {},
                            "final_state": {},
                            "report": {},
                            "error": f"Unsupported provider: {provider}",
                        }
                    )
            continue

        for level in chosen_levels:
            for repeat_index in range(repeats):
                artifacts.append(
                    run_single_engagement(
                        target_url=target_url,
                        security_level=level,
                        llm_provider=provider,
                        max_iterations=max_iterations,
                        repeat_index=repeat_index,
                        stop_policy=stop_policy,
                        coverage_target=coverage_target,
                        enriched_reporting=enriched_reporting,
                        diagnose=diagnose,
                        evasion_enabled=evasion_enabled,
                        evasion_strategy=evasion_strategy,
                        output_dir=output_dir,
                    )
                )

    if include_aggregate:
        return artifacts, _build_matrix_aggregate(artifacts)
    return artifacts
