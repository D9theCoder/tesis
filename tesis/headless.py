"""Non-interactive terminal execution for automation and LLM clients."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from evaluation.multi_llm_runner import run_provider_matrix
from evaluation.runner import run_single_engagement
from tesis.artifact_layout import allocate_artifact_layout
from tesis.config_loader import load_and_resolve_config
from tesis.model_config import EngagementConfig, ModelConfig
from tesis.runtime_events import CancellationToken


def _model_dict(config: EngagementConfig, provider: str) -> dict[str, Any]:
    model = config.models.get(provider)
    return dataclasses.asdict(model) if model else {}


def _common_kwargs(config: EngagementConfig, *, output_dir: Path) -> dict[str, Any]:
    return {
        "target_url": config.target_url,
        "max_iterations": config.iterations,
        "candidate_budget": config.candidate_budget,
        "stop_policy": config.stop_policy,
        "coverage_target": config.coverage_target,
        "enriched_reporting": config.enriched_reporting,
        "diagnose": config.diagnose,
        "evasion_enabled": config.evasion_enabled,
        "evasion_mode": config.evasion_mode,
        "evasion_max_retries": config.evasion_max_retries,
        "evasion_cooldown_threshold": config.evasion_cooldown_threshold,
        "output_dir": str(output_dir),
        "cancellation_token": CancellationToken(),
        "experiment_condition": config.experiment_condition,
        "target_method": config.target_method,
    }


def run_headless(
    *,
    config_path: str,
    cli_args: dict[str, Any],
    model_name: str | None = None,
) -> tuple[int, dict[str, Any], Path]:
    """Resolve CLI overrides, execute one run or a matrix, and index artifacts."""

    config = load_and_resolve_config(config_path=config_path, cli_args=cli_args)
    if model_name:
        existing = config.models.get(config.provider)
        if existing is None:
            config.models[config.provider] = ModelConfig(
                provider=config.provider,
                api_key="",
                model_name=model_name,
            )
        else:
            existing.model_name = model_name

    layout = allocate_artifact_layout(
        config.output_dir,
        "matrix" if config.matrix else "single-run",
    )
    common = _common_kwargs(config, output_dir=layout.root)
    artifacts: list[dict[str, Any]] = []
    result: dict[str, Any] = {"status": "error", "error": "run did not start"}
    try:
        if config.matrix:
            artifacts, result = run_provider_matrix(
                **common,
                providers=config.providers,
                security_levels=config.levels,
                surfaces=config.surfaces,
                payload_modes=config.payload_modes,
                repeats=config.repeats,
                include_aggregate=True,
                run_output_dir_factory=layout.child_directory,
                model_configs={
                    name: dataclasses.asdict(value)
                    for name, value in config.models.items()
                },
            )
        else:
            result = run_single_engagement(
                **common,
                security_level=config.level,
                llm_provider=config.provider,
                surface=config.surface,
                payload_mode=config.payload_mode,
                model_config=_model_dict(config, config.provider),
            )
    except Exception as exc:
        result = {
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        manifest_config = dataclasses.asdict(config)
        try:
            layout.write_manifest(
                config=manifest_config,
                artifacts=artifacts if config.matrix else ([result] if result else []),
                aggregate=result if config.matrix else None,
                status=str(result.get("status", "unknown")),
            )
        except Exception as exc:
            result.setdefault("artifact_manifest_error", f"{type(exc).__name__}: {exc}")

    exit_code = 0 if str(result.get("status", "error")).lower() in {"success", "cancelled"} else 1
    return exit_code, result, layout.root


__all__ = ["run_headless"]
