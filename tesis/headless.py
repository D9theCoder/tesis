"""Non-interactive terminal execution for automation and LLM clients."""

from __future__ import annotations

import dataclasses
import inspect
from pathlib import Path
from typing import Any

from evaluation.multi_llm_runner import run_provider_matrix
from evaluation.reporter import write_json_report
from evaluation.runner import run_single_engagement
from core.knowledge_graph import AttackKnowledgeGraph
from tesis.artifact_layout import allocate_artifact_layout
from tesis.artifact_repository import config_fingerprint, new_execution_id
from tesis.config_loader import load_and_resolve_config
from tesis.live_runtime import (
    RuntimeDescriptor,
    RuntimeDescriptorHeartbeatSink,
    akg_snapshot,
    build_runtime_descriptor,
    safe_target_scope,
    write_descriptor,
    write_terminal_descriptor,
)
from tesis.model_config import EngagementConfig, ModelConfig
from tesis.runtime_events import CancellationToken
from tesis.runtime_journal import JSONLJournalSink, MultiplexingRuntimeEventSink
from llm.runtime import LLMRuntime


def _model_dict(config: EngagementConfig, provider: str) -> dict[str, Any]:
    model = config.models.get(provider)
    return dataclasses.asdict(model) if model else {}


def _runtime_kwargs(config: EngagementConfig) -> dict[str, Any]:
    """Return runner-facing LLM acceleration settings without credentials."""

    runtime = config.llm_runtime
    role_configs = {
        role: dataclasses.asdict(settings)
        for role, settings in runtime.roles.items()
    }
    model_profiles = {
        name: dataclasses.asdict(value)
        for name, value in config.models.items()
    }
    return {
        "llm_max_concurrency": runtime.max_concurrency,
        "llm_cache": runtime.cache_enabled,
        "llm_cache_enabled": runtime.cache_enabled,
        "llm_cache_scope": runtime.cache_scope,
        "role_configs": role_configs,
        "llm_role_configs": role_configs,
        "model_profiles": model_profiles,
        # The nested form is useful to newer runners that want one immutable
        # settings object; the scalar fields above keep the function boundary
        # straightforward for older and test-double runners.
        "llm_runtime_config": dataclasses.asdict(runtime),
    }


def _common_kwargs(config: EngagementConfig, *, output_dir: Path) -> dict[str, Any]:
    kwargs = {
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
    kwargs.update(_runtime_kwargs(config))
    return kwargs


def _call_runner(function: Any, kwargs: dict[str, Any]) -> Any:
    """Call current or newer runners while preserving direct-call compatibility."""

    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return function(**kwargs)
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values()):
        return function(**kwargs)
    supported = {
        key: value
        for key, value in kwargs.items()
        if key in signature.parameters
    }
    return function(**supported)


def _cancelled_result(
    config: EngagementConfig,
    *,
    reason: str,
    execution_id: str | None = None,
) -> dict[str, Any]:
    """Build a minimal auditable artifact when Ctrl-C interrupts a runner."""

    execution_id = execution_id or new_execution_id()
    if config.matrix:
        total_runs = (
            len(config.providers)
            * len(config.levels)
            * len(config.surfaces)
            * len(config.payload_modes)
            * config.repeats
        )
        matrix_config = {
            "target_url": config.target_url,
            "providers": list(config.providers),
            "security_levels": list(config.levels),
            "surfaces": list(config.surfaces),
            "payload_modes": list(config.payload_modes),
            "repeats": config.repeats,
            "experiment_condition": config.experiment_condition,
            "target_method": config.target_method,
            "llm_max_concurrency": config.llm_runtime.max_concurrency,
            "llm_cache_enabled": config.llm_runtime.cache_enabled,
        }
        return {
            "schema_version": "stage8.v1",
            "execution_id": execution_id,
            "run_id": f"matrix-{execution_id[:12]}",
            "status": "cancelled",
            "config": matrix_config,
            "matrix": {**matrix_config, "runs": 0},
            "totals": {
                "total_runs": 0,
                "successful_runs": 0,
                "error_runs": 0,
                "skipped_runs": 0,
                "cancelled_runs": 0,
            },
            "runs": [],
            "cancellation": {
                "requested": True,
                "reason": reason,
                "completed_runs": 0,
                "total_runs": total_runs,
                "not_started_runs": total_runs,
            },
            "llm_performance_summary": {},
        }

    run_id = f"{config.provider}-{config.surface}-{config.level}-{config.payload_mode}-0"
    artifact_config = {
        "target_url": config.target_url,
        "provider": config.provider,
        "surface": config.surface,
        "security_level": config.level,
        "payload_mode": config.payload_mode,
        "experiment_condition": config.experiment_condition,
        "target_method": config.target_method,
        "llm_cache_enabled": config.llm_runtime.cache_enabled,
        "llm_max_concurrency": config.llm_runtime.max_concurrency,
    }
    return {
        "schema_version": "tui.v1",
        "execution_id": execution_id,
        "run_id": run_id,
        "status": "cancelled",
        "config": artifact_config,
        "final_state": {
            "task_result": None,
            "incomplete_reason": "CANCELLED",
        },
        "timing": {},
        "report": {},
        "llm_performance": [],
        "error": reason,
        "cancellation_reason": reason,
    }


def _descriptor_coordinates(config: EngagementConfig) -> dict[str, Any]:
    """Build safe, secret-free coordinate metadata for a run descriptor."""

    model = config.models.get(config.provider)
    model_name = model.model_name if model is not None else None
    return {
        "mode": "matrix" if config.matrix else "single-run",
        "provider": config.provider,
        "model": model_name,
        "surface": config.surface,
        "security_level": config.level,
        "payload_mode": config.payload_mode,
        "experiment_condition": config.experiment_condition,
        "target_method": config.target_method,
        "target_url": safe_target_scope(config.target_url),
        "candidate_budget": config.candidate_budget,
        "max_iterations": config.iterations,
    }


def _terminal_status_for_result(result: dict[str, Any]) -> str:
    """Map a runner result/exception into a terminal descriptor status."""

    status = str(result.get("status", "unknown")).lower()
    if status in {"success", "complete", "completed", "finished"}:
        return "finished"
    if status == "cancelled":
        return "cancelled"
    if status in {"error", "failed"}:
        return "failed"
    return "failed"


def _export_akg_snapshot(root: Path) -> Path:
    """Write the deterministic read-only AKG snapshot for frontend fallback."""

    return write_json_report(root / "akg.snapshot.json", akg_snapshot(AttackKnowledgeGraph()))


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
    cancellation_token = CancellationToken()
    execution_id = new_execution_id()
    common = _common_kwargs(config, output_dir=layout.root)
    common["cancellation_token"] = cancellation_token
    common["execution_id"] = execution_id
    # The matrix runner owns one runtime across all coordinates.  A single run
    # uses the same service abstraction with an effective concurrency of one so
    # direct and headless execution have identical lifecycle semantics.
    runtime_service = LLMRuntime(
        max_concurrency=config.llm_runtime.max_concurrency if config.matrix else 1,
    )
    common["llm_runtime"] = runtime_service
    artifacts: list[dict[str, Any]] = []
    result: dict[str, Any] = {"status": "error", "error": "run did not start"}
    descriptor: RuntimeDescriptor | None = None
    heartbeat_sink: RuntimeDescriptorHeartbeatSink | None = None
    journal_sink: JSONLJournalSink | None = None
    try:
        # Live observation: wire a redacted journal into the runner event sink
        # and publish an atomic "active" descriptor before invoking a runner.
        known_secrets = [model.api_key for model in config.models.values() if model.api_key]
        journal_sink = JSONLJournalSink(
            layout.root / "runtime.events.jsonl",
            known_secrets=known_secrets,
        )
        descriptor = build_runtime_descriptor(
            mode="matrix" if config.matrix else "single-run",
            experiment_dir=layout.root,
            execution_id=execution_id,
            config_fingerprint=config_fingerprint(dataclasses.asdict(config)),
            coordinates=_descriptor_coordinates(config),
        )
        write_descriptor(descriptor)
        heartbeat_sink = RuntimeDescriptorHeartbeatSink(descriptor)
        common["event_sink"] = MultiplexingRuntimeEventSink(journal_sink, heartbeat_sink)
        # The same physical execution ID is passed to the runner so the
        # descriptor, journal events, and primary artifact are discoverable
        # under one identity.
        common["execution_id"] = descriptor.execution_id
        _export_akg_snapshot(layout.root)

        if config.matrix:
            matrix_kwargs = {
                **common,
                "providers": config.providers,
                "security_levels": config.levels,
                "surfaces": config.surfaces,
                "payload_modes": config.payload_modes,
                "repeats": config.repeats,
                "include_aggregate": True,
                "run_output_dir_factory": layout.child_directory,
                "model_configs": {
                    name: dataclasses.asdict(value)
                    for name, value in config.models.items()
                },
            }
            artifacts, result = _call_runner(run_provider_matrix, matrix_kwargs)
        else:
            single_kwargs = {
                **common,
                "security_level": config.level,
                "llm_provider": config.provider,
                "surface": config.surface,
                "payload_mode": config.payload_mode,
                "model_config": _model_dict(config, config.provider),
            }
            result = _call_runner(run_single_engagement, single_kwargs)
    except KeyboardInterrupt:
        cancellation_token.cancel("keyboard interrupt")
        result = _cancelled_result(
            config,
            reason="keyboard interrupt",
            execution_id=execution_id,
        )
        artifacts = []
    except Exception as exc:
        result = {
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        runtime_service.close()
        # Always land in a terminal state, even when runner/provider setup fails.
        if descriptor is not None:
            try:
                descriptor_source = heartbeat_sink.descriptor if heartbeat_sink else descriptor
                terminal_descriptor = dataclasses.replace(
                    descriptor_source,
                    # Matrix child artifacts have their own execution IDs.
                    # The parent descriptor always retains the preallocated
                    # matrix execution ID.
                    execution_id=descriptor_source.execution_id or result.get("execution_id"),
                    run_id=(
                        result.get("run_id")
                        if not config.matrix
                        else descriptor_source.run_id
                    ) or descriptor_source.run_id,
                )
                write_terminal_descriptor(
                    terminal_descriptor,
                    _terminal_status_for_result(result),
                )
            except Exception as exc:
                result.setdefault("runtime_descriptor_error", f"{type(exc).__name__}: {exc}")
        if journal_sink is not None:
            try:
                journal_sink.close()
            except Exception as exc:
                result.setdefault("runtime_journal_error", f"{type(exc).__name__}: {exc}")
        if isinstance(result, dict) and str(result.get("status", "")).lower() == "cancelled":
            execution_id = result.get("execution_id")
            if execution_id:
                if config.matrix:
                    aggregate_path = layout.root / f"{execution_id}.matrix.json"
                else:
                    aggregate_path = layout.root / f"{execution_id}.json"
                if not aggregate_path.exists():
                    write_json_report(aggregate_path, result)
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
