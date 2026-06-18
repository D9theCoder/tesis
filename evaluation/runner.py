"""Single-engagement Stage 6 evaluation runner."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from traceback import format_exc
from typing import Any

from core.graph_builder import build_framework
from core.scorer import build_score_report
from core.state import new_default_state
from evaluation.diagnostics import diagnose_quality
from evaluation.failure_logger import write_failure_artifact
from evaluation.manual_scoring_sheet import manual_scoring_rows
from evaluation.reporter import write_events_jsonl, write_rich_report
from evaluation.telemetry import RunTelemetry, stable_sha256


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_single_engagement(
    *,
    target_url: str,
    security_level: str,
    llm_provider: str,
    surface: str = "sqli",
    payload_mode: str = "static_only",
    experiment_condition: str = "akg_guided_hybrid",
    target_method: str | None = None,
    max_iterations: int = 30,
    candidate_budget: int = 5,
    repeat_index: int = 0,
    stop_policy: str = "impact",
    coverage_target: float = 0.70,
    enriched_reporting: bool = False,
    diagnose: bool = False,
    output_dir: str | None = None,
    evasion_enabled: bool = False,
    evasion_mode: str = "reactive",
    evasion_max_retries: int = 3,
    evasion_cooldown_threshold: int = 5,
    live_display: bool = False,
    model_config: dict[str, Any] | None = None,
) -> dict:
    """Run one configured DVWA framework engagement and write evaluation artifacts.

    The runner builds an initial `ExploitationState`, compiles the LangGraph
    workflow, invokes it, computes score reports, records telemetry, and writes
    JSONL/report artifacts. Exceptions are captured into failure artifacts so a
    matrix run can continue.

    Args:
        target_url: DVWA base URL for the engagement.
        security_level: DVWA security level to configure.
        llm_provider: Provider identifier passed into framework state.
        surface: Vulnerability surface selected for the run.
        payload_mode: Payload candidate mode for the run.
        experiment_condition: Thesis condition ("linear_hybrid" or
            "akg_guided_hybrid") controlling AKG-guided method selection.
        target_method: Optional explicit method for method-level evaluation.
        max_iterations: Maximum LangGraph method iterations.
        candidate_budget: Maximum generated-candidate budget per method.
        repeat_index: Matrix repeat index used in artifact IDs.
        stop_policy: Evaluation stop policy recorded in artifacts.
        coverage_target: Coverage threshold recorded for diagnostics.
        enriched_reporting: Whether to emit richer text reports.
        diagnose: Whether to add diagnostic quality analysis.
        output_dir: Optional directory for written run artifacts.
        evasion_enabled: Whether guardrail retry behavior is enabled.
        evasion_mode: Evasion retry mode stored in state.
        evasion_max_retries: Maximum retry attempts for guardrail false positives.
        evasion_cooldown_threshold: Clean-response threshold for cooldown logic.
        live_display: Whether to run the terminal progress reporter.
        model_config: Optional provider model configuration.

    Returns:
        Run artifact containing final state, report, telemetry, paths, and
        failure details when execution fails.
    """
    method_tag = f"-{target_method}" if target_method else ""
    run_id = f"{llm_provider}-{experiment_condition}-{surface}{method_tag}-{security_level}-{payload_mode}-{repeat_index}"
    started_at = _now_iso()
    started_clock = perf_counter()
    telemetry = RunTelemetry(run_id=run_id)
    reporter = None
    if live_display:
        try:
            from tesis.progress_reporter import EngagementProgressReporter
            reporter = EngagementProgressReporter(
                max_iterations=max_iterations,
                provider=llm_provider,
                level=security_level,
            )
            reporter.start()
        except Exception as exc:
            LOGGER = logging.getLogger(__name__)
            LOGGER.warning("Live display initialization failed: %s", exc)
    telemetry.emit(
        iteration=0,
        node="runner",
        event_type="run.started",
        status="ok",
        payload={
            "target_url": target_url,
            "provider": llm_provider,
            "security_level": security_level,
            "surface": surface,
            "payload_mode": payload_mode,
        },
    )

    try:
        evasion_enabled = bool(evasion_enabled)
        app = build_framework(llm_provider=llm_provider, surface=surface)
        init_state = {
            **new_default_state(),
            "target_url": target_url,
            "security_level": security_level,
            "llm_provider": llm_provider,
            "current_surface": surface,
            "payload_mode": payload_mode,
            "experiment_condition": experiment_condition,
            "target_method": target_method,
            "candidate_budget": candidate_budget,
            "max_iterations": max_iterations,
            "stop_policy": stop_policy,
            "coverage_target": coverage_target,
            "evasion_enabled": evasion_enabled,
            "evasion_mode": evasion_mode,
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
            "model_config": model_config or {},
        }

        final_state = None
        seen_events = 0
        graph_config = {
            "configurable": {
                "thread_id": f"{llm_provider}-{surface}-{security_level}-{payload_mode}-{repeat_index}"
            }
        }
        try:
            stream_iter = app.stream(init_state, stream_mode="values", config=graph_config)
        except TypeError:
            # Lightweight test doubles may not accept LangGraph's config kwarg.
            stream_iter = app.stream(init_state, stream_mode="values")
        for state_snapshot in stream_iter:
            final_state = state_snapshot
            if reporter:
                events = final_state.get("telemetry_events", [])
                new_events = events[seen_events:]
                seen_events = len(events)
                for event in new_events:
                    reporter.update(event)
        if final_state is None:
            try:
                final_state = app.invoke(init_state, config=graph_config)
            except TypeError:
                final_state = app.invoke(init_state)
        telemetry.extend_from_state_events(list(final_state.get("telemetry_events", [])))
        report = build_score_report(final_state).to_dict()
        if reporter:
            reporter.finalize(report)
        status = "success"
        error = None
    except Exception as exc:
        final_state = new_default_state()
        final_state.update({
            "target_url": target_url,
            "security_level": security_level,
            "llm_provider": llm_provider,
            "current_surface": surface,
            "payload_mode": payload_mode,
            "experiment_condition": experiment_condition,
            "target_method": target_method,
            "candidate_budget": candidate_budget,
            "max_iterations": max_iterations,
            "stop_policy": stop_policy,
            "coverage_target": coverage_target,
            "iteration_count": 0,
            "evasion_enabled": evasion_enabled,
            "evasion_mode": evasion_mode,
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
        })
        report = build_score_report(final_state).to_dict()
        status = "error"
        error = f"{type(exc).__name__}: {exc}\n{format_exc()}"
        telemetry.emit(
            iteration=0,
            node="runner",
            event_type="run.failed",
            status="error",
            payload={"error_type": type(exc).__name__},
        )

    if reporter:
        reporter.stop()

    ended_at = _now_iso()
    duration_ms = int((perf_counter() - started_clock) * 1000)
    telemetry.emit(
        iteration=int(final_state.get("iteration_count", 0) or 0),
        node="runner",
        event_type="run.finished",
        status=status,
        payload={"duration_ms": duration_ms},
    )

    if diagnose:
        summary = report.get("summary", {}) if isinstance(report, dict) else {}
        module_scores = report.get("module_scores", {}) if isinstance(report, dict) else {}
        score_map = {
            name: int(payload.get("score", 0))
            for name, payload in module_scores.items()
            if isinstance(payload, dict)
        }
        diagnostics = diagnose_quality(
            scores=score_map,
            total_iterations_used=int(summary.get("total_iterations_used", 0) or 0),
            highest_outcome=summary.get("highest_impact_outcome"),
        )
        if isinstance(summary, dict):
            summary["diagnostics"] = diagnostics

    if enriched_reporting:
        base_dir = Path(output_dir) if output_dir else Path("results") / "runs"
        events = telemetry.as_dict_list()
        rich_payload = {
            "schema_version": "stage7.rich.v1",
            "run_id": run_id,
            "status": status,
            "prompt_response_hashes": [
                {
                    "event_type": event.get("event_type"),
                    "hash": stable_sha256(
                        json.dumps(event.get("payload", {}), sort_keys=True, separators=(",", ":"))
                    ),
                }
                for event in events
                if isinstance(event, dict)
                and str(event.get("event_type", "")).startswith("orchestrator")
            ],
            "events_count": len(events),
        }
        try:
            write_events_jsonl(base_dir / f"{run_id}.events.jsonl", events)
            write_rich_report(base_dir / f"{run_id}.rich.json", rich_payload)
            if status == "error":
                write_failure_artifact(
                    output_dir=base_dir,
                    run_id=run_id,
                    error=error or "unknown_error",
                    final_state={
                        "iteration_count": final_state.get("iteration_count", 0),
                        "confirmed_vulns": list(final_state.get("confirmed_vulns", [])),
                        "achieved_outcomes": list(final_state.get("achieved_outcomes", [])),
                        "evasion_enabled": final_state.get("evasion_enabled", False),
                        "evasion_mode": final_state.get("evasion_mode", "reactive"),
                        "evasion_max_retries": final_state.get("evasion_max_retries", 3),
                        "evasion_cooldown_threshold": final_state.get("evasion_cooldown_threshold", 5),
                    },
                    recent_events=events[-20:],
                )
        except Exception as exc:
            # Sidecar generation must never break primary artifact generation.
            summary = report.get("summary") if isinstance(report, dict) else None
            if isinstance(summary, dict):
                summary["sidecar_warning"] = f"{type(exc).__name__}: {exc}"

    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    method_scores = dict(final_state.get("method_scores", {}))
    payload_scores = dict(final_state.get("payload_scores", {}))
    exploitation_scores = dict(final_state.get("exploitation_scores", {}))
    chain_scores = dict(final_state.get("chain_scores", {}))
    selected_method = final_state.get("selected_method")
    method_score = method_scores.get(selected_method, 0)
    exploitation_score = exploitation_scores.get(selected_method, 0)
    chain_score = chain_scores.get(selected_method, 0)
    output_score = int(summary.get("output_validity_score", 0) or 0)
    composite_score = float(summary.get("composite_score", 0.0) or 0.0)

    artifact = {
        "schema_version": "stage8.v1",
        "run_id": run_id,
        "status": status,
        "provider": llm_provider,
        "surface": surface,
        "security_level": security_level,
        "payload_mode": payload_mode,
        "experiment_condition": experiment_condition,
        "target_method": target_method,
        "selected_method": selected_method,
        "akg_path": list(final_state.get("akg_path", [])),
        "viable_methods": list(final_state.get("viable_methods", [])),
        "method_score": method_score,
        "payload_scores": payload_scores,
        "exploitation_score": exploitation_score,
        "chain_score": chain_score,
        "output_score": output_score,
        "composite_score": composite_score,
        "payload_validity_rate": summary.get("payload_validity_rate", 0.0),
        "payload_execution_success_rate": summary.get("payload_execution_success_rate", 0.0),
        "payload_improvement_rate": summary.get("payload_improvement_rate", 0.0),
        "consistency_score": summary.get("consistency_score", 0.0),
        "guardrail_activations": len(final_state.get("guardrail_activations", [])),
        "payload_guardrail_activations": len(final_state.get("payload_guardrail_activations", [])),
        "invalid_json_events": len(final_state.get("invalid_json_events", [])),
        "fallback_events": len(final_state.get("fallback_events", [])),
        "containment_events": len(final_state.get("containment_events", [])),
        "attempts_to_success": int(round(summary.get("mean_attempts_to_success", 0.0) or 0.0)),
        "token_cost": summary.get("token_cost", 0.0),
        "config": {
            "target_url": target_url,
            "provider": llm_provider,
            "security_level": security_level,
            "surface": surface,
            "payload_mode": payload_mode,
            "experiment_condition": experiment_condition,
            "target_method": target_method,
            "max_iterations": max_iterations,
            "candidate_budget": candidate_budget,
            "repeat_index": repeat_index,
            "evasion_enabled": evasion_enabled,
            "evasion_mode": evasion_mode,
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
        },
        "timing": {
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_ms": duration_ms,
        },
        "final_state": {
            "iteration_count": final_state.get("iteration_count", 0),
            "confirmed_vulns": list(final_state.get("confirmed_vulns", [])),
            "achieved_outcomes": list(final_state.get("achieved_outcomes", [])),
            "guardrail_activations": list(final_state.get("guardrail_activations", [])),
            "payload_guardrail_activations": list(final_state.get("payload_guardrail_activations", [])),
            "invalid_json_events": list(final_state.get("invalid_json_events", [])),
            "fallback_events": list(final_state.get("fallback_events", [])),
            "containment_events": list(final_state.get("containment_events", [])),
            "selected_method": selected_method,
            "viable_methods": list(final_state.get("viable_methods", [])),
            "payload_candidates": dict(final_state.get("payload_candidates", {})),
            "generated_payloads": dict(final_state.get("generated_payloads", {})),
            "payload_validation_results": dict(final_state.get("payload_validation_results", {})),
            "payload_scores": payload_scores,
            "payload_provenance": dict(final_state.get("payload_provenance", {})),
            "method_scores": method_scores,
            "exploitation_scores": exploitation_scores,
            "chain_scores": chain_scores,
            "output_scores": dict(final_state.get("output_scores", {})),
            "composite_scores": dict(final_state.get("composite_scores", {})),
            "experiment_condition": final_state.get("experiment_condition", experiment_condition),
            "target_method": final_state.get("target_method", target_method),
            "evasion_enabled": final_state.get("evasion_enabled", False),
            "evasion_mode": final_state.get("evasion_mode", "reactive"),
            "evasion_max_retries": final_state.get("evasion_max_retries", 3),
            "evasion_cooldown_threshold": final_state.get("evasion_cooldown_threshold", 5),
        },
        "report": report,
        "error": error,
    }
    artifact["manual_scoring_evidence"] = manual_scoring_rows(artifact)
    return artifact
