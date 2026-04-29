"""Single-engagement Stage 6 evaluation runner."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from traceback import format_exc

from core.graph_builder import build_framework
from core.scorer import build_score_report
from core.state import new_default_state
from evaluation.diagnostics import diagnose_quality
from evaluation.failure_logger import write_failure_artifact
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
    max_iterations: int = 30,
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
) -> dict:
    run_id = f"{llm_provider}-{surface}-{security_level}-{repeat_index}"
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
            "max_iterations": max_iterations,
            "stop_policy": stop_policy,
            "coverage_target": coverage_target,
            "evasion_enabled": evasion_enabled,
            "evasion_mode": evasion_mode,
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
        }

        final_state = None
        seen_events = 0
        for state_snapshot in app.stream(init_state, stream_mode="values"):
            final_state = state_snapshot
            if reporter:
                events = final_state.get("telemetry_events", [])
                new_events = events[seen_events:]
                seen_events = len(events)
                for event in new_events:
                    reporter.update(event)
        if final_state is None:
            final_state = app.invoke(init_state)
        telemetry.extend_from_state_events(list(final_state.get("telemetry_events", [])))
        report = build_score_report(final_state).to_dict()
        if reporter:
            reporter.finalize(report)
        status = "success"
        error = None
    except Exception as exc:
        final_state = {
            "iteration_count": 0,
            "confirmed_vulns": [],
            "achieved_outcomes": [],
            "guardrail_activations": [],
            "telemetry_events": [],
            "evasion_enabled": evasion_enabled,
            "evasion_mode": evasion_mode,
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
        }
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

    return {
        "schema_version": "stage8.v1",
        "run_id": run_id,
        "status": status,
        "config": {
            "target_url": target_url,
            "provider": llm_provider,
            "security_level": security_level,
            "surface": surface,
            "max_iterations": max_iterations,
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
            "evasion_enabled": final_state.get("evasion_enabled", False),
            "evasion_mode": final_state.get("evasion_mode", "reactive"),
            "evasion_max_retries": final_state.get("evasion_max_retries", 3),
            "evasion_cooldown_threshold": final_state.get("evasion_cooldown_threshold", 5),
        },
        "report": report,
        "error": error,
    }
