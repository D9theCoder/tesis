"""Stage 6 reporting helpers for JSON and Markdown outputs."""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_json_report(path: str | Path, payload: dict) -> Path:
    """Handles write json report behavior for this module.

    Args:
        path: Value used by this function.
        payload: Value used by this function."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return out_path


def _metric_lines(aggregate: dict) -> list[str]:
    """Render availability-tracked metric means without zero-filling unknowns."""
    from evaluation.metrics import UNAVAILABLE_METRICS

    totals = aggregate.get("totals", {}) if isinstance(aggregate.get("totals"), dict) else {}
    metrics = aggregate.get("metrics", totals.get("metrics", {}))
    if not isinstance(metrics, dict) or not metrics:
        return []
    # ponytail: mean=None renders N/A; unavailable counts labeled, never averaged as zero.
    lines = ["", "Availability-tracked metrics (unavailable excluded from means):"]
    for name in UNAVAILABLE_METRICS:
        entry = metrics.get(name)
        if not isinstance(entry, dict):
            continue
        mean = entry.get("mean")
        rendered = f"{mean:g}" if isinstance(mean, (int, float)) and not isinstance(mean, bool) and math.isfinite(mean) else "N/A"
        lines.append(
            f"- {name}: {rendered} "
            f"({entry.get('n_available', 0)}/{entry.get('n_available', 0) + entry.get('n_unavailable', 0)} available)"
        )
    return lines


def _runs_for_metrics(aggregate: dict) -> list[dict[str, Any]] | None:
    """Return constituent runs when the aggregate embeds them, else None."""
    for key in ("runs", "artifacts"):
        runs = aggregate.get(key)
        if isinstance(runs, list) and runs and all(isinstance(run, dict) for run in runs):
            return runs
    return None


def build_markdown_summary(aggregate: dict) -> str:
    """Builds markdown summary for framework execution.

    Args:
        aggregate: Value used by this function."""
    totals = aggregate.get("totals", {}) if isinstance(aggregate.get("totals"), dict) else {}
    lines = [
        "# Evaluation Summary",
        "",
        f"- Total runs: {totals.get('total_runs', 0)}",
        f"- Successful runs: {totals.get('successful_runs', 0)}",
        f"- Error runs: {totals.get('error_runs', 0)}",
        f"- Skipped runs: {totals.get('skipped_runs', 0)}",
    ]
    metrics_block = aggregate.get("metrics")
    if not isinstance(metrics_block, dict) or not metrics_block:
        metrics_block = totals.get("metrics", {})
    if isinstance(metrics_block, dict) and metrics_block:
        lines.extend(_metric_lines({"metrics": metrics_block}))
    else:
        runs = _runs_for_metrics(aggregate)
        if runs is not None:
            from evaluation.metrics import UNAVAILABLE_METRICS, aggregate_metric, artifact_summary

            summaries = [artifact_summary(run) for run in runs]
            lines.extend(_metric_lines({
                "metrics": {name: aggregate_metric(summaries, name) for name in UNAVAILABLE_METRICS},
            }))
    return "\n".join(lines)


def write_markdown_report(path: str | Path, aggregate: dict) -> Path:
    """Handles write markdown report behavior for this module.

    Args:
        path: Value used by this function.
        aggregate: Value used by this function."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(build_markdown_summary(aggregate), encoding="utf-8")
    return out_path


def write_matrix_reports(output_dir: str | Path, run_id: str, aggregate: dict) -> dict[str, Path]:
    """Handles write matrix reports behavior for this module.

    Args:
        output_dir: Value used by this function.
        run_id: Value used by this function.
        aggregate: Value used by this function."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "schema_version": aggregate.get("schema_version", "stage6.v1"),
        "artifact_type": "matrix_aggregate",
        "generated_at": aggregate.get("generated_at", datetime.now(timezone.utc).isoformat()),
        **aggregate,
    }

    json_path = write_json_report(out_dir / f"matrix_{run_id}.json", payload)
    markdown_path = write_markdown_report(out_dir / f"matrix_{run_id}.md", payload)
    return {"json": json_path, "markdown": markdown_path}


def write_events_jsonl(path: str | Path, events: list[dict]) -> Path:
    """Handles write events jsonl behavior for this module.

    Args:
        path: Value used by this function.
        events: Value used by this function."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(event, sort_keys=True) for event in events]
    content = "\n".join(lines)
    if content:
        content += "\n"
    out_path.write_text(content, encoding="utf-8")
    return out_path


def write_rich_report(path: str | Path, payload: dict) -> Path:
    """Handles write rich report behavior for this module.

    Args:
        path: Value used by this function.
        payload: Value used by this function."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return out_path
