"""Stage 6 reporting helpers for JSON and Markdown outputs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def write_json_report(path: str | Path, payload: dict) -> Path:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return out_path


def build_markdown_summary(aggregate: dict) -> str:
    totals = aggregate.get("totals", {})
    return "\n".join(
        [
            "# Stage 6 Evaluation Summary",
            "",
            f"- Total runs: {totals.get('total_runs', 0)}",
            f"- Successful runs: {totals.get('successful_runs', 0)}",
            f"- Error runs: {totals.get('error_runs', 0)}",
            f"- Skipped runs: {totals.get('skipped_runs', 0)}",
        ]
    )


def write_markdown_report(path: str | Path, aggregate: dict) -> Path:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(build_markdown_summary(aggregate), encoding="utf-8")
    return out_path


def write_matrix_reports(output_dir: str | Path, run_id: str, aggregate: dict) -> dict[str, Path]:
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
