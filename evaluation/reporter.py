"""Stage 6 reporting helpers for JSON and Markdown outputs."""

from __future__ import annotations

import json
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
