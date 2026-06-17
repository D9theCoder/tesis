"""Failure artifact writer for Stage 7.1 diagnostics."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import json


def write_failure_artifact(
    *,
    output_dir: str | Path,
    run_id: str,
    error: str,
    final_state: dict[str, Any],
    recent_events: list[dict[str, Any]],
) -> Path:
    """Handles write failure artifact behavior for this module.

    Args:
        output_dir: Value used by this function.
        run_id: Value used by this function.
        error: Value used by this function.
        final_state: Value used by this function.
        recent_events: Value used by this function."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "schema_version": "stage6.failure.v1",
        "run_id": run_id,
        "error": error,
        "final_state": final_state,
        "recent_events": recent_events,
    }

    out_path = out_dir / f"{run_id}.failure.json"
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return out_path
