"""Failure artifact writer for Stage 7.1 diagnostics."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.run_status import terminal_status
from evaluation.reporter import write_json_report


def write_failure_artifact(
    *,
    output_dir: str | Path,
    run_id: str,
    error: str,
    final_state: dict[str, Any],
    recent_events: list[dict[str, Any]],
    failure: dict[str, Any] | None = None,
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
        **terminal_status(final_state),
        "error": error,
        "failure": failure,
        "final_state": final_state,
        "recent_events": recent_events,
    }

    out_path = out_dir / f"{run_id}.failure.json"
    return write_json_report(out_path, payload)
