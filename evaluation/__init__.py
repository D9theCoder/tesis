"""Evaluation package — Stage 6 runner, comparison, metrics, and reporting."""

from evaluation.metrics import aggregate_runs
from evaluation.reporter import (
    build_markdown_summary,
    write_json_report,
    write_markdown_report,
    write_matrix_reports,
)

__all__ = [
    "aggregate_runs",
    "build_markdown_summary",
    "write_json_report",
    "write_markdown_report",
    "write_matrix_reports",
]
