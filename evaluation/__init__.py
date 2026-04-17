"""Evaluation package — Stage 6 runner, comparison, metrics, and reporting."""

from evaluation.metrics import aggregate_runs
from evaluation.multi_llm_runner import run_provider_matrix
from evaluation.reporter import (
    build_markdown_summary,
    write_json_report,
    write_markdown_report,
    write_matrix_reports,
)
from evaluation.runner import run_single_engagement

__all__ = [
    "aggregate_runs",
    "run_provider_matrix",
    "build_markdown_summary",
    "write_json_report",
    "write_markdown_report",
    "write_matrix_reports",
    "run_single_engagement",
]
