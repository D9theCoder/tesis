"""Formatting helpers for Stage 7 report subcommand output."""

from __future__ import annotations

from typing import Any, Mapping

from core.run_status import terminal_status


def _extract_runs(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Supports extract runs behavior for this module."""
    if isinstance(data.get("runs"), list):
        return [item for item in data["runs"] if isinstance(item, dict)]
    if isinstance(data.get("artifacts"), list):
        return [item for item in data["artifacts"] if isinstance(item, dict)]
    if "run_id" in data:
        return [dict(data)]
    return []


def _as_table(headers: list[str], rows: list[list[str]]) -> str:
    """Supports as table behavior for this module."""
    widths = [len(header) for header in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    def _fmt(row: list[str]) -> str:
        return " | ".join(cell.ljust(widths[idx]) for idx, cell in enumerate(row))

    divider = "-+-".join("-" * width for width in widths)
    lines = [_fmt(headers), divider]
    lines.extend(_fmt(row) for row in rows)
    return "\n".join(lines)


_GRADED_COMPONENTS = ("Smethod", "Spayload", "Sexploit", "Schain", "Soutput")


def format_graded_scores_table(data: Mapping[str, Any]) -> str | None:
    """Render the graded thesis vector and its pending reasons when present.

    Accepts an observer projection run (``graded_scores``) or a bare review
    queue document (``components`` + ``component_pending_reasons``). Returns
    ``None`` when the input carries no graded projection, so runtime-only data
    is never presented as a graded score.
    """
    graded = data.get("graded_scores") if isinstance(data, Mapping) else None
    if not isinstance(graded, Mapping):
        if isinstance(data, Mapping) and isinstance(data.get("components"), Mapping) \
                and isinstance(data.get("component_pending_reasons", {}), Mapping):
            graded = data
        else:
            return None
    components = graded.get("components")
    if not isinstance(components, Mapping):
        return (f"Graded thesis components ({graded.get('rubric_version') or 'scoring.v4'}): "
                f"unavailable ({graded.get('reason') or 'missing_components'})")
    pending = graded.get("component_pending_reasons")
    pending = pending if isinstance(pending, Mapping) else {}
    rows = []
    for key in _GRADED_COMPONENTS:
        value = components.get(key)
        reason = pending.get(key)
        rows.append([key, "N/A" if value is None else str(value),
                     "" if value is not None else str(reason or "missing_evidence")])
    lines = [f"Graded thesis components ({graded.get('rubric_version') or 'scoring.v4'}):",
             _as_table(["Component", "Score", "Pending reason"], rows)]
    workflows = graded.get("workflows")
    if isinstance(workflows, Mapping):
        # Human and AI workflows stay distinct; this never selects one.
        for mode in ("human", "ai"):
            workflow = workflows.get(mode)
            if not isinstance(workflow, Mapping):
                continue
            if mode == "human":
                label = "HUMAN workflow (human review required; provisional until final receipt)"
            else:
                label = "AI workflow (experimental/provisional; not final thesis human signoff)"
            label = str(workflow.get("label") or label)
            detail = f"{label}: {workflow.get('status') or 'missing'}"
            if workflow.get("reason"):
                detail += f" ({workflow['reason']})"
            lines.append(detail)
            workflow_components = workflow.get("components")
            workflow_pending = workflow.get("component_pending_reasons")
            workflow_pending = workflow_pending if isinstance(workflow_pending, Mapping) else {}
            if isinstance(workflow_components, Mapping):
                observed = []
                for key in _GRADED_COMPONENTS:
                    value = workflow_components.get(key)
                    if value is None:
                        observed.append(f"{key}=N/A ({workflow_pending.get(key) or 'missing_evidence'})")
                    else:
                        observed.append(f"{key}={value}")
                lines.append("  components: " + ", ".join(observed))
            elif workflow_pending:
                lines.append("  pending components: " + ", ".join(
                    f"{key}=N/A ({reason})" for key, reason in workflow_pending.items()))
            mean = workflow.get("Spayload_final")
            mean_text = "N/A" if mean is None else str(mean)
            if mean is None and workflow.get("reason"):
                mean_text += f" ({workflow['reason']})"
            srun = workflow.get("Srun_final")
            lines.append(f"  Spayload mean: {mean_text}; Srun final: {'N/A' if srun is None else srun}")
    return "\n".join(lines)


def format_module_scores_table(
    data: Mapping[str, Any],
    *,
    show_chains: bool = False,
    module_filter: str | None = None,
    level_filter: str | None = None,
) -> str:
    """Formats module scores table for CLI or report output.

    Args:
        data: Value used by this function.
        show_chains: Value used by this function.
        module_filter: Value used by this function.
        level_filter: Value used by this function."""
    runs = _extract_runs(data)
    if level_filter:
        runs = [run for run in runs if str(run.get("config", {}).get("security_level", "")).lower() == level_filter.lower()]
    if not runs:
        return "No run artifacts found for score analysis."

    run = runs[0]
    fields = terminal_status(run)
    graded = format_graded_scores_table(run)
    report = run.get("report", {})
    module_scores = report.get("module_scores", {})
    if not isinstance(module_scores, Mapping) or not module_scores:
        return graded or "No module score data available."

    rows: list[list[str]] = []
    for module in sorted(module_scores.keys()):
        if module_filter and module_filter.lower() not in module.lower():
            continue
        raw = module_scores[module]
        if not isinstance(raw, Mapping):
            continue
        score = str(raw.get("score", "0"))
        label = str(raw.get("label", "Unknown"))
        chain = str(raw.get("chain", "")) if raw.get("chain") else ""

        row = [module, score, label]
        if show_chains:
            row.append(chain)
        rows.append(row)

    if not rows:
        return graded or "No modules matched the provided filters."

    headers = ["Module", "Runtime score (legacy scoring.v2)", "Label"]
    if show_chains:
        headers.append("Chain")

    from evaluation.metrics import artifact_summary as _artifact_summary

    summary = _artifact_summary(run)
    distribution = summary.get("score_distribution", {}) if isinstance(summary, Mapping) else {}
    if isinstance(distribution, Mapping):
        normalized_distribution = {
            int(key): int(value)
            for key, value in distribution.items()
            if str(key).isdigit() or isinstance(key, int)
        }
    else:
        normalized_distribution = {}

    tail = [
        "",
        f"Score Distribution: {normalized_distribution}",
        f"Highest Outcome: {summary.get('highest_impact_outcome', 'N/A') if isinstance(summary, Mapping) else 'N/A'}",
        f"Longest Chain: {summary.get('longest_chain', 'N/A') if isinstance(summary, Mapping) else 'N/A'}",
    ]
    summary_map = summary if isinstance(summary, dict) else {}
    evasion_attempts = summary_map.get("evasion_attempts")
    if evasion_attempts is not None:
        tail.append(f"Evasion Attempts: {evasion_attempts}")
    successful_evasions = summary_map.get("successful_evasions")
    if successful_evasions is not None:
        tail.append(f"Successful Evasions: {successful_evasions}")
    evasion_strategy = summary_map.get("evasion_strategy")
    if evasion_strategy is not None:
        tail.append(f"Evasion Strategy: {evasion_strategy}")
    # ponytail: unavailable renders N/A via metric_reading; never None-as-number.
    from evaluation.metrics import UNAVAILABLE_METRICS, format_metric

    for _name in UNAVAILABLE_METRICS:
        tail.append(f"{_name}: {format_metric(summary_map, _name)}")
    legacy_table = (
        "Runtime module scores (legacy scoring.v2; not a graded thesis score):\n"
        + _as_table(headers, rows)
    )
    primary = f"{graded}\n\n{legacy_table}" if graded else legacy_table
    return (f"Execution: {fields['execution_status'] or 'unknown'}; security outcome: {fields['security_outcome']}\n"
        + primary) + "\n" + "\n".join(tail)


_OBSERVATION_COLUMNS = ("Run", "Provider", "Model", "Condition", "Surface", "Level",
                        "Payload mode", "Target", "Repeat")


def _observation_identity(run: Mapping[str, Any]) -> dict[str, str]:
    identity = run.get("identity") if isinstance(run.get("identity"), Mapping) else {}
    config = run.get("config") if isinstance(run.get("config"), Mapping) else {}

    def pick(*keys, default="unknown"):
        for source in (run, identity, config):
            for key in keys:
                value = source.get(key)
                if value is not None and value != "":
                    return str(value)
        return default

    execution, run_id = pick("execution_id", default=""), pick("run_id", default="")
    return {
        "Run": " / ".join(value for value in (execution, run_id) if value) or "unknown-run",
        "Provider": pick("provider"),
        "Model": pick("model", "model_name", "model_profile"),
        "Condition": pick("experiment_condition", "condition"),
        "Surface": pick("surface"),
        "Level": pick("security_level", "level"),
        "Payload mode": pick("payload_mode", "payload_mode_label"),
        "Target": pick("target_method", "selected_method", default="none"),
        "Repeat": pick("repeat_index", "repeat"),
    }


def format_provider_comparison_table(matrix_data: Mapping[str, Any]) -> str:
    """Format one observation row per run/module without pooling or best-of-N.

    Args:
        matrix_data: Value used by this function."""
    runs = _extract_runs(matrix_data)
    if not runs:
        return "No run artifacts found for matrix comparison."

    any_evasion = any(
        run.get("config", {}).get("evasion_enabled")
        or run.get("report", {}).get("summary", {}).get("evasion_attempts")
        for run in runs
    )

    headers = [*_OBSERVATION_COLUMNS, "Module", "Runtime score (legacy scoring.v2)", "Label"]
    if any_evasion:
        headers.append("Evasion (legacy per-run)")

    rows: list[list[str]] = []
    for run in runs:
        identity = _observation_identity(run)
        module_scores = run.get("report", {}).get("module_scores", {})
        if not isinstance(module_scores, Mapping):
            continue
        report_summary = run.get("report", {}).get("summary", {})
        report_summary = report_summary if isinstance(report_summary, Mapping) else {}
        evasion_attempts = int(report_summary.get("evasion_attempts", 0) or 0)
        successful_evasions = int(report_summary.get("successful_evasions", 0) or 0)
        evasion_text = ("-" if not evasion_attempts else
                        f"{successful_evasions}/{evasion_attempts} "
                        f"({successful_evasions / evasion_attempts * 100:.0f}%)")
        for module in sorted(module_scores):
            raw = module_scores[module]
            if not isinstance(raw, Mapping):
                continue
            row = [identity[column] for column in _OBSERVATION_COLUMNS]
            row.extend([module, str(raw.get("score", 0)), str(raw.get("label", "Unknown"))])
            if any_evasion:
                row.append(evasion_text)
            rows.append(row)

    if not rows:
        return "No module score data available for matrix comparison."

    # Runtime diagnostics remain per run. Nothing is pooled across coordinates,
    # de-duplicated, or reduced to a best-of-N provider score.
    from evaluation.metrics import UNAVAILABLE_METRICS, artifact_summary, format_metric

    tail: list[str] = [
        "Every row is one run/module observation of legacy runtime_provisional_scoring.v2; "
        "no best-of-N, no pooling across coordinates, and no de-duplication."
    ]
    for run in runs:
        identity = _observation_identity(run)
        summary = artifact_summary(run)
        values = " | ".join(f"{name}={format_metric(summary, name)}" for name in UNAVAILABLE_METRICS)
        tail.append(f"{identity['Run']}: {values}")

    return _as_table(headers, rows) + "\n" + "\n".join([""] + tail)
