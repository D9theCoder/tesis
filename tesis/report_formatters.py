"""Formatting helpers for Stage 7 report subcommand output."""

from __future__ import annotations

from typing import Any, Mapping


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
    report = run.get("report", {})
    module_scores = report.get("module_scores", {})
    if not isinstance(module_scores, Mapping) or not module_scores:
        return "No module score data available."

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
        return "No modules matched the provided filters."

    headers = ["Module", "Score", "Label"]
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
    return _as_table(headers, rows) + "\n" + "\n".join(tail)


def format_provider_comparison_table(matrix_data: Mapping[str, Any]) -> str:
    """Formats provider comparison table for CLI or report output.

    Args:
        matrix_data: Value used by this function."""
    runs = _extract_runs(matrix_data)
    if not runs:
        return "No run artifacts found for matrix comparison."

    providers = sorted(
        {
            str(run.get("config", {}).get("provider", "unknown"))
            for run in runs
        }
    )

    any_evasion = any(
        run.get("config", {}).get("evasion_enabled")
        or run.get("report", {}).get("summary", {}).get("evasion_attempts")
        for run in runs
    )

    per_provider_scores: dict[str, dict[str, tuple[int, str]]] = {provider: {} for provider in providers}
    modules: set[str] = set()

    for run in runs:
        provider = str(run.get("config", {}).get("provider", "unknown"))
        module_scores = run.get("report", {}).get("module_scores", {})
        if not isinstance(module_scores, Mapping):
            continue

        for module, raw in module_scores.items():
            if not isinstance(raw, Mapping):
                continue
            modules.add(module)
            score = int(raw.get("score", 0))
            label = str(raw.get("label", "Unknown"))
            current = per_provider_scores[provider].get(module)
            if current is None or score > current[0]:
                per_provider_scores[provider][module] = (score, label)

    if not modules:
        return "No module score data available for matrix comparison."

    headers = ["Module", *providers]
    if any_evasion:
        headers.extend([f"{p} Evasion" for p in providers])

    provider_evasion: dict[str, tuple[int, int]] = {}
    if any_evasion:
        for provider in providers:
            evasion_attempts = 0
            successful_evasions = 0
            for run in runs:
                if str(run.get("config", {}).get("provider", "")) == provider:
                    report_summary = run.get("report", {}).get("summary", {})
                    evasion_attempts += int(report_summary.get("evasion_attempts", 0) or 0)
                    successful_evasions += int(report_summary.get("successful_evasions", 0) or 0)
            provider_evasion[provider] = (evasion_attempts, successful_evasions)

    rows: list[list[str]] = []
    for module in sorted(modules):
        row = [module]
        for provider in providers:
            score_payload = per_provider_scores[provider].get(module)
            if not score_payload:
                row.append("-")
                continue
            score, label = score_payload
            label_short = label.split()[0] if label else "Unknown"
            row.append(f"{score} {label_short}")
        if any_evasion:
            for provider in providers:
                evasion_attempts, successful_evasions = provider_evasion[provider]
                if evasion_attempts > 0:
                    rate = f"{(successful_evasions / evasion_attempts * 100):.0f}%"
                    row.append(f"{successful_evasions}/{evasion_attempts} ({rate})")
                else:
                    row.append("-")
        rows.append(row)

    # ponytail: mixed old/new aggregates exclude unavailable (never average as
    # zero); all-unavailable rows render N/A with the unavailable count.
    from evaluation.metrics import UNAVAILABLE_METRICS, aggregate_metric, artifact_summary

    summaries_by_provider = {provider: [] for provider in providers}
    for run in runs:
        provider = str(run.get("config", {}).get("provider", "unknown"))
        if provider in summaries_by_provider:
            summaries_by_provider[provider].append(artifact_summary(run))
    tail: list[str] = []
    for name in UNAVAILABLE_METRICS:
        cells = []
        for provider in providers:
            agg = aggregate_metric(summaries_by_provider[provider], name)
            mean = agg.get("mean")
            cells.append(
                f"{mean:g} ({agg['n_available']} avail)"
                if isinstance(mean, (int, float)) and not isinstance(mean, bool)
                else f"N/A ({agg['n_unavailable']} unavail)"
            )
        tail.append(f"{name}: " + " | ".join(cells))

    return _as_table(headers, rows) + "\n" + "\n".join([""] + tail)
