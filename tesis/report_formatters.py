"""Formatting helpers for Stage 7 report subcommand output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


def parse_artifact_or_matrix(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return {"runs": payload}
    if not isinstance(payload, dict):
        raise ValueError("Artifact JSON must be an object or list")
    return payload


def _extract_runs(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    if isinstance(data.get("runs"), list):
        return [item for item in data["runs"] if isinstance(item, dict)]
    if isinstance(data.get("artifacts"), list):
        return [item for item in data["artifacts"] if isinstance(item, dict)]
    if "run_id" in data:
        return [dict(data)]
    return []


def _as_table(headers: list[str], rows: list[list[str]]) -> str:
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


def format_rejection_table(data: Mapping[str, Any], *, verbose: bool = False) -> str:
    runs = _extract_runs(data)
    if not runs:
        return "No run artifacts found for rejection analysis."

    counts: dict[tuple[str, str], int] = {}
    total_calls: dict[str, int] = {}

    for run in runs:
        config = run.get("config", {})
        report_summary = run.get("report", {}).get("summary", {})
        final_state = run.get("final_state", {})
        provider = str(config.get("provider") or report_summary.get("llm_provider") or "unknown")

        estimated_calls = int(report_summary.get("total_iterations_used") or final_state.get("iteration_count") or 0)
        total_calls[provider] = total_calls.get(provider, 0) + estimated_calls

        activations = final_state.get("guardrail_activations")
        if not isinstance(activations, list):
            activations = []

        if not activations:
            fallback_count = int(report_summary.get("guardrail_activations", 0) or 0)
            if fallback_count > 0:
                counts[(provider, "unknown")] = counts.get((provider, "unknown"), 0) + fallback_count

        for activation in activations:
            if not isinstance(activation, Mapping):
                continue
            context = str(activation.get("context") or "unknown")
            key = (provider, context)
            counts[key] = counts.get(key, 0) + 1

    if not counts:
        return "No guardrail data available."

    rows: list[list[str]] = []
    for provider, context in sorted(counts.keys()):
        guardrails = counts[(provider, context)]
        denom = total_calls.get(provider, 0)
        rate = f"{(guardrails / denom * 100):.1f}%" if denom > 0 else "N/A"
        rows.append([provider, context, str(guardrails), str(denom), rate])

    for provider in sorted(total_calls.keys()):
        provider_guardrails = sum(value for (p, _), value in counts.items() if p == provider)
        denom = total_calls.get(provider, 0)
        rate = f"{(provider_guardrails / denom * 100):.1f}%" if denom > 0 else "N/A"
        rows.append([provider, "total", str(provider_guardrails), str(denom), rate])

    if verbose:
        rows.append(["all", "runs", str(len(runs)), "-", "-"])

    headers = ["Provider", "Task", "Guardrails", "Total Calls", "Rejection Rate"]
    return _as_table(headers, rows)


def format_module_scores_table(
    data: Mapping[str, Any],
    *,
    show_chains: bool = False,
    module_filter: str | None = None,
    level_filter: str | None = None,
) -> str:
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

    summary = report.get("summary", {})
    distribution = summary.get("score_distribution", {})
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
        f"Highest Outcome: {summary.get('highest_impact_outcome', 'N/A')}",
        f"Longest Chain: {summary.get('longest_chain', 'N/A')}",
    ]
    return _as_table(headers, rows) + "\n" + "\n".join(tail)


def format_provider_comparison_table(matrix_data: Mapping[str, Any]) -> str:
    runs = _extract_runs(matrix_data)
    if not runs:
        return "No run artifacts found for matrix comparison."

    providers = sorted(
        {
            str(run.get("config", {}).get("provider", "unknown"))
            for run in runs
        }
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
        rows.append(row)

    return _as_table(headers, rows)
