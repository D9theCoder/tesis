"""Formatting helpers for Stage 7 report subcommand output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


def parse_artifact_or_matrix(path: str | Path) -> dict[str, Any]:
    """Parses artifact or matrix into the structure expected by callers.

    Args:
        path: Value used by this function."""
    file_path = Path(path)
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return {"runs": payload}
    if not isinstance(payload, dict):
        raise ValueError("Artifact JSON must be an object or list")

    import re
    run_id = payload.get("run_id") if isinstance(payload.get("run_id"), str) else None
    if run_id and re.match(r"^[\w\-]+$", run_id):
        sibling_rich = file_path.with_name(f"{run_id}.rich.json")
        if sibling_rich.exists():
            try:
                payload["rich_sidecar"] = json.loads(sibling_rich.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
    return payload


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


def format_evasion_table(data: Mapping[str, Any]) -> str:
    """Formats evasion table for CLI or report output.

    Args:
        data: Value used by this function."""
    runs = _extract_runs(data)
    if not runs:
        return "No run artifacts found for evasion analysis."

    rows: list[list[str]] = []
    for run in runs:
        config = run.get("config", {})
        final_state = run.get("final_state", {})
        report_summary = run.get("report", {}).get("summary", {})
        provider = str(config.get("provider") or report_summary.get("llm_provider") or "unknown")
        strategy = str(config.get("evasion_strategy") or report_summary.get("evasion_strategy") or "pipeline")
        _attempts = final_state.get("evasion_attempts")
        attempts = int(_attempts if _attempts is not None else report_summary.get("evasion_attempts", 0))
        _successes = final_state.get("successful_evasions")
        successes = int(_successes if _successes is not None else report_summary.get("successful_evasions", 0))
        rate = f"{(successes / max(attempts, 1) * 100):.1f}%" if attempts > 0 else "N/A"
        guardrails = int(report_summary.get("guardrail_activations", 0))
        prevented = str(max(guardrails - (attempts - successes), 0)) if attempts > 0 else "N/A"
        rows.append([provider, strategy, str(attempts), str(successes), rate, prevented])

    headers = ["Provider", "Strategy", "Attempts", "Successes", "Success Rate", "Guardrails Prevented"]
    return _as_table(headers, rows)


def format_rejection_table(data: Mapping[str, Any], *, verbose: bool = False) -> str:
    """Formats rejection table for CLI or report output.

    Args:
        data: Value used by this function.
        verbose: Value used by this function."""
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

        _calls = report_summary.get("total_iterations_used")
        estimated_calls = int(_calls if _calls is not None else final_state.get("iteration_count", 0))
        total_calls[provider] = total_calls.get(provider, 0) + estimated_calls

        activations = final_state.get("guardrail_activations")
        if not isinstance(activations, list):
            activations = []
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
    evasion_attempts = summary.get("evasion_attempts")
    if evasion_attempts is not None:
        tail.append(f"Evasion Attempts: {evasion_attempts}")
    successful_evasions = summary.get("successful_evasions")
    if successful_evasions is not None:
        tail.append(f"Successful Evasions: {successful_evasions}")
    evasion_strategy = summary.get("evasion_strategy")
    if evasion_strategy is not None:
        tail.append(f"Evasion Strategy: {evasion_strategy}")
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

    return _as_table(headers, rows)


def format_rich_report_sections(data: Mapping[str, Any]) -> str:
    """Render Stage 7.1 rich sidecar sections when available."""
    rich = data.get("rich_sidecar")
    if not isinstance(rich, Mapping):
        return "No rich sidecar data available."

    lines: list[str] = ["Rich Trace Summary"]
    lines.append(f"- schema: {rich.get('schema_version', 'unknown')}")
    lines.append(f"- events: {rich.get('events_count', 0)}")

    hashes = rich.get("prompt_response_hashes")
    if isinstance(hashes, list) and hashes:
        rows: list[list[str]] = []
        for item in hashes[:10]:
            if not isinstance(item, Mapping):
                continue
            rows.append([
                str(item.get("event_type", "unknown")),
                str(item.get("hash", ""))[:24] + "...",
            ])
        if rows:
            lines.append("")
            lines.append(_as_table(["Event", "Payload Hash"], rows))

    report_summary = data.get("report", {}).get("summary", {})
    diagnostics = report_summary.get("diagnostics") if isinstance(report_summary, Mapping) else None
    if isinstance(diagnostics, Mapping):
        raw_coverage = diagnostics.get("coverage_ratio", 0)
        try:
            coverage_value = float(raw_coverage)
        except (TypeError, ValueError):
            coverage_value = 0.0
        lines.append("")
        lines.append("Diagnostics")
        lines.append(f"- coverage_ratio: {coverage_value:.3f}")
        lines.append(f"- flags: {diagnostics.get('flags', [])}")

    return "\n".join(lines)
