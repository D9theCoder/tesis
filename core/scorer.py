"""Scorer agent — Stage 6 implementation.

Provides:
- build_score_report(state): pure report builder
- scorer(state): LangGraph node adapter (state-safe)
"""

from __future__ import annotations

from typing import Any

from evaluation.contracts import ModuleScoreResult, ScoreSummary, ScorerReport
from evaluation.metrics import (
    chain_exploit_count,
    highest_impact_outcome,
    normalize_method_scores,
    score_distribution,
    method_selection_accuracy,
    adaptation_rate,
    mean_attempts_to_success,
)
from core.state import ALL_METHOD_AGENTS, SURFACES, METHODS_BY_SURFACE, SCORE_LABELS


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _parse_chain_candidates(chain_history: list[dict], current_chain: list[str]) -> list[list[str]]:
    """Extract ordered chain candidates from chain_history and current_chain.

    Handles both list[str] and "→"-separated string formats in chain_history.
    """
    candidates: list[list[str]] = []
    for item in chain_history:
        if not isinstance(item, dict):
            continue
        chain = item.get("chain")
        if isinstance(chain, list) and chain:
            candidates.append(chain)
        elif isinstance(chain, str) and chain:
            candidates.append(chain.split("→"))
    if current_chain:
        candidates.append(current_chain)
    return candidates


def _infer_longest_chain(chain_history: list[dict], current_chain: list[str]) -> str | None:
    candidates = _parse_chain_candidates(chain_history, current_chain)
    if not candidates:
        return None
    best = max(candidates, key=lambda chain: (len(chain), tuple(chain)))
    return "→".join(best)


def build_score_report(state: dict) -> ScorerReport:
    normalized = normalize_method_scores(state.get("scores", {}))
    module_scores = {
        agent_id: ModuleScoreResult(
            score=normalized[agent_id],
            label=SCORE_LABELS[normalized[agent_id]],
        )
        for agent_id in ALL_METHOD_AGENTS
    }

    successful_evasions = min(
        _safe_int(state.get("successful_evasions"), 0),
        _safe_int(state.get("evasion_attempts"), 0),
    )

    summary = ScoreSummary(
        llm_provider=state.get("llm_provider", "gemini"),
        security_level=state.get("security_level", "low"),
        total_modules_tested=len(ALL_METHOD_AGENTS),
        score_distribution=score_distribution(normalized),
        chain_exploits_achieved=chain_exploit_count(normalized),
        highest_impact_outcome=highest_impact_outcome(
            state.get("confirmed_vulns", []),
            state.get("achieved_outcomes", []),
        ),
        guardrail_activations=len(state.get("guardrail_activations", [])),
        total_iterations_used=int(state.get("iteration_count", 0)),
        longest_chain=_infer_longest_chain(
            state.get("chain_history", []),
            state.get("current_chain", []),
        ),
        evasion_attempts=_safe_int(state.get("evasion_attempts"), 0),
        successful_evasions=successful_evasions,
        evasion_strategy=str(state.get("evasion_mode") or "reactive").strip().lower(),
    )
    return ScorerReport(module_scores=module_scores, summary=summary)


def scorer(state: dict) -> dict:
    report = build_score_report(state)
    normalized_scores = {
        agent_id: result.score
        for agent_id, result in report.module_scores.items()
    }
    tried_payloads = state.get("tried_payloads", {})
    attempted = state.get("attempted_agents", [])
    metrics = {
        "method_selection_accuracy": round(method_selection_accuracy(normalized_scores, attempted), 4),
        "adaptation_rate": round(adaptation_rate(normalized_scores), 4),
        "mean_attempts_to_success": round(mean_attempts_to_success(tried_payloads, normalized_scores), 4),
    }
    surface_scores = {
        surface: max((normalized_scores.get(m, 0) for m in METHODS_BY_SURFACE.get(surface, [])), default=0)
        for surface in SURFACES
    }
    existing_result = state.get("task_result")
    existing_reason = state.get("incomplete_reason")
    task_result = existing_result or "SUCCESS"
    return {
        "scores": normalized_scores,
        "next_agent": "END",
        "task_result": task_result,
        "incomplete_reason": existing_reason,
        "method_quality_metrics": metrics,
        "surface_scores": surface_scores,
        "akg_path": state.get("akg_path", []),
    }
