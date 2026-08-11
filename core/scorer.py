"""Scorer agent — Stage 6 implementation.

Provides:
- build_score_report(state): pure report builder
- scorer(state): LangGraph node adapter (state-safe)
"""

from __future__ import annotations

import dataclasses
from typing import Any

from langgraph.graph import END

from evaluation.contracts import ModuleScoreResult, ScoreSummary, ScorerReport
from evaluation.metrics import (
    chain_exploit_count,
    guardrail_activation_rate,
    highest_impact_outcome,
    normalize_method_scores,
    score_distribution,
    method_selection_accuracy,
    adaptation_rate,
    mean_attempts_to_success,
    payload_execution_success_rate,
    payload_improvement_rate,
    payload_validity_rate,
)
from core.state import ALL_METHOD_AGENTS, SURFACES, METHODS_BY_SURFACE, SCORE_LABELS


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _parse_chain_candidates(chain_history: list[dict], current_chain: list[str]) -> list[list[str]]:
    """Extract ordered chain candidates from chain_history and current_chain."""
    candidates: list[list[str]] = []
    for item in chain_history:
        if isinstance(item, dict):
            chain = item.get("chain")
            if isinstance(chain, list) and chain:
                candidates.append(chain)
    if current_chain:
        candidates.append(current_chain)
    return candidates


def _infer_longest_chain(chain_history: list[dict], current_chain: list[str]) -> str | None:
    """Infers longest observed chain length from chain history entries."""
    candidates = _parse_chain_candidates(chain_history, current_chain)
    if not candidates:
        return None
    best = max(candidates, key=lambda chain: (len(chain), tuple(chain)))
    return "→".join(best)


def build_score_report(state: dict) -> ScorerReport:
    """Builds aggregate scoring metrics from the final exploitation state.

    Args:
        state: Final or intermediate shared LangGraph state.

    Returns:
        Dictionary containing method, payload, guardrail, adaptation, and surface
        metrics for reporting."""
    aggregate_scores = state.get("scores", {})
    normalized = normalize_method_scores(aggregate_scores)
    attempted = state.get("attempted_agents", [])
    tried_payloads = state.get("tried_payloads", {})
    method_selection = round(method_selection_accuracy(normalized, attempted), 4)
    adaptation = round(adaptation_rate(normalized, attempted), 4)
    mean_attempts = round(mean_attempts_to_success(tried_payloads, normalized), 4)
    payload_improve = round(
        payload_improvement_rate(
            state.get("payload_scores", {}),
            state.get("payload_provenance", {}),
        ),
        4,
    )
    guardrail_rate = round(
        guardrail_activation_rate(
            state.get("guardrail_activations", []),
            int(state.get("iteration_count", 0) or 0),
        ),
        4,
    )
    module_scores = {
        agent_id: ModuleScoreResult(
            score=normalized[agent_id],
            label=SCORE_LABELS[normalized[agent_id]],
        )
        for agent_id in ALL_METHOD_AGENTS
    }

    # Defensive clamp (also enforced by ScoreSummary.__post_init__)
    successful_evasions = min(
        _safe_int(state.get("successful_evasions"), 0),
        _safe_int(state.get("evasion_attempts"), 0),
    )

    summary = ScoreSummary(
        llm_provider=state.get("llm_provider", "gemini"),
        security_level=state.get("security_level", "low"),
        total_modules_tested=len(ALL_METHOD_AGENTS),
        score_distribution=score_distribution(normalized),
        chain_exploits_achieved=chain_exploit_count({
            key: int(value)
            for key, value in dict(state.get("chain_scores", {})).items()
        }),
        highest_impact_outcome=highest_impact_outcome(
            state.get("confirmed_vulns", []),
            state.get("achieved_outcomes", []),
        ),
        guardrail_activations=len(state.get("guardrail_activations", [])),
        payload_guardrail_activations=len(state.get("payload_guardrail_activations", [])),
        total_iterations_used=int(state.get("iteration_count", 0)),
        longest_chain=_infer_longest_chain(
            state.get("chain_history", []),
            state.get("current_chain", []),
        ),
        evasion_attempts=_safe_int(state.get("evasion_attempts"), 0),
        successful_evasions=successful_evasions,
        evasion_strategy=str(state.get("evasion_mode") or "reactive").strip().lower(),
        method_selection_accuracy=method_selection,
        adaptation_rate=adaptation,
        mean_attempts_to_success=mean_attempts,
        payload_validity_rate=round(payload_validity_rate(state.get("payload_validation_results", {})), 4),
        payload_execution_success_rate=round(payload_execution_success_rate(state.get("payload_scores", {})), 4),
        payload_improvement_rate=payload_improve,
        guardrail_activation_rate=guardrail_rate,
        consistency_score=0.0,
        token_cost=0.0,
        token_cost_per_success=0.0,
    )
    return ScorerReport(module_scores=module_scores, summary=summary)


def scorer(state: dict) -> dict:
    """Executes the scoring stage of the LangGraph workflow.

    Reads:
        Method scores, exploitation scores, chain scores, payload validation
        results, tried payloads, guardrail events, and chain history.

    Writes:
        Final task result, score report fields, and telemetry-compatible summary
        values.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update containing final scoring output."""
    report = build_score_report(state)
    normalized_scores = {
        agent_id: result.score
        for agent_id, result in report.module_scores.items()
    }
    attempted = state.get("attempted_agents", [])
    akg_path = state.get("akg_path", [])

    # Nested surface_scores per spec
    surface_scores: dict[str, dict[str, Any]] = {}
    for surface in SURFACES:
        methods = METHODS_BY_SURFACE.get(surface, [])
        surface_attempts = sum(1 for m in methods if m in attempted)
        best_method = None
        best_score = 0
        for m in methods:
            s = normalized_scores.get(m, 0)
            if s > best_score:
                best_score = s
                best_method = m

        surface_failures = [a for a in state.get("failure_agents", []) if a in methods]
        adapted = bool(surface_failures) and best_score >= 3

        surface_scores[surface] = {
            "score": best_score,
            "label": SCORE_LABELS.get(best_score, "Not Found"),
            "method_selected": best_method,
            "attempts": surface_attempts,
            "adapted": adapted,
        }

    summary = {
        **dataclasses.asdict(report.summary),
        "total_surfaces_tested": len(SURFACES),
        "akg_path": akg_path,
        "selected_method": state.get("selected_method"),
        "payload_mode": state.get("payload_mode", "static_only"),
        "method_scores": dict(state.get("method_scores", {})),
        "payload_scores": dict(state.get("payload_scores", {})),
        "exploitation_scores": dict(state.get("exploitation_scores", {})),
        "chain_scores": dict(state.get("chain_scores", {})),
        "incomplete_surfaces": [
            s for s in SURFACES
            if all(normalized_scores.get(m, 0) == 0 for m in METHODS_BY_SURFACE.get(s, []))
        ],
        "incomplete_reasons": state.get("incomplete_reason"),
    }

    selected_method = state.get("selected_method")
    output_scores = dict(state.get("output_scores", {}))
    composite_scores = dict(state.get("composite_scores", {}))
    if selected_method:
        invalid_count = len(state.get("invalid_json_events", []))
        guardrail_count = len(state.get("guardrail_activations", []))
        fallback_count = len(state.get("fallback_events", []))
        containment_count = len(state.get("containment_events", []))
        if containment_count:
            output_score = 0
        elif invalid_count or guardrail_count:
            output_score = 2
        elif fallback_count:
            output_score = 3
        else:
            output_score = 4
        output_scores[selected_method] = max(output_scores.get(selected_method, 0), output_score)

        candidate_ids = {
            str(candidate.get("candidate_id"))
            for candidate in state.get("payload_candidates", {}).get(selected_method, [])
            if isinstance(candidate, dict) and candidate.get("candidate_id")
        }
        payload_values = [
            int(score)
            for candidate_id, score in state.get("payload_scores", {}).items()
            if candidate_id in candidate_ids
        ]
        payload_score = max(payload_values, default=0)
        method_score = int(state.get("method_scores", {}).get(selected_method, 0) or 0)
        exploit_score = int(state.get("exploitation_scores", {}).get(selected_method, 0) or 0)
        chain_score = int(state.get("chain_scores", {}).get(selected_method, 0) or 0)
        composite_scores[selected_method] = round(
            0.20 * method_score
            + 0.20 * payload_score
            + 0.30 * exploit_score
            + 0.10 * chain_score
            + 0.20 * output_score,
            4,
        )
        summary["output_scores"] = output_scores
        summary["composite_scores"] = composite_scores

    existing_result = state.get("task_result")
    existing_reason = state.get("incomplete_reason")
    has_findings = bool(state.get("confirmed_vulns")) or bool(state.get("achieved_outcomes"))
    if existing_result is not None:
        task_result = existing_result
    elif existing_reason:
        task_result = "INCOMPLETE"
    elif has_findings:
        task_result = "SUCCESS"
    else:
        task_result = "INCOMPLETE"

    return {
        "scores": normalized_scores,
        "next_agent": END,
        "task_result": task_result,
        "incomplete_reason": existing_reason,
        "surface_scores": surface_scores,
        "output_scores": output_scores,
        "composite_scores": composite_scores,
        "summary": summary,
    }
