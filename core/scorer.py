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
    normalize_module_scores,
    score_distribution,
)
from core.state import MODULE_NAMES, MODULE_TO_KG_NODE, SCORE_LABELS


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


def _derive_chain_for_module(module: str, state: dict) -> str | None:
    """Derive chain path for a score=4 module using canonical KG node mapping.

    Returns None if no chain involves this module's confirmed-vuln node.
    Does NOT fall back to an unrelated chain (avoids misattribution).
    """
    candidates = _parse_chain_candidates(
        state.get("chain_history", []),
        state.get("current_chain", []),
    )

    # Use canonical MODULE_TO_KG_NODE mapping — module names and KG node
    # names follow different conventions (e.g. "sqli_blind" → "blind_sqli_confirmed").
    module_kg_node = MODULE_TO_KG_NODE.get(module)
    if module_kg_node is None:
        return None

    for chain in candidates:
        if module_kg_node in chain:
            return "→".join(chain)

    return None


def build_score_report(state: dict) -> ScorerReport:
    normalized = normalize_module_scores(state.get("scores", {}))
    module_scores = {
        module: ModuleScoreResult(
            score=normalized[module],
            label=SCORE_LABELS[normalized[module]],
            chain=_derive_chain_for_module(module, state) if normalized[module] == 4 else None,
        )
        for module in MODULE_NAMES
    }

    successful_evasions = min(
        _safe_int(state.get("successful_evasions"), 0),
        _safe_int(state.get("evasion_attempts"), 0),
    )

    summary = ScoreSummary(
        llm_provider=state.get("llm_provider", "gemini"),
        security_level=state.get("security_level", "low"),
        total_modules_tested=len(MODULE_NAMES),
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
        evasion_strategy=str(state.get("evasion_strategy") or "pipeline").strip().lower(),
    )
    return ScorerReport(module_scores=module_scores, summary=summary)


def scorer(state: dict) -> dict:
    report = build_score_report(state)
    normalized_scores = {
        module: result.score
        for module, result in report.module_scores.items()
    }
    return {
        "scores": normalized_scores,
        "next_agent": "END",
    }
