"""Run-quality diagnostics helpers for Stage 7.1."""

from __future__ import annotations

import logging

from core.state import MODULE_NAMES


logger = logging.getLogger(__name__)


def module_coverage_ratio(scores: dict[str, int]) -> float:
    if not MODULE_NAMES:
        return 0.0
    covered = 0
    for name in MODULE_NAMES:
        try:
            score = int(scores.get(name, 0))
        except (TypeError, ValueError) as exc:
            logger.debug("Non-integer score for module '%s'; defaulting to 0", name, exc_info=exc)
            score = 0
        if score > 0:
            covered += 1
    return covered / len(MODULE_NAMES)


def diagnose_quality(*, scores: dict[str, int], total_iterations_used: int, highest_outcome: str | None) -> dict:
    coverage = module_coverage_ratio(scores)
    flags: list[str] = []

    if coverage < 0.4:
        flags.append("low_module_coverage")
    if total_iterations_used <= 3:
        flags.append("early_termination")
    if highest_outcome in {"admin_session_obtained", "rce_achieved"} and coverage < 0.4:
        flags.append("impact_before_coverage")

    return {
        "coverage_ratio": coverage,
        "flags": flags,
    }
