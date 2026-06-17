"""Deterministic payload candidate ranking under fixed budgets."""

from __future__ import annotations


def rank_candidates(candidates: list[dict], max_total: int) -> list[dict]:
    """Rank validated candidates seed-first, then deterministically by ID."""
    if max_total <= 0:
        return []
    ordered = sorted(
        (dict(candidate) for candidate in candidates if isinstance(candidate, dict)),
        key=lambda candidate: (
            0 if candidate.get("source") == "static_seed" else 1,
            str(candidate.get("candidate_id", "")),
        ),
    )
    return ordered[:max_total]

