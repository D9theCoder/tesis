"""Deterministic payload candidate ranking under the fixed per-visit budget.

Ordering is part of the recorded mode semantics.  ``hybrid`` uses the frozen
generated-first order: valid model candidates are considered first, static seeds
after them as the exhaustion fallback, and route-derived credential candidates
last.  ``static_only`` keeps its historical route-derived-then-static order, and
strict modes contain model candidates only.  Candidate id remains the
deterministic tie-break.  The limit is the single versioned exploit-candidate
budget (:func:`core.payload_policy.exploit_queue_limit`); detection and
verification controls never pass through this ranker.
"""

from __future__ import annotations

from typing import Any

from core.payload_policy import normalize_payload_mode

# Historical precedence for static-only runs: a route-derived credential
# candidate is considered first, then handwritten static seeds.
_STATIC_ORIGIN_PRECEDENCE = {
    "chain_derived": 0,
    "static_seed": 1,
    "seed_mutation": 2,
    "template_generation": 2,
}
# Frozen hybrid precedence: generated candidates first, static seeds as the
# fallback, route-derived credential candidates last.
_HYBRID_ORIGIN_PRECEDENCE = {
    "seed_mutation": 0,
    "template_generation": 0,
    "static_seed": 1,
    "chain_derived": 2,
}
_SOURCE_PRECEDENCE = {"chain_derived": 0, "static_seed": 1}


def _declared_origin(candidate: dict[str, Any]) -> str:
    """Return the recorded origin kind, deriving it from ``source`` when absent.

    Missing origin kinds follow the validator's legacy derivation: a recorded
    static/route-derived source keeps that kind, and every other source is a
    model-origin candidate.
    """
    origin_kind = str(candidate.get("origin_kind") or "").strip()
    if origin_kind:
        return origin_kind
    source = str(candidate.get("source") or "").strip()
    if source in {"static_seed", "chain_derived"}:
        return source
    return "seed_mutation"


def _origin_key(candidate: dict[str, Any], mode: Any = None) -> int:
    origin_kind = _declared_origin(candidate)
    if normalize_payload_mode(mode) == "hybrid":
        if origin_kind in _HYBRID_ORIGIN_PRECEDENCE:
            return _HYBRID_ORIGIN_PRECEDENCE[origin_kind]
        # An unexpected origin never sorts ahead of the frozen hybrid order.
        return len(_HYBRID_ORIGIN_PRECEDENCE)
    if origin_kind in _STATIC_ORIGIN_PRECEDENCE:
        return _STATIC_ORIGIN_PRECEDENCE[origin_kind]
    return _SOURCE_PRECEDENCE.get(str(candidate.get("source") or ""), 2)


def rank_key(
    candidate: dict[str, Any], *, mode: Any = None
) -> tuple[int, str, str]:
    """Return the deterministic sort key for one exploit/bypass candidate."""
    return (
        _origin_key(candidate, mode),
        str(candidate.get("candidate_id", "")),
        str(candidate.get("payload_or_logic", "")),
    )


def rank_candidates(
    candidates: list[dict[str, Any]], max_total: int, *, mode: Any = None
) -> list[dict[str, Any]]:
    """Rank validated candidates by mode-aware origin then id, truncated to the budget.

    ``mode`` selects the frozen order: hybrid ranks generated candidates ahead
    of static seeds (which remain the fallback) and puts route-derived
    candidates last; every other mode keeps the historical precedence.
    """
    if max_total <= 0:
        return []
    ordered = sorted(
        (dict(candidate) for candidate in candidates if isinstance(candidate, dict)),
        key=lambda candidate: rank_key(candidate, mode=mode),
    )
    return ordered[:max_total]
