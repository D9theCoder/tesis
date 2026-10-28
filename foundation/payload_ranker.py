"""Deterministic payload candidate ranking under the fixed per-visit budget.

Ordering is part of the recorded static/hybrid semantics: a route-derived
credential candidate is considered first, then handwritten static seeds, then
model candidates, with candidate id as the deterministic tie-break.  The limit
is the single versioned exploit-candidate budget
(:func:`core.payload_policy.exploit_queue_limit`); detection and verification
controls never pass through this ranker.
"""

from __future__ import annotations

from typing import Any

# Origin precedence used to order the exploit queue.  ``seed_mutation`` and
# ``template_generation`` share the model slot because a run is in exactly one
# mode, so the two never compete.
_ORIGIN_PRECEDENCE = {
    "chain_derived": 0,
    "static_seed": 1,
    "seed_mutation": 2,
    "template_generation": 2,
}
_SOURCE_PRECEDENCE = {"chain_derived": 0, "static_seed": 1}


def _origin_key(candidate: dict[str, Any]) -> int:
    origin_kind = str(candidate.get("origin_kind") or "").strip()
    if origin_kind in _ORIGIN_PRECEDENCE:
        return _ORIGIN_PRECEDENCE[origin_kind]
    return _SOURCE_PRECEDENCE.get(str(candidate.get("source") or ""), 2)


def rank_key(candidate: dict[str, Any]) -> tuple[int, str, str]:
    """Return the deterministic sort key for one exploit/bypass candidate."""
    return (
        _origin_key(candidate),
        str(candidate.get("candidate_id", "")),
        str(candidate.get("payload_or_logic", "")),
    )


def rank_candidates(candidates: list[dict], max_total: int) -> list[dict]:
    """Rank validated candidates by origin then id, truncated to the budget."""
    if max_total <= 0:
        return []
    ordered = sorted(
        (dict(candidate) for candidate in candidates if isinstance(candidate, dict)),
        key=rank_key,
    )
    return ordered[:max_total]
