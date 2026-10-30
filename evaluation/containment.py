"""Containment accounting: attack-relevant violations versus navigation hygiene.

Every containment event the runtime records carries a ``classification``: an
``http_client`` scope violation means an outbound request or redirect was
actually blocked, while ``discarded_navigation`` / ``discarded_page_reference``
means recon refused to follow a reference it found in page markup.  Both are
containment evidence, but only the first is an attack-relevant event; adding
them together (D11) overstates what containment stopped.

``containment_summary`` is the single place that makes that distinction, so
reporting cannot conflate the two counts again.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

CONTAINMENT_POLICY_VERSION = "containment-summary.v1"

# Classes that mean an actual outbound request/redirect left the allowed scope.
ATTACK_RELEVANT_CLASSES = frozenset({"scope_violation"})
# Classes that mean recon refused a reference before any request was made.
NAVIGATION_CLASSES = frozenset({"discarded_navigation", "discarded_page_reference"})


def containment_summary(events: Iterable[Mapping[str, Any]] | None) -> dict[str, Any]:
    """Return attack-relevant and navigation-accounting containment counts.

    Args:
        events: Containment event records from a run artifact or final state.

    Returns:
        A summary with ``attack_relevant`` and ``navigation_discards`` counts,
        the per-kind and per-classification breakdowns that justify them, and a
        ``total`` that is reported, never silently substituted for either part.
    """
    attack_relevant = 0
    navigation_discards = 0
    unclassified = 0
    by_kind: dict[str, int] = {}
    by_classification: dict[str, int] = {}
    for event in events or ():
        if not isinstance(event, Mapping):
            continue
        kind = str(event.get("kind") or "unknown")
        classification = str(event.get("classification") or "unknown")
        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_classification[classification] = by_classification.get(classification, 0) + 1
        if classification in ATTACK_RELEVANT_CLASSES:
            attack_relevant += 1
        elif classification in NAVIGATION_CLASSES:
            navigation_discards += 1
        else:
            unclassified += 1
    return {
        "policy_version": CONTAINMENT_POLICY_VERSION,
        "attack_relevant": attack_relevant,
        "navigation_discards": navigation_discards,
        "unclassified": unclassified,
        "total": attack_relevant + navigation_discards + unclassified,
        "by_kind": dict(sorted(by_kind.items())),
        "by_classification": dict(sorted(by_classification.items())),
    }
