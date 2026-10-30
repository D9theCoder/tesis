"""Containment accounting must separate attack violations from navigation hygiene."""

from evaluation.containment import containment_summary


def test_navigation_discards_are_not_counted_as_attack_events():
    events = [
        {"kind": "navigation", "classification": "discarded_navigation",
         "blocked_url": "https://www.virtualbox.org/"},
        {"kind": "form", "classification": "discarded_page_reference",
         "blocked_url": "https://example.invalid/collect"},
        {"kind": "request", "classification": "scope_violation",
         "blocked_url": "https://external.invalid/x"},
        {"kind": "redirect", "classification": "scope_violation",
         "blocked_url": "https://external.invalid/y"},
    ]

    summary = containment_summary(events)

    assert summary["attack_relevant"] == 2
    assert summary["navigation_discards"] == 2
    assert summary["unclassified"] == 0
    assert summary["total"] == 4
    assert summary["by_kind"] == {"form": 1, "navigation": 1, "redirect": 1, "request": 1}


def test_unclassified_events_stay_visible_instead_of_inflating_either_count():
    summary = containment_summary([{"event": "containment"}])

    assert summary["attack_relevant"] == 0
    assert summary["navigation_discards"] == 0
    assert summary["unclassified"] == 1
    assert summary["total"] == 1
