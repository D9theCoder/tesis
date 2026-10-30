"""Decisive measured-negative verdicts for methods stopped by a false precondition.

The readiness and chaining gates are fail-closed: a method is viable only when its
declared precondition observations are ``"true"``. That default is right, but it has
one consequence worth naming. At a coordinate where *every* in-scope precondition is
measured ``false``, no method is selected, so the run records neither an attempted
method nor a verifier decision. Read on its own, such an artifact looks like a run
that never looked -- when in fact bounded detection controls were sent and the
coordinate was observed to be closed.

This module derives an explicit ``not_vulnerable`` verdict per in-scope method from
the state's own control evidence, so a decisive negative can be reported as a
finding. It does not relax a gate, and it does not relabel ``attempted_agents``:
that key keeps meaning "a method agent executed". The verdict is a second,
separately named result.

Fail-closed by construction. A verdict requires all of:

* the run attempted no method and selected no method,
* every declared precondition of the method is observed exactly ``"false"``,
* at least one detection-control event for that method was actually sent.

``"unknown"``, an absent key, or a probe snapshot without a sent event yields no
verdict for that method, and the coordinate then stays measured-not-ready.

See ``docs/reference/cross_surface_evidence.md`` for the evidence handling the
readiness and chaining gates share.
"""

from __future__ import annotations

from typing import Any, Mapping

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE
from foundation.preconditions import method_statuses

VERDICT_POLICY_VERSION = "measured-negative-verdicts.v1"
VERDICT_NOT_VULNERABLE = "not_vulnerable"
VERDICT_BASIS = "bounded_detection_control"
VERDICT_REASON = "every_required_precondition_measured_false"
INCOMPLETE_REASON = "not_measured_negative"

#: ``metric_unavailable_reason`` entry used when a run has no attempted method
#: because every in-scope precondition was measured false. The composite is not
#: zero -- it is undefined for a run that never executed a method.
SCORE_UNAVAILABLE_REASON = "no_method_attempted_measured_negative"

_PROBE_CONTROL_PREFIX = "recon:method_probe:"
_CONTROL_ID_PREFIX = "control:"


def in_scope_methods(surface: Any) -> list[str]:
    """Return the canonical method allow-list for ``surface``."""
    if not isinstance(surface, str):
        return []
    return list(METHODS_BY_SURFACE.get(surface, []))


def required_preconditions(method: str) -> list[str]:
    """Return the observation keys a method's viability depends on."""
    return list(AttackKnowledgeGraph.METHOD_PRECONDITIONS.get(method, []))


def _attempted(state: Mapping[str, Any]) -> list[str]:
    return [method for method in (state.get("attempted_agents") or []) if isinstance(method, str)]


def _surface(state: Mapping[str, Any]) -> str | None:
    surface = state.get("current_surface") or state.get("surface")
    return surface if isinstance(surface, str) and surface else None


def _control_rows(state: Mapping[str, Any]) -> list[dict]:
    return [dict(row) for row in (state.get("control_events") or []) if isinstance(row, Mapping)]


def _is_sent_detection_control(row: Mapping[str, Any]) -> bool:
    return (
        row.get("control_class") == "detection"
        and row.get("status") == "sent"
        and not row.get("establishes_exploit")
    )


def _rows_for_method(rows: list[dict], method: str) -> list[dict]:
    prefix = f"{_CONTROL_ID_PREFIX}{method}:"
    return [
        row for row in rows
        if str(row.get("control_id") or "").startswith(prefix)
        and _is_sent_detection_control(row)
    ]


def sent_control_events(state: Mapping[str, Any], method: str) -> list[dict]:
    """Return the detection-control rows actually sent for ``method``.

    The run-level ``control_events`` list is authoritative; the per-method probe
    snapshot is a fallback for states that keep only the snapshot. A probe snapshot
    that lists no sent event yields nothing, which keeps an unmeasured method from
    looking decided.
    """
    rows = _control_rows(state)
    if rows:
        return _rows_for_method(rows, method)
    snapshot = (state.get("probe_controls") or {}).get(f"{_PROBE_CONTROL_PREFIX}{method}")
    if isinstance(snapshot, Mapping):
        return _rows_for_method(
            [dict(row) for row in (snapshot.get("control_events") or []) if isinstance(row, Mapping)],
            method,
        )
    return []


def _evidence_refs(state: Mapping[str, Any], control_ids: set[str]) -> list[str]:
    return [
        f"#/control_events/{index}"
        for index, row in enumerate(state.get("control_events") or [])
        if isinstance(row, Mapping) and _is_sent_detection_control(row)
        and str(row.get("control_id") or "") in control_ids
    ]


def _security_level(rows: list[dict], state: Mapping[str, Any]) -> str | None:
    """Read the level from the control ids the evidence itself carries."""
    for row in rows:
        parts = str(row.get("control_id") or "").split(":")
        if len(parts) >= 4 and parts[2]:
            return parts[2]
    level = state.get("security_level")
    return level if isinstance(level, str) and level else None


def measured_negative_verdicts(state: Mapping[str, Any]) -> dict[str, dict]:
    """Return one ``not_vulnerable`` verdict per in-scope method, when defensible.

    An empty mapping means "not measured negative" -- either a method ran, or a
    method was viable, or some precondition was not decisively measured.
    """
    if _attempted(state) or (state.get("viable_methods") or []):
        return {}
    surface = _surface(state)
    methods = in_scope_methods(surface)
    if not methods:
        return {}
    verdicts: dict[str, dict] = {}
    for method in methods:
        required = required_preconditions(method)
        if not required:
            continue
        observed = method_statuses(state, method)
        values = {key: observed.get(key) for key in required}
        if any(value != "false" for value in values.values()):
            continue
        rows = sent_control_events(state, method)
        if not rows:
            continue
        control_ids = {str(row.get("control_id")) for row in rows if row.get("control_id")}
        verdicts[method] = {
            "method": method,
            "surface": surface,
            "security_level": _security_level(rows, state),
            "verdict": VERDICT_NOT_VULNERABLE,
            "basis": VERDICT_BASIS,
            "reason": VERDICT_REASON,
            "required_preconditions": required,
            "observed": {key: "false" for key in required},
            "measured_by": sorted(control_ids),
            "control_events_sent": len(rows),
            "signal_detected": any(bool(row.get("signal_detected")) for row in rows),
            "evidence_refs": _evidence_refs(state, control_ids),
            "control_class": sorted({
                str(row.get("control_class")) for row in rows if row.get("control_class")
            }),
            "policy_version": VERDICT_POLICY_VERSION,
        }
    return verdicts


def measured_negative_summary(
    state: Mapping[str, Any], verdicts: Mapping[str, dict] | None = None
) -> dict:
    """Return the run-level receipt that the DoD's amended clause reads."""
    verdicts = measured_negative_verdicts(state) if verdicts is None else dict(verdicts)
    surface = _surface(state)
    required = in_scope_methods(surface)
    with_verdict = [method for method in required if method in verdicts]
    missing = [method for method in required if method not in verdicts]
    complete = bool(required) and not missing
    return {
        "policy_version": VERDICT_POLICY_VERSION,
        "surface": surface,
        "security_level": _security_level(
            [row for method in verdicts for row in sent_control_events(state, method)], state),
        "basis": VERDICT_BASIS,
        "methods_required": required,
        "methods_with_verdict": with_verdict,
        "methods_missing_verdict": missing,
        "verdicts_recorded": len(verdicts),
        "control_events_sent": sum(
            int(verdict.get("control_events_sent") or 0) for verdict in verdicts.values()),
        "complete": complete,
        "reason": VERDICT_REASON if complete else INCOMPLETE_REASON,
    }
