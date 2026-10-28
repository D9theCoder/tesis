"""Deterministic eligibility, method-visit budgets, and stopping rules."""

from __future__ import annotations

from typing import Any

from core.knowledge_graph import get_attack_knowledge_graph
from core.state import METHODS_BY_SURFACE


WORKFLOW_PROTOCOL_VERSION = "workflow.v2"
ITERATION_UNIT = "method_visit"


def eligible_methods(state: dict, surface: str | None = None) -> list[str]:
    """Return unvisited methods under the configured experiment condition.

    Linear receives the canonical surface list.  AKG receives only methods
    whose derived prerequisites are currently ``true``; unknown evidence is
    never promoted to viable.  Rejected selections and preparation failures are
    never offered again as if they had not happened.
    """
    from foundation.preconditions import statuses_snapshot

    surface = surface or state.get("current_surface", "sqli")
    canonical = METHODS_BY_SURFACE.get(surface, [])
    candidates = (
        [method for method in canonical
         if all(value == "true" for value in statuses_snapshot(state, method).values())]
        if state.get("experiment_condition") == "akg_guided_hybrid" else canonical
    )
    excluded = set(state.get("attempted_agents", [])) | set(state.get("blocked_agents", [])) | set(state.get("failure_agents", []))
    excluded.update(row["method"] for row in state.get("preparation_failures", []) if row.get("method"))
    excluded.update(row.get("method") for row in state.get("selection_rejections", [])
                    if isinstance(row, dict) and row.get("method"))
    return [method for method in candidates if method in canonical and method not in excluded]


def method_coverage(state: dict) -> dict[str, Any]:
    """Measure entered method agents against the fixed configured method set."""
    target = state.get("target_method")
    methods = [target] if target else list(METHODS_BY_SURFACE.get(state.get("current_surface", "sqli"), []))
    attempted = [method for method in methods if method in set(state.get("attempted_agents", []))]
    return {"attempted": len(attempted), "total": len(methods),
        "ratio": len(attempted) / len(methods) if methods else 0.0, "methods": attempted}


def stop_reason(state: dict) -> str | None:
    """Check before reserving another visit, including chain/fallback visits."""
    target = state.get("target_method")
    if target and target in state.get("attempted_agents", []):
        return "target_method_complete"
    if int(state.get("iteration_count", 0)) >= int(state.get("max_iterations", 30)):
        return "budget_exhausted"
    if target:
        return None
    if state.get("stop_policy", "impact") == "coverage":
        if method_coverage(state)["ratio"] >= float(state.get("coverage_target", 0.70)):
            return "coverage_target_reached"
    else:
        known = set(state.get("confirmed_vulns", [])) | set(state.get("achieved_outcomes", []))
        if known & set(get_attack_knowledge_graph().HIGH_IMPACT_OUTCOMES):
            return "critical_outcome"
    return None


def workflow_progress(state: dict) -> dict[str, Any]:
    """An additive, versioned observer contract separate from matrix coverage."""
    return {"protocol_version": WORKFLOW_PROTOCOL_VERSION, "iteration_unit": ITERATION_UNIT,
        "iteration_count": int(state.get("iteration_count", 0)),
        "max_iterations": int(state.get("max_iterations", 30)),
        "stop_policy": state.get("stop_policy", "impact"),
        "coverage_target": float(state.get("coverage_target", 0.70)),
        "method_coverage": method_coverage(state),
        "stop_reason": state.get("workflow_stop_reason")}
