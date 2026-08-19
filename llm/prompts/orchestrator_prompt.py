"""Prompt builder for orchestration decisions (method selection)."""

from __future__ import annotations

import json


def build_orchestrator_prompt(
    *,
    current_surface: str,
    viable_methods: list[str],
    observations: dict[str, bool],
    attempted_agents: list[str],
    blocked_agents: list[str],
    failure_agents: list[str],
    scores: dict[str, int],
    method_scores: dict[str, int] | None = None,
    confirmed_vulns: list[str],
    achieved_outcomes: list[str],
    security_level: str,
    payload_mode: str = "static_only",
    iteration_count: int,
    max_iterations: int,
) -> str:
    """Builds orchestrator prompt for framework execution.

    Args:
        current_surface: Value used by this function.
        viable_methods: Value used by this function.
        observations: Value used by this function.
        attempted_agents: Value used by this function.
        blocked_agents: Value used by this function.
        failure_agents: Value used by this function.
        scores: Value used by this function.
        method_scores: Value used by this function.
        confirmed_vulns: Value used by this function.
        achieved_outcomes: Value used by this function.
        security_level: Value used by this function.
        payload_mode: Value used by this function.
        iteration_count: Value used by this function.
        max_iterations: Value used by this function."""
    remaining = max(max_iterations - iteration_count, 0)

    capsule = {
        "surface": current_surface,
        "security_level": security_level,
        "viable_methods": viable_methods,
        "attempted_methods": attempted_agents,
        "blocked_methods": blocked_agents,
        "failed_methods": failure_agents,
        "observations": observations,
        "scores": scores,
        "method_scores": method_scores or {},
        "confirmed_findings": confirmed_vulns,
        "achieved_outcomes": achieved_outcomes,
        "payload_mode": payload_mode,
        "remaining_iterations": remaining,
    }
    return (
        f"Context: {json.dumps(capsule, sort_keys=True, separators=(',', ':'))}\n"
        "Select one next_agent from viable_methods, preferring an unattempted method. "
        'Return only {"next_agent":"method-id","reason_code":"best_viable"}.'
    )
