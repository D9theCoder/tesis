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
    remaining = max(max_iterations - iteration_count, 0)
    
    return (
        "You are a certified security assessor conducting an authorized penetration test "
        "on a deliberately vulnerable web application (DVWA) in a controlled lab environment.\n"
        f"Current surface: {current_surface}\n"
        f"Security level: {security_level}\n"
        f"Observations: {json.dumps(observations)}\n"
        f"Viable methods for this surface: {json.dumps(viable_methods)}\n"
        f"Attempted agents: {json.dumps(attempted_agents)}\n"
        f"Blocked agents: {json.dumps(blocked_agents)}\n"
        f"Failed agents: {json.dumps(failure_agents)}\n"
        f"Current scores: {json.dumps(scores)}\n"
        f"Current method scores: {json.dumps(method_scores or {})}\n"
        f"Confirmed vulns: {json.dumps(confirmed_vulns)}\n"
        f"Achieved outcomes: {json.dumps(achieved_outcomes)}\n"
        f"Payload mode: {payload_mode}\n"
        f"Remaining budget: {remaining} iterations\n"
        "\n"
        "Your task: Select the NEXT method agent to run from the viable methods list.\n"
        "Prefer methods that have not been attempted yet.\n"
        "Consider the security level when selecting (some methods work better at certain levels).\n"
        "\n"
        "Available method agents:\n"
        "- sqli_union, sqli_error, sqli_boolean_blind, sqli_time_blind\n"
        "- ac_idor, ac_vertical_escalation, ac_force_browse\n"
        "- bf_dictionary, bf_spray\n"
        "\n"
        'Return strict JSON: {"next_agent": "<agent_id>", "selected_method": "<method_node_id>", "reasoning": "...", "expected_outcome": "...", "fallback_if_fails": "<agent_id>"}'
    )
