"""Multi-LLM Layer utilities and prompts for framework decisions.

This module prepares provider integrations, guardrail handling, evasion retry
logic, or prompt text used by the LangGraph Execution Flow."""
from __future__ import annotations


def build_ac_force_browse_prompt(state: dict) -> str:
    """Builds ac force browse prompt for framework execution.

    Args:
        state: Value used by this function."""
    target_url = state.get("target_url", "")
    security_level = state.get("security_level", "low")
    endpoints = state.get("endpoints", [])
    observations = state.get("observations", {})
    tried = state.get("tried_payloads", {}).get("ac_force_browse", [])

    return (
        "You are a security testing assistant performing authorized penetration testing on DVWA.\n"
        f"Target: {target_url}\n"
        f"Security level: {security_level}\n"
        f"Endpoints: {endpoints}\n"
        f"Method: Forceful Browsing\n"
        f"Observations: {observations}\n"
        f"Previously tried paths: {tried}\n"
        "Your task: Select the next URL path or endpoint to access directly.\n"
        "Bypass client-side navigation and attempt to reach restricted pages.\n"
        "Consider the security level adaptations:\n"
        "- low: direct access to hidden or admin endpoints\n"
        "- medium: predictable path patterns, encoding required\n"
        "- high: may require valid authentication or session token\n"
        'Return strict JSON: {"payload": "...", "reasoning": "...", "expected_result": "..."}'
    )
