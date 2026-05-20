"""Multi-LLM Layer utilities and prompts for framework decisions.

This module prepares provider integrations, guardrail handling, evasion retry
logic, or prompt text used by the LangGraph Execution Flow."""
from __future__ import annotations


def build_ac_vertical_escalation_prompt(state: dict) -> str:
    """Builds ac vertical escalation prompt for framework execution.

    Args:
        state: Value used by this function."""
    target_url = state.get("target_url", "")
    security_level = state.get("security_level", "low")
    endpoints = state.get("endpoints", [])
    observations = state.get("observations", {})
    tried = state.get("tried_payloads", {}).get("ac_vertical_escalation", [])

    return (
        "You are a security testing assistant performing authorized penetration testing on DVWA.\n"
        f"Target: {target_url}\n"
        f"Security level: {security_level}\n"
        f"Endpoints: {endpoints}\n"
        f"Method: Vertical Privilege Escalation\n"
        f"Observations: {observations}\n"
        f"Previously tried payloads: {tried}\n"
        "Your task: Select the next payload to test for vertical privilege escalation.\n"
        "Modify role, privilege, or admin-related parameters.\n"
        "Consider the security level adaptations:\n"
        "- low: direct role parameter manipulation\n"
        "- medium: encoded or hidden role fields\n"
        "- high: may require valid elevated session or token\n"
        'Return strict JSON: {"payload": "...", "reasoning": "...", "expected_result": "..."}'
    )
