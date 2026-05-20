"""Multi-LLM Layer utilities and prompts for framework decisions.

This module prepares provider integrations, guardrail handling, evasion retry
logic, or prompt text used by the LangGraph Execution Flow."""
from __future__ import annotations


def build_sqli_error_prompt(state: dict) -> str:
    """Builds sqli error prompt for framework execution.

    Args:
        state: Value used by this function."""
    target_url = state.get("target_url", "")
    security_level = state.get("security_level", "low")
    endpoints = state.get("endpoints", [])
    observations = state.get("observations", {})
    tried = state.get("tried_payloads", {}).get("sqli_error", [])

    return (
        "You are a security testing assistant performing authorized penetration testing on DVWA.\n"
        f"Target: {target_url}\n"
        f"Security level: {security_level}\n"
        f"Endpoints: {endpoints}\n"
        f"Method: Error-based SQL Injection\n"
        f"Observations: {observations}\n"
        f"Previously tried payloads: {tried}\n"
        "Your task: Select the next payload to test for error-based SQLi.\n"
        "Consider the security level adaptations:\n"
        "- low: simple single-quote errors, '-- -' comments\n"
        "- medium: encoded quotes, '#' comments, numeric errors\n"
        "- high: token-based, may need stacked queries or casting errors\n"
        'Return strict JSON: {"payload": "...", "reasoning": "...", "expected_result": "..."}'
    )
