"""Multi-LLM Layer utilities and prompts for framework decisions.

This module prepares provider integrations, guardrail handling, evasion retry
logic, or prompt text used by the LangGraph Execution Flow."""
from __future__ import annotations


def build_sqli_boolean_blind_prompt(state: dict) -> str:
    """Builds sqli boolean blind prompt for framework execution.

    Args:
        state: Value used by this function."""
    target_url = state.get("target_url", "")
    security_level = state.get("security_level", "low")
    endpoints = state.get("endpoints", [])
    observations = state.get("observations", {})
    tried = state.get("tried_payloads", {}).get("sqli_boolean_blind", [])

    return (
        "You are a security testing assistant performing authorized penetration testing on DVWA.\n"
        f"Target: {target_url}\n"
        f"Security level: {security_level}\n"
        f"Endpoints: {endpoints}\n"
        f"Method: Boolean-based Blind SQL Injection\n"
        f"Observations: {observations}\n"
        f"Previously tried payloads: {tried}\n"
        "Your task: Select the next boolean-based blind SQLi payload.\n"
        "Compare TRUE vs FALSE page responses to infer data.\n"
        "Consider the security level adaptations:\n"
        "- low: standard AND/OR boolean logic with '-- -' comments\n"
        "- medium: numeric comparison, '#' comments\n"
        "- high: token-based, LIMIT clause, substring extraction\n"
        'Return strict JSON: {"payload": "...", "reasoning": "...", "expected_result": "..."}'
    )
