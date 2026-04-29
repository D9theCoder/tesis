from __future__ import annotations


def build_sqli_time_blind_prompt(state: dict) -> str:
    target_url = state.get("target_url", "")
    security_level = state.get("security_level", "low")
    endpoints = state.get("endpoints", [])
    observations = state.get("observations", {})
    tried = state.get("tried_payloads", {}).get("sqli_time_blind", [])

    return (
        "You are a security testing assistant performing authorized penetration testing on DVWA.\n"
        f"Target: {target_url}\n"
        f"Security level: {security_level}\n"
        f"Endpoints: {endpoints}\n"
        f"Method: Time-based Blind SQL Injection\n"
        f"Observations: {observations}\n"
        f"Previously tried payloads: {tried}\n"
        "Your task: Select the next time-based blind SQLi payload.\n"
        "Use database sleep/delay functions to infer data from response timing.\n"
        "Consider the security level adaptations:\n"
        "- low: standard SLEEP/BENCHMARK with '-- -' comments\n"
        "- medium: numeric injection, '#' comments, shorter delays\n"
        "- high: token-based, LIMIT clause, may need nested delays\n"
        'Return strict JSON: {"payload": "...", "reasoning": "...", "expected_result": "..."}'
    )
