from __future__ import annotations


def build_bf_dictionary_prompt(state: dict) -> str:
    target_url = state.get("target_url", "")
    security_level = state.get("security_level", "low")
    endpoints = state.get("endpoints", [])
    observations = state.get("observations", {})
    tried = state.get("tried_payloads", {}).get("bf_dictionary", [])

    return (
        "You are a security testing assistant performing authorized penetration testing on DVWA.\n"
        f"Target: {target_url}\n"
        f"Security level: {security_level}\n"
        f"Endpoints: {endpoints}\n"
        f"Method: Dictionary Brute Force\n"
        f"Observations: {observations}\n"
        f"Previously tried credentials: {tried}\n"
        "Your task: Select the next username/password pair from a dictionary list.\n"
        "Consider the security level adaptations:\n"
        "- low: no rate limit, rapid sequential attempts allowed\n"
        "- medium: add 0.5s delay between requests\n"
        "- high: CAPTCHA present — document as scope boundary and stop\n"
        'Return strict JSON: {"payload": "...", "reasoning": "...", "expected_result": "..."}'
    )
