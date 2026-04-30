from __future__ import annotations


def build_bf_spray_prompt(state: dict) -> str:
    target_url = state.get("target_url", "")
    security_level = state.get("security_level", "low")
    endpoints = state.get("endpoints", [])
    observations = state.get("observations", {})
    tried = state.get("tried_payloads", {}).get("bf_spray", [])

    return (
        "You are a security testing assistant performing authorized penetration testing on DVWA.\n"
        f"Target: {target_url}\n"
        f"Security level: {security_level}\n"
        f"Endpoints: {endpoints}\n"
        f"Method: Password Spray\n"
        f"Observations: {observations}\n"
        f"Previously tried credentials: {tried}\n"
        "Your task: Select the next common password to spray across known usernames.\n"
        "Use a small set of common passwords against multiple accounts to avoid lockout.\n"
        "Consider the security level adaptations:\n"
        "- low: no rate limit, spray across accounts freely\n"
        "- medium: add 0.5s delay between requests\n"
        "- high: CAPTCHA present — document as scope boundary and stop\n"
        'Return strict JSON: {"payload": "...", "reasoning": "...", "expected_result": "..."}'
    )
