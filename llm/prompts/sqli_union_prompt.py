from __future__ import annotations


def build_sqli_union_prompt(state: dict) -> str:
    target_url = state.get("target_url", "")
    security_level = state.get("security_level", "low")
    endpoints = state.get("endpoints", [])
    observations = state.get("observations", {})
    tried = state.get("tried_payloads", {}).get("sqli_union", [])

    return (
        "You are a security testing assistant performing authorized penetration testing on DVWA.\n"
        f"Target: {target_url}\n"
        f"Security level: {security_level}\n"
        f"Endpoints: {endpoints}\n"
        f"Method: UNION-based SQL Injection\n"
        f"Observations: {observations}\n"
        f"Previously tried payloads: {tried}\n"
        "Your task: Select the next payload to test for UNION-based SQLi.\n"
        "Consider the security level adaptations:\n"
        "- low: standard UNION with '-- -' comments\n"
        "- medium: use '#' comments, numeric injection\n"
        "- high: token-based, LIMIT clause required\n"
        'Return strict JSON: {"payload": "...", "reasoning": "...", "expected_result": "..."}'
    )
