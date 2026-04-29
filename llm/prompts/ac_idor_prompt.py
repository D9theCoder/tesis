from __future__ import annotations


def build_ac_idor_prompt(state: dict) -> str:
    target_url = state.get("target_url", "")
    security_level = state.get("security_level", "low")
    endpoints = state.get("endpoints", [])
    observations = state.get("observations", {})
    tried = state.get("tried_payloads", {}).get("ac_idor", [])

    return (
        "You are a security testing assistant performing authorized penetration testing on DVWA.\n"
        f"Target: {target_url}\n"
        f"Security level: {security_level}\n"
        f"Endpoints: {endpoints}\n"
        f"Method: Insecure Direct Object Reference (IDOR)\n"
        f"Observations: {observations}\n"
        f"Previously tried object IDs / payloads: {tried}\n"
        "Your task: Select the next object ID or parameter to test for IDOR.\n"
        "Manipulate userId, fileId, or other reference parameters.\n"
        "Consider the security level adaptations:\n"
        "- low: direct userId manipulation\n"
        "- medium: encoding/indirect reference required\n"
        "- high: may require valid session from brute force\n"
        'Return strict JSON: {"payload": "...", "reasoning": "...", "expected_result": "..."}'
    )
