"""Prompt builder for LFI agent guidance."""


def build_lfi_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Module: lfi\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried payloads: {tried_payloads}\n"
        "Return JSON with traversal, log-read, and poisoning strategy hints."
    )
