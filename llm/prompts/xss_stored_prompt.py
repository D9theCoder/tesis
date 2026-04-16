"""Prompt builder for stored XSS agent guidance."""


def build_xss_stored_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Module: xss_s\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried payloads: {tried_payloads}\n"
        "Return JSON with stored XSS payload and verification strategy."
    )
