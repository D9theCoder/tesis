"""Prompt builder for reflected XSS agent guidance."""


def build_xss_reflected_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Module: xss_r\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried payloads: {tried_payloads}\n"
        "Return JSON with context-aware reflected XSS payload selection."
    )
