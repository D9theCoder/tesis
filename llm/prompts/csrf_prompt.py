"""Prompt builder for CSRF agent guidance."""


def build_csrf_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Module: csrf\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried payloads: {tried_payloads}\n"
        "Return JSON with token-check and direct/chain exploitation strategy."
    )
