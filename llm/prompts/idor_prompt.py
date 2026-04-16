"""Prompt builder for IDOR agent guidance."""


def build_idor_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Module: idor\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried payloads: {tried_payloads}\n"
        "Return JSON with object-reference mutation and diff strategy."
    )
