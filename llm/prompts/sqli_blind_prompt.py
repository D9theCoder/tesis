"""Prompt builder for blind SQLi agent guidance."""


def build_sqli_blind_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Module: sqli_blind\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried payloads: {tried_payloads}\n"
        "Return JSON with boolean/time extraction strategy."
    )
