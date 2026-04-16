"""Prompt builder for command injection agent guidance."""


def build_cmdi_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Module: cmdi\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried payloads: {tried_payloads}\n"
        "Return JSON with command separator and output-confirmation strategy."
    )
