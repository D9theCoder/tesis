"""Prompt builder for DOM XSS agent guidance."""


def build_xss_dom_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Module: xss_d\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried payloads: {tried_payloads}\n"
        "Return JSON with DOM source/sink payload strategy."
    )
