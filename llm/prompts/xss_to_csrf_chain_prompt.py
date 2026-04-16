"""Prompt builder for XSS-to-CSRF chain guidance."""


def build_xss_to_csrf_chain_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Chain: xss_to_csrf\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried actions: {tried_payloads}\n"
        "Return JSON with token capture and forged request flow."
    )
