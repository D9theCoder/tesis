"""Prompt builder for SQLi-to-creds chain guidance."""


def build_sqli_to_creds_chain_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Chain: sqli_to_creds\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried actions: {tried_payloads}\n"
        "Return JSON with login and admin-session verification steps."
    )
