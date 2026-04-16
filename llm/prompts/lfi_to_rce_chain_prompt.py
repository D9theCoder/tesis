"""Prompt builder for LFI-to-RCE chain guidance."""


def build_lfi_to_rce_chain_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Chain: lfi_to_rce\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried actions: {tried_payloads}\n"
        "Return JSON with log-poisoning and command-verification flow."
    )
