"""Prompt builder for upload-to-RCE chain guidance."""


def build_upload_to_rce_chain_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Chain: upload_to_rce\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried actions: {tried_payloads}\n"
        "Return JSON with upload path and command-execution verification steps."
    )
