"""Prompt builder for weak-session agent guidance."""


def build_weak_session_prompt(security_level: str, endpoint: str, tried_payloads: list[str]) -> str:
    return (
        f"Module: weak_session\n"
        f"Security level: {security_level}\n"
        f"Endpoint: {endpoint}\n"
        f"Tried payloads: {tried_payloads}\n"
        "Return JSON with predictability analysis and hijack strategy."
    )
