"""Guardrail/refusal detection helpers for LLM responses."""

from __future__ import annotations

REFUSAL_PATTERNS = (
    "i can't assist",
    "i cannot assist",
    "i can't help",
    "i cannot help",
    "i won't",
    "i must decline",
    "i'm unable to",
    "against my guidelines",
    "not able to help with",
)


def is_guardrail_refusal(text: str) -> bool:
    """Return True when response text matches known refusal phrases."""
    lowered = (text or "").lower().replace("’", "'")
    return any(pattern in lowered for pattern in REFUSAL_PATTERNS)


def make_guardrail_event(provider: str, context: str, response: str) -> dict:
    """Build a normalized guardrail activation payload."""
    return {
        "provider": provider,
        "context": context,
        "snippet": (response or "")[:200],
    }
