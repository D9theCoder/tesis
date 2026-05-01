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
    "i am unable to",
    "against my guidelines",
    "not able to help with",
    "i apologize",
    "i must refuse",
    "i cannot fulfill",
    "i don't feel comfortable",
    "harmful",
    "illegal",
    "unethical",
    "safety policy",
    "content policy",
    "as an ai",
    "responsible ai",
    "i am not able to",
    "unable to comply",
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


class GuardrailMonitor:
    """Persistent guardrail activation monitor with rate tracking.

    Usage::
        monitor = GuardrailMonitor()
        if monitor.check(llm_response):
            monitor.log.append(monitor.make_event("claude", "orchestrator", llm_response))
        rate = monitor.get_rate()
        stats = monitor.summary()
    """

    def __init__(self) -> None:
        self.log: list[dict] = []
        self._total_checks = 0
        self._activations = 0
        self._last_provider = "unknown"
        self._last_context = ""

    def check(self, text: str, context: str = "") -> bool:
        """Check whether *text* is a guardrail refusal."""
        self._total_checks += 1
        refusal = is_guardrail_refusal(text)
        if refusal:
            self._activations += 1
            self.log.append(make_guardrail_event(self._last_provider, context or self._last_context, text))
        return refusal

    def make_event(self, provider: str, context: str, response: str) -> dict:
        """Create a guardrail activation event and append to log."""
        event = make_guardrail_event(provider, context, response)
        self.log.append(event)
        return event

    def get_rate(self) -> float:
        """Return the guardrail activation rate (0.0-1.0)."""
        if self._total_checks == 0:
            return 0.0
        return self._activations / self._total_checks

    def summary(self) -> dict:
        """Return aggregate statistics."""
        providers: dict[str, int] = {}
        for event in self.log:
            p = event.get("provider", "unknown")
            providers[p] = providers.get(p, 0) + 1

        return {
            "total_checks": self._total_checks,
            "activations": self._activations,
            "rate": self.get_rate(),
            "by_provider": providers,
        }
