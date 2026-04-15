"""Verification engine — response parser + Playwright XSS verifier.

Contract freeze for Stage 2. Full behavioral implementation deferred to Stage 5.
The interfaces defined here establish the API boundary so downstream agents
can be developed against stable types without depending on future verification
implementation details.
"""

from dataclasses import dataclass, field


@dataclass
class VerificationResult:
    """Structured result from a verification check.

    Attributes:
        ok: Whether the verification passed.
        confidence: Confidence score between 0.0 and 1.0.
        evidence: List of human-readable evidence strings supporting the result.
    """

    ok: bool = False
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to a plain dict for LangGraph state compatibility."""
        return {
            "ok": self.ok,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


class Verifier:
    """Evidence-oriented verification for exploitation results.

    Stage 2 contract freeze: this class defines the API surface only.
    Full behavioral implementation (HTTP response parsing, Playwright-based
    XSS dialog verification, etc.) will be implemented in Stage 5.

    Design constraints:
    - Return structured evidence, not only booleans.
    - Keep browser verification optional (feature-flagged) for CI portability.
    - All methods must be side-effect free except ``verify_xss_dialog``
      which may launch a headless browser.
    """

    def contains_any(self, body: str, signals: list[str]) -> VerificationResult:
        """Check whether *body* contains any of the *signals* strings.

        Args:
            body: HTTP response body text.
            signals: List of strings to search for (case-insensitive).

        Returns:
            A ``VerificationResult`` with ``ok=True`` if any signal is found.

        Raises:
            NotImplementedError: Always, until Stage 5 implementation.
        """
        raise NotImplementedError(
            "Verifier.contains_any() will be implemented in Stage 5."
        )

    def regex_match(self, body: str, patterns: list[str]) -> VerificationResult:
        """Check whether *body* matches any of the *patterns* regex strings.

        Args:
            body: HTTP response body text.
            patterns: List of regex pattern strings.

        Returns:
            A ``VerificationResult`` with ``ok=True`` if any pattern matches.

        Raises:
            NotImplementedError: Always, until Stage 5 implementation.
        """
        raise NotImplementedError(
            "Verifier.regex_match() will be implemented in Stage 5."
        )

    def verify_xss_dialog(
        self, url: str, cookies: dict[str, str] | None = None
    ) -> VerificationResult:
        """Open *url* in a headless browser and check for a JS dialog (alert).

        Args:
            url: Full URL to navigate to (including payload).
            cookies: Optional cookie dict to inject before navigation.

        Returns:
            A ``VerificationResult`` with ``ok=True`` if a dialog event fires.

        Raises:
            NotImplementedError: Always, until Stage 5 implementation.
        """
        raise NotImplementedError(
            "Verifier.verify_xss_dialog() will be implemented in Stage 5."
        )
