"""Verification engine — response parser + Playwright XSS verifier."""

from dataclasses import dataclass, field
import logging
import os
import re
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


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
    """Evidence-oriented verification for exploitation results."""

    def contains_any(self, body: str, signals: list[str]) -> VerificationResult:
        """Check whether ``body`` contains any text signal (case-insensitive)."""
        # Truncate large responses to prevent memory issues
        max_body_size = 1_048_576  # 1 MB
        if len(body) > max_body_size:
            body = body[:max_body_size]

        if not body or not signals:
            return VerificationResult(ok=False, confidence=0.0, evidence=[])

        lowered = body.lower()
        matches: list[str] = []
        for signal in signals:
            normalized = str(signal)
            if normalized.lower() in lowered and normalized not in matches:
                matches.append(normalized)

        ok = bool(matches)
        confidence = 1.0 if ok else 0.0
        return VerificationResult(ok=ok, confidence=confidence, evidence=matches)

    def regex_match(self, body: str, patterns: list[str]) -> VerificationResult:
        """Check whether ``body`` matches any regex pattern."""
        # Truncate large responses to prevent memory issues
        max_body_size = 1_048_576  # 1 MB
        if len(body) > max_body_size:
            body = body[:max_body_size]

        if not body or not patterns:
            return VerificationResult(ok=False, confidence=0.0, evidence=[])

        evidence: list[str] = []
        for pattern in patterns:
            try:
                if re.search(pattern, body, flags=re.IGNORECASE | re.MULTILINE):
                    evidence.append(pattern)
            except re.error as exc:
                logger.warning("Invalid regex pattern encountered during verification: %s", pattern, exc_info=exc)
                # Do NOT include invalid regex in evidence — evidence should only contain matches
                continue

        matched = [item for item in evidence if not item.startswith("invalid_regex:")]
        ok = bool(matched)
        confidence = min(1.0, 0.6 + 0.1 * len(matched)) if ok else 0.0
        return VerificationResult(ok=ok, confidence=confidence, evidence=evidence)

def verify_method_response(agent_id: str, response_text: str, expected_signal: str) -> bool:
    """Verify if a method's expected signal is present in the response.

    .. deprecated::
        Use ``Verifier.contains_any()`` instead for consistent API.
    """
    return expected_signal.lower() in response_text.lower()
