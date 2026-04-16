"""Verification engine — response parser + Playwright XSS verifier."""

from dataclasses import dataclass, field
import os
import re
from urllib.parse import urlparse


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
        if not body or not signals:
            return VerificationResult(ok=False, confidence=0.0, evidence=[])

        lowered = body.lower()
        matches: list[str] = []
        for signal in signals:
            normalized = str(signal)
            if normalized.lower() in lowered and normalized not in matches:
                matches.append(normalized)

        ok = bool(matches)
        confidence = min(1.0, 0.5 + 0.15 * len(matches)) if ok else 0.0
        return VerificationResult(ok=ok, confidence=confidence, evidence=matches)

    def regex_match(self, body: str, patterns: list[str]) -> VerificationResult:
        """Check whether ``body`` matches any regex pattern."""
        if not body or not patterns:
            return VerificationResult(ok=False, confidence=0.0, evidence=[])

        evidence: list[str] = []
        for pattern in patterns:
            try:
                if re.search(pattern, body, flags=re.IGNORECASE | re.MULTILINE):
                    evidence.append(pattern)
            except re.error:
                evidence.append(f"invalid_regex:{pattern}")

        matched = [item for item in evidence if not item.startswith("invalid_regex:")]
        ok = bool(matched)
        confidence = min(1.0, 0.6 + 0.1 * len(matched)) if ok else 0.0
        return VerificationResult(ok=ok, confidence=confidence, evidence=evidence)

    def verify_xss_dialog(
        self, url: str, cookies: dict[str, str] | None = None
    ) -> VerificationResult:
        """Open ``url`` in Chromium and verify whether a JS dialog fires."""
        disable_flag = os.getenv("ENABLE_BROWSER_VERIFIER", "1").lower()
        if disable_flag in {"0", "false", "no"}:
            return VerificationResult(
                ok=False,
                confidence=0.0,
                evidence=["browser verifier disabled"],
            )

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return VerificationResult(
                ok=False,
                confidence=0.0,
                evidence=["invalid_url"],
            )

        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # pragma: no cover - depends on local runtime
            return VerificationResult(
                ok=False,
                confidence=0.0,
                evidence=[f"playwright_unavailable:{type(exc).__name__}"],
            )

        dialog_messages: list[str] = []
        browser = None
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context()

                if cookies:
                    cookie_payload = [
                        {
                            "name": name,
                            "value": value,
                            "domain": parsed.hostname or "localhost",
                            "path": "/",
                        }
                        for name, value in cookies.items()
                    ]
                    context.add_cookies(cookie_payload)

                page = context.new_page()

                def _on_dialog(dialog):
                    dialog_messages.append(dialog.message or "dialog_fired")
                    dialog.dismiss()

                page.on("dialog", _on_dialog)
                page.goto(url, wait_until="networkidle", timeout=10_000)

                context.close()

            if dialog_messages:
                return VerificationResult(
                    ok=True,
                    confidence=1.0,
                    evidence=dialog_messages,
                )

            return VerificationResult(
                ok=False,
                confidence=0.1,
                evidence=["no_dialog"],
            )
        except Exception as exc:  # pragma: no cover - depends on browser availability
            return VerificationResult(
                ok=False,
                confidence=0.0,
                evidence=[f"browser_error:{type(exc).__name__}"],
            )
        finally:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
