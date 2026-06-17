"""Tests for foundation/verifier.py — Verifier contract tests.

Validates:
1. VerificationResult dataclass construction and to_dict
2. Verifier.contains_any() signal detection
3. Verifier.regex_match() regex evidence detection
4. Verifier.verify_xss_dialog() browser-disabled and invalid-url behavior
"""

import pytest

from foundation.verifier import VerificationResult, Verifier


class TestVerificationResult:
    """Validate VerificationResult dataclass."""

    def test_default_values(self):
        """VerificationResult should have sensible defaults."""
        vr = VerificationResult()
        assert vr.ok is False
        assert vr.confidence == 0.0
        assert vr.evidence == []

    def test_construction_with_values(self):
        """VerificationResult should store provided values."""
        vr = VerificationResult(
            ok=True,
            confidence=0.85,
            evidence=["Found SQL error message", "Extracted user data"],
        )
        assert vr.ok is True
        assert vr.confidence == 0.85
        assert len(vr.evidence) == 2

    def test_to_dict(self):
        """to_dict should produce a plain dict compatible with LangGraph state."""
        vr = VerificationResult(
            ok=True,
            confidence=0.95,
            evidence=["XSS dialog fired"],
        )
        d = vr.to_dict()
        assert isinstance(d, dict)
        assert d["ok"] is True
        assert d["confidence"] == 0.95
        assert d["evidence"] == ["XSS dialog fired"]

    def test_to_dict_returns_new_list(self):
        """to_dict should return a copy of evidence, not a reference."""
        vr = VerificationResult(evidence=["test"])
        d = vr.to_dict()
        d["evidence"].append("extra")
        assert len(vr.evidence) == 1


class TestVerifierBehavior:
    """Validate Stage 5 verifier behavior."""

    def test_contains_any_detects_signals_case_insensitive(self):
        """Verifies contains any detects signals case insensitive behavior."""
        v = Verifier()
        result = v.contains_any("Warning: MySQL syntax error", ["mysql", "oracle"])
        assert result.ok is True
        assert "mysql" in [item.lower() for item in result.evidence]

    def test_contains_any_empty_input(self):
        """Verifies contains any empty input behavior."""
        v = Verifier()
        result = v.contains_any("", ["signal"])
        assert result.ok is False

    def test_regex_match_detects_pattern(self):
        """Verifies regex match detects pattern behavior."""
        v = Verifier()
        result = v.regex_match("uid=33(www-data)", [r"uid=\d+"])
        assert result.ok is True
        assert r"uid=\d+" in result.evidence

    def test_regex_match_skips_invalid_pattern(self):
        """Verifies regex match skips invalid pattern behavior."""
        v = Verifier()
        result = v.regex_match("text", ["(", r"uid=\\d+"])
        # Invalid regex patterns should NOT be included in evidence
        assert not any(item.startswith("invalid_regex:") for item in result.evidence)
        assert result.ok is False
        assert result.evidence == []

    def test_regex_match_valid_pattern_ignores_invalid(self):
        """Verifies regex match valid pattern ignores invalid behavior."""
        v = Verifier()
        result = v.regex_match("uid=33(www-data)", ["(", r"uid=\d+"])
        # Invalid regex should be skipped, valid regex should still match
        assert not any(item.startswith("invalid_regex:") for item in result.evidence)
        assert result.ok is True
        assert r"uid=\d+" in result.evidence

    def test_verify_xss_dialog_disabled_via_env(self, monkeypatch):
        """Verifies verify xss dialog disabled via env behavior."""
        v = Verifier()
        monkeypatch.setenv("ENABLE_BROWSER_VERIFIER", "0")
        result = v.verify_xss_dialog("http://localhost/dvwa/vulnerabilities/xss_r/")
        assert result.ok is False
        assert "browser verifier disabled" in result.evidence

    def test_verify_xss_dialog_invalid_url(self, monkeypatch):
        """Verifies verify xss dialog invalid url behavior."""
        v = Verifier()
        monkeypatch.setenv("ENABLE_BROWSER_VERIFIER", "1")
        result = v.verify_xss_dialog("not-a-url")
        assert result.ok is False
        assert "invalid_url" in result.evidence
