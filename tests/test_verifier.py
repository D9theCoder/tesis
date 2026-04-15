"""Tests for foundation/verifier.py — Verifier contract tests.

Validates:
1. VerificationResult dataclass construction and to_dict
2. Verifier.contains_any() raises NotImplementedError (Stage 2)
3. Verifier.regex_match() raises NotImplementedError (Stage 2)
4. Verifier.verify_xss_dialog() raises NotImplementedError (Stage 2)
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


class TestVerifierContractFreeze:
    """Validate that Verifier methods raise NotImplementedError (Stage 2 contract freeze)."""

    def test_contains_any_raises_not_implemented(self):
        """Verifier.contains_any() should raise NotImplementedError in Stage 2."""
        v = Verifier()
        with pytest.raises(NotImplementedError, match="Stage 5"):
            v.contains_any("some body", ["signal"])

    def test_regex_match_raises_not_implemented(self):
        """Verifier.regex_match() should raise NotImplementedError in Stage 2."""
        v = Verifier()
        with pytest.raises(NotImplementedError, match="Stage 5"):
            v.regex_match("some body", ["pattern"])

    def test_verify_xss_dialog_raises_not_implemented(self):
        """Verifier.verify_xss_dialog() should raise NotImplementedError in Stage 2."""
        v = Verifier()
        with pytest.raises(NotImplementedError, match="Stage 5"):
            v.verify_xss_dialog("http://localhost/test", {"PHPSESSID": "abc"})
