"""Tests for foundation/payload_library.py — Payload library contract tests.

Validates:
1. PayloadSet dataclass construction and immutability
2. PayloadLibrary.get() raises NotImplementedError (Stage 2 contract freeze)
3. PayloadLibrary.record_tried() produces correct partial state updates
4. PayloadLibrary.record_bypass() produces correct partial state updates
"""

import pytest

from foundation.payload_library import PayloadSet, PayloadLibrary


class TestPayloadSet:
    """Validate PayloadSet dataclass construction."""

    def test_default_construction(self):
        """PayloadSet should have empty defaults."""
        ps = PayloadSet()
        assert ps.probe == []
        assert ps.exploit == []
        assert ps.bypass == {}

    def test_construction_with_values(self):
        """PayloadSet should store provided values."""
        ps = PayloadSet(
            probe=["1'", "1 OR 1=1"],
            exploit=["1' UNION SELECT null-- -"],
            bypass={"medium": ["1 UNION SELECT#"], "high": ["1' OR '1'='1"]},
        )
        assert len(ps.probe) == 2
        assert len(ps.exploit) == 1
        assert "medium" in ps.bypass

    def test_frozen_immutability(self):
        """PayloadSet should be immutable (frozen=True)."""
        ps = PayloadSet(probe=["1'"])
        with pytest.raises(AttributeError):
            ps.probe = ["new_value"]

    def test_equality(self):
        """PayloadSet instances with same values should be equal."""
        ps1 = PayloadSet(probe=["1'"], exploit=["1 OR 1=1"])
        ps2 = PayloadSet(probe=["1'"], exploit=["1 OR 1=1"])
        assert ps1 == ps2


class TestPayloadLibraryGet:
    """Validate PayloadLibrary.get() contract freeze."""

    def test_get_raises_not_implemented(self):
        """PayloadLibrary.get() should raise NotImplementedError in Stage 2."""
        lib = PayloadLibrary()
        with pytest.raises(NotImplementedError, match="Stage 5"):
            lib.get("sqli", "low")

    def test_get_error_message_contains_vuln_class(self):
        """Error message should include the requested vuln_class."""
        lib = PayloadLibrary()
        with pytest.raises(NotImplementedError, match="sqli"):
            lib.get("sqli", "low")

    def test_get_error_message_contains_security_level(self):
        """Error message should include the requested security_level."""
        lib = PayloadLibrary()
        with pytest.raises(NotImplementedError, match="medium"):
            lib.get("xss_r", "medium")


class TestPayloadLibraryRecordTried:
    """Validate PayloadLibrary.record_tried() state update production."""

    def test_record_tried_adds_to_empty_state(self):
        """Should add first tried payload for a module."""
        state = {"tried_payloads": {}}
        update = PayloadLibrary.record_tried(state, "sqli", "1'")

        assert "tried_payloads" in update
        assert "sqli" in update["tried_payloads"]
        assert "1'" in update["tried_payloads"]["sqli"]

    def test_record_tried_appends_to_existing(self):
        """Should append to existing module payloads without mutation."""
        state = {"tried_payloads": {"sqli": ["1'"]}}
        update = PayloadLibrary.record_tried(state, "sqli", "1 OR 1=1")

        assert "1'" in update["tried_payloads"]["sqli"]
        assert "1 OR 1=1" in update["tried_payloads"]["sqli"]
        # Original state should not be mutated
        assert len(state["tried_payloads"]["sqli"]) == 1

    def test_record_tried_deduplicates(self):
        """Should not add duplicate payloads."""
        state = {"tried_payloads": {"sqli": ["1'"]}}
        update = PayloadLibrary.record_tried(state, "sqli", "1'")

        assert update["tried_payloads"]["sqli"].count("1'") == 1

    def test_record_tried_new_module(self):
        """Should create a new module entry if it doesn't exist."""
        state = {"tried_payloads": {"sqli": ["1'"]}}
        update = PayloadLibrary.record_tried(state, "xss_r", "<script>alert(1)</script>")

        assert "xss_r" in update["tried_payloads"]
        assert "<script>alert(1)</script>" in update["tried_payloads"]["xss_r"]
        # Existing module should still be present
        assert "sqli" in update["tried_payloads"]


class TestPayloadLibraryRecordBypass:
    """Validate PayloadLibrary.record_bypass() state update production."""

    def test_record_bypass_with_technique_only(self):
        """Should produce update with successful_bypasses."""
        state = {"successful_bypasses": []}
        update = PayloadLibrary.record_bypass(state, "double_encode")

        assert "successful_bypasses" in update
        assert "double_encode" in update["successful_bypasses"]
        assert "blocked_patterns" not in update

    def test_record_bypass_with_blocked_pattern(self):
        """Should include blocked_patterns when provided."""
        state = {}
        update = PayloadLibrary.record_bypass(state, "null_byte", "extension_check")

        assert "successful_bypasses" in update
        assert "null_byte" in update["successful_bypasses"]
        assert "blocked_patterns" in update
        assert "extension_check" in update["blocked_patterns"]

    def test_record_bypass_does_not_mutate_state(self):
        """Should not mutate the input state dict."""
        state = {"successful_bypasses": []}
        PayloadLibrary.record_bypass(state, "technique")
        assert state["successful_bypasses"] == []
