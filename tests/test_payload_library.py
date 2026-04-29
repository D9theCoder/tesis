"""Tests for foundation/payload_library.py — Payload library contract tests.

Validates:
1. PayloadSet dataclass construction and immutability
2. PayloadLibrary.get() returns deterministic payload sets
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
    """Validate PayloadLibrary.get() behavior."""

    def test_get_known_module_returns_payloads(self):
        lib = PayloadLibrary()
        payload_set = lib.get("sqli_union", "low")

        assert payload_set.probe
        assert payload_set.exploit
        assert isinstance(payload_set.bypass, dict)

    def test_get_unknown_module_returns_empty_payload_set(self):
        lib = PayloadLibrary()
        payload_set = lib.get("not_a_module", "low")

        assert payload_set.probe == []
        assert payload_set.exploit == []
        assert payload_set.bypass == {}

    def test_get_unknown_security_level_falls_back_to_low(self):
        lib = PayloadLibrary()
        payload_set = lib.get("sqli_union", "ultra")
        assert "low" in payload_set.bypass

    def test_get_returns_defensive_copy(self):
        lib = PayloadLibrary()
        payload_a = lib.get("sqli_error", "low")
        payload_b = lib.get("sqli_error", "low")

        payload_a.probe.append("tamper")
        assert "tamper" not in payload_b.probe


class TestPayloadLibraryRecordTried:
    """Validate PayloadLibrary.record_tried() state update production."""

    def test_record_tried_adds_to_empty_state(self):
        """Should add first tried payload for a module."""
        state = {"tried_payloads": {}}
        update = PayloadLibrary.record_tried(state, "sqli_union", "1'")

        assert "tried_payloads" in update
        assert "sqli_union" in update["tried_payloads"]
        assert "1'" in update["tried_payloads"]["sqli_union"]

    def test_record_tried_appends_to_existing(self):
        """Should append to existing module payloads without mutation."""
        state = {"tried_payloads": {"sqli_union": ["1'"]}}
        update = PayloadLibrary.record_tried(state, "sqli_union", "1 OR 1=1")

        assert "1'" in update["tried_payloads"]["sqli_union"]
        assert "1 OR 1=1" in update["tried_payloads"]["sqli_union"]
        # Original state should not be mutated
        assert len(state["tried_payloads"]["sqli_union"]) == 1

    def test_record_tried_deduplicates(self):
        """Should not add duplicate payloads."""
        state = {"tried_payloads": {"sqli_union": ["1'"]}}
        update = PayloadLibrary.record_tried(state, "sqli_union", "1'")

        assert update["tried_payloads"]["sqli_union"].count("1'") == 1

    def test_record_tried_new_module(self):
        """Should create a new module entry if it doesn't exist."""
        state = {"tried_payloads": {"sqli_union": ["1'"]}}
        update = PayloadLibrary.record_tried(state, "ac_idor", "<script>alert(1)</script>")

        assert "ac_idor" in update["tried_payloads"]
        assert "<script>alert(1)</script>" in update["tried_payloads"]["ac_idor"]
        # Existing module should still be present
        assert "sqli_union" in update["tried_payloads"]


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

    def test_record_bypass_deduplicates_against_state(self):
        state = {"successful_bypasses": ["double_encode"]}
        update = PayloadLibrary.record_bypass(state, "double_encode")
        assert update["successful_bypasses"] == []
