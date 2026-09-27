"""Tests for foundation/payload_library.py — Payload library contract tests.

Validates:
1. PayloadSet dataclass construction and immutability
2. PayloadLibrary.get() returns deterministic payload sets
3. PayloadLibrary.record_tried() produces correct partial state updates
4. PayloadLibrary.record_bypass() produces correct partial state updates
"""

from foundation.payload_library import PayloadLibrary

class TestPayloadLibraryGet:
    """Validate PayloadLibrary.get() behavior."""

    def test_get_returns_defensive_copy(self):
        """Verifies get returns defensive copy behavior."""
        lib = PayloadLibrary()
        payload_a = lib.get("sqli_error", "low")
        payload_b = lib.get("sqli_error", "low")

        payload_a.probe.append("tamper")
        assert "tamper" not in payload_b.probe
