"""Payload library — per-vulnerability payload database and mutation engine.

Contract freeze for Stage 2. Full behavioral implementation deferred to Stage 5.
The interfaces defined here establish the API boundary so downstream agents
can be developed against stable types without depending on future payload
implementation details.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PayloadSet:
    """Immutable container for payloads associated with a single vulnerability class.

    Attributes:
        probe: Simple detection payloads used in Stage 1 of exploitation.
        exploit: Exploitation payloads used when a vulnerability is confirmed.
        bypass: Security-level–specific bypass payloads. Keyed by level name
            (``"low"``, ``"medium"``, ``"high"``).
    """

    probe: list[str] = field(default_factory=list)
    exploit: list[str] = field(default_factory=list)
    bypass: dict[str, list[str]] = field(default_factory=dict)


class PayloadLibrary:
    """Retrieve payloads by vulnerability class and security level.

    Stage 2 contract freeze: this class defines the API surface only.
    Full payload definitions and mutation logic will be implemented in Stage 5.

    Design constraints:
    - Retrieval must be deterministic and side-effect free.
    - Payload data should be data-driven (YAML/JSON or constants map), not
      scattered across agents.
    - ``record_tried`` and ``record_bypass`` produce partial state updates
      compatible with LangGraph's immutable state model.
    """

    def get(self, vuln_class: str, security_level: str = "low") -> PayloadSet:
        """Return the ``PayloadSet`` for *vuln_class* at *security_level*.

        Args:
            vuln_class: Module identifier (e.g. ``"sqli"``, ``"xss_r"``).
            security_level: DVWA security level (``"low"``, ``"medium"``, ``"high"``).

        Returns:
            A ``PayloadSet`` containing probe, exploit, and bypass payloads.

        Raises:
            NotImplementedError: Always, until Stage 5 implementation.
        """
        raise NotImplementedError(
            f"PayloadLibrary.get() will be implemented in Stage 5. "
            f"Requested: vuln_class={vuln_class!r}, security_level={security_level!r}"
        )

    @staticmethod
    def record_tried(state: dict, module: str, payload: str) -> dict:
        """Produce a partial state update recording *payload* as tried for *module*.

        This is a pure function that returns a new dict without mutating *state*.
        The returned dict can be merged into LangGraph state via the appropriate
        reducer.

        Args:
            state: Current exploitation state (read-only).
            module: Module name (e.g. ``"sqli"``).
            payload: Payload string that was attempted.

        Returns:
            Partial state update: ``{"tried_payloads": {module: [...tried + payload]}}``
        """
        tried = dict(state.get("tried_payloads", {}))
        module_tried = list(tried.get(module, []))
        if payload not in module_tried:
            module_tried.append(payload)
        tried[module] = module_tried
        return {"tried_payloads": tried}

    @staticmethod
    def record_bypass(
        state: dict, technique: str, blocked_pattern: str | None = None
    ) -> dict:
        """Produce a partial state update recording a successful bypass technique.

        This is a pure function that returns a new dict without mutating *state*.

        Args:
            state: Current exploitation state (read-only).
            technique: Bypass technique that succeeded (e.g. ``"double_encode"``).
            blocked_pattern: The pattern that was bypassed, if known.

        Returns:
            Partial state update with ``"successful_bypasses"`` and optionally
            ``"blocked_patterns"``.
        """
        update: dict = {
            "successful_bypasses": [technique],
        }
        if blocked_pattern:
            update["blocked_patterns"] = [blocked_pattern]
        return update
