"""Append-only observation facts and derived tri-state method preconditions.

Endpoints and run labels are never proof.  A condition is ``true`` or ``false``
only when an applicable fact records measured positive or negative evidence;
missing, transport-failed, or unscoped observations stay ``unknown``.  History
is preserved: a later fact changes the derived current status but never erases
an earlier row.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from core.knowledge_graph import get_attack_knowledge_graph

PRECONDITION_POLICY_VERSION = "preconditions.v1"
PRECONDITION_STATUSES = ("true", "false", "unknown")

# Facts that describe the fixture/session rather than a method precondition.
SESSION_FACT_KEYS = frozenset({
    "authenticated_crawl",
    "low_priv_session_available",
    "authentication_ambiguous",
})

_SCOPE_FIELDS = (
    "fixture_id",
    "protocol_version",
    "security_level",
    "principal_id",
    "session_fingerprint",
    "phase",
)


def precondition_keys() -> list[str]:
    """Return every declared method-precondition key in method order."""
    keys: list[str] = []
    for method in get_attack_knowledge_graph().METHOD_PRECONDITIONS:
        for key in get_attack_knowledge_graph().METHOD_PRECONDITIONS[method]:
            if key not in keys:
                keys.append(key)
    return keys


def precondition_keys_for_method(method: str) -> list[str]:
    """Return the declared precondition keys for one method."""
    return list(get_attack_knowledge_graph().METHOD_PRECONDITIONS.get(method, []))


def methods_for_precondition(key: str) -> list[str]:
    """Return every method that declares ``key`` as a precondition."""
    return [method for method, keys in
            get_attack_knowledge_graph().METHOD_PRECONDITIONS.items() if key in keys]


def make_observation_fact(
    key: str,
    value: bool | None,
    *,
    source: str,
    method: str | None = None,
    visit_id: str | None = None,
    control_id: str | None = None,
    evidence_refs: Iterable[str] | None = None,
    fixture_id: str | None = None,
    protocol_version: str | None = None,
    security_level: str | None = None,
    principal_id: str | None = None,
    session_fingerprint: str | None = None,
    phase: str = "detection",
    session_scope: str = "run",
    detail: str = "",
) -> dict[str, Any]:
    """Build one immutable observation fact.

    ``value`` is ``True``/``False`` for measured evidence and ``None`` for an
    explicit unknown result such as a transport failure or missing control.
    """
    normalized = value if isinstance(value, bool) else None
    return {
        "key": str(key),
        "value": normalized,
        "source": str(source or "unknown"),
        "method": method,
        "visit_id": visit_id,
        "control_id": control_id,
        "evidence_refs": list(dict.fromkeys(str(ref) for ref in (evidence_refs or []) if ref)),
        "scope": {
            "fixture_id": fixture_id,
            "protocol_version": protocol_version,
            "security_level": security_level,
            "principal_id": principal_id,
            "session_fingerprint": session_fingerprint,
            "session_scope": str(session_scope or "run"),
            "phase": phase,
        },
        "policy_version": PRECONDITION_POLICY_VERSION,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "detail": str(detail or ""),
    }


def fact_scope(state: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return the run-level scope fields used to filter applicable facts."""
    state = state or {}
    readiness = state.get("readiness") if isinstance(state.get("readiness"), Mapping) else {}
    session = readiness.get("session") if isinstance(readiness.get("session"), Mapping) else {}
    principals = state.get("method_principals")
    method_fingerprints = state.get("method_session_fingerprints")
    return {
        "fixture_id": state.get("fixture_id"),
        "protocol_version": state.get("protocol_version"),
        "security_level": state.get("security_level"),
        "principal_id": session.get("principal"),
        "session_fingerprint": session.get("fingerprint"),
        "method_principals": dict(principals) if isinstance(principals, Mapping) else {},
        "method_session_fingerprints": (
            dict(method_fingerprints) if isinstance(method_fingerprints, Mapping) else {}
        ),
    }


def _fact_timestamp(fact: Mapping[str, Any]) -> tuple[float, str]:
    """Order facts by a real aware timestamp, then by the raw string."""
    raw = str(fact.get("observed_at") or "")
    try:
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp(), raw
    except (TypeError, ValueError):
        return float("-inf"), raw


def _scope_applicable(fact: Mapping[str, Any], run_scope: Mapping[str, Any]) -> bool:
    fact_scope_value = fact.get("scope") if isinstance(fact.get("scope"), Mapping) else {}
    for key in ("fixture_id", "protocol_version", "security_level"):
        expected, observed = run_scope.get(key), fact_scope_value.get(key)
        if expected not in (None, "") and str(expected) != str(observed):
            return False
    # Explicit, source-bound fixture attestations are session independent.
    if str(fact_scope_value.get("session_scope") or "run") == "fixture":
        return True
    method = fact.get("method")
    method_principals = run_scope.get("method_principals") or {}
    expected_principal = (
        method_principals.get(str(method)) if method and str(method) in method_principals
        else run_scope.get("principal_id")
    )
    observed_principal = fact_scope_value.get("principal_id")
    if expected_principal not in (None, ""):
        if observed_principal in (None, "") or str(expected_principal) != str(observed_principal):
            return False
    method_fingerprints = run_scope.get("method_session_fingerprints") or {}
    run_fingerprint = (
        method_fingerprints.get(str(method)) if method and str(method) in method_fingerprints
        else run_scope.get("session_fingerprint")
    )
    if str(fact_scope_value.get("session_scope") or "run") == "session":
        observed_fingerprint = fact_scope_value.get("session_fingerprint")
        if not run_fingerprint or not observed_fingerprint:
            # A session-scoped measurement without both identities is unknown,
            # never silently applicable to an unrelated session.
            return False
        if str(run_fingerprint) != str(observed_fingerprint):
            return False
    return True


def _facts(state_or_facts: Mapping[str, Any] | Iterable[dict] | None) -> list[dict]:
    if isinstance(state_or_facts, Mapping):
        rows = state_or_facts.get("observation_facts", [])
    else:
        rows = state_or_facts
    return [dict(row) for row in (rows or []) if isinstance(row, Mapping)]


def derive_precondition_status(
    state_or_facts: Mapping[str, Any] | Iterable[dict] | None,
    *,
    keys: Iterable[str] | None = None,
    method: str | None = None,
) -> dict[str, str]:
    """Derive current ``true|false|unknown`` status from append-only facts.

    The latest applicable fact for a key wins; a later measured negative
    therefore corrects an earlier positive without deleting the history.
    """
    run_scope = fact_scope(state_or_facts) if isinstance(state_or_facts, Mapping) else {}
    wanted = list(keys) if keys is not None else precondition_keys()
    latest: dict[str, dict] = {}
    facts = _facts(state_or_facts)
    fact_keys = {str(fact.get("key") or "") for fact in facts}
    for order, fact in enumerate(facts):
        key = str(fact.get("key") or "")
        if (not key or not _scope_applicable(fact, run_scope)
                or (method is not None and fact.get("method") not in (None, method))):
            continue
        stamp = _fact_timestamp(fact)
        previous = latest.get(key)
        if previous is None or (stamp, order) >= (_fact_timestamp(previous), previous.get("_order", -1)):
            latest[key] = {**fact, "_order": order}
    legacy = (state_or_facts.get("observations", {})
              if isinstance(state_or_facts, Mapping) else {})
    status: dict[str, str] = {}
    for key in wanted:
        fact = latest.get(key)
        if isinstance(fact, Mapping):
            value = fact.get("value")
            status[key] = "true" if value is True else "false" if value is False else "unknown"
        elif key not in fact_keys and isinstance(legacy, Mapping) and isinstance(legacy.get(key), bool):
            # Historical booleans apply only when no scoped fact exists.
            # An expired fact must never be revived through its legacy view.
            status[key] = "true" if legacy[key] is True else "false"
        else:
            status[key] = "unknown"
    return status


def derived_legacy_observations(facts: Iterable[dict], *, run_scope: Mapping[str, Any] | None = None) -> dict[str, bool]:
    """Return the supported legacy ``observations`` view of proven-positive facts."""
    scope = dict(run_scope or {})
    latest: dict[str, dict] = {}
    for order, fact in enumerate(_facts(facts)):
        if not _scope_applicable(fact, scope):
            continue
        key = str(fact.get("key") or "")
        if not key:
            continue
        stamp = _fact_timestamp(fact)
        previous = latest.get(key)
        if previous is None or (stamp, order) >= (_fact_timestamp(previous), previous.get("_order", -1)):
            latest[key] = {**fact, "_order": order}
    return {key: bool(fact.get("value")) for key, fact in latest.items()
            if isinstance(fact.get("value"), bool)}


def derived_selector_observations(state: Mapping[str, Any]) -> dict[str, bool]:
    """Return the current bool view used for model inputs and Smethod snapshots.

    Latest applicable facts win (a measured false is included) and unknown keys
    stay absent. Legacy observations are used only for keys with no fact at all,
    never to resurrect a disproved fact.
    """
    facts = _facts(state)
    run_scope = fact_scope(state)
    current = derived_legacy_observations(facts, run_scope=run_scope)
    fact_keys = {str(fact.get("key") or "") for fact in facts}
    legacy = state.get("observations") if isinstance(state.get("observations"), Mapping) else {}
    for key, value in legacy.items():
        if key not in fact_keys and isinstance(value, bool):
            current[str(key)] = value
    return current


def observation_update(
    state: Mapping[str, Any],
    facts: Iterable[dict],
    *,
    method: str | None = None,
) -> dict[str, Any]:
    """Build the shared state update for new facts plus their derived views.

    Only this helper produces ``observations`` and ``precondition_status``.
    ``keys`` is restricted to the method's declared preconditions when a
    method-scoped measurement is recorded, while unrelated keys retain their
    run-level derived status.
    """
    new_facts = [dict(fact) for fact in facts if isinstance(fact, Mapping)]
    combined = [*_facts(state), *new_facts]
    status = derive_precondition_status({**dict(state), "observation_facts": combined})
    if method:
        scoped = derive_precondition_status(
            {**dict(state), "observation_facts": combined},
            keys=precondition_keys_for_method(method),
            method=method,
        )
        for key, value in scoped.items():
            status[key] = value
    return {
        "observation_facts": new_facts,
        "precondition_status": status,
        "observations": derived_selector_observations(
            {**dict(state), "observation_facts": combined, "precondition_status": status}),
    }


def statuses_snapshot(state: Mapping[str, Any], method: str) -> dict[str, str]:
    """Return the current tri-state status of one method's prerequisites."""
    derived = derive_precondition_status(state, method=method)
    return {key: str(derived.get(key, "unknown")) for key in precondition_keys_for_method(method)}


def fact_references(state: Mapping[str, Any], keys: Iterable[str], *, method: str) -> list[str]:
    """Return evidence references from the latest applicable fact per key."""
    status_refs: list[str] = []
    run_scope = fact_scope(state)
    latest: dict[str, dict] = {}
    for order, fact in enumerate(_facts(state)):
        key = str(fact.get("key") or "")
        if key not in set(keys) or not _scope_applicable(fact, run_scope):
            continue
        stamp = _fact_timestamp(fact)
        previous = latest.get(key)
        if previous is None or (stamp, order) >= (_fact_timestamp(previous), previous.get("_order", -1)):
            latest[key] = {**fact, "_order": order}
    for fact in latest.values():
        for ref in fact.get("evidence_refs", []):
            if isinstance(ref, str) and ref not in status_refs:
                status_refs.append(ref)
    return status_refs
