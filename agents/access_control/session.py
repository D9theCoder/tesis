"""Contained principal selection for Access Control method visits."""
from __future__ import annotations

from foundation.session_manager import (
    open_documented_nonadmin_session,
    open_verified_principal_session,
    session_fingerprint,
)


def open_access_control_session(state: dict, method: str, security_level: str):
    """Use a route-bound source identity or the fixture's documented non-admin."""
    target = str(state.get("target_url") or "")
    route = state.get("active_chain_route") or {}
    if route.get("target_agent") == method and route.get("source") == "authenticated_session":
        source_ids = set(route.get("source_evidence_ids", []))
        source_rows = {row.get("evidence_id"): row for row in state.get("response_evidence", [])
            if isinstance(row, dict) and row.get("agent_id", "").startswith("bf_")}
        bound = [credential for credential in state.get("found_credentials", [])
            if isinstance(credential, dict)
            and credential.get("source_evidence_id") in source_ids
            and credential.get("source_candidate_id")
            and source_rows.get(credential.get("source_evidence_id"), {}).get("candidate_id") == credential.get("source_candidate_id")
            and credential.get("username") and credential["username"].lower() != "admin"
            and credential.get("password")
            and source_rows.get(credential.get("source_evidence_id"), {}).get("visit_id") == credential.get("source_visit_id")]
        if not bound:
            raise ValueError("No route-bound authenticated-session material is available")
        credential = bound[0]
        session, principal, initial = open_verified_principal_session(
            target, credential["username"], credential["password"], security_level)
        if not credential.get("source_evidence_id"):
            session.close()
            raise ValueError("Route credential has no source evidence binding")
        return session, principal, initial, credential["source_evidence_id"]

    session, principal, initial = open_documented_nonadmin_session(target, security_level)
    return session, principal, initial, None


def permission_evidence_fields(session, principal: str, initial: str, *, object_id: str,
                               action: str = "read", consumed_source_evidence_id: str | None = None) -> dict:
    """Return safe identity and object bindings for a candidate response event."""
    result = {
        "principal_id": principal,
        "session_fingerprint": session_fingerprint(session),
        "initial_session_fingerprint": initial,
        "object_id": object_id,
        "action": action,
    }
    if consumed_source_evidence_id:
        result["consumed_source_evidence_id"] = consumed_source_evidence_id
    return result


def user_object_id(user_id: str) -> str:
    return f"dvwa-user:{str(user_id).strip()}"
