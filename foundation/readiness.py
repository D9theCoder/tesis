"""Requested versus observed run readiness with a fail-closed decision.

A run is ready only when authentication, the requested security level, every
required endpoint, and any required form token are observed rather than
assumed.  A failed or unknown required component blocks method selection and
candidate execution; the requested coordinate is preserved instead of being
relabeled as a different level.  Environment failures are never model failures.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any, Iterable, Mapping

from core.state import METHODS_BY_SURFACE

READINESS_POLICY_VERSION = "readiness.v1"
READINESS_STATUSES = ("ready", "failed", "unknown")
BLOCKING_SEVERITY = "blocking"
ADVISORY_SEVERITY = "advisory"

REASON_AUTHENTICATION_FAILED = "authentication_failed"
REASON_AUTHENTICATION_UNVERIFIED = "authentication_unverified"
REASON_LEVEL_MISMATCH = "security_level_mismatch"
REASON_LEVEL_UNVERIFIED = "security_level_unverified"
REASON_ENDPOINT_MISSING = "required_endpoint_missing"
REASON_ENDPOINT_UNVERIFIED = "required_endpoint_unverified"
REASON_TOKEN_MISSING = "required_token_missing"
REASON_TOKEN_UNVERIFIED = "required_token_unverified"
REASON_FIXTURE_UNCONFIGURED = "fixture_identity_unconfigured"
REASON_FIXTURE_MISMATCH = "fixture_identity_mismatch"
REASON_PROTOCOL_MISMATCH = "protocol_version_mismatch"
REASON_RESTORATION_UNKNOWN = "fixture_restoration_unverified"
REASON_RESTORATION_INVALID = "fixture_restoration_invalid"
REASON_RESTORATION_SCOPE_MISMATCH = "fixture_restoration_scope_mismatch"
REASON_READINESS_MISSING = "readiness_missing"

FIXTURE_RESTORATION_POLICY_VERSION = "fixture-restoration.v1"
FIXTURE_RESTORATION_KEYS = frozenset({
    "policy_version", "evidence_id", "kind", "fixture_id", "protocol_version",
    "security_level", "epoch_id", "source_hashes_sha256", "restoration",
    "authorized_protocol", "evidence_refs", "evidence_sha256", "observed_at",
    "operator", "details",
})
FIXTURE_RESTORATION_KINDS = frozenset({"reset", "isolated_equivalent"})


def validate_fixture_restoration_evidence(
    evidence: Mapping[str, Any] | None,
    *,
    fixture_id: str | None,
    protocol_version: str | None,
    security_level: str | None,
    epoch_id: str | None = None,
    source_hashes_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate a source-bound operator fixture-restoration attestation.

    The evidence is an external authorized input; it is never inferred from
    HTTP serialization, setup pages, or a run label. Mismatched scope raises
    ``ValueError`` and callers must record the missing prerequisite.
    """
    if not isinstance(evidence, Mapping):
        raise ValueError("fixture restoration evidence must be a mapping")
    unknown = sorted(set(evidence) - FIXTURE_RESTORATION_KEYS)
    if unknown:
        raise ValueError(f"fixture restoration evidence has unknown keys: {unknown}")
    if evidence.get("policy_version") != FIXTURE_RESTORATION_POLICY_VERSION:
        raise ValueError("unsupported fixture restoration policy version")
    if evidence.get("kind") != "operator_attestation":
        raise ValueError("fixture restoration evidence must be an operator attestation")
    for field in ("evidence_id", "fixture_id", "protocol_version", "security_level",
                  "epoch_id", "authorized_protocol", "evidence_sha256", "operator"):
        value = evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"fixture restoration evidence requires nonempty {field}")
    if evidence.get("restoration") not in FIXTURE_RESTORATION_KINDS:
        raise ValueError("fixture restoration must be reset or isolated_equivalent")
    refs = evidence.get("evidence_refs")
    if not isinstance(refs, list) or not refs or any(
            not isinstance(ref, str) or not ref.strip() for ref in refs):
        raise ValueError("fixture restoration evidence requires nonempty evidence_refs")
    digest = str(evidence.get("evidence_sha256") or "")
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
        raise ValueError("fixture restoration evidence_sha256 must be a hex digest")
    hashes = evidence.get("source_hashes_sha256")
    if not isinstance(hashes, str) or len(hashes) != 64:
        raise ValueError("fixture restoration requires source_hashes_sha256")
    try:
        observed = datetime.fromisoformat(str(evidence.get("observed_at")))
    except (TypeError, ValueError) as exc:
        raise ValueError("fixture restoration observed_at must be an ISO timestamp") from exc
    if observed.tzinfo is None:
        raise ValueError("fixture restoration observed_at requires a timezone")
    expected = {
        "fixture_id": fixture_id,
        "protocol_version": protocol_version,
        "security_level": security_level,
    }
    for key, value in expected.items():
        if value not in (None, "") and str(evidence.get(key)) != str(value):
            raise ValueError(f"fixture restoration {key} does not match the current run")
    if epoch_id not in (None, "") and str(evidence["epoch_id"]) != str(epoch_id):
        raise ValueError("fixture restoration epoch does not match the current run")
    if source_hashes_sha256 not in (None, "") and str(hashes) != str(source_hashes_sha256):
        raise ValueError("fixture restoration source hashes do not match the current run")
    return dict(evidence)


FIXTURE_RESTORATION_PROVENANCE_KEYS = frozenset({"identity_sha256", "source_path", "sha256"})
FIXTURE_RESTORATION_LEVELS = ("low", "medium", "high")


def canonical_fixture_restoration_document(
    evidence: Mapping[str, Any] | None,
    *,
    allow_provenance: bool = True,
) -> dict[str, Any]:
    """Project one attestation onto the exact validated schema.

    Plan/freeze metadata (identity/source hashes and paths) is provenance, not
    scientific input. Known provenance keys are removed only when explicitly
    allowed; any other unknown key is rejected rather than silently stripped.
    """
    if not isinstance(evidence, Mapping):
        raise ValueError("fixture restoration evidence must be a mapping")
    allowed = set(FIXTURE_RESTORATION_KEYS)
    if allow_provenance:
        allowed.update(FIXTURE_RESTORATION_PROVENANCE_KEYS)
    unknown = sorted(set(evidence) - allowed)
    if unknown:
        raise ValueError(f"fixture restoration evidence has unknown keys: {unknown}")
    return {key: evidence[key] for key in FIXTURE_RESTORATION_KEYS if key in evidence}


def fixture_restoration_documents(evidence: Any) -> list[dict[str, Any]]:
    """Return canonical documents from a single document, list, or level map.

    Envelopes may be ``{"by_level": {level: doc}}`` or a mapping keyed directly
    by security level. Provenance metadata is removed; arbitrary keys are not.
    """
    if evidence in (None, {}, []):
        return []
    documents: list[Any] = []
    if isinstance(evidence, Mapping) and "policy_version" in evidence:
        documents = [evidence]
    elif isinstance(evidence, (list, tuple)):
        documents = list(evidence)
    elif isinstance(evidence, Mapping):
        by_level = evidence.get("by_level") if isinstance(evidence.get("by_level"), Mapping) else evidence
        if not isinstance(by_level, Mapping):
            raise ValueError("fixture restoration envelope must map security levels to documents")
        documents = list(by_level.values())
    else:
        raise ValueError("fixture restoration evidence must be a document, list, or level mapping")
    canonical: list[dict[str, Any]] = []
    for document in documents:
        canonical_document = canonical_fixture_restoration_document(document)
        level = str(canonical_document.get("security_level") or "")
        if level not in FIXTURE_RESTORATION_LEVELS:
            raise ValueError("fixture restoration document requires a known security_level")
        canonical.append(canonical_document)
    return canonical


def fixture_restoration_refs(
    evidence: Mapping[str, Any] | None,
    state: Mapping[str, Any],
) -> list[str]:
    """Return attestation refs only when the evidence matches current scope."""
    if not isinstance(evidence, Mapping):
        return []
    epoch = state.get("policy_epoch") if isinstance(state.get("policy_epoch"), Mapping) else {}
    try:
        validated = validate_fixture_restoration_evidence(
            evidence,
            fixture_id=state.get("fixture_id"),
            protocol_version=state.get("protocol_version"),
            security_level=state.get("security_level"),
            epoch_id=epoch.get("epoch_id"),
            source_hashes_sha256=epoch.get("source_hashes_sha256"),
        )
    except ValueError:
        return []
    return list(validated["evidence_refs"])
REASON_CRAWL_INCOMPLETE = "crawl_incomplete"


def _reason(code: str, detail: str, *, severity: str = BLOCKING_SEVERITY,
            evidence_refs: Iterable[str] | None = None) -> dict[str, Any]:
    return {"code": code, "detail": detail, "severity": severity,
            "evidence_refs": list(dict.fromkeys(str(ref) for ref in (evidence_refs or []) if ref))}


_SURFACE_ENDPOINT_FRAGMENTS: dict[str, list[str]] = {
    "sqli": ["/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/"],
    "access_control": ["/vulnerabilities/authbypass/"],
    "brute_force": ["/vulnerabilities/brute/"],
}


def required_endpoints_for_surface(surface: str) -> list[str]:
    """Return the crawl-observable module pages required for one surface.

    Method handlers such as ``get_user_data.php`` are invoked by the page and
    are not required to appear as crawlable form actions.
    """
    if str(surface or "") not in METHODS_BY_SURFACE:
        return []
    return list(_SURFACE_ENDPOINT_FRAGMENTS.get(str(surface), []))


def observed_endpoint_fragments(endpoints: Iterable[Mapping[str, Any]]) -> list[str]:
    """Return a stable list of observed endpoint URL paths."""
    paths: list[str] = []
    for endpoint in endpoints or []:
        url = str(endpoint.get("url") or "")
        path = url.split("?", 1)[0].split("#", 1)[0]
        if path and path not in paths:
            paths.append(path)
    return paths


def _token_required(surface: str, requested_level: str) -> bool:
    return surface == "brute_force" and requested_level in {"medium", "high"}


def build_readiness(
    *,
    state: Mapping[str, Any],
    login_ok: bool | None,
    requested_level: str,
    observed_level: str | None,
    endpoints: Iterable[Mapping[str, Any]],
    requested_principal: str | None,
    observed_principal: str | None,
    token_present: bool | None,
    setup_state: str,
    fixture_restoration_evidence: Mapping[str, Any] | Iterable[str] | None = None,
    measured_session_fingerprint: str | None = None,
    crawl_ok: bool | None = True,
) -> dict[str, Any]:
    """Assess one run's readiness from observed evidence only."""
    surface = str(state.get("current_surface") or "sqli")
    required = required_endpoints_for_surface(surface)
    observed_paths = observed_endpoint_fragments(endpoints)
    missing = [fragment for fragment in required
               if not any(fragment in path for path in observed_paths)]
    reasons: list[dict[str, Any]] = []
    authentication = {
        "requested_principal": requested_principal,
        "observed_principal": observed_principal,
        "login_ok": login_ok,
        "identity_verified": bool(login_ok and requested_principal and observed_principal
                                  and str(requested_principal) == str(observed_principal)),
        "evidence_refs": ["session:login"] if login_ok is not None else [],
    }
    if login_ok is False:
        reasons.append(_reason(REASON_AUTHENTICATION_FAILED,
                               "Fixture login did not establish an authenticated session.",
                               evidence_refs=["session:login"]))
    elif login_ok is None:
        reasons.append(_reason(REASON_AUTHENTICATION_UNVERIFIED,
                               "No measured authentication result is available."))
    elif not authentication["identity_verified"]:
        reasons.append(_reason(REASON_AUTHENTICATION_UNVERIFIED,
                               "The observed authenticated principal could not be verified against the requested principal.",
                               evidence_refs=["session:login", "session:identity"]))

    if observed_level is None:
        reasons.append(_reason(REASON_LEVEL_UNVERIFIED,
                               "The server-side security level could not be observed.",
                               evidence_refs=["session:security.php"]))
    elif str(observed_level) != str(requested_level):
        reasons.append(_reason(REASON_LEVEL_MISMATCH,
                               f"Requested level {requested_level!r} observed as {observed_level!r}.",
                               evidence_refs=["session:security.php"]))
    if missing and crawl_ok is not False:
        reasons.append(_reason(REASON_ENDPOINT_MISSING,
                               "Required surface endpoints were not observed: " + ", ".join(missing),
                               evidence_refs=[f"endpoint:{fragment}" for fragment in missing]))
    elif missing:
        reasons.append(_reason(REASON_ENDPOINT_UNVERIFIED,
                               "Required endpoints could not be verified because the crawl was incomplete.",
                               evidence_refs=[f"endpoint:{fragment}" for fragment in missing]))
    token_required = _token_required(surface, requested_level)
    token: dict[str, Any] = {"required": token_required, "present": token_present,
             "evidence_refs": ["endpoint:/vulnerabilities/brute/"] if token_present is not None else []}
    if token_required and token_present is False:
        reasons.append(_reason(REASON_TOKEN_MISSING,
                               "The brute-force form token required at this level was not observed.",
                               evidence_refs=token["evidence_refs"]))
    elif token_required and token_present is None:
        reasons.append(_reason(REASON_TOKEN_UNVERIFIED,
                               "The required brute-force form token could not be verified."))
    fixture = {
        "fixture_id": state.get("fixture_id"),
        "protocol_version": state.get("protocol_version"),
        "configured": bool(state.get("fixture_id") and state.get("protocol_version")),
        "equivalence": "configured" if state.get("fixture_id") and state.get("protocol_version") else "unavailable",
    }
    if not fixture["configured"]:
        reasons.append(_reason(REASON_FIXTURE_UNCONFIGURED,
                               "No fixture/protocol identity is pinned for this run; final comparable-scope scoring stays pending.",
                               severity=ADVISORY_SEVERITY))
    restoration_refs: list[str] = []
    restoration_reason = REASON_RESTORATION_UNKNOWN
    restoration_detail = (
        "No validated operator fixture-restoration or isolated-equivalent attestation is recorded."
    )
    if isinstance(fixture_restoration_evidence, Mapping):
        epoch = state.get("policy_epoch") if isinstance(state.get("policy_epoch"), Mapping) else {}
        try:
            validated = validate_fixture_restoration_evidence(
                fixture_restoration_evidence,
                fixture_id=state.get("fixture_id"),
                protocol_version=state.get("protocol_version"),
                security_level=state.get("security_level"),
                epoch_id=epoch.get("epoch_id"),
                source_hashes_sha256=epoch.get("source_hashes_sha256"),
            )
            restoration_refs = list(validated["evidence_refs"])
            restoration_reason = ""
            restoration_detail = ""
        except ValueError as exc:
            restoration_reason = (
                REASON_RESTORATION_SCOPE_MISMATCH
                if "does not match" in str(exc) or "epoch" in str(exc)
                else REASON_RESTORATION_INVALID
            )
            restoration_detail = str(exc)
    elif fixture_restoration_evidence:
        restoration_reason = REASON_RESTORATION_INVALID
        restoration_detail = "Unvalidated restoration evidence refs are not accepted as an attestation."
    fixture_restoration = {
        "equivalence": "attested" if restoration_refs else "unknown",
        "evidence_refs": restoration_refs,
        "reason": restoration_reason or None,
    }
    if not restoration_refs:
        reasons.append(_reason(restoration_reason, restoration_detail,
                               severity=ADVISORY_SEVERITY))
    if crawl_ok is False:
        reasons.append(_reason(REASON_CRAWL_INCOMPLETE,
                               "The reconnaissance crawl did not complete; missing endpoints stay unverified."))
    blocking = any(reason["severity"] == BLOCKING_SEVERITY for reason in reasons)
    status = "failed" if blocking else "unknown" if not login_ok or observed_level is None else "ready"
    return {
        "policy_version": READINESS_POLICY_VERSION,
        "status": status,
        "requested_level": requested_level,
        "observed_level": observed_level,
        "authentication": authentication,
        "endpoints": {
            "required": required,
            "observed": observed_paths,
            "missing": missing,
            "evidence_refs": [f"endpoint:{path}" for path in observed_paths],
        },
        "token": token,
        "fixture": fixture,
        "fixture_restoration": fixture_restoration,
        "session": {
            "principal": observed_principal,
            "fingerprint": measured_session_fingerprint or (
                state.get("readiness", {}).get("session", {}).get("fingerprint")
                if isinstance(state.get("readiness"), Mapping) else None),
        },
        "setup_state": str(setup_state),
        "reasons": reasons,
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }


def readiness_gate(state_or_receipt: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a fail-closed decision for one readiness receipt."""
    receipt = state_or_receipt
    if isinstance(receipt, Mapping) and "readiness" in receipt:
        receipt = receipt.get("readiness")
    if not isinstance(receipt, Mapping):
        # Every supported execution path must supply an observed readiness
        # receipt. Historical artifact reads do not execute a run.
        return {"decision": "block", "status": "unknown",
                "code": REASON_READINESS_MISSING,
                "detail": "No observed readiness receipt was recorded for this run.",
                "evidence_refs": []}
    status = str(receipt.get("status") or "unknown")
    reasons = [reason for reason in receipt.get("reasons", []) if isinstance(reason, Mapping)]
    blocking = [reason for reason in reasons if reason.get("severity") == BLOCKING_SEVERITY]
    if status == "ready" and not blocking:
        return {"decision": "allow", "status": status, "code": "ready", "detail": "", "evidence_refs": []}
    first = (blocking or reasons or [{}])[0]
    return {
        "decision": "block",
        "status": status,
        "code": str(first.get("code") or f"readiness_{status}"),
        "detail": str(first.get("detail") or ""),
        "evidence_refs": list(first.get("evidence_refs") or []),
    }


def readiness_reason_code(gate: Mapping[str, Any]) -> str:
    """Return the canonical StatusReasonCode for a blocked readiness gate."""
    return "READINESS_FAILED" if gate.get("status") == "failed" else "READINESS_UNKNOWN"


def readiness_block_update(gate: Mapping[str, Any]) -> dict[str, Any]:
    """Build a terminal state update for a blocked readiness gate."""
    if gate.get("decision") != "block":
        return {}
    from core.run_status import reason
    code = readiness_reason_code(gate)
    return {
        "next_agent": "scorer",
        "selected_method": None,
        "task_result": "INCOMPLETE",
        "incomplete_reason": code,
        "workflow_stop_reason": str(gate.get("code") or "readiness_not_ready"),
        "execution_status": "failed",
        "execution_reason": reason(code, str(gate.get("detail") or ""), list(gate.get("evidence_refs") or [])),
        "security_outcome": "fixture_limited",
        "security_outcome_reason": reason(code, str(gate.get("detail") or ""),
                                          list(gate.get("evidence_refs") or [])),
    }
