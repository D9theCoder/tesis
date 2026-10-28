"""Candidate-bound, read-only Access Control controls for the DVWA fixture."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from agents.state_utils import candidate_evidence_payloads, normalize_force_browse_path
from evaluation.scoring_evidence import evidence_hash, validate_sources
from foundation.session_manager import (
    DVWASession,
    open_configured_principal_session,
    open_documented_nonadmin_session,
    open_verified_principal_session,
    session_fingerprint,
)
from foundation.http_client import http_accounted
from foundation.verifier import fixture_attestation_valid


_AC_METHODS = {"ac_idor", "ac_vertical_escalation", "ac_force_browse"}
_USER_METHODS = {"ac_idor", "ac_vertical_escalation"}
_ADMIN_ONLY_POLICY = "This page should only be accessible by the admin user"


def _body_hash(response) -> str:
    return sha256(str(getattr(response, "text", "")).encode()).hexdigest()


def _protocol_source(sources: list[dict]) -> dict | None:
    matches = [source for source in sources if source["document"].get("oracle_protocol", {}).get("kind")
        == "dvwa_candidate_permission.v1" and source["document"]["oracle_protocol"].get("enabled") is True
        and "status" not in source["document"]]
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError("Permission collection requires exactly one enabled protocol")
    return matches[0]


def _request_descriptor(target: str, row: dict, protocol: dict) -> tuple[str, dict, str, str] | None:
    parsed_target, parsed_endpoint = urlparse(target), urlparse(str(row.get("endpoint") or ""))
    if (parsed_endpoint.scheme, parsed_endpoint.hostname, parsed_endpoint.port) != (
        parsed_target.scheme, parsed_target.hostname, parsed_target.port
    ):
        return None
    base_path = parsed_target.path.rstrip("/")
    if base_path and not (parsed_endpoint.path == base_path or parsed_endpoint.path.startswith(base_path + "/")):
        return None
    relative_path = parsed_endpoint.path[len(base_path):] if base_path else parsed_endpoint.path
    if not relative_path.startswith("/"):
        relative_path = "/" + relative_path
    method = row.get("agent_id")
    if method in _USER_METHODS:
        match = re.fullmatch(r"userId\s*=\s*(\d+)", str(row.get("payload") or ""), re.I)
        expected_path = "/vulnerabilities/authbypass/get_user_data.php"
        protected_ids = protocol.get("protected_user_ids", [str(protocol.get("protected_user_id", "1"))])
        if (not isinstance(protected_ids, list) or not all(isinstance(value, str) and value.isdecimal() for value in protected_ids)
                or relative_path != expected_path or parsed_endpoint.query or not match or match.group(1) not in protected_ids):
            return None
        protected_id = match.group(1)
        object_id = f"dvwa-user:{protected_id}"
        if row.get("object_id") != object_id:
            return None
        return relative_path, {"userId": protected_id}, object_id, "read"
    if method == "ac_force_browse":
        protected_paths = protocol.get("protected_paths", [])
        canonical_path = normalize_force_browse_path(relative_path)
        if canonical_path not in protected_paths or parsed_endpoint.query:
            return None
        object_id = row.get("object_id")
        if not isinstance(object_id, str) or not object_id.startswith("dvwa-path:/"):
            return None
        object_path = object_id[len("dvwa-path:"):]
        payload_path = "/" + str(row.get("payload") or "").lstrip("/")
        if (normalize_force_browse_path(object_path) != canonical_path
                or normalize_force_browse_path(payload_path) != canonical_path):
            return None
        return canonical_path, {}, object_id, "read"
    return None


def _resource_visible(method: str, path: str, params: dict, response, protocol: dict) -> bool:
    if response.status_code != 200:
        return False
    body = str(response.text)
    if method in _USER_METHODS:
        try:
            decoded = json.loads(body)
        except (TypeError, ValueError):
            return False
        records = decoded if isinstance(decoded, list) else [decoded] if isinstance(decoded, dict) else []
        requested_id = str(params.get("userId", ""))
        return any(isinstance(record, dict)
            and next((str(record[key]) for key in ("user_id", "userId", "id") if record.get(key) is not None), None) == requested_id
            and (requested_id != "1" or "admin" in " ".join(str(v) for v in record.values()).lower())
            for record in records)
    signal_map = protocol.get("path_signals", {})
    signals = signal_map.get(path, [])
    text = BeautifulSoup(body, "html.parser").get_text(" ", strip=True).lower()
    return bool(signals) and any(str(signal).lower() in text for signal in signals)


def _request(session, method: str, descriptor: tuple[str, dict, str, str], protocol: dict):
    path, params, _, _ = descriptor
    response = session.get(path, params=params) if params else session.get(path)
    return response, _resource_visible(method, path, params, response, protocol)


def _denial_observed(method: str, response) -> bool:
    """Recognize the fixture's explicit read-API denial, never absent markers."""
    if method == "ac_force_browse" and response.status_code == 403:
        return str(response.text).strip().lower() in {"unauthorised", "unauthorized"}
    if method not in _USER_METHODS or response.status_code != 200:
        return False
    try:
        body = json.loads(response.text)
    except (TypeError, ValueError):
        return False
    return isinstance(body, dict) and body.get('result') == 'fail' and str(body.get('error', '')).lower() == 'access denied'


def _candidate_session(target: str, level: str, row: dict, raw_state: dict):
    source_id = row.get("consumed_source_evidence_id")
    if source_id:
        source_rows = {item.get("evidence_id"): item for item in raw_state.get("response_evidence", [])
            if isinstance(item, dict)}
        source = source_rows.get(source_id)
        credential = next((item for item in raw_state.get("found_credentials", [])
            if isinstance(item, dict) and item.get("source_evidence_id") == source_id
            and source and item.get("source_candidate_id") == source.get("candidate_id")
            and item.get("source_visit_id") == source.get("visit_id")
            and item.get("username") and item.get("password")), None)
        if not credential:
            return None
        session, principal, initial = open_verified_principal_session(
            target, credential["username"], credential["password"], level)
        return session, principal, initial
    return open_documented_nonadmin_session(target, level)


def _control_record(name: str, principal: str, expected_principal: str, session,
                    initial: str | None, object_id: str, action: str,
                    expected_allowed: bool, observed_allowed: bool, response) -> dict:
    return {
        "control": name,
        "principal_id": principal,
        "expected_principal_id": expected_principal,
        "session_fingerprint": session_fingerprint(session),
        "initial_session_fingerprint": initial or session_fingerprint(session),
        "object_id": object_id,
        "action": action,
        "status_code": int(response.status_code),
        "response_sha256": _body_hash(response),
        "expected_allowed": expected_allowed,
        "observed_allowed": observed_allowed,
        "expected_confirmed": False,
    }


def _collect_candidate(artifact: dict, raw_state: dict, protocol_source: dict, row: dict) -> dict:
    target = artifact["config"]["target_url"]
    config = artifact["config"]
    protocol_document = protocol_source["document"]
    protocol = protocol_document["oracle_protocol"]
    descriptor = _request_descriptor(target, row, protocol)
    if descriptor is None:
        return {
            "fixture_id": config["fixture_id"], "protocol_version": config["protocol_version"],
            "oracle_protocol": protocol, "protocol_source_sha256": protocol_source["sha256"],
            "policy_evidence": {}, "controls": [], "candidate_replay": {},
            "attestations": [], "status": "pending", "reason": "candidate_resource_outside_frozen_protocol",
        }
    method = row["agent_id"]
    path, params, object_id, action = descriptor
    source_raw = next((item for item in raw_state.get("response_evidence", [])
        if isinstance(item, dict) and item.get("evidence_id") == row.get("evidence_id")), None)
    candidates = raw_state.get("payload_candidates", {}).get(method, [])
    candidate = next((item for item in candidates if isinstance(item, dict)
        and item.get("candidate_id") == row.get("candidate_id")), None)
    valid = any(item.get("candidate_id") == row.get("candidate_id") and item.get("valid") is True
        for item in raw_state.get("payload_validation_results", {}).get(method, []) if isinstance(item, dict))
    if (not candidate or not valid or candidate.get("stage") not in {"exploit", "bypass"}
            or row.get("payload") not in candidate_evidence_payloads(method, candidate.get("payload_or_logic"))
            or not source_raw or any(source_raw.get(key) != row.get(key) for key in (
                "agent_id", "candidate_id", "visit_id", "response_sha256", "object_id", "action"))
            or row.get("status_code") not in (200, 403) or type(row.get("signal_detected")) is not bool
            or not row.get("principal_id") or not row.get("session_fingerprint")
            or not row.get("initial_session_fingerprint") or row.get("object_id") != object_id
            or row.get("action") != action):
        return {
            "fixture_id": config["fixture_id"], "protocol_version": config["protocol_version"],
            "oracle_protocol": protocol, "protocol_source_sha256": protocol_source["sha256"],
            "policy_evidence": {}, "controls": [], "candidate_replay": {},
            "attestations": [], "status": "pending", "reason": "candidate_evidence_binding_incomplete",
        }

    sessions = []
    controls: list[dict] = []
    document = {
        "fixture_id": config["fixture_id"], "protocol_version": config["protocol_version"],
        "oracle_protocol": protocol, "protocol_source_sha256": protocol_source["sha256"],
        "policy_evidence": {}, "admin_principal_id": "admin", "controls": [],
        "candidate_replay": {}, "attestations": [], "status": "pending",
        "scope_outcome": "pending",
    }
    try:
        admin, admin_principal, admin_initial = open_configured_principal_session(target, config.get("security_level"))
        sessions.append(admin)
        policy_response = admin.get("/vulnerabilities/authbypass/")
        policy_text = BeautifulSoup(policy_response.text, "html.parser").get_text(" ", strip=True)
        policy_ok = policy_response.status_code == 200 and _ADMIN_ONLY_POLICY in policy_text
        document["policy_evidence"] = {
            "endpoint": "/vulnerabilities/authbypass/", "status_code": int(policy_response.status_code),
            "response_sha256": _body_hash(policy_response), "admin_only_marker_observed": policy_ok,
        }
        allowed_response, admin_allowed = _request(admin, method, descriptor, protocol)
        controls.append(_control_record("admin_allowed", admin_principal, "admin", admin,
            admin_initial, object_id, action, True, admin_allowed, allowed_response))

        candidate_session, candidate_principal, candidate_initial = _candidate_session(
            target, config.get("security_level", "low"), row, raw_state)
        if candidate_session is None:
            raise ValueError("Candidate source material is not bound to its source evidence")
        sessions.append(candidate_session)
        candidate_response, candidate_allowed = _request(candidate_session, method, descriptor, protocol)
        candidate_denied = _denial_observed(method, candidate_response)
        replay = {
            "run_id": artifact["run_id"], "execution_id": artifact["execution_id"],
            "fixture_id": config["fixture_id"], "protocol_version": config["protocol_version"],
            "method": method, "visit_id": row["visit_id"], "candidate_id": row["candidate_id"],
            "evidence_id": row["evidence_id"], "original_response_sha256": row["response_sha256"],
            "principal_id": candidate_principal, "object_id": object_id, "action": action,
            "payload": row["payload"], "endpoint": row["endpoint"],
            "session_fingerprint": session_fingerprint(candidate_session),
            "initial_session_fingerprint": candidate_initial,
            "status_code": int(candidate_response.status_code),
            "response_sha256": _body_hash(candidate_response),
            "expected_allowed": False, "observed_allowed": candidate_allowed,
            "denial_observed": candidate_denied,
        }
        document["candidate_replay"] = replay

        anonymous = DVWASession(target)
        sessions.append(anonymous)
        anonymous.get("login.php")
        anonymous_initial = session_fingerprint(anonymous)
        anonymous.set_security_level(config.get("security_level", "low"))
        denied_response, anonymous_allowed = _request(anonymous, method, descriptor, protocol)
        controls.append(_control_record("anonymous_denied", "anonymous", "anonymous", anonymous,
            anonymous_initial, object_id, action, False, anonymous_allowed, denied_response))
        scope_outcome = "broad_exposure" if anonymous_allowed else "candidate_specific"
        controls[-1]["expected_confirmed"] = anonymous_allowed
        controls = [{**control, "fixture_id": config["fixture_id"],
            "protocol_version": config["protocol_version"]} for control in controls]
        document["controls"] = controls
        document["scope_outcome"] = scope_outcome
        replay["scope_outcome"] = scope_outcome

        if admin_principal != "admin" or candidate_principal != row["principal_id"] or candidate_principal == "admin":
            document["reason"] = "principal_identity_mismatch_or_privileged_candidate"
            return document
        if not policy_ok:
            document["reason"] = "admin_only_policy_not_observed"
            return document
        if candidate_allowed is not row.get("signal_detected"):
            document["reason"] = "candidate_control_outcome_disagrees"
            return document
        negative = row.get("signal_detected") is False and candidate_denied
        if not admin_allowed or (not candidate_allowed and not negative) or (
            anonymous_allowed and protocol.get("allow_broad_exposure") is not True
        ):
            document["reason"] = "matched_allowed_denied_or_candidate_control_failed"
            return document

        attestation = {
            "kind": "permission", "run_id": artifact["run_id"], "execution_id": artifact["execution_id"],
            "fixture_id": config["fixture_id"], "protocol_version": config["protocol_version"],
            "method": method, "visit_id": row["visit_id"], "candidate_id": row["candidate_id"],
            "evidence_id": row["evidence_id"], "response_sha256": row["response_sha256"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_id": row["principal_id"], "expected_principal_id": row["principal_id"],
            "session_fingerprint": row["session_fingerprint"],
            "initial_session_fingerprint": row["initial_session_fingerprint"],
            "object_id": object_id, "action": action,
            "expected_allowed": False, "observed_allowed": not negative,
            "outcome": "not_confirmed" if negative else "confirmed", "denial_observed": candidate_denied,
            "scope_outcome": scope_outcome,
        }
        field = "negative_attestations" if negative else "attestations"
        document[field] = [attestation]
        if fixture_attestation_valid(attestation, row, document, artifact, outcome=attestation["outcome"]):
            document["status"] = attestation["outcome"]
        else:
            document["reason"] = "attestation_binding_rejected"
        return document
    except Exception as exc:
        document["reason"] = type(exc).__name__
        document["controls"] = controls
        return document
    finally:
        for session in sessions:
            session.close()


@http_accounted(phase="verification", role="independent_control")
def collect_permission_oracles(artifact: dict, raw_state: dict) -> dict:
    """Add read-only, exact-resource authorization controls to a copied artifact."""
    existing_sources = artifact["config"].get("scoring_oracles", [])
    validate_sources(existing_sources)
    protocol_source = _protocol_source(existing_sources)
    if protocol_source is None:
        return artifact
    config = artifact["config"]
    protocol_document = protocol_source["document"]
    protocol = protocol_document["oracle_protocol"]
    if any(not config.get(key) or config[key] != protocol_document.get(key) for key in ("fixture_id", "protocol_version")):
        raise ValueError("Permission protocol coordinate mismatch")
    if protocol_source["origin"] != "operator_fixture" and artifact.get("validation_scope") != "offline_synthetic_fixture":
        raise ValueError("Live permission collection requires an operator fixture protocol")

    result = deepcopy(artifact)
    rows = result["final_state"].get("response_evidence", [])
    for row in rows:
        if not isinstance(row, dict) or row.get("agent_id") not in _AC_METHODS or row.get("stage") not in {"exploit", "bypass"}:
            continue
        source_id = f"{protocol_source['source_id']}:{row.get('agent_id')}:{row.get('evidence_id')}"
        if any(source.get("source_id") == source_id for source in result["config"].get("scoring_oracles", [])):
            continue
        document = _collect_candidate(artifact, raw_state, protocol_source, row)
        source = {"source_id": source_id, "origin": protocol_source["origin"],
            "document": document, "sha256": evidence_hash(document)}
        validate_sources([source])
        source_index = len(result["config"]["scoring_oracles"])
        result["config"]["scoring_oracles"].append(source)
        if document.get("status") == "confirmed" and len(document.get("attestations", [])) == 1:
            attestation = document["attestations"][0]
            if fixture_attestation_valid(attestation, row, document, result):
                row["oracle_ref"] = f"#/config/scoring_oracles/{source_index}/document/attestations/0"
    return result
