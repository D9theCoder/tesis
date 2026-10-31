"""Independent positive/negative controls for candidate-bound chain consumption."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256

from agents.brute_force.bf_dictionary_agent import _parse_credential
from evaluation.permission_oracle import _request, _request_descriptor
from evaluation.scoring_evidence import (
    candidate_base,
    evidence_hash,
    oracle_confirmed,
    validate_sources,
)
from foundation.session_manager import DVWASession, open_verified_principal_session, session_fingerprint
from foundation.http_client import http_accounted


def _enabled_source(sources: list[dict], kind: str) -> dict | None:
    matches = [source for source in sources if source["document"].get("oracle_protocol", {}).get("kind") == kind
        and source["document"]["oracle_protocol"].get("enabled") is True
        and "status" not in source["document"]]
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError(f"Causal collection requires exactly one enabled {kind} protocol")
    return matches[0]


def _candidate(state: dict, method: str, candidate_id: str):
    return next((candidate for candidate in state.get("payload_candidates", {}).get(method, [])
        if isinstance(candidate, dict) and candidate.get("candidate_id") == candidate_id), None)


def _validated(state: dict, method: str, candidate_id: str) -> bool:
    return any(isinstance(item, dict) and item.get("candidate_id") == candidate_id and item.get("valid") is True
        for item in state.get("payload_validation_results", {}).get(method, []))


def _material(candidate: dict, raw_state: dict, source: dict) -> tuple[str, str] | None:
    pair = _parse_credential(candidate.get("payload_or_logic", ""))
    if not all(pair):
        return None
    credential = next((item for item in raw_state.get("found_credentials", [])
        if isinstance(item, dict) and item.get("source_evidence_id") == source.get("evidence_id")
        and item.get("source_candidate_id") == source.get("candidate_id")
        and item.get("source_visit_id") == source.get("visit_id")
        and item.get("representation", "plaintext") == "plaintext"
        and item.get("username") and item.get("password")
        and (item["username"], item["password"]) == pair), None)
    if not credential:
        return None
    return credential["username"], credential["password"]


CONTROL_POSITIVE = "candidate_material_positive"
CONTROL_NEGATIVE = "wrong_credential_negative"


def _control_error(exc: Exception, *secrets: str) -> str:
    """Return the exception message with credential material removed."""
    message = str(exc)
    for secret in secrets:
        if secret:
            message = message.replace(str(secret), "<redacted>")
    return message[:500]


def _dependency_control(target: str, level: str, method: str, descriptor: tuple | None,
                        username: str, password: str, expected_available: bool,
                        protocol: dict, control: str) -> dict:
    """Run one dependency control, returning an auditable failure row on error.

    ``bf_*`` destinations are confirmed by login identity alone, so they never
    set a DVWA security level; Access Control destinations still do because the
    frozen request protocol is level-scoped.
    """
    session = None
    stage = "open_session"
    identity_only = method.startswith("bf_")
    try:
        if expected_available:
            session, principal, initial = open_verified_principal_session(
                target, username, password, None if identity_only else level)
            login_valid = principal == username
        else:
            session = DVWASession(target)
            stage = "initial_visit"
            session.get("login.php")
            initial = session_fingerprint(session)
            stage = "login"
            login_valid = session.login(username, "tesis-oracle-invalid-credential")
            principal = username if login_valid else "anonymous"
            if not identity_only:
                stage = "security_level"
                session.set_security_level(level)
        if identity_only:
            from evaluation.session_oracle import _identity
            stage = "identity_check"
            response = session.get("index.php")
            destination_confirmed = bool(login_valid and _identity(response) == username)
        else:
            stage = "destination_request"
            response, destination_confirmed = _request(session, method, descriptor, protocol)
        stage = "observation"
        source_available = bool(login_valid)
        return {
            "control": control,
            "source_available": source_available,
            "destination_confirmed": destination_confirmed,
            "principal_id": principal if login_valid else "anonymous",
            "session_fingerprint": session_fingerprint(session),
            "initial_session_fingerprint": initial,
            "status_code": int(response.status_code),
            "response_sha256": sha256(str(response.text).encode()).hexdigest(),
            "expected_source_available": expected_available,
            "expected_destination_confirmed": expected_available,
        }
    except Exception as exc:
        return {
            "control": control,
            "stage": stage,
            "failure": type(exc).__name__,
            "error": _control_error(exc, username, password),
            "source_available": False,
            "destination_confirmed": False,
        }
    finally:
        if session is not None:
            session.close()


@http_accounted(phase="verification", role="independent_control")
def collect_dependency_oracles(artifact: dict, raw_state: dict) -> dict:
    """Attach a dependency attestation only when the exact source material works downstream."""
    sources = artifact["config"].get("scoring_oracles", [])
    validate_sources(sources)
    protocol_source = _enabled_source(sources, "dvwa_causal_dependency.v1")
    permission_source = _enabled_source(sources, "dvwa_candidate_permission.v1")
    if protocol_source is None:
        return artifact
    config = artifact["config"]
    document_source = protocol_source["document"]
    protocol = document_source["oracle_protocol"]
    if any(not config.get(key) or config[key] != document_source.get(key) for key in ("fixture_id", "protocol_version")):
        raise ValueError("Dependency protocol coordinate mismatch")
    if protocol_source["origin"] != "operator_fixture" and artifact.get("validation_scope") != "offline_synthetic_fixture":
        raise ValueError("Live dependency collection requires an operator fixture protocol")
    if permission_source is not None:
        permission_document = permission_source["document"]
        if any(config[key] != permission_document.get(key) for key in ("fixture_id", "protocol_version")):
            raise ValueError("Dependency permission protocol coordinate mismatch")
        if permission_source["origin"] != "operator_fixture" and artifact.get("validation_scope") != "offline_synthetic_fixture":
            raise ValueError("Live dependency collection requires an operator permission protocol")

    from evaluation.thesis_scoring import _resolve

    result = deepcopy(artifact)
    raw_method_state = raw_state
    pending_sources = []
    existing_ids = {source["source_id"] for source in sources}
    existing_indices = {source["source_id"]: i for i, source in enumerate(sources)}
    for route in result["final_state"].get("chain_history", []):
        if route.get("status") != "completed":
            continue
        source_refs, destination_refs = route.get("source_evidence_refs", []), route.get("destination_evidence_refs", [])
        source_rows = [_resolve(result, ref) for ref in source_refs]
        destination_rows = [_resolve(result, ref) for ref in destination_refs]
        for consumption in route.get("consumption", []):
            source_id = f"{protocol_source['source_id']}:{route['route_id']}:{consumption.get('source_evidence_id')}:{consumption.get('destination_evidence_id')}"
            if source_id in existing_ids:
                index = existing_indices.get(source_id)
                if index is not None:
                    saved = result["config"]["scoring_oracles"][index]["document"]
                    if saved.get("status") == "confirmed" and len(saved.get("dependencies", [])) == 1:
                        consumption["dependency_ref"] = f"#/config/scoring_oracles/{index}/document/dependencies/0"
                continue
            document = {
                "fixture_id": config["fixture_id"], "protocol_version": config["protocol_version"],
                "oracle_protocol": protocol, "protocol_source_sha256": protocol_source["sha256"],
                "route_id": route["route_id"], "source_evidence_id": consumption.get("source_evidence_id"),
                "destination_evidence_id": consumption.get("destination_evidence_id"),
                "dependencies": [], "dependency_controls": [], "status": "pending",
                "reason": "candidate_evidence_binding_incomplete",
            }
            pending_sources.append((source_id, document, consumption))
            existing_ids.add(source_id)
            source = next((row for row in source_rows if isinstance(row, dict)
                and row.get("evidence_id") == consumption.get("source_evidence_id")), None)
            destination = next((row for row in destination_rows if isinstance(row, dict)
                and row.get("evidence_id") == consumption.get("destination_evidence_id")), None)
            if not source or not destination:
                continue
            session_route = (source.get("agent_id") in {"bf_dictionary", "bf_spray"}
                and destination.get("agent_id") in {"ac_idor", "ac_force_browse"})
            credential_route = (source.get("agent_id") == "sqli_union"
                and destination.get("agent_id") == "bf_dictionary")
            if not (session_route or credential_route):
                document["reason"] = "source_consumption_adapter_unavailable"
                continue
            if session_route and permission_source is None:
                document["reason"] = "permission_protocol_unavailable"
                continue
            if (destination.get("consumed_source_evidence_id") != source.get("evidence_id")
                    or not oracle_confirmed(result, destination)
                    or candidate_base(result, source.get("candidate_id"), source.get("agent_id"), source_refs) != 3
                    or candidate_base(result, destination.get("candidate_id"), destination.get("agent_id"), destination_refs) != 3):
                document["reason"] = "independent_candidate_outcome_unavailable"
                continue
            source_candidate = _candidate(raw_method_state, source["agent_id"], source["candidate_id"])
            destination_candidate = _candidate(raw_method_state, destination["agent_id"], destination["candidate_id"])
            if (not source_candidate or not destination_candidate or not _validated(raw_method_state, source["agent_id"], source["candidate_id"])
                    or not _validated(raw_method_state, destination["agent_id"], destination["candidate_id"])):
                continue
            material = _material(destination_candidate if credential_route else source_candidate, raw_method_state, source)
            if not material:
                document["reason"] = "plaintext_source_credentials_unavailable"
                continue
            username, password = material
            permission_protocol = permission_source["document"]["oracle_protocol"] if permission_source else {}
            descriptor = _request_descriptor(config["target_url"], destination, permission_protocol) if session_route else None
            if session_route and descriptor is None:
                document["reason"] = "candidate_resource_outside_frozen_protocol"
                continue
            if any(consumption.get(key) != value for key, value in {
                "route_id": route.get("route_id"), "visit_id": destination.get("visit_id"),
                "source_candidate_id": source.get("candidate_id"), "source_visit_id": source.get("visit_id"),
                "candidate_id": destination.get("candidate_id"), "source_evidence_id": source.get("evidence_id"),
                "destination_evidence_id": destination.get("evidence_id"),
            }.items()):
                continue

            controls = [
                _dependency_control(config["target_url"], config.get("security_level", "low"),
                    destination["agent_id"], descriptor, username, password, True,
                    permission_protocol, CONTROL_POSITIVE),
                _dependency_control(config["target_url"], config.get("security_level", "low"),
                    destination["agent_id"], descriptor, username, password, False,
                    permission_protocol, CONTROL_NEGATIVE),
            ]
            document["dependency_controls"] = controls
            controls_clean = len(controls) == 2 and not any(item.get("failure") for item in controls)
            if not (controls_clean and controls[0].get("source_available") is True
                    and controls[0].get("destination_confirmed") is True
                    and controls[1].get("source_available") is False
                    and controls[1].get("destination_confirmed") is False):
                document["reason"] = "dependency_controls_not_confirmed"
                if controls_clean and controls[1].get("source_available") is False and controls[1].get("destination_confirmed") is True:
                    document.update(status="not_dependent", reason="destination_available_without_source")
                continue
            attestation = {
                "run_id": result["run_id"], "execution_id": result["execution_id"],
                "fixture_id": config["fixture_id"], "protocol_version": config["protocol_version"],
                "route_id": route["route_id"], "source_candidate_id": source["candidate_id"],
                "source_visit_id": source["visit_id"], "candidate_id": destination["candidate_id"],
                "visit_id": destination["visit_id"], "source_evidence_id": source["evidence_id"],
                "destination_evidence_id": destination["evidence_id"],
                "source_response_sha256": source["response_sha256"],
                "destination_response_sha256": destination["response_sha256"],
                "source_at": source["timestamp"], "consumed_at": destination["timestamp"],
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "material_fingerprint": sha256(f"{username}\0{password}".encode()).hexdigest(),
                "depends_on_source": True, "controls": [
                    {"control": item.get("control"),
                     "source_available": item["source_available"],
                     "destination_confirmed": item["destination_confirmed"],
                     "response_sha256": item["response_sha256"], "status_code": item["status_code"]}
                    for item in controls],
            }
            document.update(dependencies=[attestation], status="confirmed")
            document.pop("reason", None)
    for source_id, document, consumption in pending_sources:
        oracle_source = {"source_id": source_id, "origin": protocol_source["origin"],
            "document": document, "sha256": evidence_hash(document)}
        validate_sources([oracle_source])
        index = len(result["config"]["scoring_oracles"])
        result["config"]["scoring_oracles"].append(oracle_source)
        if document["status"] == "confirmed":
            consumption["dependency_ref"] = f"#/config/scoring_oracles/{index}/document/dependencies/0"
    return result
