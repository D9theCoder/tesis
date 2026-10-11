"""Independent positive/negative controls for candidate-bound chain consumption."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256

from evaluation.permission_oracle import _request, _request_descriptor
from evaluation.scoring_evidence import (
    candidate_base,
    evidence_hash,
    oracle_confirmed,
    validate_sources,
)
from foundation.session_manager import DVWASession, open_verified_principal_session, session_fingerprint


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
    value = str(candidate.get("payload_or_logic") or "")
    if ":" not in value:
        return None
    username, password = value.split(":", 1)
    credential = next((item for item in raw_state.get("found_credentials", [])
        if isinstance(item, dict) and item.get("source_evidence_id") == source.get("evidence_id")
        and item.get("source_candidate_id") == source.get("candidate_id")
        and item.get("source_visit_id") == source.get("visit_id")
        and item.get("username") == username and item.get("password") == password), None)
    if not credential:
        return None
    return username, password


def _dependency_control(target: str, level: str, method: str, descriptor: tuple,
                        username: str, password: str, expected_available: bool,
                        protocol: dict) -> dict:
    session = None
    try:
        if expected_available:
            session, principal, initial = open_verified_principal_session(target, username, password, level)
            login_valid = principal == username
        else:
            session = DVWASession(target)
            session.get("login.php")
            initial = session_fingerprint(session)
            login_valid = session.login(username, "tesis-oracle-invalid-credential")
            principal = username if login_valid else "anonymous"
        response, destination_confirmed = _request(session, method, descriptor, protocol)
        source_available = bool(login_valid)
        return {
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
    finally:
        if session is not None:
            session.close()


def collect_dependency_oracles(artifact: dict, raw_state: dict) -> dict:
    """Attach a dependency attestation only when the exact source material works downstream."""
    sources = artifact["config"].get("scoring_oracles", [])
    validate_sources(sources)
    protocol_source = _enabled_source(sources, "dvwa_causal_dependency.v1")
    permission_source = _enabled_source(sources, "dvwa_candidate_permission.v1")
    if protocol_source is None or permission_source is None:
        return artifact
    config = artifact["config"]
    document_source = protocol_source["document"]
    protocol = document_source["oracle_protocol"]
    if any(config.get(key) != document_source.get(key) for key in ("fixture_id", "protocol_version")):
        raise ValueError("Dependency protocol coordinate mismatch")
    if protocol_source["origin"] != "operator_fixture" and artifact.get("validation_scope") != "offline_synthetic_fixture":
        raise ValueError("Live dependency collection requires an operator fixture protocol")

    from evaluation.thesis_scoring import _resolve

    result = deepcopy(artifact)
    response_rows = result["final_state"].get("response_evidence", [])
    raw_method_state = raw_state
    now = datetime.now(timezone.utc).isoformat()
    for route in result["final_state"].get("chain_history", []):
        if route.get("status") != "completed":
            continue
        source_refs, destination_refs = route.get("source_evidence_refs", []), route.get("destination_evidence_refs", [])
        source_rows = [_resolve(result, ref) for ref in source_refs]
        destination_rows = [_resolve(result, ref) for ref in destination_refs]
        for consumption in route.get("consumption", []):
            source = next((row for row in source_rows if isinstance(row, dict)
                and row.get("evidence_id") == consumption.get("source_evidence_id")), None)
            destination = next((row for row in destination_rows if isinstance(row, dict)
                and row.get("evidence_id") == consumption.get("destination_evidence_id")), None)
            if not source or not destination or destination.get("agent_id") not in {
                "ac_idor", "ac_vertical_escalation", "ac_force_browse",
            }:
                continue
            if (source.get("agent_id") not in {"bf_dictionary", "bf_spray"}
                    or destination.get("consumed_source_evidence_id") != source.get("evidence_id")
                    or not oracle_confirmed(result, destination)
                    or candidate_base(result, source.get("candidate_id"), source.get("agent_id"), source_refs) != 3
                    or candidate_base(result, destination.get("candidate_id"), destination.get("agent_id"), destination_refs) != 3):
                continue
            source_candidate = _candidate(raw_method_state, source["agent_id"], source["candidate_id"])
            destination_candidate = _candidate(raw_method_state, destination["agent_id"], destination["candidate_id"])
            if (not source_candidate or not destination_candidate or not _validated(raw_method_state, source["agent_id"], source["candidate_id"])
                    or not _validated(raw_method_state, destination["agent_id"], destination["candidate_id"])):
                continue
            material = _material(source_candidate, raw_method_state, source)
            if not material:
                continue
            username, password = material
            permission_protocol = permission_source["document"]["oracle_protocol"]
            descriptor = _request_descriptor(config["target_url"], destination, permission_protocol)
            if descriptor is None:
                continue
            if any(consumption.get(key) != value for key, value in {
                "route_id": route.get("route_id"), "visit_id": destination.get("visit_id"),
                "source_candidate_id": source.get("candidate_id"), "source_visit_id": source.get("visit_id"),
                "candidate_id": destination.get("candidate_id"), "source_evidence_id": source.get("evidence_id"),
                "destination_evidence_id": destination.get("evidence_id"),
            }.items()):
                continue

            controls = []
            try:
                positive = _dependency_control(config["target_url"], config.get("security_level", "low"),
                    destination["agent_id"], descriptor, username, password, True, permission_protocol)
                negative = _dependency_control(config["target_url"], config.get("security_level", "low"),
                    destination["agent_id"], descriptor, username, password, False, permission_protocol)
                controls = [positive, negative]
            except Exception as exc:
                controls = [{"failure": type(exc).__name__, "source_available": False,
                    "destination_confirmed": False}]
            if not (len(controls) == 2 and controls[0].get("source_available") is True
                    and controls[0].get("destination_confirmed") is True
                    and controls[1].get("source_available") is False
                    and controls[1].get("destination_confirmed") is False):
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
                "verified_at": now,
                "material_fingerprint": sha256(f"{username}\0{password}".encode()).hexdigest(),
                "depends_on_source": True, "controls": [
                    {"source_available": item["source_available"],
                     "destination_confirmed": item["destination_confirmed"],
                     "response_sha256": item["response_sha256"], "status_code": item["status_code"]}
                    for item in controls],
            }
            oracle_document = {
                "fixture_id": config["fixture_id"], "protocol_version": config["protocol_version"],
                "oracle_protocol": protocol, "protocol_source_sha256": protocol_source["sha256"],
                "dependencies": [attestation], "dependency_controls": [
                    {"source_available": item["source_available"],
                     "destination_confirmed": item["destination_confirmed"],
                     "response_sha256": item["response_sha256"], "status_code": item["status_code"]}
                    for item in controls],
                "status": "confirmed",
            }
            source_id = f"{protocol_source['source_id']}:{route['route_id']}:{source['evidence_id']}:{destination['evidence_id']}"
            if any(existing.get("source_id") == source_id for existing in result["config"]["scoring_oracles"]):
                continue
            oracle_source = {"source_id": source_id, "origin": protocol_source["origin"],
                "document": oracle_document, "sha256": evidence_hash(oracle_document)}
            validate_sources([oracle_source])
            index = len(result["config"]["scoring_oracles"])
            result["config"]["scoring_oracles"].append(oracle_source)
            consumption["dependency_ref"] = f"#/config/scoring_oracles/{index}/document/dependencies/0"
    return result
