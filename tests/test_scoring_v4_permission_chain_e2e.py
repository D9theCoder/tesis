"""Permission and causal-chain acceptance controls declared before changes.

Failure inventory: an AC agent authenticates as admin; a page or response is
mistaken for permission proof; the fixture policy is absent or its credentials
are not verified; candidate, visit, method, response hash, principal, object,
or action is rebound; allowed and denied controls cover different resources;
an anonymous or wrong-role control unexpectedly sees protected data; control
secrets leak; a disabled protocol performs HTTP; source credentials are copied
without their candidate evidence ID; a destination uses different material;
source and destination candidates, visits, response hashes, timestamps, or AKG
route do not bind; a negative dependency control is missing; Human, AI, output,
and automatic scores are merged. These are offline E2E controls, not live DVWA
acceptance.
"""
from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace

import pytest

from evaluation.scoring_evidence import evidence_hash, oracle_confirmed, verified_dependencies
from foundation.verifier import fixture_attestation_valid


FIXTURE = "offline-dvwa-permission-fixture"
PROTOCOL = "permission-chain-offline.v1"
TARGET = "http://fixture.invalid/dvwa"


class FakeSession:
    """Contained in-memory DVWA with allowed, denied, and candidate principals."""

    instances = []

    def __init__(self, target_url):
        assert target_url == TARGET
        self.http = self
        self._client = SimpleNamespace(event_hooks={"response": []})
        self.cookies = {}
        self.principal = None
        self.username = None
        self.closed = False
        self.calls = []
        self.instances.append(self)

    def login(self, username="admin", password="password"):
        self.calls.append(("login", username))
        if (username, password) not in {
            ("admin", "password"), ("gordonb", "fixture-secret"),
        }:
            return False
        self.username = username
        self.principal = username
        self.cookies["PHPSESSID"] = f"session-{username}-{len(self.instances)}"
        return True

    def get(self, path, params=None):
        self.calls.append(("GET", path, deepcopy(params or {})))
        path = str(path)
        if path.endswith("login.php") and "PHPSESSID" not in self.cookies:
            self.cookies["PHPSESSID"] = f"anonymous-{len(self.instances)}"
        if path.rstrip("/").endswith("authbypass") and not path.endswith("get_user_data.php"):
            body = ("This page should only be accessible by the admin user. for example gordonb/fixture-secret"
                    if self.principal == "admin" else "Login")
            status = 200 if self.principal == "admin" else 302
        elif path.endswith("get_user_data.php"):
            body = '[{"user_id":"1","first_name":"admin"}]' if self.principal in {"admin", "gordonb"} else "Login"
            status = 200 if self.principal in {"admin", "gordonb"} else 302
        elif path.endswith("index.php"):
            body = f"Username: {self.principal}" if self.principal else "Login"
            status = 200
        else:
            body, status = "Login", 302
        return SimpleNamespace(text=body, status_code=status, url=f"{TARGET}/{path.lstrip('/')}")

    def set_security_level(self, level):
        self.calls.append(("security", level))

    def close(self):
        self.closed = True


def permission_protocol():
    document = {
        "fixture_id": FIXTURE,
        "protocol_version": PROTOCOL,
        "oracle_protocol": {
            "kind": "dvwa_candidate_permission.v1",
            "enabled": True,
            "resource": "DVWA user manager and its read API",
            "policy": "The existing fixture page states that only admin may access it.",
            "protected_paths": ["/vulnerabilities/authbypass/"],
            "path_signals": {"/vulnerabilities/authbypass/": [
                "This page should only be accessible by the admin user"]},
            "allow_broad_exposure": True,
            "controls": ["admin_allowed", "anonymous_denied", "candidate_replay"],
        },
    }
    return {"source_id": "fixture-permission", "origin": "operator_fixture",
            "document": document, "sha256": evidence_hash(document)}


def session_protocol():
    document = {"fixture_id": FIXTURE, "protocol_version": PROTOCOL,
        "oracle_protocol": {"kind": "dvwa_candidate_session.v1", "enabled": True}}
    return {"source_id": "fixture-session", "origin": "operator_fixture",
        "document": document, "sha256": evidence_hash(document)}


def dependency_protocol():
    document = {"fixture_id": FIXTURE, "protocol_version": PROTOCOL,
        "oracle_protocol": {"kind": "dvwa_causal_dependency.v1", "enabled": True}}
    return {"source_id": "fixture-dependency", "origin": "operator_fixture",
        "document": document, "sha256": evidence_hash(document)}


def chain_artifact():
    source_candidate = {
        "candidate_id": "bf_dictionary_generated_0",
        "source_seed_id": "bf_dictionary_low_exploit_1",
        "source": "llm_generated", "method": "bf_dictionary", "stage": "exploit",
        "payload_or_logic": "gordonb:fixture-secret", "target_param": "credential_pair",
        "expected_signal": "valid_login",
    }
    dest_candidate = {
        "candidate_id": "ac_idor_generated_0", "source_seed_id": "ac_idor_low_exploit_0",
        "source": "llm_generated", "method": "ac_idor", "stage": "exploit",
        "payload_or_logic": "1", "target_param": "userId",
        "expected_signal": "unauthorized_object_access",
    }
    source = {
        "agent_id": "bf_dictionary", "candidate_id": source_candidate["candidate_id"],
        "evidence_id": "response:0", "visit_id": "bf_dictionary:visit:0", "stage": "exploit",
        "status_code": 200, "response_sha256": "a" * 64,
        "timestamp": "2026-10-10T22:00:00+00:00", "principal_id": "gordonb",
        "session_fingerprint": "b" * 64, "initial_session_fingerprint": "c" * 64,
        "verification_reason": "verified_login", "verified_grade": 3, "success": True,
    }
    dest = {
        "agent_id": "ac_idor", "candidate_id": dest_candidate["candidate_id"],
        "evidence_id": "response:1", "visit_id": "ac_idor:visit:1", "stage": "exploit",
        "endpoint": f"{TARGET}/vulnerabilities/authbypass/get_user_data.php",
        "payload": "userId=1", "status_code": 200, "response_sha256": "d" * 64,
        "timestamp": "2026-10-10T22:00:10+00:00", "principal_id": "gordonb",
        "session_fingerprint": "e" * 64, "initial_session_fingerprint": "f" * 64,
        "object_id": "dvwa-user:1", "action": "read", "signal_detected": True,
        "verified_grade": 2, "verification_reason": "visibility_without_permission_oracle",
        "consumed_source_evidence_id": "response:0",
    }
    route = {
        "route_id": "route:0", "source": "authenticated_session", "target": "ac_idor",
        "target_agent": "ac_idor", "target_visit_id": dest["visit_id"],
        "preconditions": ["authenticated_session"], "prerequisites_proved": True,
        "source_verifier_ids": ["verifier:bf"], "source_evidence_ids": [source["evidence_id"]],
        "source_evidence_refs": ["#/final_state/response_evidence/0"],
        "destination_evidence_refs": ["#/final_state/response_evidence/1"],
        "prerequisite_evidence_refs": {"authenticated_session": ["#/final_state/verifier_history/0"]},
        "destination_verifier_id": "verifier:ac",
        "consumption": [{"route_id": "route:0", "visit_id": dest["visit_id"],
            "source_candidate_id": source_candidate["candidate_id"],
            "source_visit_id": source["visit_id"], "candidate_id": dest_candidate["candidate_id"],
            "source_evidence_id": source["evidence_id"], "destination_evidence_id": dest["evidence_id"],
            "representation": "plaintext"}],
        "status": "completed",
    }
    artifact = {
        "run_id": "run:chain", "execution_id": "execution:chain",
        "selected_method": "ac_idor", "fixture_id": FIXTURE, "protocol_version": PROTOCOL,
        "config": {"target_url": TARGET, "fixture_id": FIXTURE, "protocol_version": PROTOCOL,
            "security_level": "low", "scoring_rubric_version": "scoring.v4",
            "scoring_oracles": [permission_protocol(), session_protocol(), dependency_protocol()]},
        "final_state": {
            "response_evidence": [source, dest],
            "payload_candidates": {"bf_dictionary": [source_candidate], "ac_idor": [dest_candidate]},
            "payload_validation_results": {"bf_dictionary": [{"candidate_id": source_candidate["candidate_id"], "valid": True}],
                "ac_idor": [{"candidate_id": dest_candidate["candidate_id"], "valid": True}]},
            "payload_provenance": {source_candidate["candidate_id"]: {"method": "bf_dictionary", "source": "llm_generated"},
                dest_candidate["candidate_id"]: {"method": "ac_idor", "source": "llm_generated"}},
            "verifier_history": [
                {"verifier_id": "verifier:bf", "agent_id": "bf_dictionary", "visit_id": source["visit_id"],
                    "decision": "confirmed", "confirmed_vulns": ["bf_dictionary_confirmed"],
                    "achieved_outcomes": ["authenticated_session"],
                    "evidence_refs": ["#/final_state/response_evidence/0"], "source": "method_agent_evidence"},
                {"verifier_id": "verifier:ac", "agent_id": "ac_idor", "visit_id": dest["visit_id"],
                    "decision": "confirmed", "confirmed_vulns": ["ac_idor_confirmed"],
                    "achieved_outcomes": [], "evidence_refs": ["#/final_state/response_evidence/1"],
                    "source": "method_agent_evidence"},
            ],
            "chain_history": [route], "weak_chain_opportunities": [],
            "scoring_decisions": [], "confirmed_vulns": ["bf_dictionary_confirmed", "ac_idor_confirmed"],
            "achieved_outcomes": ["authenticated_session"],
        },
    }
    return artifact, source_candidate, dest_candidate, source, dest, route


def test_documented_nonadmin_helper_uses_fixture_identity_and_fails_closed(monkeypatch):
    from foundation import session_manager
    FakeSession.instances = []
    monkeypatch.setattr(session_manager, "DVWASession", FakeSession)
    session, principal, initial_fingerprint = session_manager.open_documented_nonadmin_session(TARGET, "low")
    assert principal == "gordonb"
    assert session.username == principal
    assert initial_fingerprint
    assert all("fixture-secret" not in repr(call) for item in FakeSession.instances for call in item.calls)
    session.close()

    class MissingPolicy(FakeSession):
        def get(self, path, params=None):
            response = super().get(path, params)
            if str(path).rstrip("/").endswith("authbypass"):
                response.text = "No operator permission policy here"
            return response

    monkeypatch.setattr(session_manager, "DVWASession", MissingPolicy)
    with pytest.raises(ValueError, match="documented non-admin"):
        session_manager.open_documented_nonadmin_session(TARGET, "low")


def test_candidate_permission_oracle_binds_same_resource_and_identity(monkeypatch):
    from evaluation import permission_oracle
    from evaluation.scoring_evidence import oracle_confirmed
    FakeSession.instances = []
    monkeypatch.setattr(permission_oracle, "DVWASession", FakeSession)
    monkeypatch.setattr("foundation.session_manager.DVWASession", FakeSession)
    artifact, _, _, _, row, _ = chain_artifact()
    row.update(object_id="dvwa-user:1", action="read")
    raw = {
        "target_url": TARGET, "security_level": "low", "selected_visit_id": row["visit_id"],
        "selected_method": "ac_idor", "run_id": artifact["run_id"], "execution_id": artifact["execution_id"],
        "payload_candidates": {"ac_idor": [artifact["final_state"]["payload_candidates"]["ac_idor"][0]]},
        "payload_validation_results": {"ac_idor": [{"candidate_id": row["candidate_id"], "valid": True}]},
        "response_evidence": artifact["final_state"]["response_evidence"],
        "found_credentials": [{"username": "gordonb", "password": "fixture-secret",
            "source_evidence_id": "response:0", "source_candidate_id": "bf_dictionary_generated_0",
            "source_visit_id": "bf_dictionary:visit:0"}],
    }
    result = permission_oracle.collect_permission_oracles(artifact, raw)
    assert result is not artifact
    enriched = next(e for e in result["final_state"]["response_evidence"] if e["evidence_id"] == row["evidence_id"])
    assert oracle_confirmed(result, enriched)
    assert enriched["oracle_ref"].startswith("#/config/scoring_oracles/")
    bundle = result["config"]["scoring_oracles"][int(enriched["oracle_ref"].split("/")[3])]
    doc = bundle["document"]
    assert doc["candidate_replay"]["candidate_id"] == row["candidate_id"]
    assert doc["candidate_replay"]["object_id"] == row["object_id"]
    assert {(c["expected_allowed"], c["observed_allowed"], c["object_id"], c["action"]) for c in doc["controls"]} == {
        (True, True, row["object_id"], row["action"]),
        (False, False, row["object_id"], row["action"]),
    }
    assert "fixture-secret" not in repr(bundle)


def test_candidate_permission_oracle_records_broader_public_exposure_without_dropping_candidate_binding(monkeypatch):
    from evaluation import permission_oracle
    from evaluation.scoring_evidence import oracle_confirmed

    class PublicUserData(FakeSession):
        def get(self, path, params=None):
            response = super().get(path, params)
            if str(path).endswith("get_user_data.php") and str((params or {}).get("userId")) == "1":
                response.text = '[{"user_id":"1","first_name":"admin"}]'
                response.status_code = 200
            return response

    PublicUserData.instances = []
    monkeypatch.setattr(permission_oracle, "DVWASession", PublicUserData)
    monkeypatch.setattr("foundation.session_manager.DVWASession", PublicUserData)
    artifact, _, _, _, row, _ = chain_artifact()
    raw = {
        "target_url": TARGET, "security_level": "low", "selected_visit_id": row["visit_id"],
        "selected_method": "ac_idor", "run_id": artifact["run_id"], "execution_id": artifact["execution_id"],
        "payload_candidates": {"ac_idor": [artifact["final_state"]["payload_candidates"]["ac_idor"][0]]},
        "payload_validation_results": {"ac_idor": [{"candidate_id": row["candidate_id"], "valid": True}]},
        "response_evidence": artifact["final_state"]["response_evidence"],
        "found_credentials": [{"username": "gordonb", "password": "fixture-secret",
            "source_evidence_id": "response:0", "source_candidate_id": "bf_dictionary_generated_0",
            "source_visit_id": "bf_dictionary:visit:0"}],
    }
    result = permission_oracle.collect_permission_oracles(artifact, raw)
    evidence = result["final_state"]["response_evidence"][1]
    assert result["config"]["scoring_oracles"][-1]["document"]["status"] == "confirmed", result["config"]["scoring_oracles"][-1]["document"]
    assert oracle_confirmed(result, evidence)
    bundle = result["config"]["scoring_oracles"][int(evidence["oracle_ref"].split("/")[3])]
    doc = bundle["document"]
    assert doc["scope_outcome"] == "broad_exposure"
    assert doc["candidate_replay"]["principal_id"] == "gordonb"
    assert doc["candidate_replay"]["object_id"] == row["object_id"]
    controls = {control["control"]: control for control in doc["controls"]}
    assert controls["admin_allowed"]["observed_allowed"] is True
    assert controls["anonymous_denied"]["expected_allowed"] is False
    assert controls["anonymous_denied"]["observed_allowed"] is True
    assert controls["anonymous_denied"]["expected_confirmed"] is True
    assert all(control["object_id"] == row["object_id"] and control["action"] == row["action"]
        for control in controls.values())
    assert "fixture-secret" not in repr(bundle)


def test_permission_oracle_rejects_broad_exposure_when_protocol_did_not_opt_in(monkeypatch):
    from evaluation import permission_oracle
    from evaluation.scoring_evidence import oracle_confirmed

    class PublicUserData(FakeSession):
        def get(self, path, params=None):
            response = super().get(path, params)
            if str(path).endswith("get_user_data.php") and str((params or {}).get("userId")) == "1":
                response.text = '[{"user_id":"1","first_name":"admin"}]'
                response.status_code = 200
            return response

    PublicUserData.instances = []
    monkeypatch.setattr(permission_oracle, "DVWASession", PublicUserData)
    monkeypatch.setattr("foundation.session_manager.DVWASession", PublicUserData)
    artifact, _, _, _, row, _ = chain_artifact()
    artifact["config"]["scoring_oracles"][0]["document"]["oracle_protocol"].pop("allow_broad_exposure")
    source = artifact["config"]["scoring_oracles"][0]
    source["sha256"] = evidence_hash(source["document"])
    raw = {
        "target_url": TARGET, "security_level": "low", "selected_visit_id": row["visit_id"],
        "selected_method": "ac_idor", "run_id": artifact["run_id"], "execution_id": artifact["execution_id"],
        "payload_candidates": {"ac_idor": [artifact["final_state"]["payload_candidates"]["ac_idor"][0]]},
        "payload_validation_results": {"ac_idor": [{"candidate_id": row["candidate_id"], "valid": True}]},
        "response_evidence": artifact["final_state"]["response_evidence"],
        "found_credentials": [{"username": "gordonb", "password": "fixture-secret",
            "source_evidence_id": "response:0", "source_candidate_id": "bf_dictionary_generated_0",
            "source_visit_id": "bf_dictionary:visit:0"}],
    }
    result = permission_oracle.collect_permission_oracles(artifact, raw)
    evidence = result["final_state"]["response_evidence"][1]
    assert not oracle_confirmed(result, evidence)


@pytest.mark.parametrize("mutation", ["candidate", "object", "action", "response_hash", "source_hash"])
def test_permission_oracle_rejects_rebound_or_tampered_evidence(monkeypatch, mutation):
    from evaluation import permission_oracle
    FakeSession.instances = []
    monkeypatch.setattr(permission_oracle, "DVWASession", FakeSession)
    monkeypatch.setattr("foundation.session_manager.DVWASession", FakeSession)
    artifact, _, _, _, row, _ = chain_artifact()
    raw = {
        "target_url": TARGET, "security_level": "low", "selected_visit_id": row["visit_id"],
        "selected_method": "ac_idor", "run_id": artifact["run_id"], "execution_id": artifact["execution_id"],
        "payload_candidates": {"ac_idor": deepcopy(artifact["final_state"]["payload_candidates"]["ac_idor"])},
        "payload_validation_results": {"ac_idor": [{"candidate_id": row["candidate_id"], "valid": True}]},
        "response_evidence": artifact["final_state"]["response_evidence"],
    }
    if mutation == "candidate": raw["payload_candidates"]["ac_idor"][0]["candidate_id"] = "other"
    if mutation == "object": row["object_id"] = "other-user"
    if mutation == "action": row["action"] = "write"
    if mutation == "response_hash": row["response_sha256"] = "0" * 64
    if mutation == "source_hash":
        artifact["config"]["scoring_oracles"][0]["sha256"] = "0" * 64
        with pytest.raises(ValueError, match="hash mismatch"):
            permission_oracle.collect_permission_oracles(artifact, raw)
        return
    result = permission_oracle.collect_permission_oracles(artifact, raw)
    evidence = result["final_state"]["response_evidence"][1]
    assert not oracle_confirmed(result, evidence)


def test_dependency_oracle_requires_source_material_and_positive_negative_controls(monkeypatch):
    from evaluation import dependency_oracle
    FakeSession.instances = []
    monkeypatch.setattr(dependency_oracle, "DVWASession", FakeSession)
    monkeypatch.setattr("foundation.session_manager.DVWASession", FakeSession)
    artifact, source_candidate, dest_candidate, source, dest, route = chain_artifact()
    raw = {
        "target_url": TARGET, "security_level": "low",
        "found_credentials": [{"username": "gordonb", "password": "fixture-secret",
            "source_evidence_id": source["evidence_id"], "source_candidate_id": source_candidate["candidate_id"],
            "source_visit_id": source["visit_id"]}],
        "payload_candidates": artifact["final_state"]["payload_candidates"],
        "payload_validation_results": artifact["final_state"]["payload_validation_results"],
        "response_evidence": artifact["final_state"]["response_evidence"],
        "chain_history": [route],
    }
    from evaluation import permission_oracle
    monkeypatch.setattr(permission_oracle, "DVWASession", FakeSession)
    from evaluation import session_oracle
    monkeypatch.setattr(session_oracle, "DVWASession", FakeSession)
    artifact = permission_oracle.collect_permission_oracles(artifact, raw)
    artifact = session_oracle.collect_session_oracles(artifact, raw)
    from evaluation.scoring_evidence import attach_oracle_evidence
    attach_oracle_evidence(artifact)
    result = dependency_oracle.collect_dependency_oracles(artifact, raw)
    dependencies = verified_dependencies(result)
    assert len(dependencies) == 1
    assert dependencies[0]["source"]["candidate_id"] == source_candidate["candidate_id"]
    assert dependencies[0]["destination"]["candidate_id"] == dest_candidate["candidate_id"]
    assert dependencies[0]["destination"]["consumed_source_evidence_id"] == source["evidence_id"]
    saved_route = next(row for row in result["final_state"]["chain_history"] if row["route_id"] == route["route_id"])
    ref = saved_route["consumption"][0]["dependency_ref"]
    bundle = result["config"]["scoring_oracles"][int(ref.split("/")[3])]
    assert any(c["source_available"] is True and c["destination_confirmed"] is True
        for c in bundle["document"]["dependency_controls"])
    assert any(c["source_available"] is False and c["destination_confirmed"] is False
        for c in bundle["document"]["dependency_controls"])
    assert "fixture-secret" not in repr(bundle)


def test_dependency_oracle_accepts_consumed_credentials_for_confirmed_force_browse(monkeypatch):
    from evaluation import dependency_oracle, permission_oracle, session_oracle
    from evaluation.scoring_evidence import attach_oracle_evidence
    from core.knowledge_graph import AttackKnowledgeGraph

    class ForceBrowseSession(FakeSession):
        def get(self, path, params=None):
            response = super().get(path, params)
            if str(path).rstrip("/").endswith("authbypass") and self.principal == "gordonb":
                response.text = "This page should only be accessible by the admin user"
                response.status_code = 200
            return response

    ForceBrowseSession.instances = []
    for module in (dependency_oracle, permission_oracle, session_oracle):
        monkeypatch.setattr(module, "DVWASession", ForceBrowseSession)
    monkeypatch.setattr("foundation.session_manager.DVWASession", ForceBrowseSession)

    artifact, source_candidate, _, source, destination, route = chain_artifact()
    assert any(edge.get("target") == "ac_force_browse" and edge.get("is_chain") is True
        for edge in AttackKnowledgeGraph().get_next_actions("authenticated_session"))
    destination_candidate = {
        "candidate_id": "ac_force_browse_generated_0",
        "source_seed_id": "ac_force_browse_low_exploit_2",
        "source": "llm_generated", "method": "ac_force_browse", "stage": "exploit",
        "payload_or_logic": "vulnerabilities/authbypass/", "target_param": "path",
        "expected_signal": "restricted_endpoint_accessible",
    }
    destination.update({
        "agent_id": "ac_force_browse", "candidate_id": destination_candidate["candidate_id"],
        "endpoint": f"{TARGET}/vulnerabilities/authbypass/",
        "payload": "vulnerabilities/authbypass/", "object_id": "dvwa-path:/vulnerabilities/authbypass/",
        "consumed_source_evidence_id": source["evidence_id"], "verified_grade": 2,
        "verification_reason": "visibility_without_permission_oracle",
    })
    route.update({"target": "ac_force_browse", "target_agent": "ac_force_browse",
        "target_visit_id": destination["visit_id"]})
    route["consumption"][0].update({
        "candidate_id": destination_candidate["candidate_id"],
        "destination_evidence_id": destination["evidence_id"],
    })
    state = artifact["final_state"]
    state["payload_candidates"].pop("ac_idor")
    state["payload_candidates"]["ac_force_browse"] = [destination_candidate]
    state["payload_validation_results"].pop("ac_idor")
    state["payload_validation_results"]["ac_force_browse"] = [
        {"candidate_id": destination_candidate["candidate_id"], "valid": True}]
    state["payload_provenance"].pop("ac_idor_generated_0")
    state["payload_provenance"][destination_candidate["candidate_id"]] = {
        "method": "ac_force_browse", "source": "llm_generated"}
    state["verifier_history"][1].update({
        "agent_id": "ac_force_browse", "confirmed_vulns": ["ac_force_browse_confirmed"],
        "evidence_refs": ["#/final_state/response_evidence/1"],
    })
    state["confirmed_vulns"] = ["bf_dictionary_confirmed", "ac_force_browse_confirmed"]
    artifact["selected_method"] = "ac_force_browse"
    raw = {
        "target_url": TARGET, "security_level": "low",
        "found_credentials": [{"username": "gordonb", "password": "fixture-secret",
            "source_evidence_id": source["evidence_id"],
            "source_candidate_id": source_candidate["candidate_id"],
            "source_visit_id": source["visit_id"]}],
        "payload_candidates": state["payload_candidates"],
        "payload_validation_results": state["payload_validation_results"],
        "response_evidence": state["response_evidence"], "chain_history": [route],
    }
    artifact = permission_oracle.collect_permission_oracles(artifact, raw)
    artifact = session_oracle.collect_session_oracles(artifact, raw)
    attach_oracle_evidence(artifact)
    result = dependency_oracle.collect_dependency_oracles(artifact, raw)

    dependencies = verified_dependencies(result)
    assert len(dependencies) == 1
    assert dependencies[0]["source"]["candidate_id"] == source_candidate["candidate_id"]
    assert dependencies[0]["destination"]["candidate_id"] == destination_candidate["candidate_id"]
    assert dependencies[0]["destination"]["consumed_source_evidence_id"] == source["evidence_id"]
    assert "fixture-secret" not in repr(result["config"]["scoring_oracles"])


def test_dependency_oracle_does_not_bind_different_candidate_material(monkeypatch):
    from evaluation import dependency_oracle
    FakeSession.instances = []
    monkeypatch.setattr(dependency_oracle, "DVWASession", FakeSession)
    monkeypatch.setattr("foundation.session_manager.DVWASession", FakeSession)
    artifact, source_candidate, _, source, _, route = chain_artifact()
    raw = {
        "target_url": TARGET, "security_level": "low",
        "found_credentials": [{"username": "admin", "password": "other-secret",
            "source_evidence_id": source["evidence_id"], "source_candidate_id": source_candidate["candidate_id"]}],
        "payload_candidates": artifact["final_state"]["payload_candidates"], "chain_history": [route],
        "payload_validation_results": artifact["final_state"]["payload_validation_results"],
        "response_evidence": artifact["final_state"]["response_evidence"],
    }
    result = dependency_oracle.collect_dependency_oracles(artifact, raw)
    assert not verified_dependencies(result)
    assert not any(s["document"].get("dependencies") for s in result["config"]["scoring_oracles"])
