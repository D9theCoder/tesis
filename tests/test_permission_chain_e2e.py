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
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from evaluation.scoring_evidence import (
    evidence_hash,
    oracle_confirmed,
    oracle_negative_confirmed,
    verified_dependencies,
)
from foundation.verifier import permission_evidence_mode


FIXTURE = "offline-dvwa-permission-fixture"
PROTOCOL = "permission-chain-offline.v1"
TARGET = "http://fixture.invalid/dvwa"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_ARTIFACT = (
    REPOSITORY_ROOT
    / "results/runs/restored-primary-2026-11-06/selection/run-007"
    / "exec-20261106T100020480863Z-8695cf91f1b149ff8cbc3f597ff9d797.json"
)


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
        final_path = path
        if path.rstrip("/").endswith("authbypass") and not path.endswith("get_user_data.php"):
            body = ("This page should only be accessible by the admin user. for example gordonb/fixture-secret"
                    if self.principal == "admin" else "Login")
            status = 200 if self.principal == "admin" else 302
            if status == 302:
                final_path = "login.php"
        elif path.endswith("get_user_data.php"):
            body = '[{"user_id":"1","first_name":"admin"}]' if self.principal in {"admin", "gordonb"} else "Login"
            status = 200 if self.principal in {"admin", "gordonb"} else 302
            if status == 302:
                final_path = "login.php"
        elif path.endswith("index.php"):
            body = f"Username: {self.principal}" if self.principal else "Login"
            status = 200
        else:
            body, status = "Login", 302
            final_path = "login.php"
        return SimpleNamespace(text=body, status_code=status, url=f"{TARGET}/{final_path.lstrip('/')}")

    def set_security_level(self, level):
        self.calls.append(("security", level))

    def close(self):
        self.closed = True


def permission_protocol():
    document = {
        "fixture_id": FIXTURE,
        "protocol_version": PROTOCOL,
        "oracle_protocol": {
            "kind": 'dvwa_candidate_permission',
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
        "oracle_protocol": {"kind": 'dvwa_candidate_session', "enabled": True}}
    return {"source_id": "fixture-session", "origin": "operator_fixture",
        "document": document, "sha256": evidence_hash(document)}


def dependency_protocol():
    document = {"fixture_id": FIXTURE, "protocol_version": PROTOCOL,
        "oracle_protocol": {"kind": 'dvwa_causal_dependency', "enabled": True}}
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
            "security_level": "low", "scoring_rubric_version": "thesis-scoring",
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


def _permission_collect(monkeypatch, session_type):
    from evaluation import permission_oracle
    FakeSession.instances = []
    monkeypatch.setattr(permission_oracle, "DVWASession", session_type)
    monkeypatch.setattr("foundation.session_manager.DVWASession", session_type)
    artifact, _, _, _, row, _ = chain_artifact()
    row.update(object_id="dvwa-user:1", action="read")
    raw = {
        "target_url": TARGET, "security_level": "low", "selected_visit_id": row["visit_id"],
        "selected_method": "ac_idor", "run_id": artifact["run_id"], "execution_id": artifact["execution_id"],
        "payload_candidates": {"ac_idor": deepcopy(artifact["final_state"]["payload_candidates"]["ac_idor"])},
        "payload_validation_results": {"ac_idor": [{"candidate_id": row["candidate_id"], "valid": True}]},
        "response_evidence": artifact["final_state"]["response_evidence"],
        "found_credentials": [{"username": "gordonb", "password": "fixture-secret",
            "source_evidence_id": "response:0", "source_candidate_id": "bf_dictionary_generated_0",
            "source_visit_id": "bf_dictionary:visit:0"}],
    }
    result = permission_oracle.collect_permission_oracles(artifact, raw)
    from evaluation.scoring_evidence import attach_oracle_evidence
    attach_oracle_evidence(result)
    enriched = next(e for e in result["final_state"]["response_evidence"]
                    if e["evidence_id"] == row["evidence_id"])
    return result, enriched, raw


class AnonymousErrorSession(FakeSession):
    def get(self, path, params=None):
        if self.principal is None and str(path).endswith("get_user_data.php"):
            self.calls.append(("GET", str(path), deepcopy(params or {})))
            return SimpleNamespace(text="Server error", status_code=500,
                                   url=f"{TARGET}/vulnerabilities/authbypass/get_user_data.php")
        return super().get(path, params)


class AnonymousAmbiguousSession(FakeSession):
    def get(self, path, params=None):
        if self.principal is None and str(path).endswith("get_user_data.php"):
            self.calls.append(("GET", str(path), deepcopy(params or {})))
            return SimpleNamespace(text="Nothing to see here", status_code=200,
                                   url=f"{TARGET}/vulnerabilities/authbypass/get_user_data.php")
        return super().get(path, params)


class AnonymousTransportSession(FakeSession):
    def get(self, path, params=None):
        if self.principal is None and str(path).endswith("get_user_data.php"):
            raise RuntimeError("fixture transport failed")
        return super().get(path, params)


class AdminErrorSession(FakeSession):
    def get(self, path, params=None):
        if self.principal == "admin" and str(path).endswith("get_user_data.php"):
            self.calls.append(("GET", str(path), deepcopy(params or {})))
            return SimpleNamespace(text="Server error", status_code=500,
                                   url=f"{TARGET}/vulnerabilities/authbypass/get_user_data.php")
        return super().get(path, params)


@pytest.mark.parametrize(
    "session_type",
    [AnonymousErrorSession, AnonymousAmbiguousSession, AdminErrorSession],
    ids=["anonymous-500", "anonymous-ambiguous", "admin-500"],
)
def test_error_or_ambiguous_control_cannot_confirm_positive_candidate(monkeypatch, session_type):
    result, enriched, _raw = _permission_collect(monkeypatch, session_type)
    assert not oracle_confirmed(result, enriched)


def test_transport_failure_cannot_confirm_positive_candidate(monkeypatch):
    result, enriched, _raw = _permission_collect(monkeypatch, AnonymousTransportSession)
    bundle = next(source for source in result["config"]["scoring_oracles"]
                  if source["source_id"].endswith(f":ac_idor:{enriched['evidence_id']}"))
    assert bundle["document"]["status"] == "pending"
    assert bundle["document"].get("reason")
    assert not oracle_confirmed(result, enriched)


class CandidateDeniedSession(FakeSession):
    def get(self, path, params=None):
        if self.principal == "gordonb" and str(path).endswith("get_user_data.php"):
            self.calls.append(("GET", str(path), deepcopy(params or {})))
            return SimpleNamespace(
                text='{"result":"fail","error":"Access Denied"}', status_code=200,
                url=f"{TARGET}/vulnerabilities/authbypass/get_user_data.php")
        return super().get(path, params)


class DeniedAnonymousError(CandidateDeniedSession):
    def get(self, path, params=None):
        if self.principal is None and str(path).endswith("get_user_data.php"):
            self.calls.append(("GET", str(path), deepcopy(params or {})))
            return SimpleNamespace(text="Server error", status_code=500,
                                   url=f"{TARGET}/vulnerabilities/authbypass/get_user_data.php")
        return super().get(path, params)


class DeniedAnonymousAmbiguous(CandidateDeniedSession):
    def get(self, path, params=None):
        if self.principal is None and str(path).endswith("get_user_data.php"):
            self.calls.append(("GET", str(path), deepcopy(params or {})))
            return SimpleNamespace(text="Nothing to see here", status_code=200,
                                   url=f"{TARGET}/vulnerabilities/authbypass/get_user_data.php")
        return super().get(path, params)


class DeniedAdminError(CandidateDeniedSession):
    def get(self, path, params=None):
        if self.principal == "admin" and str(path).endswith("get_user_data.php"):
            self.calls.append(("GET", str(path), deepcopy(params or {})))
            return SimpleNamespace(text="Server error", status_code=500,
                                   url=f"{TARGET}/vulnerabilities/authbypass/get_user_data.php")
        return super().get(path, params)


class DeniedAnonymousTransport(CandidateDeniedSession):
    def get(self, path, params=None):
        if self.principal is None and str(path).endswith("get_user_data.php"):
            raise RuntimeError("fixture transport failed")
        return super().get(path, params)


def _negative_permission_collect(monkeypatch, session_type):
    from evaluation import permission_oracle
    FakeSession.instances = []
    monkeypatch.setattr(permission_oracle, "DVWASession", session_type)
    monkeypatch.setattr("foundation.session_manager.DVWASession", session_type)
    artifact, _, _, _, row, _ = chain_artifact()
    row.update(object_id="dvwa-user:1", action="read", signal_detected=False,
               verified_grade=0, success=True,
               verification_reason="no_verified_exploit_signal")
    artifact["final_state"]["verifier_history"][1]["decision"] = "not_confirmed"
    raw = {
        "target_url": TARGET, "security_level": "low", "selected_visit_id": row["visit_id"],
        "selected_method": "ac_idor", "run_id": artifact["run_id"],
        "execution_id": artifact["execution_id"],
        "payload_candidates": {"ac_idor": deepcopy(
            artifact["final_state"]["payload_candidates"]["ac_idor"])},
        "payload_validation_results": {"ac_idor": [
            {"candidate_id": row["candidate_id"], "valid": True}]},
        "response_evidence": artifact["final_state"]["response_evidence"],
        "found_credentials": [{"username": "gordonb", "password": "fixture-secret",
            "source_evidence_id": "response:0", "source_candidate_id": "bf_dictionary_generated_0",
            "source_visit_id": "bf_dictionary:visit:0"}],
    }
    result = permission_oracle.collect_permission_oracles(artifact, raw)
    from evaluation.scoring_evidence import attach_oracle_evidence
    attach_oracle_evidence(result)
    enriched = next(e for e in result["final_state"]["response_evidence"]
                    if e["evidence_id"] == row["evidence_id"])
    return result, enriched


@pytest.mark.parametrize(
    "session_type",
    [DeniedAnonymousError, DeniedAnonymousAmbiguous, DeniedAdminError,
     DeniedAnonymousTransport],
    ids=["anonymous-500", "anonymous-ambiguous", "admin-500", "anonymous-transport"],
)
def test_error_or_ambiguous_control_cannot_confirm_negative_candidate(monkeypatch, session_type):
    result, enriched = _negative_permission_collect(monkeypatch, session_type)
    assert not oracle_negative_confirmed(result, enriched)


def test_explicit_endpoint_denial_with_matched_controls_confirms_negative(monkeypatch):
    result, enriched = _negative_permission_collect(monkeypatch, CandidateDeniedSession)
    assert oracle_negative_confirmed(result, enriched)
    bundle = result["config"]["scoring_oracles"][
        int(enriched["negative_oracle_ref"].split("/")[3])]
    document = bundle["document"]
    assert document["control_semantics"] == "permission-outcome-bound"
    assert document["candidate_replay"]["control_outcome"] == "denied"
    assert document["candidate_replay"]["denial_kind"] == "endpoint_denied"
    assert document["negative_attestations"][0]["outcome"] == "not_confirmed"
    assert document["scope_outcome"] == "candidate_specific"


def test_authentication_redirect_is_a_distinct_anonymous_denial(monkeypatch):
    result, enriched, _raw = _permission_collect(monkeypatch, FakeSession)
    assert oracle_confirmed(result, enriched)
    bundle = result["config"]["scoring_oracles"][
        int(enriched["oracle_ref"].split("/")[3])]
    control = next(c for c in bundle["document"]["controls"]
                   if c["control"] == "anonymous_denied")
    assert control["control_outcome"] == "authentication_redirect"
    assert control["denial_kind"] == "authentication_redirect"
    assert control["status_code"] == 302
    assert control["final_url"].endswith("/login.php")
    assert control["security_level"] == "low"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("final_url", "https://external.invalid/"),
        ("security_level", "high"),
        ("observed_at", "2000-01-01T00:00:00+00:00"),
        ("control_outcome", "ambiguous"),
    ],
)
def test_strict_control_binding_rejects_tampered_outcome(monkeypatch, field, value):
    result, enriched, _raw = _permission_collect(monkeypatch, FakeSession)
    bundle_index = int(enriched["oracle_ref"].split("/")[3])
    bundle = result["config"]["scoring_oracles"][bundle_index]
    admin = next(c for c in bundle["document"]["controls"] if c["control"] == "admin_allowed")
    admin[field] = value
    bundle["sha256"] = evidence_hash(bundle["document"])
    assert not oracle_confirmed(result, enriched)


def test_negative_candidate_requires_interpretable_endpoint_denial(monkeypatch):
    class RedirectedCandidate(CandidateDeniedSession):
        def get(self, path, params=None):
            if self.principal == "gordonb" and str(path).endswith("get_user_data.php"):
                self.calls.append(("GET", str(path), deepcopy(params or {})))
                return SimpleNamespace(text="Login", status_code=302,
                                       url=f"{TARGET}/login.php")
            return super().get(path, params)

    result, enriched = _negative_permission_collect(monkeypatch, RedirectedCandidate)
    assert not oracle_negative_confirmed(result, enriched)


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
    assert [control["control"] for control in bundle["document"]["dependency_controls"]] == [
        "candidate_material_positive", "wrong_credential_negative"]
    assert [control["control"] for control in bundle["document"]["dependencies"][0]["controls"]] == [
        "candidate_material_positive", "wrong_credential_negative"]
    assert "fixture-secret" not in repr(bundle)


def test_dependency_control_failure_records_control_stage_and_error(monkeypatch):
    """A failed control stays auditable without leaking credential material."""
    from evaluation import dependency_oracle

    class ExplodingSession(FakeSession):
        def get(self, path, params=None):
            if str(path).endswith("login.php"):
                raise RuntimeError("fixture control failed for gordonb:fixture-secret")
            return super().get(path, params)

    ExplodingSession.instances = []
    monkeypatch.setattr(dependency_oracle, "DVWASession", ExplodingSession)

    row = dependency_oracle._dependency_control(
        TARGET, "low", "ac_idor", None, "gordonb", "fixture-secret", False, {},
        "wrong_credential_negative")

    assert row["control"] == "wrong_credential_negative"
    assert row["stage"] == "initial_visit"
    assert row["failure"] == "RuntimeError"
    assert "<redacted>" in row["error"]
    assert "gordonb" not in row["error"]
    assert "fixture-secret" not in row["error"]
    assert row["source_available"] is False
    assert row["destination_confirmed"] is False


def test_bf_dependency_controls_skip_security_level(monkeypatch):
    """bf_* confirms login identity only; AC controls still set the level."""
    from evaluation import dependency_oracle
    FakeSession.instances = []
    monkeypatch.setattr(dependency_oracle, "DVWASession", FakeSession)
    monkeypatch.setattr("foundation.session_manager.DVWASession", FakeSession)

    positive = dependency_oracle._dependency_control(
        TARGET, "low", "bf_dictionary", None, "gordonb", "fixture-secret", True, {},
        "candidate_material_positive")
    negative = dependency_oracle._dependency_control(
        TARGET, "low", "bf_dictionary", None, "gordonb", "fixture-secret", False, {},
        "wrong_credential_negative")

    assert positive["control"] == "candidate_material_positive"
    assert positive["source_available"] is True
    assert positive["destination_confirmed"] is True
    assert negative["control"] == "wrong_credential_negative"
    assert negative["source_available"] is False
    assert negative["destination_confirmed"] is False
    assert not any(call[0] == "security"
        for session in FakeSession.instances for call in session.calls)

    descriptor = ("/vulnerabilities/authbypass/get_user_data.php",
                  {"userId": "1"}, "dvwa-user:1", "read")
    protocol = permission_protocol()["document"]["oracle_protocol"]
    ac_negative = dependency_oracle._dependency_control(
        TARGET, "low", "ac_idor", descriptor, "gordonb", "fixture-secret", False,
        protocol, "wrong_credential_negative")

    assert ac_negative["control"] == "wrong_credential_negative"
    assert ("security", "low") in FakeSession.instances[-1].calls


def _collect_with_prospective_identity(monkeypatch, session_type, *, negative):
    import tests.test_permission_chain_e2e as fixtures

    original = fixtures.chain_artifact

    def prospective():
        parts = original()
        parts[0]["research_plan_identity"] = {
            "plan_sha256": "a" * 64, "epoch_id": "offline-permission-review",
        }
        parts[0]["policy_epoch"] = {"epoch_id": "offline-permission-review"}
        parts[0]["config"]["policy_epoch"] = {"epoch_id": "offline-permission-review"}
        return parts

    monkeypatch.setattr(fixtures, "chain_artifact", prospective)
    if negative:
        result, row = _negative_permission_collect(monkeypatch, session_type)
        return result, row, "negative_oracle_ref"
    result, row, _raw = _permission_collect(monkeypatch, session_type)
    return result, row, "oracle_ref"


def _oracle_row(artifact, evidence_id):
    return next(
        row for row in artifact["final_state"]["response_evidence"]
        if row.get("evidence_id") == evidence_id
    )


@pytest.mark.parametrize("negative", [False, True], ids=["positive", "negative"])
def test_prospective_controls_cannot_downgrade_by_omitting_semantics(monkeypatch, negative):
    result, enriched, ref_key = _collect_with_prospective_identity(
        monkeypatch, CandidateDeniedSession if negative else FakeSession,
        negative=negative,
    )
    accepted = oracle_negative_confirmed if negative else oracle_confirmed
    assert accepted(result, enriched)
    index = int(enriched[ref_key].split("/")[3])
    document = result["config"]["scoring_oracles"][index]["document"]
    assert permission_evidence_mode(result, document) == "current-outcome-bound"

    def resealed(artifact, source_index):
        source = artifact["config"]["scoring_oracles"][source_index]
        source["sha256"] = evidence_hash(source["document"])
        return _oracle_row(artifact, enriched["evidence_id"])

    # A true error control is refused while current semantics remain explicit.
    changed = deepcopy(result)
    source = changed["config"]["scoring_oracles"][index]
    control = next(c for c in source["document"]["controls"]
                   if c["control"] == "anonymous_denied")
    control.update(status_code=500, control_outcome="http_error", interpretable=False,
                   denial_kind=None, final_url=f"{TARGET}/login.php",
                   response_sha256=sha256(b"offline synthetic HTTP500").hexdigest())
    assert not accepted(changed, resealed(changed, index))

    # Removing the self-declared marker cannot select a weaker verifier.
    changed = deepcopy(result)
    changed["config"]["scoring_oracles"][index]["document"].pop("control_semantics")
    assert not accepted(changed, resealed(changed, index))

    # An unknown marker is not legacy evidence either.
    changed = deepcopy(result)
    changed["config"]["scoring_oracles"][index]["document"]["control_semantics"] = (
        "unknown-semantics"
    )
    assert not accepted(changed, resealed(changed, index))

    # An unknown permission protocol cannot fall through to the generic path.
    changed = deepcopy(result)
    document = changed["config"]["scoring_oracles"][index]["document"]
    document["oracle_protocol"] = {
        **document["oracle_protocol"], "kind": "unknown-permission-protocol",
    }
    assert not accepted(changed, resealed(changed, index))

    # Current-only outcome metadata without the marker stays current and refused,
    # even when the independently recorded plan identity is also stripped.
    changed = deepcopy(result)
    changed.pop("research_plan_identity", None)
    changed["config"]["scoring_oracles"][index]["document"].pop("control_semantics")
    assert permission_evidence_mode(
        changed, changed["config"]["scoring_oracles"][index]["document"],
    ) == "invalid"
    assert not accepted(changed, resealed(changed, index))


def test_http500_login_url_is_not_an_authentication_redirect():
    from evaluation import permission_oracle
    from foundation.verifier import (
        permission_control_outcome_problem,
        permission_url_is_login,
    )

    response = SimpleNamespace(
        status_code=500, text="Server error", url=f"{TARGET}/login.php",
    )
    outcome = permission_oracle._control_outcome(
        "ac_idor", response, resource_visible=False, target=TARGET,
    )
    assert outcome["control_outcome"] == "http_error"
    assert outcome["interpretable"] is False
    assert permission_url_is_login(outcome["final_url"])
    assert permission_control_outcome_problem(
        {"control_outcome": "denied", "denial_kind": "endpoint_denied",
         "status_code": 500, "final_url": f"{TARGET}/login.php",
         "interpretable": True},
        target=TARGET,
    ) == "denied_outcome_inconsistent"


@pytest.mark.skipif(
    not HISTORICAL_ARTIFACT.is_file(),
    reason="retained restored-epoch permission artifact is not present",
)
def test_historical_permission_evidence_is_source_bound_read_only():
    raw = HISTORICAL_ARTIFACT.read_bytes()
    artifact = json.loads(raw)
    row = next(
        row for row in artifact["final_state"]["response_evidence"]
        if isinstance(row, dict) and row.get("oracle_ref")
    )
    index = int(row["oracle_ref"].split("/")[3])
    document = artifact["config"]["scoring_oracles"][index]["document"]
    assert permission_evidence_mode(artifact, document) == "historical-source-bound"
    assert oracle_confirmed(artifact, row)

    changed = deepcopy(artifact)
    source = changed["config"]["scoring_oracles"][index]
    control = next(c for c in source["document"]["controls"]
                   if c["control"] == "anonymous_denied")
    control["status_code"] = 500
    source["sha256"] = evidence_hash(source["document"])
    assert not oracle_confirmed(changed, _oracle_row(changed, row["evidence_id"]))

    changed = deepcopy(artifact)
    source = changed["config"]["scoring_oracles"][index]
    control = next(c for c in source["document"]["controls"]
                   if c["control"] == "anonymous_denied")
    control.update(
        status_code=200, control_outcome="denied", denial_kind="endpoint_denied",
        interpretable=True, final_url=f"{changed['config']['target_url']}/login.php",
    )
    source["sha256"] = evidence_hash(source["document"])
    assert permission_evidence_mode(changed, source["document"]) == "invalid"
    assert not oracle_confirmed(changed, _oracle_row(changed, row["evidence_id"]))
    assert HISTORICAL_ARTIFACT.read_bytes() == raw
