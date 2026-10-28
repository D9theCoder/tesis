"""Focused regressions for static routing and independent oracle collection."""
from copy import deepcopy

import pytest

from core.knowledge_graph import AttackKnowledgeGraph
from evaluation import dependency_oracle, permission_oracle, session_oracle
from evaluation.scoring_evidence import attach_oracle_evidence, oracle_confirmed
from tests.test_scoring_v4_permission_chain_e2e import FakeSession, chain_artifact


@pytest.mark.parametrize("value", ["false", "true", 1, [], {"value": True}])
def test_method_preconditions_require_observed_boolean_true(value):
    assert AttackKnowledgeGraph().get_viable_methods("brute_force", {"no_rate_limit": value}) == []


def test_static_chain_rejects_unregistered_destination_agent():
    class InvalidAgentGraph(AttackKnowledgeGraph):
        def _build_graph(self):
            super()._build_graph()
            self.graph.edges["authenticated_session", "ac_idor"]["target_agent"] = "unknown_agent"

    with pytest.raises(ValueError, match="target_agent"):
        InvalidAgentGraph()


def session_fixture(monkeypatch, material="gordonb:fixture-secret"):
    FakeSession.instances = []
    monkeypatch.setattr(session_oracle, "DVWASession", FakeSession)
    artifact, candidate, _, row, _, _ = chain_artifact()
    candidate["payload_or_logic"] = material
    raw = deepcopy(artifact["final_state"])
    return artifact, raw, row


def test_session_collection_is_idempotent(monkeypatch):
    artifact, raw, _ = session_fixture(monkeypatch)
    collected = session_oracle.collect_session_oracles(artifact, raw)
    calls = len(FakeSession.instances)
    assert session_oracle.collect_session_oracles(collected, raw) == collected
    assert len(FakeSession.instances) == calls


def test_session_oracle_uses_same_credential_prefix_as_executor(monkeypatch):
    artifact, raw, _ = session_fixture(monkeypatch, "gordonb:fixture-secret; pacing=slow")
    collected = session_oracle.collect_session_oracles(artifact, raw)
    attach_oracle_evidence(collected)
    assert oracle_confirmed(collected, collected["final_state"]["response_evidence"][0])


def test_session_collection_preserves_original_response_identity(monkeypatch):
    artifact, raw, row = session_fixture(monkeypatch)
    original = deepcopy(row)
    collected = session_oracle.collect_session_oracles(artifact, raw)
    enriched = collected["final_state"]["response_evidence"][0]
    assert {key: enriched[key] for key in original} == original
    attach_oracle_evidence(collected)
    assert oracle_confirmed(collected, enriched)
    assert artifact["final_state"]["response_evidence"][0] == original


def test_session_collection_keeps_missing_binding_diagnostic(monkeypatch):
    artifact, raw, _ = session_fixture(monkeypatch)
    raw["payload_validation_results"]["bf_dictionary"] = []
    collected = session_oracle.collect_session_oracles(artifact, raw)
    generated = [source["document"] for source in collected["config"]["scoring_oracles"]
                 if source["document"].get("protocol_source_sha256")]
    assert len(generated) == 1
    assert generated[0]["status"] == "pending"
    assert generated[0]["reason"] == "candidate_evidence_binding_incomplete"
    assert FakeSession.instances == []


def collected_chain(monkeypatch, session_type=FakeSession):
    FakeSession.instances = []
    for module in (dependency_oracle, permission_oracle, session_oracle):
        monkeypatch.setattr(module, "DVWASession", session_type)
    monkeypatch.setattr("foundation.session_manager.DVWASession", session_type)
    artifact, candidate, _, source, _, _ = chain_artifact()
    raw = deepcopy(artifact["final_state"])
    raw["found_credentials"] = [{"username": "gordonb", "password": "fixture-secret",
        "source_evidence_id": source["evidence_id"], "source_candidate_id": candidate["candidate_id"],
        "source_visit_id": source["visit_id"], "representation": "plaintext"}]
    result = permission_oracle.collect_permission_oracles(artifact, raw)
    result = session_oracle.collect_session_oracles(result, raw)
    attach_oracle_evidence(result)
    return result, raw


def test_dependency_collection_is_idempotent_before_http(monkeypatch):
    artifact, raw = collected_chain(monkeypatch)
    result = dependency_oracle.collect_dependency_oracles(artifact, raw)
    calls = len(FakeSession.instances)
    assert dependency_oracle.collect_dependency_oracles(result, raw) == result
    assert len(FakeSession.instances) == calls


def test_dependency_collection_restores_existing_reference_without_http(monkeypatch):
    artifact, raw = collected_chain(monkeypatch)
    result = dependency_oracle.collect_dependency_oracles(artifact, raw)
    consumption = result['final_state']['chain_history'][0]['consumption'][0]
    expected = consumption.pop('dependency_ref')
    calls = len(FakeSession.instances)
    restored = dependency_oracle.collect_dependency_oracles(result, raw)
    assert restored['final_state']['chain_history'][0]['consumption'][0]['dependency_ref'] == expected
    assert len(FakeSession.instances) == calls
    from evaluation.scoring_evidence import verified_dependencies
    assert len(verified_dependencies(restored)) == 1


def test_public_exposure_retains_failed_causal_control(monkeypatch):
    class PublicDataSession(FakeSession):
        def get(self, path, params=None):
            response = super().get(path, params)
            if str(path).endswith("get_user_data.php"):
                response.text = '[{"user_id":"1","first_name":"admin"}]'
                response.status_code = 200
            return response

    artifact, raw = collected_chain(monkeypatch, PublicDataSession)
    result = dependency_oracle.collect_dependency_oracles(artifact, raw)
    docs = [source["document"] for source in result["config"]["scoring_oracles"]
            if source["document"].get("oracle_protocol", {}).get("kind") == "dvwa_causal_dependency.v1"
            and source["document"].get("protocol_source_sha256")]
    assert len(docs) == 1
    assert docs[0]["status"] == "not_dependent"
    assert docs[0]["reason"] == "destination_available_without_source"
    assert len(docs[0]["dependency_controls"]) == 2
    assert docs[0]["dependencies"] == []
    from evaluation.scoring_evidence import verified_dependencies
    assert verified_dependencies(result) == []


def test_admin_credentials_do_not_schedule_nonadmin_permission_chain():
    from core.chaining_coordinator import evaluate_chain_route
    from tests.test_chaining_coordinator import proved_chain_source
    state = {**proved_chain_source("authenticated_session"), "achieved_outcomes": ["authenticated_session"],
        "experiment_condition": "akg_guided_hybrid", "current_surface": "brute_force",
        "observations": {"force_browse_endpoints_visible": True}, "iteration_count": 1}
    state["found_credentials"][0]["username"] = "admin"
    agent, event = evaluate_chain_route(state)
    assert agent != "ac_force_browse"
    assert any(row["reason"] == "nonadmin_source_principal_unavailable" for row in event["infeasible_routes"])


@pytest.mark.parametrize("method,status_code", [("ac_idor", 200), ("ac_force_browse", 403)])
def test_permission_denial_has_independent_negative_oracle(monkeypatch, method, status_code):
    class DeniedSession(FakeSession):
        def get(self, path, params=None):
            response = super().get(path, params)
            if str(path).endswith("get_user_data.php") and self.principal != "admin":
                response.text = '{"result":"fail","error":"Access denied"}'
                response.status_code = 200
            if method == "ac_force_browse" and str(path).rstrip("/").endswith("authbypass") and self.principal != "admin":
                response.text = 'Unauthorised'
                response.status_code = 403
            return response

    monkeypatch.setattr(permission_oracle, "DVWASession", DeniedSession)
    monkeypatch.setattr("foundation.session_manager.DVWASession", DeniedSession)
    artifact, _, _, _, row, _ = chain_artifact()
    row.update(signal_detected=False, success=False, verified_grade=0, status_code=status_code, agent_id=method)
    state = artifact["final_state"]
    state["verifier_history"][1].update(decision="not_confirmed", confirmed_vulns=[], agent_id=method)
    if method == "ac_force_browse":
        candidate = state["payload_candidates"].pop("ac_idor")[0]
        candidate.update(method=method, payload_or_logic="vulnerabilities/authbypass/", target_param="path")
        state["payload_candidates"][method] = [candidate]
        state["payload_validation_results"][method] = state["payload_validation_results"].pop("ac_idor")
        row.update(payload="vulnerabilities/authbypass/", object_id="dvwa-path:/vulnerabilities/authbypass/",
                   endpoint="http://fixture.invalid/dvwa/vulnerabilities/authbypass/")
    raw = deepcopy(artifact["final_state"])
    row.pop("consumed_source_evidence_id")
    raw["response_evidence"][1].pop("consumed_source_evidence_id")
    result = permission_oracle.collect_permission_oracles(artifact, raw)
    attach_oracle_evidence(result)
    from evaluation.scoring_evidence import oracle_negative_confirmed, candidate_base
    saved = result["final_state"]["response_evidence"][1]
    assert oracle_negative_confirmed(result, saved)
    assert not oracle_confirmed(result, saved)
    assert candidate_base(result, saved["candidate_id"], saved["agent_id"],
                          ["#/final_state/response_evidence/1"]) == 0
    from core.run_status import terminal_status
    result['final_state']['payload_candidates'].pop('bf_dictionary')
    assert terminal_status(result, classify=True)['security_outcome'] == 'no_finding'
    saved["object_id"] = "different-object"
    assert not oracle_negative_confirmed(result, saved)


def test_rejected_credential_has_independent_negative_oracle(monkeypatch):
    artifact, raw, row = session_fixture(monkeypatch, "gordonb:wrong-secret")
    row.update(success=False, signal_detected=False, verified_grade=0,
               verification_reason="login_not_confirmed", response_excerpt="Username and/or password incorrect.")
    raw = deepcopy(artifact["final_state"])
    result = session_oracle.collect_session_oracles(artifact, raw)
    attach_oracle_evidence(result)
    from evaluation.scoring_evidence import oracle_negative_confirmed
    saved = result["final_state"]["response_evidence"][0]
    assert oracle_negative_confirmed(result, saved)
    assert not oracle_confirmed(result, saved)
    # Historical collected sources are checked again when read, even when an
    # older collector issued a negative from a token-error response.
    saved["response_excerpt"] = "CSRF token is incorrect"
    assert not oracle_negative_confirmed(result, saved)


def test_collected_oracle_rejects_missing_frozen_parent(monkeypatch):
    artifact, raw, _ = session_fixture(monkeypatch)
    result = session_oracle.collect_session_oracles(artifact, raw)
    attach_oracle_evidence(result)
    row = result["final_state"]["response_evidence"][0]
    assert oracle_confirmed(result, row)
    result["config"]["scoring_oracles"][1]["sha256"] = "0" * 64
    assert not oracle_confirmed(result, row)


def test_replay_success_cannot_overwrite_a_negative_execution(monkeypatch):
    artifact, raw, row = session_fixture(monkeypatch)
    row.update(success=False, signal_detected=False)
    raw = deepcopy(artifact["final_state"])
    result = session_oracle.collect_session_oracles(artifact, raw)
    attach_oracle_evidence(result)
    assert not oracle_confirmed(result, result["final_state"]["response_evidence"][0])


def test_unsuccessful_execution_retains_explicit_negative_signal():
    from agents.agent_telemetry import exploit_event
    from agents.state_utils import make_update
    update = make_update(state={"target_url": "http://fixture.invalid/dvwa"}, module_name="bf_dictionary",
        score=0, tried_payloads=["gordonb:bad"], telemetry_events=[exploit_event("bf_dictionary", "gordonb:bad", 200, False)])
    assert update['response_evidence'][0]['signal_detected'] is False


def test_permission_descriptor_supports_all_explicitly_frozen_objects():
    from evaluation.permission_oracle import _request_descriptor
    row={'agent_id':'ac_idor', 'endpoint':'http://fixture.invalid/dvwa/vulnerabilities/authbypass/get_user_data.php',
         'payload':'userId=2', 'object_id':'dvwa-user:2'}
    assert _request_descriptor('http://fixture.invalid/dvwa', row, {'protected_user_ids':['1','2']}) is not None
    assert _request_descriptor('http://fixture.invalid/dvwa', row, {'protected_user_ids':['1']}) is None


def test_permission_descriptor_matches_original_dot_alias_to_same_wire_resource():
    from evaluation.permission_oracle import _request_descriptor
    row={'agent_id':'ac_force_browse', 'endpoint':'http://fixture.invalid/dvwa/vulnerabilities/authbypass/./',
         'payload':'vulnerabilities/authbypass/./', 'object_id':'dvwa-path:/vulnerabilities/authbypass/./'}
    descriptor=_request_descriptor('http://fixture.invalid/dvwa', row, {'protected_paths':['/vulnerabilities/authbypass/']})
    assert descriptor == ('/vulnerabilities/authbypass/', {}, row['object_id'], 'read')
    row['endpoint']='http://fixture.invalid/dvwa/vulnerabilities/authbypass/'
    assert _request_descriptor('http://fixture.invalid/dvwa', row, {'protected_paths':['/vulnerabilities/authbypass/']}) == descriptor
    row['object_id']='dvwa-path:/security.php'
    assert _request_descriptor('http://fixture.invalid/dvwa', row, {'protected_paths':['/vulnerabilities/authbypass/']}) is None


def test_force_browse_does_not_repeat_equivalent_wire_paths():
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from agents.access_control.ac_force_browse_agent import _attempt_exploit
    session=MagicMock()
    session.http.cookies={'PHPSESSID':'control'}
    session._principal_id='gordonb'
    session._initial_session_fingerprint='initial'
    session.get.return_value=SimpleNamespace(status_code=403, text='Unauthorised')
    _attempt_exploit(session,['vulnerabilities/authbypass/','vulnerabilities/authbypass/./'],set())
    assert session.get.call_count == 1


def test_permission_denial_envelope_does_not_prove_vertical_probe():
    from types import SimpleNamespace
    from agents.access_control.ac_vertical_escalation_agent import _probe_preconditions
    class Denied:
        _principal_id='gordonb'
        _initial_session_fingerprint='initial'
        def get(self, *args, **kwargs):
            return SimpleNamespace(status_code=200, text='{"result":"fail","error":"Access denied"}')
    passed, _, observations, _ = _probe_preconditions(Denied(), ['2'], set())
    assert passed is False
    assert observations['role_based_access_present'] is False


def test_selected_exploit_replay_retains_saved_queue_probes(monkeypatch, tmp_path):
    from evaluation.payload_replay import replay_method_inputs
    from evaluation.reporter import write_json_report
    from tests.test_scoring_remediation_e2e import control
    artifact, _, _ = control(monkeypatch, 'mixed_candidates')
    frozen = artifact['method_execution_inputs'][0]['state']
    method = frozen['selected_method']
    queue = frozen['payload_candidates'][method]
    assert any(candidate.get('stage') == 'probe' for candidate in queue)
    selected = next(candidate['candidate_id'] for candidate in queue if candidate.get('stage') == 'exploit')
    source = tmp_path / 'source.json'
    write_json_report(source, artifact)
    result = replay_method_inputs(source, output_path=tmp_path / 'replay.json', candidate_ids=[selected])
    assert result['validation_rejections'] == []
    assert result['fresh_provider_calls'] == 0
    assert any(row.get('stage') == 'probe' for row in result['response_evidence'])
    assert {row['candidate_id'] for row in result['response_evidence'] if row.get('stage') == 'exploit'} == {selected}


@pytest.mark.parametrize("visible", [True, False])
def test_chain_measures_idor_in_recovered_principal_once(monkeypatch, visible):
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from core.chaining_coordinator import chaining_router_node
    from core.state import new_default_state
    from evaluation.payload_replay import _apply_state_update
    from tests.test_chaining_coordinator import proved_chain_source
    state={**new_default_state(), **proved_chain_source('authenticated_session'),
        'target_url':'http://fixture.invalid/dvwa', 'experiment_condition':'akg_guided_hybrid',
        'current_surface':'brute_force','stop_policy':'coverage','coverage_target':1.0,
        'achieved_outcomes':['authenticated_session'],'attempted_agents':['bf_dictionary','ac_force_browse'],
        'observations':{'no_rate_limit':True,'object_ids_enumerable':False}}
    session=MagicMock()
    session.http.cookies={'PHPSESSID':'control-session'}
    session.get.return_value=SimpleNamespace(status_code=200, url='http://fixture.invalid/dvwa/vulnerabilities/authbypass/get_user_data.php',
        text='[{"user_id":"2","first_name":"gordonb"}]' if visible else '{"result":"fail","error":"Access denied"}')
    factory=MagicMock(return_value=(session,'fixture-user','initial-session','source-evidence'))
    monkeypatch.setattr('agents.access_control.session.open_access_control_session', factory)
    update=chaining_router_node(state)
    assert update['observations']['object_ids_enumerable'] is visible
    assert state['observations']['object_ids_enumerable'] is False
    assert (update['next_agent']=='ac_idor') is visible
    assert factory.call_args.args[0]['active_chain_route']['source_evidence_ids']==['source-evidence']
    session.close.assert_called_once()
    calls=session.get.call_count
    chaining_router_node(_apply_state_update(state, update))
    assert session.get.call_count==calls


def test_ready_higher_priority_chain_skips_lower_priority_probe(monkeypatch):
    from importlib import import_module
    from unittest.mock import MagicMock
    from core.chaining_coordinator import chaining_router_node
    from tests.test_chaining_coordinator import proved_chain_source
    state={**proved_chain_source('authenticated_session'),'achieved_outcomes':['authenticated_session'],
        'experiment_condition':'akg_guided_hybrid','observations':{'force_browse_endpoints_visible':True}}
    probe=MagicMock(side_effect=AssertionError('unnecessary HTTP'))
    monkeypatch.setattr(import_module('foundation.recon'),'probe_access_control_destination',probe)
    assert chaining_router_node(state)['next_agent']=='ac_force_browse'
    probe.assert_not_called()


def test_separate_chain_branches_do_not_create_a_nonexistent_path_edge():
    from core.chaining_coordinator import chaining_router_node
    from tests.test_chaining_coordinator import proved_chain_source
    state={**proved_chain_source('authenticated_session'),'achieved_outcomes':['authenticated_session'],
        'experiment_condition':'akg_guided_hybrid','current_surface':'brute_force',
        'attempted_agents':['bf_dictionary','ac_force_browse'],
        'observations':{'no_rate_limit':True,'object_ids_enumerable':True},
        'akg_path':['authenticated_session','ac_force_browse']}
    update=chaining_router_node(state)
    assert update['next_agent']=='ac_idor'
    assert 'akg_path' not in update
    assert update['current_chain']==['authenticated_session','ac_idor']
    assert update['active_chain_route']['chain']==['authenticated_session','ac_idor']


def test_access_control_destination_probe_records_scope_violation(monkeypatch):
    from importlib import import_module
    from foundation.http_client import ContainmentError
    def rejected(*args):
        raise ContainmentError('external redirect blocked', url='https://external.invalid/', allowed_host='fixture.invalid')
    monkeypatch.setattr('agents.access_control.session.open_access_control_session', rejected)
    result=import_module('foundation.recon').probe_access_control_destination(
        {'target_url':'http://fixture.invalid/dvwa'},'ac_idor',['source-evidence'])
    assert result['observations']=={}
    assert result['containment_events'][0]['blocked_url']=='https://external.invalid/'
    assert result['telemetry_events'][-1]['payload']['reason']=='containment_violation'


def test_extracted_plaintext_dependency_needs_no_permission_protocol(monkeypatch):
    for module in (dependency_oracle, session_oracle):
        monkeypatch.setattr(module, "DVWASession", FakeSession)
    monkeypatch.setattr("foundation.session_manager.DVWASession", FakeSession)
    artifact, source_candidate, dest_candidate, source, dest, route = chain_artifact()
    source_candidate.update(method="sqli_union", payload_or_logic="union candidate", target_param="id")
    dest_candidate.update(method="bf_dictionary", payload_or_logic="gordonb:fixture-secret", target_param="credential_pair")
    source.update(agent_id="sqli_union", verification_reason="verified_account_extraction")
    dest.update(agent_id="bf_dictionary", success=True, signal_detected=True,
                verification_reason="verified_login", verified_grade=3)
    route.update(source="credentials_extracted", target="bf_dictionary", target_agent="bf_dictionary",
        preconditions=["credentials_extracted"], prerequisite_evidence_refs={"credentials_extracted": ["#/final_state/verifier_history/0"]})
    state = artifact["final_state"]
    state["payload_candidates"] = {"sqli_union": [source_candidate], "bf_dictionary": [dest_candidate]}
    state["payload_validation_results"] = {method: [{"candidate_id": candidates[0]["candidate_id"], "valid": True}]
        for method, candidates in state["payload_candidates"].items()}
    for method, candidates in state["payload_candidates"].items():
        state["payload_provenance"][candidates[0]["candidate_id"]]["method"] = method
    state["verifier_history"][0].update(agent_id="sqli_union", confirmed_vulns=["sqli_union_confirmed"], achieved_outcomes=["credentials_extracted"])
    state["verifier_history"][1].update(agent_id="bf_dictionary", confirmed_vulns=["bf_dictionary_confirmed"])
    artifact["config"]["scoring_oracles"] = [s for s in artifact["config"]["scoring_oracles"]
        if s["document"]["oracle_protocol"]["kind"] != "dvwa_candidate_permission.v1"]
    raw = deepcopy(state)
    raw["found_credentials"] = [{"username": "gordonb", "password": "fixture-secret", "representation": "plaintext",
        "source_evidence_id": source["evidence_id"], "source_candidate_id": source["candidate_id"], "source_visit_id": source["visit_id"]}]
    # Put another valid recovered pair first: the consumed candidate is Gordon's.
    raw["found_credentials"].insert(0, {**raw["found_credentials"][0], "username": "admin", "password": "password"})
    artifact = session_oracle.collect_session_oracles(artifact, raw)
    attach_oracle_evidence(artifact)
    result = dependency_oracle.collect_dependency_oracles(artifact, raw)
    from evaluation.scoring_evidence import verified_dependencies
    dependencies = verified_dependencies(result)
    assert len(dependencies) == 1
    from hashlib import sha256
    from evaluation.thesis_scoring import _resolve
    attestation = _resolve(result, dependencies[0]["consumption"]["dependency_ref"])
    assert attestation["material_fingerprint"] == sha256(b"gordonb\0fixture-secret").hexdigest()


@pytest.mark.parametrize("body", ["CSRF token is incorrect", "CSRF token is incorrect. Username and/or password incorrect.", "Please enter credentials", "CAPTCHA challenge"])
def test_unevaluated_credentials_cannot_receive_negative_attestation(monkeypatch, body):
    artifact, raw, row = session_fixture(monkeypatch, "gordonb:wrong-secret")
    row.update(success=False, signal_detected=False, response_excerpt=body,
        verified_grade=0, verification_reason="login_not_confirmed")
    artifact["final_state"]["verifier_history"][0]["decision"] = "not_confirmed"
    raw = deepcopy(artifact["final_state"])
    result = session_oracle.collect_session_oracles(artifact, raw)
    attach_oracle_evidence(result)
    from evaluation.scoring_evidence import oracle_negative_confirmed, candidate_base
    saved = result["final_state"]["response_evidence"][0]
    assert not oracle_negative_confirmed(result, saved)
    assert FakeSession.instances == []
    assert result["config"]["scoring_oracles"][-1]["document"]["reason"] == "execution_credential_rejection_unavailable"
    assert candidate_base(result, saved["candidate_id"], saved["agent_id"], ["#/final_state/response_evidence/0"]) == 0
    from core.run_status import terminal_status
    result["final_state"]["payload_candidates"].pop("ac_idor")
    status = terminal_status(result, classify=True)
    assert status["security_outcome"] == "fixture_limited"
    assert status["security_outcome_reason"]["code"] == "SESSION_ORACLE_UNAVAILABLE"


def test_dependency_material_matches_consumed_pair_among_multiple_extractions():
    source = dict(agent_id="sqli_union", evidence_id="source", candidate_id="union", visit_id="visit")
    credentials = [dict(username=user, password=secret, representation="plaintext",
        source_evidence_id="source", source_candidate_id="union", source_visit_id="visit")
        for user, secret in [("admin", "first"), ("gordonb", "second")]]
    state = dict(found_credentials=credentials)
    assert dependency_oracle._material(dict(payload_or_logic="gordonb:second"), state, source) == ("gordonb", "second")
    assert dependency_oracle._material(dict(payload_or_logic="gordonb:missing"), state, source) is None
