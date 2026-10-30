"""Focused regressions for static routing and independent oracle collection."""
from copy import deepcopy

import pytest

from core.knowledge_graph import AttackKnowledgeGraph
from evaluation import session_oracle
from evaluation.scoring_evidence import attach_oracle_evidence, oracle_confirmed
from tests.test_scoring_v4_permission_chain_e2e import FakeSession, chain_artifact


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


def test_replay_success_cannot_overwrite_a_negative_execution(monkeypatch):
    artifact, raw, row = session_fixture(monkeypatch)
    row.update(success=False, signal_detected=False)
    raw = deepcopy(artifact["final_state"])
    result = session_oracle.collect_session_oracles(artifact, raw)
    attach_oracle_evidence(result)
    assert not oracle_confirmed(result, result["final_state"]["response_evidence"][0])


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


@pytest.mark.parametrize("visible", [True, False])
def test_chain_measures_idor_in_recovered_principal_once(monkeypatch, visible):
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from core.chaining_coordinator import chaining_router_node
    from core.state import new_default_state
    from evaluation.payload_replay import _apply_state_update
    from foundation.preconditions import make_observation_fact
    from tests.test_chaining_coordinator import proved_chain_source
    state={**new_default_state(), **proved_chain_source('authenticated_session'),
        'target_url':'http://fixture.invalid/dvwa', 'experiment_condition':'akg_guided_hybrid',
        'current_surface':'brute_force','stop_policy':'coverage','coverage_target':1.0,
        'achieved_outcomes':['authenticated_session'],'attempted_agents':['bf_dictionary','ac_force_browse'],
        'observations':{'no_rate_limit':True,'object_ids_enumerable':False}}
    # The old negative was measured in a different session; it cannot block
    # a destination control for the recovered principal.
    state['observation_facts'] = [make_observation_fact(
        'object_ids_enumerable', False, source='previous_session',
        method='ac_idor', security_level='low', principal_id='pablo',
        session_fingerprint='previous-session', session_scope='session')]
    session=MagicMock()
    session.http.cookies={'PHPSESSID':'control-session'}
    from foundation.session_manager import session_fingerprint
    session.get.return_value=SimpleNamespace(status_code=200, url='http://fixture.invalid/dvwa/vulnerabilities/authbypass/get_user_data.php',
        text='[{"user_id":"2","first_name":"gordonb"}]' if visible else '{"result":"fail","error":"Access denied"}')
    factory=MagicMock(return_value=(session,'gordonb',session_fingerprint(session),'source-evidence'))
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


def test_every_chain_edge_has_an_adapter_or_an_explicit_opt_out():
    """D4: static AKG chain edges and the source-consumption adapters cannot drift apart."""
    from core.chaining_coordinator import chain_adapter_gaps

    assert chain_adapter_gaps() == []
