"""Behavior controls for readiness, scoped evidence, and bounded detection.

These tests cover the runtime contract implemented by slice B.  They do not
perform live DVWA or provider calls; every HTTP interaction is a fake session.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agents.state_utils import (
    candidate_budget_receipt,
    candidate_lifecycle_fact,
    candidate_payloads_for_stage,
    make_update,
    method_selection_update,
    previously_executed_exploit_payloads,
    probe_outcome_update,
)
from core.chaining_coordinator import build_chain_assessment
from core.state import new_default_state
from foundation.control_catalog import (
    INVALID_OBJECT_ID,
    catalog_rows,
    excluded_unsafe_controls,
    freeze_detection_controls,
    resolve_control_payload,
    validate_detection_controls,
)
from foundation.preconditions import (
    derive_precondition_status,
    make_observation_fact,
    observation_update,
)
from foundation.readiness import build_readiness, readiness_gate
from foundation.session_manager import DVWASession
from tests.support import ready_state


def _fact(key, value, **overrides):
    payload = {"source": "detection_control", "method": "sqli_error",
               "security_level": "low", "visit_id": "sqli_error:visit:1"}
    payload.update(overrides)
    return make_observation_fact(key, value, **payload)


def _state_with_fact(key, value, **overrides):
    state = ready_state()
    fact = _fact(key, value, **overrides)
    state.update(observation_update(state, [fact], method="sqli_error"))
    state["observation_facts"] = [fact]
    return state


def _fake_llm(decisions):
    class FakeLLM:
        def __init__(self):
            self.calls = 0

        def invoke(self, messages):
            decision = decisions[min(self.calls, len(decisions) - 1)]
            self.calls += 1
            return SimpleNamespace(content=json.dumps(decision))

    return FakeLLM()


# ---------------------------------------------------------------- evidence


def test_endpoint_discovery_never_becomes_precondition_evidence():
    update = _state_with_fact("error_messages_enabled", True)
    # A discovered endpoint label alone is not a fact.
    state = new_default_state()
    state["endpoints"] = [{"url": "http://x/vulnerabilities/sqli/", "module_name": "sqli"}]
    assert derive_precondition_status(state)["error_messages_enabled"] == "unknown"
    assert "error_messages_enabled" not in state["observations"]
    # A measured fact does establish it; the legacy view reflects measured truth.
    assert update["precondition_status"]["error_messages_enabled"] == "true"
    assert update["observations"]["error_messages_enabled"] is True


def test_latest_measured_negative_corrects_positive_without_erasing_history():
    first = _fact("error_messages_enabled", True, detail="probe positive")
    second = _fact("error_messages_enabled", False, detail="repeat negative")
    state = new_default_state()
    update = observation_update(state, [first, second], method="sqli_error")
    assert update["precondition_status"]["error_messages_enabled"] == "false"
    assert update["observations"]["error_messages_enabled"] is False
    assert len(update["observation_facts"]) == 2


def test_transport_unknown_does_not_become_false():
    unknown = _fact("response_delay_measurable", None, method="sqli_time_blind",
                    detail="baseline unavailable")
    state = new_default_state()
    state["observation_facts"] = [unknown]
    status = derive_precondition_status(state)
    assert status["response_delay_measurable"] == "unknown"


def test_failed_detection_transport_keeps_precondition_unknown():
    from foundation.http_client import TransportError
    from foundation.recon import _probe_with_catalog_controls

    session = MagicMock()
    session.http.cookies = {"PHPSESSID": "offline-session"}
    session.get.side_effect = TransportError("offline failure")
    state = new_default_state()
    state.update(target_url="http://localhost/dvwa", security_level="low",
                 execution_id="failed-control")

    update, quarantine = _probe_with_catalog_controls(
        state, "ac_force_browse", session, "low", principal_id="gordonb",
        phase="method_probe", snapshot_key="control")

    assert quarantine is None
    assert update["control_events"][0]["status"] == "failed"
    assert update["probe_controls"]["control"]["physical_requests_used"] == 1
    assert update["precondition_status"]["force_browse_endpoints_visible"] == "unknown"
    assert "force_browse_endpoints_visible" not in update["observations"]


# ---------------------------------------------------------------- readiness


def test_readiness_fails_closed_on_level_mismatch_and_preserves_coordinate():
    receipt = build_readiness(
        state={"current_surface": "sqli", "security_level": "high"},
        login_ok=True, requested_level="high", observed_level="low",
        endpoints=[{"url": "http://x/vulnerabilities/sqli/"},
                   {"url": "http://x/vulnerabilities/sqli_blind/"}],
        requested_principal="admin", observed_principal="admin",
        token_present=None, setup_state="authenticated_crawl")
    assert receipt["requested_level"] == "high"
    assert receipt["observed_level"] == "low"
    gate = readiness_gate(receipt)
    assert receipt["status"] == "failed"
    assert gate["decision"] == "block"
    assert gate["code"] == "security_level_mismatch"


def test_brute_force_token_requirement_is_observed_not_assumed():
    """Only a level whose form declares ``user_token`` requires a token."""
    medium = build_readiness(
        state={"current_surface": "brute_force", "security_level": "medium"},
        login_ok=True, requested_level="medium", observed_level="medium",
        endpoints=[{"url": "http://x/vulnerabilities/brute/",
                    "method": "get", "params": ["username", "password", "Login"]}],
        requested_principal="admin", observed_principal="admin",
        token_present=False, setup_state="authenticated_crawl")
    assert medium["token"]["required"] is False
    assert medium["status"] == "ready"

    declared_but_absent = build_readiness(
        state={"current_surface": "brute_force", "security_level": "high"},
        login_ok=True, requested_level="high", observed_level="high",
        endpoints=[{"url": "http://x/vulnerabilities/brute/",
                    "method": "get", "params": ["username", "password", "user_token"],
                    "csrf_token": "tok"}],
        requested_principal="admin", observed_principal="admin",
        token_present=False, setup_state="authenticated_crawl")
    assert declared_but_absent["token"]["required"] is True
    assert declared_but_absent["status"] == "failed"
    assert readiness_gate(declared_but_absent)["code"] == "required_token_missing"

    declared_and_present = build_readiness(
        state={"current_surface": "brute_force", "security_level": "high"},
        login_ok=True, requested_level="high", observed_level="high",
        endpoints=[{"url": "http://x/vulnerabilities/brute/",
                    "method": "get", "params": ["username", "password", "user_token"],
                    "csrf_token": "tok"}],
        requested_principal="admin", observed_principal="admin",
        token_present=True, setup_state="authenticated_crawl")
    assert declared_and_present["status"] == "ready"


def test_cookie_value_is_not_security_level_proof():
    session = DVWASession("http://localhost/dvwa")
    response = MagicMock()
    response.text = "no level marker here"
    session.http.get = MagicMock(return_value=response)
    session.http._client.cookies.set("security", "high", path="/")
    assert session.observed_security_level() is None
    # Legacy detection may still expose the cookie hint, but readiness never
    # consumes it as observed evidence.
    assert session.detect_security_level() == "high"


def test_security_form_requires_server_side_persistence():
    session = DVWASession("http://localhost/dvwa")
    page = MagicMock()
    page.text = '<input name="user_token" value="tok">'
    session.http.get = MagicMock(return_value=page)
    session.http.post = MagicMock(return_value=MagicMock())
    session.observed_security_level = MagicMock(return_value="medium")
    assert session._submit_security_form("low") is False
    session.observed_security_level = MagicMock(return_value="low")
    assert session._submit_security_form("low") is True


# --------------------------------------------------------------- catalog


def test_catalog_excludes_sensitive_canonical_force_browse_probes():
    rows = catalog_rows("ac_force_browse", "low")
    payloads = [row["payload_or_logic"] for row in rows]
    assert payloads == ["vulnerabilities/authbypass/"]
    excluded = excluded_unsafe_controls("ac_force_browse", "low")
    assert {row["payload_or_logic"] for row in excluded} == {"setup.php", "phpinfo.php"}
    assert all(row["sensitive_disclosure_risk"] for row in excluded)
    assert all(row["safety_class"] == "precondition_only" for row in rows)


def test_frozen_control_validation_is_fail_closed_on_tamper():
    state = {"selected_visit_id": "sqli_error:visit:1", "security_level": "low"}
    snapshot = freeze_detection_controls(state, "sqli_error", "sqli_error:visit:1")
    assert all(row["valid"] for row in validate_detection_controls(state, "sqli_error", snapshot))
    tampered = json.loads(json.dumps(snapshot))
    tampered["candidates"][0]["payload_or_logic"] += " tampered"
    assert any(not row["valid"] for row in validate_detection_controls(state, "sqli_error", tampered))
    tampered_budget = json.loads(json.dumps(snapshot))
    tampered_budget["candidates"][0]["requests_used"] = 99
    assert any(not row["valid"] for row in
               validate_detection_controls(state, "sqli_error", tampered_budget))


def test_synthetic_object_controls_resolve_against_verified_principal():
    assert resolve_control_payload("@self", "gordonb") == "2"
    assert resolve_control_payload("@self", "1337") == "3"
    assert resolve_control_payload("@self", "unknown") is None
    assert resolve_control_payload("@nonexistent", "gordonb") == INVALID_OBJECT_ID


def test_empty_brute_force_control_list_sends_zero_requests():
    from agents.brute_force.bf_dictionary_agent import _probe_preconditions

    session = MagicMock()
    ok, tried, observations, events = _probe_preconditions(
        session, [], set(), security_level="low")
    assert ok is False and tried == [] and observations == {} and events == []
    session.get.assert_not_called()
    session.post.assert_not_called()


# ------------------------------------------------------------- selection


def test_forced_false_precondition_stops_without_model_or_substitute(monkeypatch):
    from agents.orchestrator import orchestrator

    calls = []
    monkeypatch.setattr("agents.orchestrator.get_llm",
                        lambda *args, **kwargs: calls.append(1))
    state = _state_with_fact("error_messages_enabled", False)
    state.update({"target_url": "http://localhost/dvwa", "current_surface": "sqli",
                  "target_method": "sqli_error", "security_level": "low",
                  "selected_visit_id": None})
    update = orchestrator(state)
    assert calls == []
    assert update["next_agent"] == "scorer"
    assert update["selected_method"] is None
    assert update["task_result"] == "INCOMPLETE"
    assert update["selection_rejections"][0]["reason_code"] == "precondition_false"
    assert update["model_call_requirements"][0]["decision_source"] == "forced"
    assert update["model_call_requirements"][0]["required"] is False


def test_forced_unknown_precondition_allows_bounded_measurement(monkeypatch):
    from agents.orchestrator import orchestrator

    calls = []
    monkeypatch.setattr("agents.orchestrator.get_llm",
                        lambda *args, **kwargs: calls.append(1))
    state = ready_state()
    state.update({"target_url": "http://localhost/dvwa", "current_surface": "sqli",
                  "target_method": "sqli_union", "security_level": "low"})
    update = orchestrator(state)
    assert calls == []
    assert update["next_agent"] == "payload_candidate_builder"
    assert update["selected_method"] == "sqli_union"
    assert update["scoring_decisions"][0]["decision_origin"] == "forced"
    assert update["scoring_decisions"][0]["candidate_set_source"] == "forced"


def test_linear_canonical_and_akg_viable_inputs_are_distinct():
    from core.workflow_policy import eligible_methods

    state = _state_with_fact("error_messages_enabled", False)
    state.update({"current_surface": "sqli", "experiment_condition": "linear_hybrid"})
    linear = eligible_methods(state)
    state["experiment_condition"] = "akg_guided_hybrid"
    akg = eligible_methods(state)
    assert "sqli_error" in linear
    assert "sqli_error" not in akg


def test_rejected_model_selection_records_and_stops_without_retry(monkeypatch):
    from agents.orchestrator import orchestrator

    fake = _fake_llm([{"next_agent": "sqli_error", "reason_code": "first"}])
    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: fake)
    state = _state_with_fact("error_messages_enabled", False)
    state.update({"target_url": "http://localhost/dvwa", "current_surface": "sqli",
                  "experiment_condition": "linear_hybrid", "security_level": "low"})
    update = orchestrator(state)
    assert update["next_agent"] == "scorer"
    assert update["task_result"] == "INCOMPLETE"
    assert update["incomplete_reason"] == "SELECTION_REJECTED"
    assert update["selection_rejections"][0]["method"] == "sqli_error"
    assert update["selection_rejections"][0]["decision_origin"] == "model"
    assert update["selection_rejections"][0]["observations"]["error_messages_enabled"] is False
    assert update["model_call_requirements"][0]["status"] == "completed"
    assert "selection_rejected" in update["model_call_requirements"][0]["reason"]
    assert fake.calls == 1


def test_missing_readiness_blocks_direct_runtime_path(monkeypatch):
    from agents.orchestrator import orchestrator

    calls = []
    monkeypatch.setattr("agents.orchestrator.get_llm",
                        lambda *args, **kwargs: calls.append(1))
    state = new_default_state()
    state["readiness"] = None
    state.update({"target_url": "http://localhost/dvwa", "current_surface": "sqli"})
    update = orchestrator(state)
    assert calls == []
    assert update["next_agent"] == "scorer"
    assert update["llm_skip_reason"] == "READINESS_NOT_READY"
    assert update["execution_status"] == "failed"
    assert update["security_outcome"] == "fixture_limited"


# ------------------------------------------------------- execution identity


def _queue_state(payload="1' AND 1=1-- -"):
    state = new_default_state()
    state.update({
        "selected_visit_id": "sqli_error:visit:1",
        "selected_method": "sqli_error",
        "security_level": "low",
        "active_payload_candidates": {"sqli_error": {
            "visit_id": "sqli_error:visit:1", "candidate_ids": ["c1"],
            "status": "validated"}},
        "payload_candidates": {"sqli_error": [{
            "candidate_id": "c1", "method": "sqli_error", "stage": "exploit",
            "payload_or_logic": payload, "source": "static_seed"}]},
        "payload_validation_results": {"sqli_error": [{
            "candidate_id": "c1", "valid": True, "reason": "ok",
            "visit_id": "sqli_error:visit:1"}]},
    })
    return state


def test_probe_collision_is_not_execution_without_own_request():
    state = _queue_state()
    probe_event = {
        "event": "agent.probe.sent", "status": "ok",
        "payload": {"agent_id": "sqli_error", "payload": "1' AND 1=1-- -",
                    "status_code": 200, "signal_detected": True,
                    "response_sha256": "probehash", "response_excerpt": "err",
                    "control_id": "control:1", "identity_kind": "independent_control"},
    }
    update = make_update(state=state, module_name="sqli_error", score=1,
                         tried_payloads=["1' AND 1=1-- -"], telemetry_events=[probe_event])
    probe_evidence = update["response_evidence"][0]
    assert probe_evidence["identity_kind"] == "independent_control"
    assert probe_evidence.get("candidate_id") is None
    assert probe_evidence["eligible_for_exploit_denominator"] is False
    # The candidate stays explicitly unexecuted because no own request exists.
    row = update["candidate_lifecycle"][0]
    assert row["candidate_id"] == "c1"
    assert row["status"] == "stopped_before_execution"
    assert row["reason"] == "skipped_already_probed"


def test_own_candidate_request_binds_execution_and_budget_receipt():
    state = _queue_state()
    event = {
        "event": "agent.exploit.sent", "status": "ok",
        "payload": {"agent_id": "sqli_error", "payload": "1' AND 1=1-- -",
                    "status_code": 200, "success": True, "signal_detected": True,
                    "verified_grade": 3, "verification_reason": "verified_error_extraction",
                    "candidate_id": "c1", "response_sha256": "candidatehash",
                    "response_excerpt": "XPATH syntax error: '~dvwa'"},
    }
    update = make_update(state=state, module_name="sqli_error", score=3,
                         tried_payloads=["1' AND 1=1-- -"],
                         confirmed_vulns=["sqli_error_confirmed"], telemetry_events=[event])
    row = update["response_evidence"][0]
    assert row["identity_kind"] == "candidate"
    assert row["candidate_id"] == "c1"
    assert row["eligible_for_exploit_denominator"] is True
    assert previously_executed_exploit_payloads(
        {**state, **update}, "sqli_error", "sqli_error:visit:1") == {"1' AND 1=1-- -"}
    lifecycle = update["candidate_lifecycle"]
    assert lifecycle[0]["status"] == "executed"
    assert lifecycle[0]["reason"] == "own_request_recorded"
    receipt = candidate_budget_receipt({**state, **update}, "sqli_error", "sqli_error:visit:1")
    assert receipt["executed"] == ["c1"]
    assert receipt["candidate_evidence_rows"] == 1


def test_candidate_baseline_row_survives_export_without_candidate_credit():
    state = _queue_state()
    events = [
        {"event": "agent.probe.sent", "status": "ok",
         "payload": {"agent_id": "sqli_error", "payload": "1", "status_code": 200,
                     "signal_detected": False, "response_sha256": "basehash",
                     "response_excerpt": "clean", "control_id": "control:c1:baseline",
                     "source_candidate_id": "c1",
                     "validation_relation": "candidate_baseline"}},
        {"event": "agent.exploit.sent", "status": "ok",
         "payload": {"agent_id": "sqli_error", "payload": "1' AND 1=1-- -",
                     "status_code": 200, "success": True, "signal_detected": True,
                     "verified_grade": 1, "verification_reason": "candidate_error_signal",
                     "candidate_id": "c1", "response_sha256": "candidatehash",
                     "baseline_response_sha256": "basehash",
                     "baseline_control_id": "control:c1:baseline",
                     "response_excerpt": "You have an error in your SQL syntax"}},
    ]
    update = make_update(state=state, module_name="sqli_error", score=1,
                         tried_payloads=["1", "1' AND 1=1-- -"], telemetry_events=events)
    control_row = update["response_evidence"][0]
    candidate_row = update["response_evidence"][1]
    assert control_row["identity_kind"] == "derived_control"
    assert control_row["source_candidate_id"] == "c1"
    assert control_row.get("candidate_id") is None
    assert control_row["validation"]["candidate_id"] == "c1"
    assert control_row["validation_ref"] == "#/final_state/payload_validation_results/sqli_error/0"
    assert candidate_row["identity_kind"] == "candidate"
    assert candidate_row["baseline_response_sha256"] == "basehash"
    assert candidate_row["baseline_control_id"] == "control:c1:baseline"
    assert "control_id" not in candidate_row
    assert candidate_row["eligible_for_exploit_denominator"] is True


def test_derived_control_cannot_borrow_another_candidate_validation():
    state = _queue_state()
    event = {"event": "agent.probe.sent", "status": "ok",
             "payload": {"agent_id": "sqli_error", "payload": "1", "status_code": 200,
                         "control_id": "control:other:baseline",
                         "source_candidate_id": "other", "response_sha256": "basehash"}}
    update = make_update(state=state, module_name="sqli_error", score=0,
                         tried_payloads=["1"], telemetry_events=[event])
    row = update["response_evidence"][0]
    assert row["source_candidate_id"] == "other"
    assert row["candidate_link_status"] == "unmatched"
    assert row["validation"] is None and row["validation_ref"] is None
    assert row["eligible_for_exploit_denominator"] is False


# -------------------------------------------------------------- quarantine


def test_quarantined_run_blocks_orchestrator_without_model_call(monkeypatch):
    from agents.orchestrator import orchestrator

    calls = []
    monkeypatch.setattr("agents.orchestrator.get_llm",
                        lambda *args, **kwargs: calls.append(1))
    state = ready_state()
    state.update({
        "target_url": "http://localhost/dvwa", "current_surface": "sqli",
        "quarantined_visits": [{
            "visit_id": "sqli_error:visit:1", "method": "sqli_error",
            "control_id": "control:1", "control_class": "detection",
            "reason": "unexpected_sensitive_disclosure", "detail": "restricted data",
            "evidence_refs": ["control:1"],
            "restoration": {"status": "not-established", "evidence_refs": []}}],
    })
    update = orchestrator(state)
    assert calls == []
    assert update["next_agent"] == "scorer"
    assert update["incomplete_reason"] == "CONTROL_CONTAMINATION"
    assert update["security_outcome"] == "fixture_limited"


# ------------------------------------------------------------ chain trace


def test_chain_assessment_is_explicit_for_linear_and_missing_opportunity():
    state = new_default_state()
    state["experiment_condition"] = "linear_hybrid"
    linear = build_chain_assessment(state, status="not_applicable",
                                    reason="linear_condition_not_applicable")
    assert linear["assessed"] is False
    assert linear["status"] == "not_applicable"
    state["experiment_condition"] = "akg_guided_hybrid"
    missing = build_chain_assessment(state, status="insufficient_evidence",
                                     reason="no_proved_enabling_outcome")
    assert missing["assessed"] is False
    assert missing["status"] == "insufficient_evidence"
    assert missing["reason"] == "no_proved_enabling_outcome"


def test_chain_assessment_records_infeasible_conceptual_edge():
    state = new_default_state()
    state["experiment_condition"] = "akg_guided_hybrid"
    state["achieved_outcomes"] = ["credentials_extracted"]
    assessment = build_chain_assessment(state, status="assessed",
                                        reason="chain_opportunity_evaluated",
                                        evaluated_edges=1)
    edge = next(row for row in assessment["edges"]
                if row["source"] == "credentials_extracted"
                and row["target_agent"] == "bf_dictionary")
    assert edge["status"] in {"available", "infeasible"}
    assert edge["prerequisite_status"]["credentials_extracted"] == "proved"


# ------------------------------------------------------- method selection


def test_method_selection_receipts_record_origin_and_input_source():
    state = new_default_state()
    state.update({"current_surface": "sqli", "experiment_condition": "linear_hybrid"})
    update = method_selection_update(
        state, "sqli_union", "model_orchestrator",
        considered_methods=["sqli_union", "sqli_error"],
        candidate_set_source="canonical", decision_origin="model")
    decision = update["scoring_decisions"][0]
    assert decision["decision_origin"] == "model"
    assert decision["candidate_set_source"] == "canonical"
    assert decision["first_choice"] is True
    assert decision["considered_methods"] == ["sqli_union", "sqli_error"]


# --------------------------------------------------- correction regressions


def test_fixture_restoration_evidence_is_source_bound():
    from foundation.readiness import validate_fixture_restoration_evidence

    evidence = {
        "policy_version": "fixture-restoration.v1",
        "evidence_id": "restore-1",
        "kind": "operator_attestation",
        "fixture_id": "fixture-1",
        "protocol_version": "protocol-1",
        "security_level": "low",
        "epoch_id": "epoch-1",
        "source_hashes_sha256": "a" * 64,
        "restoration": "reset",
        "authorized_protocol": "operator-reset.v1",
        "evidence_refs": ["evidence/restore-1.json"],
        "evidence_sha256": "b" * 64,
        "observed_at": "2026-10-28T00:00:00+00:00",
        "operator": "owner",
        "details": "authorized reset",
    }
    validated = validate_fixture_restoration_evidence(
        evidence, fixture_id="fixture-1", protocol_version="protocol-1",
        security_level="low", epoch_id="epoch-1",
        source_hashes_sha256="a" * 64)
    assert validated["restoration"] == "reset"
    with pytest.raises(ValueError):
        validate_fixture_restoration_evidence(
            evidence, fixture_id="other", protocol_version="protocol-1",
            security_level="low")


def test_fact_scope_requires_matching_principal_or_explicit_fixture_scope():
    from foundation.preconditions import derive_precondition_status, make_observation_fact

    privileged = make_observation_fact(
        "error_messages_enabled", True, source="detection_control",
        method="sqli_error", principal_id="admin", security_level="low")
    state = ready_state()
    state["readiness"] = {**state["readiness"],
        "session": {"principal": "gordonb", "fingerprint": "fp-gordonb"}}
    state["observation_facts"] = [privileged]
    assert derive_precondition_status(state)["error_messages_enabled"] == "unknown"
    state["method_principals"] = {"sqli_error": "admin"}
    assert derive_precondition_status(state)["error_messages_enabled"] == "true"


def test_linear_destination_gate_rejects_measured_false_prerequisite():
    from core.chaining_coordinator import _chain_infeasibility

    state = _state_with_fact("object_ids_enumerable", False, method="ac_idor")
    from tests.test_chaining_coordinator import proved_chain_source
    state.update(proved_chain_source("authenticated_session"))
    state.update({"current_surface": "access_control",
                  "experiment_condition": "linear_hybrid"})
    edge = {"source": "authenticated_session", "target": "idor_confirmed",
            "target_agent": "ac_idor", "preconditions": ["authenticated_session"]}
    assert _chain_infeasibility(state, edge, check_destination=False) is None
    assert _chain_infeasibility(state, edge) == "destination_preconditions_not_proved"


def test_failed_request_lifecycle_is_not_executed_or_denominator_eligible():
    state = _queue_state()
    event = {
        "event": "agent.exploit.sent", "status": "failed",
        "payload": {"agent_id": "sqli_error", "payload": "1' AND 1=1-- -",
                    "status_code": None, "success": False, "signal_detected": False,
                    "candidate_id": "c1"},
    }
    update = make_update(state=state, module_name="sqli_error", score=0,
                         tried_payloads=["1' AND 1=1-- -"], telemetry_events=[event])
    row = update["response_evidence"][0]
    assert row["eligible_for_exploit_denominator"] is False
    lifecycle = update["candidate_lifecycle"]
    assert lifecycle[0]["status"] == "stopped_before_execution"
    assert lifecycle[0]["reason"] == "request_failed"
    assert all(item["status"] != "executed" for item in lifecycle)


def test_budget_receipt_records_configured_and_effective_limit():
    state = _queue_state()
    state["candidate_budget"] = 1
    state["candidate_lifecycle"] = [
        candidate_lifecycle_fact(
            method="sqli_error", visit_id="sqli_error:visit:1",
            candidate_id="c1", origin_kind="static_seed",
            status="queued", reason=None),
    ]
    receipt = candidate_budget_receipt(state, "sqli_error", "sqli_error:visit:1")
    assert receipt["configured_candidate_budget"] == 1
    assert receipt["effective_candidate_budget"] == 1
    assert receipt["queued"] == ["c1"]


def test_http_request_accounting_counts_dispatch_redirect_and_failure():
    from foundation.http_client import (
        http_request_accounting,
        request_scope,
        snapshot_http_request_counters,
    )

    class FakeClient:
        def __init__(self):
            self.calls = 0

        def request(self, method, url, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return SimpleNamespace(status_code=302, headers={"location": "/next"})
            if self.calls == 2:
                return SimpleNamespace(status_code=200, headers={},
                    elapsed=SimpleNamespace(total_seconds=lambda: 0.0))
            raise __import__("httpx").NetworkError("down")

    client = __import__("foundation.http_client", fromlist=["HTTPClient"]).HTTPClient(
        "http://localhost/dvwa")
    client._client = FakeClient()
    with http_request_accounting() as counter:
        with request_scope(phase="recon", role="detection_control", method="sqli_error"):
            client.get("start")
    result = snapshot_http_request_counters(counter)
    assert result["total_requests"] == 2
    assert result["redirect_hops"] == 1
    assert result["by_phase"]["recon"] == 2
    assert result["by_role"]["detection_control"] == 2


def test_expired_session_evidence_cannot_revive_cached_preconditions():
    from core.workflow_policy import eligible_methods
    from foundation.preconditions import statuses_snapshot

    state = ready_state()
    state["readiness"]["session"] = {"principal": "admin", "fingerprint": "old"}
    fact = _fact(
        "error_messages_enabled", True, principal_id="admin",
        session_fingerprint="old", session_scope="session",
    )
    state.update(observation_update(state, [fact], method="sqli_error"))
    assert statuses_snapshot(state, "sqli_error")["error_messages_enabled"] == "true"
    state["readiness"]["session"]["fingerprint"] = "new"
    state["current_surface"] = "sqli"
    state["experiment_condition"] = "akg_guided_hybrid"
    assert state["observations"]["error_messages_enabled"] is True
    assert derive_precondition_status(state)["error_messages_enabled"] == "unknown"
    assert statuses_snapshot(state, "sqli_error")["error_messages_enabled"] == "unknown"
    assert "sqli_error" not in eligible_methods(state)


def test_shared_precondition_key_does_not_merge_distinct_method_measurements():
    from core.workflow_policy import eligible_methods
    from foundation.preconditions import statuses_snapshot

    state = ready_state()
    state.update(current_surface="brute_force", experiment_condition="akg_guided_hybrid")
    facts = [
        _fact("no_rate_limit", False, method="bf_dictionary"),
        _fact("no_rate_limit", True, method="bf_spray"),
    ]
    state.update(observation_update(state, facts))
    assert statuses_snapshot(state, "bf_dictionary")["no_rate_limit"] == "false"
    assert statuses_snapshot(state, "bf_spray")["no_rate_limit"] == "true"
    assert eligible_methods(state) == ["bf_spray"]


def test_unverified_security_level_is_a_setup_failure(monkeypatch):
    session = DVWASession("http://localhost/dvwa")
    try:
        monkeypatch.setattr(session, "_submit_security_form", lambda level: False)
        with pytest.raises(RuntimeError, match="not verified server-side"):
            session.set_security_level("high")
    finally:
        session.close()


def test_dvwa_view_source_affordance_is_not_sensitive_disclosure():
    """The per-page 'view source' button must not quarantine an AC control."""
    from foundation.control_catalog import structured_contamination_reason

    page = (
        '<input type="button" value="view source" class="popup_button" '
        "id='source_button' data-source-url='../../vulnerabilities/view_source.php?id=authbypass'>"
        "This page should only be accessible by the admin user."
    )
    event = {"event": "agent.probe.sent",
             "payload": {"status_code": 200, "response_excerpt": page,
                         "principal_id": "gordonb"}}
    assert structured_contamination_reason("ac_force_browse", [event]) is None

    disclosed = {"event": "agent.probe.sent",
                 "payload": {"status_code": 200,
                             "response_excerpt": "<?php $db = mysqli_connect(...); ",
                             "principal_id": "gordonb"}}
    assert structured_contamination_reason(
        "ac_force_browse", [disclosed]) == "unexpected_sensitive_disclosure"


def test_visit_login_is_not_a_control_driven_session_change():
    """A control run inside the visit's own session must not be quarantined."""
    from foundation.control_catalog import structured_contamination_reason

    event = {"event": "agent.probe.sent",
             "payload": {"status_code": 200, "principal_id": "gordonb",
                         "initial_session_fingerprint": "pre-login",
                         "session_fingerprint": "post-login"}}
    assert structured_contamination_reason("ac_idor", [event]) is None

    changed = {"event": "agent.probe.sent",
               "payload": {"status_code": 200, "principal_id": "gordonb",
                           "session_fingerprint": "post-login"}}
    other = {"event": "agent.probe.sent",
             "payload": {"status_code": 200, "principal_id": "gordonb",
                         "session_fingerprint": "rotated-mid-control"}}
    assert structured_contamination_reason(
        "ac_idor", [changed, other]) == "unexpected_session_change"
