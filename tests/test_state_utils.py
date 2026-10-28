"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from hashlib import sha256
from types import SimpleNamespace

import httpx
import json
import pytest

from agents.state_utils import candidate_payloads_for_stage




from core.state import new_default_state
from agents.agent_telemetry import _request_structure, exploit_event, probe_event
from agents.state_utils import make_update


@pytest.mark.parametrize('body,encoding,fields', [
    ({'data': {'username': 'fixture-user', 'password': 'fixture-secret'}},
     'form', ['username', 'password']),
    ({'json': {'username': 'fixture-user', 'password': 'fixture-secret'}},
     'json', ['password', 'username']),
    ({}, 'empty', []),
])
@pytest.mark.parametrize('wrapped', [False, True])
def test_httpx_request_body_evidence_retains_fields_without_values(body, encoding, fields, wrapped):
    request = httpx.Request('POST', 'http://localhost/dvwa/login.php', **body)
    response = httpx.Response(200, request=request)
    shape = _request_structure(SimpleNamespace(response=response) if wrapped else response)

    assert shape['body']['present'] is bool(fields)
    assert shape['body']['encoding'] == encoding
    assert [field['name'] for field in shape['body']['fields']] == fields
    assert all(field['redacted'] is True for field in shape['body']['fields'])
    assert 'fixture-secret' not in json.dumps(shape)
    assert 'fixture-user' not in json.dumps(shape)


def test_httpx_unbuffered_request_evidence_does_not_consume_stream():
    consumed = []

    def stream():
        consumed.append(True)
        yield b'password=fixture-secret'

    response = httpx.Response(200, request=httpx.Request(
        'POST', 'http://localhost/dvwa/login.php', content=stream()))
    body = _request_structure(response)['body']

    assert body['present'] is None
    assert body['encoding'] == 'unavailable'
    assert body['reason'] == 'request_body_not_buffered'
    assert consumed == []


def test_make_update_deduplicates_failure_agents():
    """Verifies make update deduplicates failure agents behavior."""
    state = new_default_state()
    state["failure_agents"] = ["sqli_union"]
    update = make_update(
        state=state, module_name="sqli_union", score=0,
        tried_payloads=[], failure_agents=["sqli_union", "sqli_error"],
    )
    assert update["failure_agents"] == ["sqli_error"]


def test_make_update_materializes_request_and_timing_evidence():
    """Method telemetry must populate the reproducibility evidence fields."""
    state = new_default_state()
    state["target_url"] = "http://localhost/dvwa"
    telemetry = [
        probe_event(
            "sqli_time_blind",
            "1' AND SLEEP(3)-- -",
            404,
            True,
            endpoint="/vulnerabilities/sqli_blind/",
            elapsed_ms=2900,
            baseline_elapsed_ms=20,
            delay_ms=2880,
        ),
        exploit_event("sqli_time_blind", "1' AND IF(...)", 404, True),
    ]

    update = make_update(
        state=state,
        module_name="sqli_time_blind",
        score=3,
        tried_payloads=["1' AND SLEEP(3)-- -", "1' AND IF(...)"],
        confirmed_vulns=["sqli_time_blind_confirmed"],
        telemetry_events=telemetry,
    )

    assert update["telemetry_events"][0]["payload"]["endpoint"] == (
        "http://localhost/dvwa/vulnerabilities/sqli_blind/"
    )
    assert len(update["response_evidence"]) == 2
    assert update["timing_evidence"][0]["delay_ms"] == 2880
    assert update["verifier_decision"]["decision"] == "confirmed"


def test_make_update_records_negative_verifier_decision():
    """Auditable request evidence must not leave verifier status ambiguous."""
    state = new_default_state()
    state["target_url"] = "http://localhost/dvwa"
    update = make_update(
        state=state,
        module_name="sqli_union",
        score=0,
        tried_payloads=["1'"],
        telemetry_events=[
            probe_event(
                "sqli_union",
                "1'",
                200,
                False,
                endpoint="/vulnerabilities/sqli/",
            )
        ],
    )

    assert update["verifier_decision"]["decision"] == "not_confirmed"
    assert update["verifier_decision"]["confirmed_vulns"] == []


def test_make_update_binds_response_to_validated_candidate_and_redacted_request():
    state = new_default_state()
    state.update({
        "target_url": "http://localhost/dvwa",
        "selected_method": "sqli_union",
        "selected_visit_id": "sqli_union:visit:1",
        "run_id": "run-capture-test",
        "execution_id": "exec-capture-test",
        "payload_candidates": {"sqli_union": [
            {"candidate_id": "probe-1", "method": "sqli_union", "stage": "probe",
             "payload_or_logic": "probe-value", "source": "static_seed", "source_seed_id": "probe-1"},
            {"candidate_id": "exploit-1", "method": "sqli_union", "stage": "exploit",
             "payload_or_logic": "exploit-value", "source": "static_seed", "source_seed_id": "exploit-1"},
        ]},
        "payload_validation_results": {"sqli_union": [
            {"candidate_id": "probe-1", "valid": True, "reason": "ok"},
            {"candidate_id": "exploit-1", "valid": True, "reason": "ok"},
        ]},
        "payload_provenance": {
            "probe-1": {"method": "sqli_union", "source": "static_seed"},
            "exploit-1": {"method": "sqli_union", "source": "static_seed"},
        },
    })

    def response(text, method, url, body=None):
        return SimpleNamespace(
            text=text,
            status_code=200,
            request=SimpleNamespace(
                method=method,
                url=url,
                headers={"Content-Type": "application/x-www-form-urlencoded"} if body else {},
                body=body,
            ),
        )

    update = make_update(
        state=state,
        module_name="sqli_union",
        score=3,
        tried_payloads=["probe-value", "exploit-value"],
        telemetry_events=[
            probe_event("sqli_union", "probe-value", 200, False,
                endpoint="/vulnerabilities/sqli/", response=response(
                    "probe response", "GET",
                    "http://localhost/dvwa/vulnerabilities/sqli/?id=probe-value&password=hidden-query",
                )),
            exploit_event("sqli_union", "exploit-value", 200, True,
                endpoint="/vulnerabilities/sqli/", response=response(
                    "exploit response", "POST", "http://localhost/dvwa/vulnerabilities/sqli/",
                    "id=exploit-value&password=hidden-body",
                )),
        ],
    )

    probe, exploit = update["response_evidence"]
    assert probe["candidate_id"] == "probe-1"
    assert probe["method"] == "sqli_union"
    assert probe["visit_id"] == "sqli_union:visit:1"
    assert probe["validation_ref"] == "#/final_state/payload_validation_results/sqli_union/0"
    assert probe["eligible_for_exploit_denominator"] is False
    assert exploit["candidate_id"] == "exploit-1"
    assert exploit["eligible_for_exploit_denominator"] is True
    assert exploit["validation_ref"] == "#/final_state/payload_validation_results/sqli_union/1"
    assert exploit["response_sha256"] == sha256(b"exploit response").hexdigest()
    assert exploit["request_structure"]["method"] == "POST"
    assert exploit["request_structure"]["path"] == "/dvwa/vulnerabilities/sqli/"
    assert [field["name"] for field in exploit["request_structure"]["body"]["fields"]] == ["id", "password"]
    assert "hidden-body" not in str(exploit["request_structure"])
    json_structure = _request_structure(SimpleNamespace(request=SimpleNamespace(
        method="POST", url="http://localhost/dvwa/api", headers={"Content-Type": "application/json"},
        body=b'{"id":"json-secret"}',
    )))
    assert json_structure["body"]["fields"] == [
        {"name": "id", "value_type": "str", "redacted": True},
    ]
    assert "json-secret" not in str(json_structure)
    assert probe["request_id"] == update["telemetry_events"][0]["payload"]["request_id"]
    assert probe["request_ref"] is None
    assert probe["request_link_status"] == "pending_export"
    assert probe["session_descriptor"]["redaction_applied"] is True
    assert probe["session_descriptor"]["raw_values_included"] is False
    assert [d["candidate_id"] for d in update["scoring_decisions"] if d["dimension"] == "Spayload"] == [
        "probe-1", "exploit-1",
    ]


def test_make_update_assigns_independent_probe_control_id_without_payload_score():
    from evaluation.scoring_evidence import evidence_hash
    from foundation.payload_library import PayloadLibrary
    from foundation.payload_validator import validate_probe_controls

    state = new_default_state()
    state.update({
        "target_url": "http://localhost/dvwa",
        "selected_method": "sqli_union",
        "selected_visit_id": "sqli_union:visit:1",
    })
    probes = [candidate for candidate in PayloadLibrary().load_seed_candidates("sqli_union", "low")
        if candidate.get("stage") == "probe"]
    controls = {
        "visit_id": state["selected_visit_id"],
        "candidates": probes,
        "sha256": evidence_hash(probes),
    }
    controls["validation_results"] = validate_probe_controls(state, controls)
    state["probe_controls"] = {"sqli_union": controls}
    payload = probes[0]["payload_or_logic"]

    update = make_update(
        state=state,
        module_name="sqli_union",
        score=0,
        tried_payloads=[payload],
        telemetry_events=[probe_event("sqli_union", payload, 200, False)],
    )

    evidence = update["response_evidence"][0]
    assert evidence["candidate_id"] == probes[0]["candidate_id"]
    assert evidence["control_id"] == probes[0]["candidate_id"]
    assert evidence["identity_kind"] == "independent_control"
    assert evidence["eligible_for_exploit_denominator"] is False
    assert evidence["validation"]["visit_id"] == state["selected_visit_id"]
    assert evidence["validation_ref"] == "#/final_state/probe_controls/sqli_union/validation_results/0"
    assert not [decision for decision in update["scoring_decisions"] if decision["dimension"] == "Spayload"]


def test_make_update_keeps_failed_complementary_boolean_request_as_source_control():
    state = new_default_state()
    state.update({
        "target_url": "http://localhost/dvwa",
        "selected_method": "sqli_boolean_blind",
        "selected_visit_id": "sqli_boolean_blind:visit:1",
        "payload_candidates": {"sqli_boolean_blind": [{
            "candidate_id": "boolean-1", "method": "sqli_boolean_blind", "stage": "exploit",
            "payload_or_logic": "candidate-expression", "source": "static_seed",
            "source_seed_id": "boolean-1",
        }]},
        "payload_validation_results": {"sqli_boolean_blind": [
            {"candidate_id": "boolean-1", "valid": True, "reason": "ok"},
        ]},
        "payload_provenance": {"boolean-1": {"method": "sqli_boolean_blind", "source": "static_seed"}},
    })
    update = make_update(
        state=state,
        module_name="sqli_boolean_blind",
        score=2,
        tried_payloads=["candidate-expression"],
        telemetry_events=[
            exploit_event("sqli_boolean_blind", "candidate-expression", 200, False),
            probe_event("sqli_boolean_blind", "derived-control-expression", 404, False),
        ],
    )

    control = update["response_evidence"][1]
    assert control.get("candidate_id") is None
    assert control["source_candidate_id"] == "boolean-1"
    assert control["control_id"] == "control:boolean-1:complementary_boolean"
    assert control["identity_kind"] == "derived_control"
    assert control["validation_relation"] == "derived_from_candidate"
    assert control["validation_ref"] == "#/final_state/payload_validation_results/sqli_boolean_blind/0"
    assert control["eligible_for_exploit_denominator"] is False


def test_duplicate_payload_values_keep_their_distinct_candidate_identity():
    state = new_default_state()
    state.update({
        "target_url": "http://localhost/dvwa",
        "selected_method": "sqli_union",
        "selected_visit_id": "sqli_union:visit:1",
        "payload_candidates": {"sqli_union": [
            {"candidate_id": "static-duplicate", "method": "sqli_union", "stage": "exploit",
             "payload_or_logic": "same-value", "source": "static_seed",
             "origin_kind": "static_seed", "visit_id": "sqli_union:visit:1",
             "policy_version": "payload-policy.v2"},
            {"candidate_id": "llm-duplicate", "method": "sqli_union", "stage": "exploit",
             "payload_or_logic": "same-value", "source": "llm_generated",
             "origin_kind": "seed_mutation", "visit_id": "sqli_union:visit:1",
             "policy_version": "payload-policy.v2"},
        ]},
        "payload_validation_results": {"sqli_union": [
            {"candidate_id": "static-duplicate", "valid": True, "reason": "ok",
             "visit_id": "sqli_union:visit:1"},
            {"candidate_id": "llm-duplicate", "valid": True, "reason": "ok",
             "visit_id": "sqli_union:visit:1"},
        ]},
    })
    payloads = candidate_payloads_for_stage(state, "sqli_union", "low", "exploit")

    update = make_update(
        state=state,
        module_name="sqli_union",
        score=0,
        tried_payloads=payloads,
        telemetry_events=[
            exploit_event("sqli_union", payload, 200, False)
            for payload in payloads
        ],
    )

    assert [str(payload) for payload in payloads] == ["same-value", "same-value"]
    assert [row["candidate_id"] for row in update["response_evidence"]] == [
        "static-duplicate", "llm-duplicate",
    ]
    assert [row["candidate_link_status"] for row in update["response_evidence"]] == [
        "linked", "linked",
    ]
