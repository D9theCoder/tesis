"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""


from agents.state_utils import candidate_payloads_for_stage


from core.state import new_default_state
from agents.agent_telemetry import exploit_event, probe_event
from agents.state_utils import make_update


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
