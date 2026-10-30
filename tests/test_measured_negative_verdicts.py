"""Regression tests for measured-negative verdicts and run-scope ``Srun``.

A coordinate whose every in-scope precondition is measured false by a *sent*
bounded control has looked at the target and found it closed. These tests pin the
fail-closed rules of that claim (`evaluation/method_verdicts.py`) and the run-scope
composite that counts a chain visit (`core/scorer.py`)."""

from core.scorer import (
    composite_from_components,
    run_scope_composite,
    run_scope_score_components,
)
from evaluation.method_verdicts import (
    SCORE_UNAVAILABLE_REASON,
    measured_negative_summary,
    measured_negative_verdicts,
)
from evaluation.runner import _run_scope_scoring


def _control(control_id: str, **overrides) -> dict:
    row = {
        "control_id": control_id,
        "control_class": "detection",
        "status": "sent",
        "establishes_exploit": False,
        "signal_detected": False,
        "policy_version": "detection-controls.v2",
    }
    row.update(overrides)
    return row


#: Probe facts are recorded under the account that ran the probe, which is not
#: the run principal: an access-control probe executes as the low-privilege user.
_PROBE_SCOPE = {
    "fixture_id": "dvwa-test-fixture",
    "protocol_version": "ranking-session-acceptance.v1",
    "security_level": "high",
    "principal_id": "gordonb",
    "session_fingerprint": "probe-fingerprint",
    "session_scope": "session",
}


def _fact(key: str, method: str, value: bool | None = True, **scope) -> dict:
    return {
        "key": key,
        "value": value,
        "method": method,
        "scope": {**_PROBE_SCOPE, **scope},
        "evidence_refs": [f"control:control:{method}:high:method_probe:0"],
    }


_AC_FACTS = [
    _fact("object_ids_enumerable", "ac_idor", False),
    _fact("role_based_access_present", "ac_vertical_escalation", False),
    _fact("force_browse_endpoints_visible", "ac_force_browse", False),
]


def _ac_state(facts: list[dict] | None = None, **overrides) -> dict:
    state = {
        "current_surface": "access_control",
        "security_level": "high",
        "fixture_id": "dvwa-test-fixture",
        "protocol_version": "ranking-session-acceptance.v1",
        "readiness": {"session": {"principal": "admin", "fingerprint": "run-fingerprint"}},
        "attempted_agents": [],
        "viable_methods": [],
        "precondition_status": {
            "object_ids_enumerable": "false",
            "role_based_access_present": "false",
            "force_browse_endpoints_visible": "false",
            "error_messages_enabled": "unknown",
            "no_rate_limit": "unknown",
            "response_delay_measurable": "unknown",
            "response_diff_detectable": "unknown",
            "union_select_possible": "unknown",
        },
        "observation_facts": _AC_FACTS if facts is None else facts,
        "control_events": [
            _control("control:ac_idor:high:method_probe:0"),
            _control("control:ac_idor:high:method_probe:1"),
            _control("control:ac_vertical_escalation:high:method_probe:0"),
            _control("control:ac_force_browse:high:method_probe:0"),
        ],
        "probe_controls": {},
    }
    state.update(overrides)
    return state


def test_every_in_scope_method_gets_a_verdict_from_its_sent_controls():
    state = _ac_state()
    verdicts = measured_negative_verdicts(state)
    assert set(verdicts) == {"ac_idor", "ac_vertical_escalation", "ac_force_browse"}
    idor = verdicts["ac_idor"]
    assert idor["verdict"] == "not_vulnerable"
    assert idor["basis"] == "bounded_detection_control"
    assert idor["required_preconditions"] == ["object_ids_enumerable"]
    assert idor["observed"] == {"object_ids_enumerable": "false"}
    assert idor["control_events_sent"] == 2
    assert idor["security_level"] == "high"
    assert idor["evidence_refs"] == ["#/control_events/0", "#/control_events/1"]
    summary = measured_negative_summary(state, verdicts)
    assert summary["complete"] is True
    assert summary["control_events_sent"] == 4
    assert summary["methods_missing_verdict"] == []


def test_attempted_run_is_never_relabelled_as_measured_negative():
    state = _ac_state(attempted_agents=["ac_idor"], viable_methods=["ac_idor"])
    assert measured_negative_verdicts(state) == {}
    assert measured_negative_summary(state)["complete"] is False


def test_viable_method_blocks_the_negative_claim():
    state = _ac_state(viable_methods=["ac_force_browse"])
    assert measured_negative_verdicts(state) == {}


def test_unknown_precondition_stays_undecided():
    # No fact for the method: the flattened view claiming "false" cannot decide it.
    state = _ac_state(facts=[fact for fact in _AC_FACTS if fact["method"] != "ac_idor"])
    verdicts = measured_negative_verdicts(state)
    assert "ac_idor" not in verdicts
    summary = measured_negative_summary(state, verdicts)
    assert summary["complete"] is False
    assert summary["methods_missing_verdict"] == ["ac_idor"]


def test_false_precondition_without_a_sent_control_is_not_a_verdict():
    state = _ac_state(control_events=[], probe_controls={})
    verdicts = measured_negative_verdicts(state)
    assert verdicts == {}
    assert measured_negative_summary(state, verdicts)["complete"] is False


def test_control_rows_that_establish_exploitation_are_not_negative_evidence():
    state = _ac_state(control_events=[
        _control("control:ac_idor:high:method_probe:0", establishes_exploit=True),
    ])
    assert "ac_idor" not in measured_negative_verdicts(state)


def test_probe_snapshot_supplies_evidence_when_the_run_list_is_empty():
    state = _ac_state(
        control_events=[],
        probe_controls={
            "recon:method_probe:ac_idor": {
                "control_events": [_control("control:ac_idor:high:method_probe:0")]},
            "recon:method_probe:ac_vertical_escalation": {
                "control_events": [_control("control:ac_vertical_escalation:high:method_probe:0")]},
            "recon:method_probe:ac_force_browse": {
                "control_events": [_control("control:ac_force_browse:high:method_probe:0")]},
        },
    )
    verdicts = measured_negative_verdicts(state)
    assert verdicts["ac_idor"]["control_events_sent"] == 1
    assert measured_negative_summary(state, verdicts)["complete"] is True


def test_another_surface_is_not_judged_by_access_control_evidence():
    state = _ac_state(current_surface="brute_force")
    assert measured_negative_verdicts(state) == {}
    assert measured_negative_summary(state)["complete"] is False


def test_another_methods_measurement_cannot_complete_a_shared_key():
    # Both brute-force methods declare ``no_rate_limit``. Only the spray probe
    # measured it, so the dictionary method stays undecided even though the
    # flattened view carries the measurement.
    state = {
        "current_surface": "brute_force",
        "security_level": "medium",
        "fixture_id": "dvwa-test-fixture",
        "protocol_version": "ranking-session-acceptance.v1",
        "readiness": {"session": {"principal": "admin", "fingerprint": "run-fingerprint"}},
        "attempted_agents": [],
        "viable_methods": [],
        "precondition_status": {"no_rate_limit": "false"},
        "observation_facts": [_fact("no_rate_limit", "bf_spray", False, security_level="medium")],
        "control_events": [
            _control("control:bf_spray:medium:method_probe:0"),
            _control("control:bf_dictionary:medium:method_probe:0"),
        ],
        "probe_controls": {},
    }
    verdicts = measured_negative_verdicts(state)
    assert set(verdicts) == {"bf_spray"}
    assert measured_negative_summary(state, verdicts)["complete"] is False


def test_probe_evidence_from_another_security_level_is_not_used():
    state = _ac_state(facts=[{**fact, "scope": {**_PROBE_SCOPE, "security_level": "medium"}}
                             for fact in _AC_FACTS])
    assert measured_negative_verdicts(state) == {}


def test_state_without_append_only_facts_falls_back_to_the_flat_view():
    state = _ac_state()
    state.pop("observation_facts")
    assert set(measured_negative_verdicts(state)) == {
        "ac_idor", "ac_vertical_escalation", "ac_force_browse"}
    # A shared key carries no method attribution, so it stays unknown.
    shared = {
        **state,
        "current_surface": "brute_force",
        "security_level": "medium",
        "precondition_status": {"no_rate_limit": "false"},
        "control_events": [
            _control("control:bf_spray:medium:method_probe:0"),
            _control("control:bf_dictionary:medium:method_probe:0"),
        ],
    }
    assert measured_negative_verdicts(shared) == {}


def test_run_scope_composite_counts_a_chain_visit():
    state = {
        "selected_method": "sqli_union",
        "method_scores": {"sqli_union": 3},
        "exploitation_scores": {"sqli_union": 3},
        "output_scores": {"sqli_union": 4},
        "payload_candidates": {"sqli_union": [{"candidate_id": "c1"}]},
        "payload_scores": {"c1": 3},
        "chain_scores": {"sqli_union": 0, "bf_dictionary": 4},
    }
    components = run_scope_score_components(state)
    assert components["Schain"] == 4
    assert run_scope_composite(state) == 3.3
    # The per-method composite keeps the selected visit's own chain grade.
    assert composite_from_components({**components, "Schain": 0}) == 2.9


def test_run_scope_composite_is_undefined_without_a_selection():
    assert run_scope_score_components({"selected_method": None}) is None
    assert run_scope_composite({}) is None


def test_measured_negative_run_reports_no_composite_with_a_reason():
    scoring = _run_scope_scoring(_ac_state(), {})
    assert scoring["composite_score"] is None
    assert scoring["metric_availability"]["composite_score"] is False
    assert scoring["metric_unavailable_reason"]["composite_score"] == SCORE_UNAVAILABLE_REASON
    assert scoring["measured_negative"]["complete"] is True
    assert set(scoring["method_verdicts"]) == {
        "ac_idor", "ac_vertical_escalation", "ac_force_browse"}


def test_run_without_evidence_keeps_the_zero_default_and_no_verdicts():
    scoring = _run_scope_scoring(_ac_state(control_events=[], probe_controls={}), {})
    assert scoring["composite_score"] == 0
    assert scoring["method_verdicts"] == {}
    assert scoring["measured_negative"]["complete"] is False
