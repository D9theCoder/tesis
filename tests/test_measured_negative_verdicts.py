"""Regression tests for measured-negative verdicts and run-scope ``Srun``.

A coordinate whose every in-scope precondition is measured false by a *sent*
bounded control has looked at the target and found it closed. These tests pin the
fail-closed rules of that claim (`evaluation/method_verdicts.py`) and the run-scope
composite that counts a chain visit (`core/scorer.py`)."""

from evaluation.method_verdicts import (
    measured_negative_summary,
    measured_negative_verdicts,
)


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


def test_false_precondition_without_a_sent_control_is_not_a_verdict():
    state = _ac_state(control_events=[], probe_controls={})
    verdicts = measured_negative_verdicts(state)
    assert verdicts == {}
    assert measured_negative_summary(state, verdicts)["complete"] is False


def test_another_surface_is_not_judged_by_access_control_evidence():
    state = _ac_state(current_surface="brute_force")
    assert measured_negative_verdicts(state) == {}
    assert measured_negative_summary(state)["complete"] is False
