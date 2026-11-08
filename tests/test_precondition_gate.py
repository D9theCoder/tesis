"""Behavioral checks for the measured-false prerequisite gate.

The gate is a runtime invariant: a genuinely measured-false prerequisite must
reject the method, an unknown stays unknown, and another method's fact cannot
satisfy a scoped prerequisite.  The false -> reject path is also exercised in a
subprocess under ``python -O`` so an assert-based bypass cannot hide it.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from foundation.control_catalog import precondition_gate
from foundation.preconditions import (
    make_observation_fact,
    observation_update,
    statuses_snapshot,
)

FIXTURE = "offline-precondition-fixture"
PROTOCOL = "offline-precondition-protocol"
METHOD = "ac_vertical_escalation"
KEY = "role_based_access_present"


def _state(value, *, method=METHOD, key=KEY, principal="gordonb"):
    fact = make_observation_fact(
        key, value, source="matched_permission_control", method=method,
        visit_id="visit-1", control_id="control-1", evidence_refs=["control:1"],
        fixture_id=FIXTURE, protocol_version=PROTOCOL, security_level="high",
        principal_id=principal, session_fingerprint="fingerprint",
        phase="applicability_probe", session_scope="session",
    )
    base = {
        "fixture_id": FIXTURE,
        "protocol_version": PROTOCOL,
        "security_level": "high",
        "target_url": "http://fixture.invalid/dvwa",
        "execution_id": "offline-precondition",
        "observation_facts": [],
        "observations": {},
        "precondition_status": {},
        "method_principals": {},
        "method_session_fingerprints": {},
    }
    scoped = {
        **base,
        "observation_facts": [fact],
        "method_principals": {method: principal},
        "method_session_fingerprints": {method: "fingerprint"},
    }
    update = observation_update(base, [fact], method=method)
    return {**scoped, **update}


def test_measured_false_rejects_the_method():
    state = _state(False)
    assert statuses_snapshot(state, METHOD)[KEY] == "false"
    gate = precondition_gate(state, METHOD)
    assert gate["decision"] == "reject"
    assert gate["reason"] == "precondition_false"
    assert gate["false_keys"] == [KEY]


def test_measured_true_allows_the_method():
    state = _state(True)
    assert statuses_snapshot(state, METHOD)[KEY] == "true"
    gate = precondition_gate(state, METHOD)
    assert gate["decision"] == "allow"
    assert gate["reason"] == "precondition_proved"
    assert gate["false_keys"] == []


def test_explicit_unknown_stays_unknown_and_is_not_false():
    state = _state(None)
    assert statuses_snapshot(state, METHOD)[KEY] == "unknown"
    gate = precondition_gate(state, METHOD)
    assert gate["status"][KEY] == "unknown"
    assert gate["false_keys"] == []
    # The method has a safe detection control, so the gate may allow a bounded
    # measurement; it must never relabel unknown as a measured false.
    assert gate["reason"] in {"precondition_measurable",
                              "precondition_unknown_no_safe_control"}


def test_another_methods_fact_does_not_satisfy_this_method():
    state = _state(True, method="bf_dictionary", key="no_rate_limit")
    assert statuses_snapshot(state, "bf_spray")["no_rate_limit"] == "unknown"
    assert statuses_snapshot(state, "bf_dictionary")["no_rate_limit"] == "true"


def test_false_rejection_survives_optimized_python(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    script = """
import json
from foundation.control_catalog import precondition_gate
from foundation.preconditions import make_observation_fact, observation_update, statuses_snapshot

base = {
    "fixture_id": "offline-precondition-fixture",
    "protocol_version": "offline-precondition-protocol",
    "security_level": "high",
    "target_url": "http://fixture.invalid/dvwa",
    "execution_id": "offline-precondition",
    "observation_facts": [],
    "observations": {},
    "precondition_status": {},
    "method_principals": {"ac_vertical_escalation": "gordonb"},
    "method_session_fingerprints": {"ac_vertical_escalation": "fingerprint"},
}
fact = make_observation_fact(
    "role_based_access_present", False, source="matched_permission_control",
    method="ac_vertical_escalation", visit_id="visit-1", control_id="control-1",
    evidence_refs=["control:1"], fixture_id=base["fixture_id"],
    protocol_version=base["protocol_version"], security_level="high",
    principal_id="gordonb", session_fingerprint="fingerprint",
    phase="applicability_probe", session_scope="session",
)
state = {**base, **observation_update(base, [fact], method="ac_vertical_escalation")}
gate = precondition_gate(state, "ac_vertical_escalation")
print(json.dumps({
    "status": statuses_snapshot(state, "ac_vertical_escalation")["role_based_access_present"],
    "decision": gate["decision"],
    "reason": gate["reason"],
}, sort_keys=True))
"""
    completed = subprocess.run(
        [sys.executable, "-O", "-c", script],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    observed = json.loads(completed.stdout.strip())
    assert observed == {
        "status": "false",
        "decision": "reject",
        "reason": "precondition_false",
    }
