"""Matched role-boundary applicability controls.

These are offline controls over the real recon dispatch.  Applicability is true
only for a verified non-admin explicitly denied the declared admin-only page
while the known-admin reference is allowed at the same level.  A bare denial, a
login redirect, a server error or a missing positive reference is unknown, never
a measured false and never an exploit.
"""
from __future__ import annotations

from importlib import import_module
from types import SimpleNamespace

import pytest

from agents.state_utils import probe_outcome_update
from evaluation.scoring_evidence import evidence_hash
from foundation.preconditions import make_observation_fact, observation_update

recon_module = import_module("foundation.recon")

FIXTURE = "offline-role-boundary-fixture"
PROTOCOL = "offline-role-boundary-protocol"
TARGET = "http://fixture.invalid/dvwa"
PAGE = "/vulnerabilities/authbypass/"
MARKER = "This page should only be accessible by the admin user"


def permission_source():
    document = {
        "fixture_id": FIXTURE,
        "protocol_version": PROTOCOL,
        "oracle_protocol": {
            "kind": "dvwa_candidate_permission",
            "enabled": True,
            "protected_paths": [PAGE],
            "path_signals": {PAGE: [MARKER]},
            "allow_broad_exposure": True,
        },
    }
    return {
        "source_id": "fixture-permission",
        "origin": "operator_fixture",
        "document": document,
        "sha256": evidence_hash(document),
    }


class PageSession:
    def __init__(self, principal: str, *, status: int, body: str,
                 final_path: str = PAGE):
        self.principal = principal
        self.http = self
        self.cookies = {"PHPSESSID": f"session-{principal}", "security": "high"}
        self._principal_id = principal
        self._initial_session_fingerprint = f"initial-{principal}"
        self._status = status
        self._body = body
        self._final_path = final_path
        self.calls: list[tuple[str, dict]] = []

    def get(self, path, params=None):
        self.calls.append((str(path), dict(params or {})))
        return SimpleNamespace(
            status_code=self._status,
            text=self._body,
            url=f"{TARGET}/{self._final_path.lstrip('/')}",
        )

    def observed_security_level(self):
        return "high"

    def close(self):
        pass


def state():
    return {
        "target_url": TARGET,
        "fixture_id": FIXTURE,
        "protocol_version": PROTOCOL,
        "security_level": "high",
        "current_surface": "access_control",
        "target_method": "ac_vertical_escalation",
        "execution_id": "exec-role-boundary",
        "scoring_oracles": [permission_source()],
        "observation_facts": [],
        "observations": {},
        "precondition_status": {},
        "control_events": [],
        "method_principals": {},
        "method_session_fingerprints": {},
        "attempted_agents": [],
    }


@pytest.fixture
def dispatch(monkeypatch):
    def run(admin: PageSession, nonadmin: PageSession):
        monkeypatch.setattr(
            "foundation.session_manager.open_documented_nonadmin_session",
            lambda *_args, **_kwargs: (nonadmin, "gordonb", "initial-gordonb"),
        )
        return recon_module._measure_recon_surface_controls(
            state(), admin, "high", "access_control", "admin",
        )

    return run


def test_allowed_admin_and_explicit_nonadmin_denial_measure_applicability(dispatch):
    admin = PageSession("admin", status=200, body=f"<p>{MARKER}</p>")
    nonadmin = PageSession("gordonb", status=403, body="Unauthorised")
    update = dispatch(admin, nonadmin)

    fact = update["observation_facts"][0]
    assert fact["key"] == "role_based_access_present"
    assert fact["value"] is True
    assert fact["source"] == "matched_permission_control"
    assert update["precondition_status"]["role_based_access_present"] == "true"
    assert update["method_principals"]["ac_vertical_escalation"] == "gordonb"
    events = update["control_events"]
    assert len(events) == 2
    assert {event["control_class"] for event in events} == {"detection"}
    assert {event["establishes_exploit"] for event in events} == {False}
    assert {event["control_outcome"] for event in events} == {"allowed", "denied"}
    assert {event["principal_id"] for event in events} == {"admin", "gordonb"}
    assert {event["security_level"] for event in events} == {"high"}
    assert all(event["final_url"] == f"{TARGET}{PAGE}" for event in events)
    # The page control is dispatched to the declared policy path, not as a
    # userId value substituted into the user-record API.
    assert admin.calls == [(PAGE, {})]
    assert nonadmin.calls == [(PAGE, {})]
    assert all("get_user_data.php" not in path for path, _params in nonadmin.calls)
    assert update.get("payload_candidates", {}) == {}
    assert all(event["candidate_id"] is None for event in events)
    assert update["probe_controls"]["applicability_probe:ac_vertical_escalation"][
        "quarantined"] is False


def test_nonadmin_allowed_page_is_a_measured_false_boundary(dispatch):
    admin = PageSession("admin", status=200, body=f"<p>{MARKER}</p>")
    nonadmin = PageSession("gordonb", status=200, body=f"<p>{MARKER}</p>")
    update = dispatch(admin, nonadmin)
    assert update["observation_facts"][0]["value"] is False
    assert update["precondition_status"]["role_based_access_present"] == "false"


@pytest.mark.parametrize(
    "nonadmin",
    [
        PageSession("gordonb", status=500, body="Server error"),
        PageSession("gordonb", status=302, body="Login", final_path="login.php"),
        PageSession("gordonb", status=200, body="<p>Nothing to see</p>"),
    ],
    ids=("server-error", "login-redirect", "ambiguous-body"),
)
def test_bare_denial_redirect_or_error_does_not_prove_applicability(dispatch, nonadmin):
    admin = PageSession("admin", status=200, body=f"<p>{MARKER}</p>")
    update = dispatch(admin, nonadmin)
    assert update["observation_facts"][0]["value"] is None
    assert update["precondition_status"]["role_based_access_present"] == "unknown"
    assert all(event["control_outcome"] != "denied" for event in update["control_events"])


def test_missing_admin_positive_reference_stays_unknown(dispatch):
    admin = PageSession("admin", status=302, body="Login", final_path="login.php")
    nonadmin = PageSession("gordonb", status=403, body="Unauthorised")
    update = dispatch(admin, nonadmin)
    assert update["observation_facts"][0]["value"] is None
    assert update["precondition_status"]["role_based_access_present"] == "unknown"


def test_nonadmin_session_must_be_a_distinct_valid_principal(dispatch):
    admin = PageSession("admin", status=200, body=f"<p>{MARKER}</p>")
    nonadmin = PageSession("admin", status=403, body="Unauthorised")
    assert dispatch(admin, nonadmin) == {}


def test_protocol_identity_mismatch_skips_the_control(monkeypatch):
    admin = PageSession("admin", status=200, body=f"<p>{MARKER}</p>")
    nonadmin = PageSession("gordonb", status=403, body="Unauthorised")
    monkeypatch.setattr(
        "foundation.session_manager.open_documented_nonadmin_session",
        lambda *_args, **_kwargs: (nonadmin, "gordonb", "initial-gordonb"),
    )
    mutated = state()
    mutated["fixture_id"] = "different-fixture"
    assert recon_module._measure_recon_surface_controls(
        mutated, admin, "high", "access_control", "admin",
    ) == {}


def test_agent_probe_update_retains_the_recon_applicability_fact():
    """The vertical agent must see the matched-control fact before exploiting."""
    base = {
        **state(),
        "probe_controls": {},
        "method_principals": {"ac_vertical_escalation": "gordonb"},
        "method_session_fingerprints": {
            "ac_vertical_escalation": "fingerprint"},
    }
    fact = make_observation_fact(
        "role_based_access_present", True, source="matched_permission_control",
        method="ac_vertical_escalation", visit_id="visit-1",
        fixture_id=FIXTURE, protocol_version=PROTOCOL, security_level="high",
        principal_id="gordonb", session_fingerprint="fingerprint",
        phase="applicability_probe", session_scope="session",
    )
    merged = {**base, **observation_update(
        base, [fact], method="ac_vertical_escalation")}
    merged["method_principals"] = {"ac_vertical_escalation": "gordonb"}
    merged["method_session_fingerprints"] = {
        "ac_vertical_escalation": "fingerprint"}
    update, quarantine = probe_outcome_update(
        merged, "ac_vertical_escalation", {}, [],
        principal_id="gordonb", session_fingerprint="fingerprint",
    )
    assert update["precondition_status"]["role_based_access_present"] == "true"
    assert quarantine is None
