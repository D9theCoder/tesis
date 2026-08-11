"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from agents.state_utils import prepare_agent_session


def test_prepare_agent_session_skips_login_when_not_required():
    """Verifies prepare agent session skips login when not required behavior."""
    class FakeSession:
        """Groups regression tests for FakeSession behavior."""
        def __init__(self):
            self.login_calls = 0
            self.level_calls = 0

        def login(self):
            """Supports regression tests for test state utils."""
            self.login_calls += 1
            return True

        def set_security_level(self, _level):
            """Supports regression tests for test state utils."""
            self.level_calls += 1

    session = FakeSession()
    ready, notes = prepare_agent_session(session, "low", require_login=False)

    assert ready is True
    assert notes == []
    assert session.login_calls == 0
    assert session.level_calls == 1


def test_prepare_agent_session_requires_login_when_requested():
    """Verifies prepare agent session requires login when requested behavior."""
    class FakeSession:
        """Groups regression tests for FakeSession behavior."""
        def login(self):
            """Supports regression tests for test state utils."""
            return False

    ready, notes = prepare_agent_session(FakeSession(), "low", require_login=True)

    assert ready is False
    assert "session_login_failed" in notes


from core.state import new_default_state
from agents.agent_telemetry import exploit_event, probe_event
from agents.state_utils import make_update


def test_make_update_handles_failure_agents():
    """Verifies make update handles failure agents behavior."""
    state = new_default_state()
    update = make_update(
        state=state, module_name="sqli_union", score=0,
        tried_payloads=[], failure_agents=["sqli_union"],
    )
    assert "failure_agents" in update
    assert update["failure_agents"] == ["sqli_union"]


def test_make_update_no_failure_agents_when_none():
    """Verifies make update no failure agents when none behavior."""
    state = new_default_state()
    update = make_update(
        state=state, module_name="sqli_union", score=0,
        tried_payloads=[],
    )
    assert "failure_agents" not in update


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
