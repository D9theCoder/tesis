"""Tests for agent telemetry event builders."""

from __future__ import annotations

import pytest

from agents.agent_telemetry import exploit_event, probe_event, score_event


class TestProbeEvent:
    def test_probe_event_structure(self):
        event = probe_event("sqli_union", "1' ORDER BY 1-- -", 200, True)
        assert event["node"] == "sqli_union"
        assert event["event"] == "agent.probe.sent"
        assert event["status"] == "ok"
        assert event["payload"]["agent_id"] == "sqli_union"
        assert event["payload"]["payload"] == "1' ORDER BY 1-- -"
        assert event["payload"]["status_code"] == 200
        assert event["payload"]["signal_detected"] is True

    def test_probe_event_no_status_code(self):
        event = probe_event("sqli_error", "1'", None, False)
        assert event["payload"]["status_code"] is None
        assert event["payload"]["signal_detected"] is False


class TestExploitEvent:
    def test_exploit_event_success(self):
        event = exploit_event("sqli_union", "1' UNION SELECT 1,2-- -", 200, True)
        assert event["node"] == "sqli_union"
        assert event["event"] == "agent.exploit.sent"
        assert event["status"] == "ok"
        assert event["payload"]["success"] is True

    def test_exploit_event_failure(self):
        event = exploit_event("sqli_union", "1' UNION SELECT 1,2-- -", 500, False)
        assert event["status"] == "failed"
        assert event["payload"]["success"] is False


class TestScoreEvent:
    def test_score_event_full_exploit(self):
        event = score_event(
            "sqli_union",
            4,
            ["sqli_union_confirmed"],
            ["credentials_extracted"],
        )
        assert event["node"] == "sqli_union"
        assert event["event"] == "agent.score.final"
        assert event["payload"]["score"] == 4
        assert event["payload"]["confirmed_vulns"] == ["sqli_union_confirmed"]
        assert event["payload"]["achieved_outcomes"] == ["credentials_extracted"]

    def test_score_event_not_found(self):
        event = score_event("sqli_error", 0, [], [])
        assert event["payload"]["score"] == 0
        assert event["payload"]["confirmed_vulns"] == []
        assert event["payload"]["achieved_outcomes"] == []

    def test_score_event_invalid_score_raises(self):
        with pytest.raises(ValueError, match="score must be an int between 0 and 4"):
            score_event("sqli_union", 5, [], [])

    def test_score_event_negative_score_raises(self):
        with pytest.raises(ValueError, match="score must be an int between 0 and 4"):
            score_event("sqli_union", -1, [], [])


class TestEndpointParameter:
    def test_probe_event_with_endpoint(self):
        event = probe_event("sqli_union", "1'", 200, True, endpoint="/vulnerabilities/sqli/")
        assert event["payload"]["endpoint"] == "/vulnerabilities/sqli/"

    def test_probe_event_endpoint_defaults_to_none(self):
        event = probe_event("sqli_union", "1'", 200, True)
        assert event["payload"]["endpoint"] is None
