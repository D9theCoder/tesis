"""Failure cases absent from runner tests: missing links, cross-method payload
collisions, invented evidence for unused candidates, input mutation, discarded
earlier verifier decisions, unmatched normalized paths, accidental SQL trimming.
Additional failures: normalized aliases borrowing an unused candidate's evidence;
lost stripped ID telemetry; reversed execution order; ambiguous legacy exports.
Formatted-alias failures: retries borrowing another literal credential's ID;
legacy exports inventing parameter prefixes for SQL or force-browse evidence.
"""

from copy import deepcopy
import importlib
from types import SimpleNamespace

import pytest

from evaluation.manual_scoring_sheet import manual_scoring_rows
from tests.support import ready_state


@pytest.mark.parametrize("method", ["bf_dictionary", "bf_spray"])
def test_high_security_token_retry_retains_the_same_candidate_identity(monkeypatch, method):
    module = importlib.import_module(f"agents.brute_force.{method}_agent")
    state = ready_state(method, level="high")
    state["target_url"] = "http://localhost/dvwa"
    candidate = next(row for row in state["payload_candidates"][method]
                     if row["payload_or_logic"] == "admin:password")
    candidate_id = candidate["candidate_id"]
    state["payload_candidates"] = {method: [candidate]}

    class Session:
        requests = 0
        http = SimpleNamespace(cookies={"PHPSESSID": "fixture-admin"})
        _principal_id = "admin"
        _username = "admin"

        def login(self):
            return True

        def set_security_level(self, level):
            pass

        def close(self):
            pass

        def _extract_user_token(self, body):
            return "local-test-token"

        def get(self, path, params=None):
            body = "No match"
            if params and params.get("username") == "admin":
                self.requests += 1
                body = "CSRF token is incorrect" if self.requests == 1 else "Welcome to the password protected area"
            return type("Response", (), {"status_code": 200, "text": body, "elapsed_ms": 10})()

    monkeypatch.setattr(module, "DVWASession", lambda _target: Session())
    update = getattr(module, f"{method}_agent")(state)
    attempts = [r for r in update["response_evidence"] if r["stage"] == "exploit"]
    assert update["scores"][method] == 3 and len(attempts) == 2
    assert all(r["candidate_id"] == candidate_id for r in attempts)


def test_manual_scoring_links_only_the_candidate_recorded_evidence():
    artifact = {
        "config": {},
        "final_state": {
            "payload_provenance": {
                "executed": {"method": "sqli_union", "source": "static_seed"},
                "unused": {"method": "sqli_union", "source": "llm_generated"},
            },
            "payload_candidates": {"sqli_union": [
                {"candidate_id": "executed", "payload_or_logic": "probe"},
                {"candidate_id": "unused", "payload_or_logic": "unused"},
            ]},
            "payload_validation_results": {"sqli_union": [
                {"candidate_id": "executed", "valid": True, "reason": "ok"},
                {"candidate_id": "unused", "valid": True, "reason": "ok"},
            ]},
            "payload_scores": {"executed": 3},
        },
        "execution_log": [
            {"event_type": "agent.probe.sent", "data": {"agent_id": "sqli_error", "payload": "probe"}},
            {"event_type": "agent.probe.sent", "data": {"agent_id": "sqli_union", "payload": "probe"}},
        ],
        "response_evidence": [
            {"agent_id": "sqli_error", "payload": "probe"},
            {"agent_id": "sqli_union", "payload": "probe"},
        ],
        "timing_evidence": [{"agent_id": "sqli_union", "payload": "probe", "elapsed_ms": 10}],
        "verifier_decision": {"agent_id": "sqli_union", "decision": "confirmed"},
    }
    original = deepcopy(artifact)
    rows = {row["candidate_id"]: row for row in manual_scoring_rows(artifact)}
    executed = rows["executed"]
    assert executed["validator_result"] == {"candidate_id": "executed", "valid": True, "reason": "ok"}
    assert executed["execution_log_ref"] == ["#/execution_log/1"]
    assert executed["response_evidence_ref"] == ["#/response_evidence/1"]
    assert executed["timing_evidence_ref"] == ["#/timing_evidence/0"]
    assert executed["verifier_decision"] == artifact["verifier_decision"]
    unused = rows["unused"]
    assert unused["validator_result"]["valid"] is True
    assert unused["execution_log_ref"] == unused["response_evidence_ref"] == unused["timing_evidence_ref"] == []
    assert unused["verifier_decision"] is None
    assert unused["score_0_4"] is None
    assert unused["scoring_reason"] == ""
    assert artifact == original
