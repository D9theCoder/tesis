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
import json
from pathlib import Path

import pytest

from agents.access_control.ac_force_browse_agent import _probe_preconditions
from evaluation.manual_scoring_sheet import manual_scoring_rows
from core.state import new_default_state
from foundation.payload_library import PayloadLibrary
from foundation.payload_validator import validate_payload_candidates


@pytest.mark.parametrize("method", ["bf_dictionary", "bf_spray"])
def test_brute_force_literal_credentials_keep_their_own_retry_evidence(monkeypatch, method):
    """Validate→agent→artifact→export, including old evidence without IDs."""
    module = importlib.import_module(f"agents.brute_force.{method}_agent")
    seeds = PayloadLibrary().load_seed_candidates(method, "high")
    probe = next(c for c in seeds if c["stage"] == "probe")
    seed = next(c for c in seeds if c["stage"] == "exploit")
    candidates = [probe, *[
        {**seed, "candidate_id": candidate_id, "source": "llm_generated",
         "mutation_type": "pacing_strategy", "payload_or_logic": payload}
        for candidate_id, payload in [
            ("a-prefixed", "credential_pair=admin:unused"),
            ("b-plain", "admin:unused"),
        ]
    ]]
    state = new_default_state()
    state.update(target_url="http://localhost/dvwa", security_level="high",
                 current_surface="brute_force", selected_method=method, payload_mode="hybrid")
    state["payload_candidates"] = {method: candidates}
    state.update(validate_payload_candidates(state))
    assert all(v["valid"] for v in state["payload_validation_results"][method])
    original = deepcopy(state)
    requests = []

    class Session:
        def login(self):
            return True

        def set_security_level(self, level):
            assert level == "high"

        def close(self):
            pass

        def _extract_user_token(self, body):
            return "offline-token"

        def get(self, path, params=None):
            body = "Username and/or password incorrect"
            if params:
                credential = (params["username"], params["password"])
                requests.append(credential)
                if credential[0] == "credential_pair=admin" and requests.count(credential) == 1:
                    body = "CSRF token is incorrect"
            return type("Response", (), {"status_code": 200, "text": body, "elapsed_ms": 10})()

    monkeypatch.setattr(module, "DVWASession", lambda _target: Session())
    update = getattr(module, f"{method}_agent")(state)
    artifact = {
        "config": {"provider": "openai_compatible", "security_level": "high", "payload_mode": "hybrid"},
        "final_state": {**state, **update},
        "execution_log": [{"event_type": e["event"], "data": e["payload"]} for e in update["telemetry_events"]],
        "response_evidence": update["response_evidence"],
        "timing_evidence": update.get("timing_evidence", []),
        "verifier_decision": update["verifier_decision"],
    }
    artifact["manual_scoring_evidence"] = manual_scoring_rows(artifact)
    legacy = deepcopy(artifact)
    for field in ("execution_log", "response_evidence", "timing_evidence"):
        for evidence in legacy[field]:
            record = evidence["data"] if field == "execution_log" else evidence
            record.pop("candidate_id", None)
    legacy["manual_scoring_evidence"] = manual_scoring_rows(legacy)
    evidence_dir = Path("results/validation/formatted-alias-2026-09-29/artifacts")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / f"{method}.json").write_text(json.dumps({
        "live_calls": 0, "credential_requests": requests, "artifact": artifact, "legacy_artifact": legacy,
    }, indent=2) + "\n")

    assert requests == [("rate_test", "test"), ("credential_pair=admin", "unused"),
                        ("credential_pair=admin", "unused"), ("admin", "unused")]
    attempts = [e for e in update["response_evidence"] if e["stage"] == "exploit"]
    assert [e["candidate_id"] for e in attempts] == ["a-prefixed", "a-prefixed", "b-plain"]
    assert [e["payload"] for e in attempts] == ["credential_pair=admin:unused"] * 2 + ["admin:unused"]
    for exported in (artifact, legacy):
        rows = {r["candidate_id"]: r for r in exported["manual_scoring_evidence"]}
        for candidate_id, payload, count in [("a-prefixed", "credential_pair=admin:unused", 2),
                                             ("b-plain", "admin:unused", 1)]:
            row = rows[candidate_id]
            assert len(row["response_evidence_ref"]) == len(row["execution_log_ref"]) == count
            assert row["verifier_decision"]["decision"] == "not_confirmed"
            for field in ("response_evidence", "execution_log"):
                for pointer in row[f"{field}_ref"]:
                    record = exported[field][int(pointer.rsplit("/", 1)[1])]
                    record = record["data"] if field == "execution_log" else record
                    assert record["payload"] == payload
    assert state == original


@pytest.mark.parametrize("method,param,payload", [
    ("sqli_union", "id", "1"), ("ac_force_browse", "path", "setup.php"),
])
def test_legacy_export_does_not_invent_unemitted_parameter_prefixes(method, param, payload):
    artifact = {
        "final_state": {
            "payload_provenance": {"candidate": {"method": method, "target_param": param}},
            "payload_candidates": {method: [{"candidate_id": "candidate", "stage": "exploit",
                                              "payload_or_logic": payload, "target_param": param}]},
            "payload_validation_results": {method: [{"candidate_id": "candidate", "valid": True}]},
            "payload_scores": {"candidate": 1},
        },
        "response_evidence": [{"agent_id": method, "stage": "exploit", "payload": f"{param}={payload}"}],
        "verifier_decision": {"agent_id": method, "decision": "not_confirmed"},
    }
    row = manual_scoring_rows(artifact)[0]
    assert row["response_evidence_ref"] == []
    assert row["verifier_decision"] is None


@pytest.mark.parametrize("method,probe,first,unused", [
    ("ac_force_browse", "security.php", "vulnerabilities/view_source.php", "  vulnerabilities/view_source.php  "),
    ("ac_force_browse", "security.php", "  vulnerabilities/view_source.php  ", "vulnerabilities/view_source.php"),
    ("ac_idor", " 4 ", "5", " 5 "),
    ("ac_idor", "2", " 4 ", "4"),
    ("ac_vertical_escalation", " 1 ", "4", " 4 "),
])
def test_access_control_agent_exports_only_actual_candidate_attempts(monkeypatch, method, probe, first, unused):
    """Offline agent→state→artifact check; no provider or DVWA calls."""
    module = importlib.import_module(f"agents.access_control.{method}_agent")
    state = new_default_state()
    state.update(target_url="http://localhost/dvwa", security_level="low", payload_mode="hybrid")
    candidates = [
        {"candidate_id": candidate_id, "method": method, "stage": stage, "payload_or_logic": payload,
         "target_param": "path" if method == "ac_force_browse" else "userId", "source": "llm_generated"}
        for candidate_id, stage, payload in [("probe", "probe", probe), ("attempted", "exploit", first), ("unused", "exploit", unused)]
    ]
    state["payload_candidates"] = {method: candidates}
    state["payload_provenance"] = {c["candidate_id"]: c for c in candidates}
    state["payload_validation_results"] = {method: [{"candidate_id": c["candidate_id"], "valid": True} for c in candidates]}
    original = deepcopy(state)

    class Session:
        def login(self):
            return True

        def set_security_level(self, level):
            pass

        def close(self):
            pass

        def get(self, path, params=None):
            uid = (params or {}).get("userId", "1")
            text = "View Source" if method == "ac_force_browse" else (
                "First name: admin" if uid.strip() == "1" or method == "ac_vertical_escalation"
                else f"First name: Gordon; surname: Brown; user id: {uid}"
            )
            return type("Response", (), {"status_code": 200, "text": text})()

    monkeypatch.setattr(module, "DVWASession", lambda _target: Session())
    update = getattr(module, f"{method}_agent")(state)
    artifact = {
        "config": {"provider": "openai_compatible", "surface": "access_control", "payload_mode": "hybrid"},
        "final_state": {**state, **update},
        "execution_log": [{"event_type": e["event"], "data": e["payload"]} for e in update["telemetry_events"]],
        "response_evidence": update["response_evidence"],
        "timing_evidence": update.get("timing_evidence", []),
        "verifier_decision": update["verifier_decision"],
    }
    artifact["manual_scoring_evidence"] = manual_scoring_rows(artifact)
    evidence_dir = Path("results/validation/manual-evidence-2026-09-29")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / f"{method}-{'spaces' if first != first.strip() else 'plain'}-{probe.strip()}.json").write_text(json.dumps(artifact, indent=2) + "\n")
    rows = {row["candidate_id"]: row for row in artifact["manual_scoring_evidence"]}
    assert update["scores"][method] == 2
    for candidate_id in ["probe", "attempted"]:
        row = rows[candidate_id]
        assert row["response_evidence_ref"] and row["execution_log_ref"]
        assert row["verifier_decision"]["decision"] == "unverified"
        assert row["score_0_4"] == 2
        for field in ["response_evidence", "execution_log"]:
            for pointer in row[f"{field}_ref"]:
                record = artifact[field][int(pointer.rsplit("/", 1)[1])]
                if field == "execution_log":
                    record = record["data"]
                assert record["candidate_id"] == candidate_id
    assert rows["unused"]["response_evidence_ref"] == rows["unused"]["execution_log_ref"] == []
    assert rows["unused"]["verifier_decision"] is None
    assert rows["unused"]["score_0_4"] is None
    assert state == original


@pytest.mark.parametrize("score", [3, None])
def test_legacy_normalized_aliases_use_recorded_candidate_score_or_remain_unlinked(score):
    artifact = {
        "final_state": {
            "payload_provenance": {c: {"method": "ac_force_browse", "target_param": "path"} for c in ["seed", "variant"]},
            "payload_candidates": {"ac_force_browse": [
                {"candidate_id": "seed", "payload_or_logic": "setup.php"},
                {"candidate_id": "variant", "payload_or_logic": " setup.php "},
            ]},
            "payload_validation_results": {"ac_force_browse": [{"candidate_id": c, "valid": True} for c in ["seed", "variant"]]},
            "payload_scores": {"seed": score} if score is not None else {},
        },
        "response_evidence": [{"agent_id": "ac_force_browse", "payload": "setup.php"}],
        "verifier_decision": {"agent_id": "ac_force_browse", "decision": "confirmed"},
    }
    rows = {r["candidate_id"]: r for r in manual_scoring_rows(artifact)}
    assert rows["seed"]["response_evidence_ref"] == (["#/response_evidence/0"] if score is not None else [])
    assert rows["variant"]["response_evidence_ref"] == []
    assert rows["variant"]["verifier_decision"] is None


@pytest.mark.parametrize("method", ["ac_idor", "ac_vertical_escalation"])
def test_legacy_access_control_links_stripped_ids(method):
    artifact = {
        "final_state": {
            "payload_provenance": {"id": {"method": method, "target_param": "userId"}},
            "payload_candidates": {method: [{"candidate_id": "id", "payload_or_logic": " 4 "}]},
            "payload_validation_results": {method: [{"candidate_id": "id", "valid": True}]},
            "payload_scores": {"id": 3},
        },
        "response_evidence": [{"agent_id": method, "payload": "userId=4"}],
        "verifier_decision": {"agent_id": method, "decision": "confirmed"},
    }
    row = manual_scoring_rows(artifact)[0]
    assert row["response_evidence_ref"] == ["#/response_evidence/0"]
    assert row["verifier_decision"] == artifact["verifier_decision"]


@pytest.mark.parametrize("method", ["bf_dictionary", "bf_spray"])
def test_high_security_token_retry_retains_the_same_candidate_identity(monkeypatch, method):
    module = importlib.import_module(f"agents.brute_force.{method}_agent")
    state = new_default_state()
    state.update(target_url="http://localhost/dvwa", security_level="high")
    state["payload_candidates"] = {method: [
        {"candidate_id": "probe", "stage": "probe", "payload_or_logic": "rate_test:test"},
        {"candidate_id": "login", "stage": "exploit", "payload_or_logic": "admin:password"},
    ]}
    state["payload_validation_results"] = {method: [{"candidate_id": c, "valid": True} for c in ["probe", "login"]]}

    class Session:
        requests = 0

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
    assert all(r["candidate_id"] == "login" for r in attempts)


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
    assert executed["score_0_4"] == executed["payload_score_0_4"] == 3
    unused = rows["unused"]
    assert unused["validator_result"]["valid"] is True
    assert unused["execution_log_ref"] == unused["response_evidence_ref"] == unused["timing_evidence_ref"] == []
    assert unused["verifier_decision"] is None
    assert unused["score_0_4"] is None
    assert unused["scoring_reason"] == ""
    assert artifact == original


def test_manual_scoring_recovers_earlier_method_verifier_from_graph_history():
    earlier = {"agent_id": "bf_dictionary", "decision": "confirmed", "score": 3}
    latest = {"agent_id": "bf_spray", "decision": "confirmed", "score": 3}
    artifact = {
        "final_state": {
            "payload_provenance": {
                "executed": {"method": "bf_dictionary"},
                "unused": {"method": "bf_dictionary"},
            },
            "payload_candidates": {"bf_dictionary": [
                {"candidate_id": "executed", "payload_or_logic": "admin:password"},
                {"candidate_id": "unused", "payload_or_logic": "admin:unused"},
            ]},
            "payload_validation_results": {"bf_dictionary": [
                {"candidate_id": "executed", "valid": True},
                {"candidate_id": "unused", "valid": True},
            ]},
        },
        "execution_log": [
            {"event_type": "graph.state", "data": {"latest_verifier": {
                "agent_id": "bf_dictionary", "decision": "not_confirmed", "score": 0,
            }}},
            {"event_type": "graph.state", "data": {"latest_verifier": earlier}},
            {"event_type": "graph.state", "data": {"latest_verifier": latest}},
        ],
        "response_evidence": [{"agent_id": "bf_dictionary", "payload": "admin:password"}],
        "verifier_decision": latest,
    }
    original = deepcopy(artifact)
    rows = {row["candidate_id"]: row for row in manual_scoring_rows(artifact)}
    assert rows["executed"]["verifier_decision"] == earlier
    assert rows["unused"]["verifier_decision"] is None
    assert artifact == original


@pytest.mark.parametrize("payload", [
    "  vulnerabilities/view_source.php  ",
    " //vulnerabilities/view_source.php ",
    "vulnerabilities/view_source.php",
])
def test_manual_scoring_links_the_force_browse_agent_normalized_path(payload):
    class Session:
        def get(self, path):
            assert path == "vulnerabilities/view_source.php"
            return type("Response", (), {"status_code": 200, "text": "View Source"})()

    probe_ok, _, _, events = _probe_preconditions(Session(), [payload], set())
    assert probe_ok
    recorded = events[0]["payload"]
    artifact = {
        "final_state": {
            "payload_provenance": {"generated": {"method": "ac_force_browse", "target_param": "path"}},
            "payload_candidates": {"ac_force_browse": [{"candidate_id": "generated", "payload_or_logic": payload}]},
            "payload_validation_results": {"ac_force_browse": [{"candidate_id": "generated", "valid": True}]},
        },
        "execution_log": [{"event_type": events[0]["event"], "data": recorded}],
        "response_evidence": [recorded],
        "timing_evidence": [{**recorded, "elapsed_ms": 10}],
        "verifier_decision": {"agent_id": "ac_force_browse", "decision": "confirmed"},
    }
    original = deepcopy(artifact)
    row = manual_scoring_rows(artifact)[0]
    assert row["execution_log_ref"] == ["#/execution_log/0"]
    assert row["response_evidence_ref"] == ["#/response_evidence/0"]
    assert row["timing_evidence_ref"] == ["#/timing_evidence/0"]
    assert row["verifier_decision"] == artifact["verifier_decision"]
    assert artifact == original


def test_manual_scoring_preserves_sql_payload_whitespace_when_matching():
    artifact = {
        "final_state": {
            "payload_provenance": {"sql": {"method": "sqli_union"}},
            "payload_candidates": {"sqli_union": [{"candidate_id": "sql", "payload_or_logic": " 1 "}]},
            "payload_validation_results": {"sqli_union": [{"candidate_id": "sql", "valid": True}]},
        },
        "response_evidence": [{"agent_id": "sqli_union", "payload": "1"}],
        "verifier_decision": {"agent_id": "sqli_union", "decision": "confirmed"},
    }
    row = manual_scoring_rows(artifact)[0]
    assert row["response_evidence_ref"] == []
    assert row["verifier_decision"] is None
