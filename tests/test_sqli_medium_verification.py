"""Evidence-backed regression tests for the DVWA SQLi medium coordinate."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


from agents.sqli.sqli_union_agent import sqli_union_agent
from core.payload_policy import PAYLOAD_POLICY_VERSION
from tests.support import ready_state
from foundation.payload_library import PayloadLibrary

def _make_response(text: str, status_code: int = 200) -> MagicMock:
    response = MagicMock()
    response.text = text
    response.status_code = status_code
    return response

def _make_session() -> MagicMock:
    session = MagicMock()
    session.login.return_value = True
    session.set_security_level.return_value = None
    return session

def _make_state(method: str, security_level: str, candidates: list[dict]) -> dict:
    """Supply a level-matched receipt, validated exploit rows and frozen controls."""
    visit_id = f"{method}:visit:1"
    prepared: list[dict] = []
    validations: list[dict] = []
    for candidate in candidates:
        row = dict(candidate)
        row.setdefault("origin_kind", "static_seed")
        row["visit_id"] = visit_id
        row["policy_version"] = PAYLOAD_POLICY_VERSION
        prepared.append(row)
        if str(row.get("stage")) in {"exploit", "bypass"} and row.get("candidate_id"):
            validations.append({
                "candidate_id": row["candidate_id"], "valid": True, "reason": "ok",
                "method": method, "visit_id": visit_id,
            })
    state = ready_state(method, level=security_level)
    state.update({
        "target_url": "http://localhost/dvwa",
        "security_level": security_level,
        "selected_visit_id": visit_id,
        "payload_candidates": {method: [row for row in prepared if row.get("stage") in {"exploit", "bypass"}]},
    })
    if validations:
        state["payload_validation_results"] = {method: validations}
        state["active_payload_candidates"] = {method: {
            "visit_id": visit_id, "status": "validated",
            "candidate_ids": [row["candidate_id"] for row in validations],
        }}
    return state

def test_union_medium_bypass_confirms_with_limit_variant():
    """A medium-only LIMIT seed reaches the existing credential evidence gate."""
    library = PayloadLibrary()
    seeds = library.load_seed_candidates("sqli_union", "medium")
    probe_seed = next(
        seed for seed in seeds
        if seed["payload_or_logic"] == "1 UNION SELECT null,null"
    )
    limit_seed = next(
        seed for seed in seeds
        if "LIMIT 1#" in seed["payload_or_logic"]
    )
    session = _make_session()

    def mock_get(_path, params=None, data=None):
        payload = str((params or data or {}).get("id", ""))
        if "LIMIT 1#" in payload:
            return _make_response("First name: admin<br>Surname: password")
        if payload == "1 UNION SELECT null,null":
            return _make_response("First name: <br>Surname: ")
        return _make_response("No results")

    session.get.side_effect = mock_get
    session.post.side_effect = mock_get
    state = _make_state("sqli_union", "medium", [probe_seed, limit_seed])

    with patch("agents.sqli.sqli_union_agent.DVWASession", return_value=session):
        result = sqli_union_agent(state)

    assert result["scores"]["sqli_union"] >= 3
    assert result["confirmed_vulns"] == ["sqli_union_confirmed"]
    assert result["verifier_decision"]["decision"] == "confirmed"
    assert limit_seed["payload_or_logic"] in result["tried_payloads"]["sqli_union"]
    assert session.post.call_count > 0
