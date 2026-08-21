"""Evidence-backed regression tests for the DVWA SQLi medium coordinate."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agents.sqli.sqli_boolean_blind_agent import sqli_boolean_blind_agent
from agents.sqli.sqli_error_agent import sqli_error_agent
from agents.sqli.sqli_time_blind_agent import sqli_time_blind_agent
from agents.sqli.sqli_union_agent import sqli_union_agent
from core.state import new_default_state
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
    state = new_default_state()
    state.update({
        "target_url": "http://localhost/dvwa",
        "security_level": security_level,
        "payload_candidates": {method: candidates},
    })
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


def test_error_medium_updatexml_tilde_is_enough():
    """A truncated medium XPath envelope is confirmed by its tilde marker."""
    library = PayloadLibrary()
    seeds = library.load_seed_candidates("sqli_error", "medium")
    probe_seed = next(seed for seed in seeds if seed["payload_or_logic"] == "1 AND")
    updatexml_seed = next(seed for seed in seeds if "updatexml" in seed["payload_or_logic"])
    session = _make_session()

    def mock_get(_path, params=None, data=None):
        payload = str((params or data or {}).get("id", ""))
        if "updatexml" in payload:
            return _make_response("XPATH syntax error: '~admin")
        if payload == probe_seed["payload_or_logic"]:
            return _make_response("You have an error in your SQL syntax")
        return _make_response("No extraction")

    session.get.side_effect = mock_get
    session.post.side_effect = mock_get
    state = _make_state("sqli_error", "medium", [probe_seed, updatexml_seed])

    with patch("agents.sqli.sqli_error_agent.DVWASession", return_value=session):
        result = sqli_error_agent(state)

    assert result["scores"]["sqli_error"] >= 3
    assert result["confirmed_vulns"] == ["sqli_error_confirmed"]
    assert result["verifier_decision"]["decision"] == "confirmed"
    assert session.post.call_count > 0


@pytest.mark.parametrize("security_level,expected_score,confirmed", [
    ("medium", 3, True),
    ("high", 2, False),
])
def test_boolean_medium_single_true_confirms_but_high_requires_two(
    security_level: str,
    expected_score: int,
    confirmed: bool,
):
    """Medium accepts one true response while high retains two-hit strictness."""
    seeds = PayloadLibrary().load_seed_candidates("sqli_boolean_blind", security_level)
    candidates = [seed for seed in seeds if seed["stage"] == "probe"]
    candidates.append(next(seed for seed in seeds if seed["stage"] == "exploit"))
    session = _make_session()

    current_payload = {"value": ""}

    def mock_get(_path, params=None, data=None):
        payload_data = params or data or {}
        if "id" in payload_data:
            current_payload["value"] = str(payload_data["id"])
        payload = current_payload["value"]
        if "1=1" in payload or "1=2" not in payload:
            return _make_response("User ID exists in the database")
        return _make_response("User ID is missing from the database")

    session.get.side_effect = mock_get
    session.post.side_effect = mock_get
    state = _make_state("sqli_boolean_blind", security_level, candidates)

    with patch("agents.sqli.sqli_boolean_blind_agent.DVWASession", return_value=session):
        result = sqli_boolean_blind_agent(state)

    assert result["scores"]["sqli_boolean_blind"] == expected_score
    assert ("sqli_boolean_blind_confirmed" in result.get("confirmed_vulns", [])) is confirmed
    assert (session.post.call_count > 0) is (security_level in {"medium", "high"})


def _time_monotonic_values(delay: float) -> list[float]:
    values: list[float] = []
    for index in range(3):
        start = float(index)
        values.extend([start, start + 0.04])
    values.extend([10.0, 10.0 + delay])
    for index in range(3):
        start = 20.0 + index
        values.extend([start, start + 0.04])
    values.extend([30.0, 30.0 + delay])
    return values


@pytest.mark.parametrize("security_level,delay,expected_confirmed", [
    ("medium", 2.0, True),
    ("high", 2.0, False),
    ("medium", 1.9, True),
    ("medium", 1.5, False),
])
def test_time_medium_threshold_and_single_delay_are_level_scoped(
    security_level: str,
    delay: float,
    expected_confirmed: bool,
):
    """Medium uses a 1.8s/single-hit gate while high remains at 2.5s/two-hit."""
    seeds = PayloadLibrary().load_seed_candidates("sqli_time_blind", security_level)
    candidates = [seed for seed in seeds if seed["stage"] in {"probe", "exploit"}]
    session = _make_session()
    session.get.return_value = _make_response("User ID exists")
    session.post.return_value = _make_response("User ID exists")
    state = _make_state("sqli_time_blind", security_level, candidates)

    with patch(
        "agents.sqli.sqli_time_blind_agent.time.monotonic",
        side_effect=_time_monotonic_values(delay),
    ):
        with patch("agents.sqli.sqli_time_blind_agent.DVWASession", return_value=session):
            result = sqli_time_blind_agent(state)

    if expected_confirmed:
        assert result["scores"]["sqli_time_blind"] >= 3
        assert "sqli_time_blind_confirmed" in result.get("confirmed_vulns", [])
    else:
        assert result["scores"]["sqli_time_blind"] < 3
        assert "sqli_time_blind_confirmed" not in result.get("confirmed_vulns", [])
    assert (session.post.call_count > 0) is (security_level in {"medium", "high"})


def test_medium_bypass_seeds_do_not_enter_high_candidates():
    """The evidence additions are isolated to medium payload loading."""
    library = PayloadLibrary()
    medium_payloads = {
        candidate["payload_or_logic"]
        for method in ("sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind")
        for candidate in library.load_seed_candidates(method, "medium")
    }
    high_payloads = {
        candidate["payload_or_logic"]
        for method in ("sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind")
        for candidate in library.load_seed_candidates(method, "high")
    }

    assert "1 UNION SELECT null,null#" in medium_payloads
    assert "1 UNION SELECT null,null#" not in high_payloads
    assert "1 AND IF(1=1,SLEEP(3),0)#" in medium_payloads
    assert "1 AND IF(1=1,SLEEP(3),0)#" not in high_payloads
    assert "1 AND 1=1" in medium_payloads
    assert "1 AND 1=1" not in high_payloads
