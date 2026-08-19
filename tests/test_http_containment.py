"""Focused regression tests for HTTP containment audit propagation."""

from unittest.mock import MagicMock, patch

import pytest

from evaluation.runner import run_single_engagement
from foundation.http_client import ContainmentError, HTTPClient
from foundation.recon import parse_forms, recon


def test_http_client_records_structured_request_event():
    """Blocked requests retain enough metadata for state/artifact logging."""
    client = HTTPClient("http://localhost/dvwa")
    try:
        with pytest.raises(ContainmentError) as raised:
            client.get("https://example.invalid/escape")

        error = raised.value
        assert error.kind == "request"
        assert error.url == "https://example.invalid/escape"
        assert client.containment_events == [error.as_event()]
        assert client.containment_events[0]["allowed_host"] == "localhost"
    finally:
        client.close()


def test_http_client_records_redirect_event_without_following_it():
    """External redirect targets are blocked and classified separately."""
    client = HTTPClient("http://localhost/dvwa")
    try:
        with pytest.raises(ContainmentError) as raised:
            client._assert_in_scope("https://example.invalid/escape", kind="redirect")

        assert raised.value.kind == "redirect"
        assert client.containment_events[0]["kind"] == "redirect"
    finally:
        client.close()


def test_recon_records_discarded_external_form_action():
    """Recon filtering is itself auditable even when no HTTP request is made."""
    events: list[dict] = []
    endpoints, vectors = parse_forms(
        '<form action="https://example.invalid/escape"><input name="id"></form>',
        "http://localhost/dvwa/index.php",
        containment_events=events,
    )

    assert endpoints == []
    assert vectors == []
    assert events[0]["kind"] == "form"
    assert events[0]["blocked_url"] == "https://example.invalid/escape"


def test_recon_propagates_http_containment_to_state_update():
    """A containment exception caught during recon reaches LangGraph state."""
    with patch("foundation.recon.DVWASession") as session_factory:
        session = MagicMock()
        session.login.side_effect = ContainmentError(
            "blocked",
            url="https://example.invalid/login",
            allowed_host="localhost",
            kind="request",
        )
        session.detect_security_level.return_value = "low"
        session.http.base_url = "http://localhost/dvwa/"
        session.http.containment_events = []
        session.http.get.return_value = MagicMock(text="", status_code=200, headers={})
        session.close.return_value = None
        session_factory.return_value = session

        update = recon({"target_url": "http://localhost/dvwa", "security_level": "low"})

    assert len(update["containment_events"]) == 1
    assert update["containment_events"][0]["blocked_url"] == "https://example.invalid/login"


def test_runner_carries_containment_state_into_artifact(monkeypatch, tmp_path):
    """The artifact exposes containment evidence from the graph final state."""
    event = {
        "kind": "request",
        "blocked_url": "https://example.invalid/escape",
        "allowed_host": "localhost",
        "reason": "blocked by DVWA containment",
    }

    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {
                **state,
                "task_result": "SUCCESS",
                "iteration_count": 1,
                "containment_events": [event],
            }

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_: FakeApp())
    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        surface="sqli",
        payload_mode="static_only",
        target_method="sqli_union",
        output_dir=str(tmp_path),
    )

    assert artifact["containment_events"] == [event]
    assert artifact["final_state"]["containment_events"] == [event]
