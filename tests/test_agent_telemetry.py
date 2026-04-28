"""Tests for Stage 8.2 agent-level telemetry emission."""

from __future__ import annotations

from types import SimpleNamespace

import importlib

cmdi_module = importlib.import_module("agents.tier1.cmdi_agent")
sqli_module = importlib.import_module("agents.tier1.sqli_agent")
upload_module = importlib.import_module("agents.tier2.upload_agent")


class FakeResult:
    def __init__(self, text: str = "", elapsed_ms: float = 0.0, headers: dict | None = None):
        self.text = text
        self.elapsed_ms = elapsed_ms
        self.headers = headers or {}


def test_sqli_agent_emits_telemetry_events(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={})

        def get(self, _endpoint, params=None):
            return FakeResult(text="First name: admin Surname: user password")

        def close(self):
            return None

    monkeypatch.setattr(sqli_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "sqli", "url": "/vulnerabilities/sqli/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = sqli_module.sqli_agent(state)

    telemetry = update.get("telemetry_events", [])
    events = [t["event"] for t in telemetry]
    assert "sqli_agent.started" in events
    assert "sqli_agent.probe.result" in events
    assert "sqli_agent.completed" in events

    # Verify payload structure
    result_event = next(t for t in telemetry if t["event"] == "sqli_agent.probe.result")
    assert "payload" in result_event
    assert "error_ok" in result_event["payload"]
    assert "credential_ok" in result_event["payload"]


def test_cmdi_agent_emits_telemetry_events(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={})

        def post(self, _endpoint, data=None):
            return FakeResult(text="uid=33(www-data) gid=33(www-data)")

        def close(self):
            return None

    monkeypatch.setattr(cmdi_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "cmdi", "url": "/vulnerabilities/exec/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = cmdi_module.cmdi_agent(state)

    telemetry = update.get("telemetry_events", [])
    events = [t["event"] for t in telemetry]
    assert "cmdi_agent.started" in events
    assert "cmdi_agent.probe.result" in events
    assert "cmdi_agent.completed" in events

    result_event = next(t for t in telemetry if t["event"] == "cmdi_agent.probe.result")
    assert result_event["payload"]["regex_ok"] is True


def test_upload_agent_emits_telemetry_events(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={})

        def post(self, _endpoint, data=None, files=None):
            return FakeResult(text="hackable/uploads/shell.php succesfully uploaded")

        def get(self, _endpoint, params=None):
            return FakeResult(text="uid=33(www-data) gid=33(www-data)")

        def close(self):
            return None

    monkeypatch.setattr(upload_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "upload", "url": "/vulnerabilities/upload/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = upload_module.upload_agent(state)

    telemetry = update.get("telemetry_events", [])
    events = [t["event"] for t in telemetry]
    assert "upload_agent.started" in events
    assert "upload_agent.upload.attempt" in events
    assert "upload_agent.upload.success" in events
    assert "upload_agent.execution.verify" in events
    assert "upload_agent.completed" in events

    verify_event = next(t for t in telemetry if t["event"] == "upload_agent.execution.verify")
    assert "uploaded_path" in verify_event["payload"]
    assert "regex_ok" in verify_event["payload"]


def test_upload_agent_no_target_emits_completion_telemetry(monkeypatch):
    state = {
        "target_url": "",
        "security_level": "low",
        "endpoints": [],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = upload_module.upload_agent(state)

    telemetry = update.get("telemetry_events", [])
    events = [t["event"] for t in telemetry]
    assert "upload_agent.started" in events
    assert "upload_agent.completed" in events
    completion = next(t for t in telemetry if t["event"] == "upload_agent.completed")
    assert completion["payload"]["reason"] == "no_target_url"
