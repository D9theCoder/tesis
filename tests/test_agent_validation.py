"""Standalone agent validation harness against live DVWA target.

These tests require a running DVWA instance. Set DVWA_TARGET_URL env var.
They are skipped by default if the target is unreachable.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from core.state import new_default_state
from foundation.session_manager import DVWASession


TARGET_URL = os.getenv("DVWA_TARGET_URL", "http://172.19.48.1/dvwa")


def _target_reachable() -> bool:
    try:
        import httpx
        response = httpx.get(TARGET_URL, timeout=5.0, follow_redirects=True)
        return response.status_code < 500
    except Exception:
        return False


@pytest.fixture(scope="module")
def dvwa_session():
    if not _target_reachable():
        pytest.skip(f"DVWA target unreachable: {TARGET_URL}")
    session = DVWASession(TARGET_URL)
    session.login()
    return session


def _agent_state(level: str = "low") -> dict[str, Any]:
    return {
        **new_default_state(),
        "target_url": TARGET_URL,
        "security_level": level,
    }


class TestSQLiAgent:
    def test_low_level_finds_error(self, dvwa_session):
        from agents.tier1.sqli_agent import SQLiAgent
        agent = SQLiAgent()
        state = _agent_state("low")
        result = agent.run(state)
        assert result["scores"]["sqli"] >= 1
        assert "sqli_confirmed" in result.get("confirmed_vulns", [])


class TestCommandInjectionAgent:
    def test_low_level_executes_command(self, dvwa_session):
        from agents.tier1.cmdi_agent import CommandInjectionAgent
        agent = CommandInjectionAgent()
        state = _agent_state("low")
        result = agent.run(state)
        assert result["scores"]["cmdi"] >= 1
        if result["scores"]["cmdi"] == 4:
            assert "cmd_injection_confirmed" in result.get("confirmed_vulns", [])
            assert "rce_achieved" in result.get("achieved_outcomes", [])


class TestUploadAgent:
    def test_low_level_upload_and_execution(self, dvwa_session):
        from agents.tier2.upload_agent import UploadAgent
        agent = UploadAgent()
        state = _agent_state("low")
        result = agent.run(state)
        assert result["scores"]["upload"] >= 1
        telemetry = result.get("telemetry_events", [])
        verify_events = [e for e in telemetry if e["event"] == "upload_agent.execution.verify"]
        if verify_events:
            assert "uploaded_path" in verify_events[0].get("payload", {})
