"""Telemetry event builders for method agents."""

from __future__ import annotations

from typing import Any


def probe_event(
    agent_id: str,
    payload: str,
    status_code: int | None,
    signal_detected: bool,
    endpoint: str | None = None,
) -> dict[str, Any]:
    """Return a telemetry event for a PROBE stage HTTP request."""
    return {
        "node": agent_id,
        "event": "agent.probe.sent",
        "status": "ok",
        "payload": {
            "agent_id": agent_id,
            "payload": payload,
            "endpoint": endpoint,
            "status_code": status_code,
            "signal_detected": signal_detected,
        },
    }


def exploit_event(
    agent_id: str,
    payload: str,
    status_code: int | None,
    success: bool,
    endpoint: str | None = None,
) -> dict[str, Any]:
    """Return a telemetry event for an EXPLOIT stage HTTP request."""
    return {
        "node": agent_id,
        "event": "agent.exploit.sent",
        "status": "ok" if success else "failed",
        "payload": {
            "agent_id": agent_id,
            "payload": payload,
            "endpoint": endpoint,
            "status_code": status_code,
            "success": success,
        },
    }


def score_event(
    agent_id: str,
    score: int,
    confirmed: list[str],
    outcomes: list[str],
) -> dict[str, Any]:
    """Return a telemetry event summarizing the agent's final score."""
    if not isinstance(score, int) or not (0 <= score <= 4):
        raise ValueError(f"score must be an int between 0 and 4, got {score!r}")
    return {
        "node": agent_id,
        "event": "agent.score.final",
        "status": "ok",
        "payload": {
            "agent_id": agent_id,
            "score": score,
            "confirmed_vulns": confirmed,
            "achieved_outcomes": outcomes,
        },
    }
