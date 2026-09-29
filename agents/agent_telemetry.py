"""Telemetry event builders for method agents."""

from __future__ import annotations

from typing import Any
from hashlib import sha256


def _response_receipt(response: Any) -> dict:
    if response is None:
        return {}
    body = str(getattr(response, "text", ""))
    # ponytail: bounded excerpt; retain the full-body hash and add matched snippets if 8 KiB falls short.
    return {"response_sha256": sha256(body.encode()).hexdigest(),
        "response_excerpt": body[:8192], "response_truncated": len(body) > 8192}


def probe_event(
    agent_id: str,
    payload: str,
    status_code: int | None,
    signal_detected: bool,
    endpoint: str | None = None,
    elapsed_ms: float | None = None,
    baseline_elapsed_ms: float | None = None,
    delay_ms: float | None = None,
    response: Any = None,
) -> dict[str, Any]:
    """Return a telemetry event for a PROBE stage HTTP request."""
    event_payload: dict[str, Any] = {
        "agent_id": agent_id,
        "payload": payload,
        "endpoint": endpoint,
        "status_code": status_code,
        "signal_detected": signal_detected,
        "verified_grade": 1 if signal_detected else 0,
        "verification_reason": "probe_signal" if signal_detected else "probe_signal_absent",
        **_response_receipt(response),
    }
    if elapsed_ms is not None:
        event_payload["elapsed_ms"] = float(elapsed_ms)
    if baseline_elapsed_ms is not None:
        event_payload["baseline_elapsed_ms"] = float(baseline_elapsed_ms)
    if delay_ms is not None:
        event_payload["delay_ms"] = float(delay_ms)
    return {
        "node": agent_id,
        "event": "agent.probe.sent",
        "status": "ok",
        "payload": event_payload,
    }


def exploit_event(
    agent_id: str,
    payload: str,
    status_code: int | None,
    success: bool,
    endpoint: str | None = None,
    elapsed_ms: float | None = None,
    baseline_elapsed_ms: float | None = None,
    delay_ms: float | None = None,
    response: Any = None,
) -> dict[str, Any]:
    """Return a telemetry event for an EXPLOIT stage HTTP request."""
    event_payload: dict[str, Any] = {
        "agent_id": agent_id,
        "payload": payload,
        "endpoint": endpoint,
        "status_code": status_code,
        "success": success,
        "verified_grade": 0,
        "verification_reason": "no_verified_exploit_signal",
        **_response_receipt(response),
    }
    if elapsed_ms is not None:
        event_payload["elapsed_ms"] = float(elapsed_ms)
    if baseline_elapsed_ms is not None:
        event_payload["baseline_elapsed_ms"] = float(baseline_elapsed_ms)
    if delay_ms is not None:
        event_payload["delay_ms"] = float(delay_ms)
    return {
        "node": agent_id,
        "event": "agent.exploit.sent",
        "status": "ok" if success else "failed",
        "payload": event_payload,
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
