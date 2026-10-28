"""Telemetry event builders for method agents."""

from __future__ import annotations

import json
from typing import Any
from hashlib import sha256
from urllib.parse import parse_qsl, urlparse

from httpx import RequestNotRead


def _request_structure(response: Any) -> dict[str, Any]:
    """Describe an HTTP request without retaining query or body values."""
    raw_response = getattr(response, "response", response) if response is not None else None
    request = getattr(response, "request", None) if response is not None else None
    if request is None and raw_response is not None:
        request = getattr(raw_response, "request", None)
    if request is None:
        return {
            "available": False,
            "reason": "prepared_request_unavailable",
            "redaction_applied": True,
            "raw_values_included": False,
        }

    url = str(getattr(request, "url", "") or "")
    parsed = urlparse(url)
    query_fields = [
        {"name": key, "value_type": "string", "redacted": True}
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    headers = getattr(request, "headers", {}) or {}
    content_type = str(headers.get("Content-Type", "")).split(";", 1)[0].strip().lower()
    body = getattr(request, "body", None)
    body_unavailable = False
    if body is None:
        try:
            body = getattr(request, "content", None)
        except RequestNotRead:
            # Do not consume a request stream merely to collect telemetry.
            body_unavailable = True
    body_empty = body is None or body == b"" or body == ""
    body_shape: dict[str, Any] = {
        "present": None if body_unavailable else not body_empty,
        "content_type": content_type or None,
    }
    if body_unavailable:
        body_shape.update(encoding="unavailable", fields=[], reason="request_body_not_buffered")
    elif body_empty:
        body_shape["encoding"] = "empty"
        body_shape["fields"] = []
    elif isinstance(body, dict):
        body_shape["encoding"] = "mapping"
        body_shape["fields"] = [
            {"name": str(key), "value_type": type(value).__name__, "redacted": True}
            for key, value in body.items()
        ]
    else:
        body_text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
        if content_type == "application/x-www-form-urlencoded":
            body_shape["encoding"] = "form"
            body_shape["fields"] = [
                {"name": key, "value_type": "string", "redacted": True}
                for key, _ in parse_qsl(body_text, keep_blank_values=True)
            ]
        elif content_type == "application/json":
            body_shape["encoding"] = "json"
            try:
                parsed_body = json.loads(body_text)
            except (json.JSONDecodeError, TypeError):
                body_shape["fields"] = []
                body_shape["parse_status"] = "invalid_json"
            else:
                body_shape["fields"] = [
                    {"name": str(key), "value_type": type(value).__name__, "redacted": True}
                    for key, value in sorted(parsed_body.items())
                ] if isinstance(parsed_body, dict) else []
                body_shape["root_type"] = type(parsed_body).__name__
        else:
            body_shape["encoding"] = "opaque"
            body_shape["fields"] = []

    shape = {
        "available": True,
        "method": str(getattr(request, "method", "") or "").upper() or None,
        "path": parsed.path or None,
        "query_fields": query_fields,
        "body": body_shape,
        "redaction_applied": True,
        "raw_values_included": False,
    }
    shape["shape_sha256"] = sha256(
        json.dumps(shape, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return shape


def _response_receipt(response: Any) -> dict:
    if response is None:
        return {"request_structure": _request_structure(response)}
    body = str(getattr(response, "text", ""))
    # ponytail: bounded excerpt; retain the full-body hash and add matched snippets if 8 KiB falls short.
    return {"response_sha256": sha256(body.encode()).hexdigest(),
        "response_excerpt": body[:8192], "response_truncated": len(body) > 8192,
        "request_structure": _request_structure(response)}


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
    candidate_id: str | None = None,
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
    candidate_id = candidate_id or getattr(payload, "candidate_id", None)
    if candidate_id:
        event_payload["candidate_id"] = str(candidate_id)
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
    candidate_id: str | None = None,
) -> dict[str, Any]:
    """Return a telemetry event for an EXPLOIT stage HTTP request."""
    event_payload: dict[str, Any] = {
        "agent_id": agent_id,
        "payload": payload,
        "endpoint": endpoint,
        "status_code": status_code,
        "success": success,
        "signal_detected": success,
        "verified_grade": 0,
        "verification_reason": "no_verified_exploit_signal",
        **_response_receipt(response),
    }
    candidate_id = candidate_id or getattr(payload, "candidate_id", None)
    if candidate_id:
        event_payload["candidate_id"] = str(candidate_id)
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
