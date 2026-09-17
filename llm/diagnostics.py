"""Safe, actionable diagnostics for model-provider failures.

Provider SDK exceptions can contain useful HTTP metadata alongside credentials,
URLs, and request details.  This module extracts only the fields needed to
diagnose an experiment and redacts the human-readable message before it is
written to lifecycle events or artifacts.
"""

from __future__ import annotations

import re
from typing import Any, Mapping


_SECRET_NAME = r"(?:api[_-]?key|authorization|access[_-]?token|secret|password)"
_URL = re.compile(r"(?i)https?://[^\s'\"<>]+")
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(https?://)[^/@\s]+@"), r"\1[REDACTED]@"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (
        re.compile(rf"(?i)(['\"]?{_SECRET_NAME}['\"]?\s*[:=]\s*['\"]?)[^,'\"\s}}]+"),
        r"\1[REDACTED]",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"), "[REDACTED_API_KEY]"),
    (
        re.compile(r"(?is)\b(request\s+(?:body|payload)|request_body)\s*[:=].*$"),
        r"\1=[REDACTED]",
    ),
)


def _redact_url_values(match: re.Match[str]) -> str:
    """Preserve URL parameter names while removing every query/fragment value."""
    raw_url = match.group(0)
    before_fragment, fragment_separator, fragment = raw_url.partition("#")
    base, query_separator, query = before_fragment.partition("?")

    def redact_component(component: str) -> str:
        segments = re.split(r"([&;])", component)
        for index in range(0, len(segments), 2):
            segment = segments[index]
            if not segment:
                continue
            if "=" in segment:
                key, _value = segment.split("=", 1)
                segments[index] = f"{key}=[REDACTED]"
            else:
                segments[index] = "[REDACTED]"
        return "".join(segments)

    redacted = base
    if query_separator:
        redacted += f"?{redact_component(query)}"
    if fragment_separator:
        redacted += f"#{redact_component(fragment)}"
    return redacted


def redact_diagnostic_text(value: Any, *, limit: int = 800) -> str:
    """Return bounded diagnostic text with credentials and request bodies removed."""
    text = " ".join(str(value or "").split())
    text = _URL.sub(_redact_url_values, text)
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    if len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def _exception_chain(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _status_code(chain: list[BaseException]) -> int | None:
    for item in chain:
        value = getattr(item, "status_code", None)
        if value is None:
            value = getattr(getattr(item, "response", None), "status_code", None)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _request_id(chain: list[BaseException]) -> str | None:
    for item in chain:
        value = getattr(item, "request_id", None)
        if value:
            return redact_diagnostic_text(value, limit=160)
        headers = getattr(getattr(item, "response", None), "headers", None)
        if isinstance(headers, Mapping):
            for key in ("x-request-id", "request-id", "x-amzn-requestid"):
                if headers.get(key):
                    return redact_diagnostic_text(headers[key], limit=160)
    return None


def _remediation(*, status_code: int | None, error_type: str, message: str) -> str:
    lowered = f"{error_type} {message}".lower()
    if status_code in {401, 403} or any(word in lowered for word in ("authentication", "unauthorized")):
        return "Check the provider credential, account permissions, and the selected model's access."
    if status_code == 429 or "rate limit" in lowered:
        return "Wait for the provider quota window or lower LLM concurrency, then retry the coordinate."
    if status_code == 404 or "model not found" in lowered:
        return "Check the configured base URL and model name for this provider profile."
    if status_code in {400, 422}:
        return "Check model parameters, reasoning effort support, and structured-output compatibility."
    if status_code is not None and status_code >= 500:
        return "The provider endpoint failed; retry later and use the request ID when contacting the provider."
    if "timeout" in lowered:
        return "Check provider reachability and timeout settings, then retry the affected coordinate."
    if any(word in lowered for word in ("connection", "connecterror", "dns", "name resolution")):
        return "Check network/DNS reachability and the provider base URL, then retry."
    if "structured" in lowered or "response_format" in lowered or "tool_choice" in lowered:
        return "Use json_prompt structured output or choose a model endpoint that supports the configured schema mode."
    return "Check the provider profile, model name, endpoint, and credential, then retry the coordinate."


def provider_error_details(
    exc: BaseException,
    *,
    provider: str,
    model: str | None,
    role: str,
    coordinate_id: str,
) -> dict[str, Any]:
    """Extract a redacted diagnostic record from a provider SDK exception."""
    chain = _exception_chain(exc)
    status_code = _status_code(chain)
    message = redact_diagnostic_text(exc)
    cause_type = type(chain[1]).__name__ if len(chain) > 1 else None
    details: dict[str, Any] = {
        "provider": redact_diagnostic_text(provider, limit=120),
        "model": redact_diagnostic_text(model or "unknown", limit=200),
        "role": redact_diagnostic_text(role, limit=120),
        "coordinate_id": redact_diagnostic_text(coordinate_id, limit=240),
        "error_type": type(exc).__name__,
        "message": message or "provider call failed without an error message",
        "remediation": _remediation(
            status_code=status_code,
            error_type=type(exc).__name__,
            message=message,
        ),
    }
    if status_code is not None:
        details["status_code"] = status_code
    request_id = _request_id(chain)
    if request_id:
        details["request_id"] = request_id
    if cause_type:
        details["cause_type"] = cause_type
    return details


def format_provider_error(details: Mapping[str, Any]) -> str:
    """Format one safe provider diagnostic for logs and caught exceptions."""
    context = ", ".join(
        f"{key}={details.get(key)}"
        for key in ("provider", "model", "role", "coordinate_id")
    )
    metadata = " ".join(
        f"{key}={details[key]}"
        for key in ("status_code", "request_id", "cause_type")
        if details.get(key) is not None
    )
    if metadata:
        metadata = f" ({metadata})"
    return (
        f"LLM provider call failed [{context}]: {details.get('error_type', 'ProviderError')}"
        f"{metadata}: {details.get('message', '')} Remediation: {details.get('remediation', '')}"
    )


def enrich_provider_exception(exc: BaseException, details: Mapping[str, Any]) -> None:
    """Make a caught exception actionable while retaining its concrete type."""
    message = format_provider_error(details)
    try:
        exc.args = (message,)
    except (AttributeError, TypeError):
        pass
    if isinstance(getattr(exc, "message", None), str):
        try:
            setattr(exc, "message", message)
        except (AttributeError, TypeError):
            pass
    add_note = getattr(exc, "add_note", None)
    if callable(add_note):
        add_note(message)


__all__ = [
    "enrich_provider_exception",
    "format_provider_error",
    "provider_error_details",
    "redact_diagnostic_text",
]
