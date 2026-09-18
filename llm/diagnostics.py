"""Safe, actionable diagnostics for model-provider failures.

Provider SDK exceptions can contain useful HTTP metadata alongside credentials,
URLs, and request details.  This module extracts only the fields needed to
diagnose an experiment and redacts the human-readable message before it is
written to lifecycle events or artifacts.
"""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import urlsplit


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
    # Provider messages often place a sentence after a semicolon without a
    # separating space in the URL token (``?token=x; retry later``).  Treat
    # that semicolon as prose rather than consuming and redacting the tail.
    tail = ""
    semicolon_tail = re.search(r";(?=\s)", raw_url)
    if semicolon_tail:
        raw_url, tail = raw_url[:semicolon_tail.start()], raw_url[semicolon_tail.start():]

    # Keep ordinary punctuation outside the URL.  This both makes the
    # rendered diagnostic easier to read and prevents a closing sentence
    # delimiter from becoming part of a redacted query value.
    punctuation = ".,!?)]}"
    trailing = ""
    while raw_url and raw_url[-1] in punctuation:
        trailing = raw_url[-1] + trailing
        raw_url = raw_url[:-1]
    before_fragment, fragment_separator, fragment = raw_url.partition("#")
    base, query_separator, query = before_fragment.partition("?")
    # Redact URL userinfo while the URL is still structured.  The generic
    # credential regex below remains a second line of defense for malformed
    # provider messages, but must not be the only protection here.
    scheme, scheme_separator, authority_path = base.partition("://")
    if scheme_separator and "@" in authority_path:
        base = f"{scheme}://[REDACTED]@{authority_path.rsplit('@', 1)[-1]}"

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
    return redacted + trailing + tail


def sanitize_endpoint(value: Any, *, limit: int = 240) -> str | None:
    """Return a provider endpoint without userinfo, query, or fragment.

    ``base_url`` is useful in a failure record, but it must never echo a
    credential embedded in ``https://user:password@host`` or a signed query
    string.  The path is retained because ``/v1`` versus a root endpoint is
    actionable when comparing provider profiles.
    """
    text = " ".join(str(value or "").split()).strip()
    if not text:
        return None
    try:
        parts = urlsplit(text)
        if not parts.scheme or not parts.netloc:
            return redact_diagnostic_text(text, limit=limit) or None
        hostname = parts.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        try:
            port = parts.port
        except ValueError:
            port = None
        netloc = hostname + (f":{port}" if port is not None else "")
        path = parts.path.rstrip("/")
        endpoint = f"{parts.scheme.lower()}://{netloc}{path}"
    except (TypeError, ValueError):
        endpoint = text
    return redact_diagnostic_text(endpoint, limit=limit) or None


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


def classify_failure(
    *,
    parse_status: str | None = None,
    status_code: int | None = None,
    error_type: str | None = None,
    cause_type: str | None = None,
    message: str | None = None,
) -> str:
    """Map a provider/runtime result to the stable failure classes.

    The class deliberately uses only normalized metadata.  It therefore
    remains deterministic for simulated provider exceptions and does not
    need to inspect a concrete SDK exception type at the artifact boundary.
    """
    normalized_parse = str(parse_status or "").strip().lower()
    if normalized_parse in {"incomplete", "truncated", "output_truncated"}:
        return "output_truncated"
    if status_code is not None:
        try:
            if int(status_code) >= 400:
                return "http_rejected"
        except (TypeError, ValueError):
            pass
    lowered = " ".join(
        str(value or "")
        for value in (error_type, cause_type, message)
    ).lower()
    if any(marker in lowered for marker in (
        "timeout",
        "readtimeout",
        "connecttimeout",
        "timed out",
    )):
        return "transport_timeout"
    if normalized_parse in {"invalid", "schema_rejected", "parse_error"}:
        return "schema_rejected"
    if any(marker in lowered for marker in (
        "connection",
        "connecterror",
        "dns",
        "name resolution",
        "network is unreachable",
        "unreachable",
        "socket",
    )):
        return "transport_error"
    return "provider_error_unknown"


def _remediation(*, status_code: int | None, error_type: str, message: str) -> str:
    lowered = f"{error_type} {message}".lower()
    if any(word in lowered for word in (
        "insufficient",
        "quota",
        "balance",
        "credits",
        "billing",
        "credit limit",
    )):
        return (
            "Provider account/budget rejection: top up quota or use another profile; "
            "a retry alone will not succeed."
        )
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
    endpoint: str | None = None,
    model_profile: str | None = None,
    timeout_s: float | int | None = None,
    attempts: int | None = None,
    max_retries: int | None = None,
    elapsed_ms: int | None = None,
    parse_status: str = "provider_error",
    run_id: str | None = None,
    call_id: str | None = None,
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
        "parse_status": parse_status,
        "failure_class": classify_failure(
            parse_status=parse_status,
            status_code=status_code,
            error_type=type(exc).__name__,
            cause_type=cause_type,
            message=message,
        ),
        "remediation": _remediation(
            status_code=status_code,
            error_type=type(exc).__name__,
            message=message,
        ),
    }
    if endpoint:
        details["endpoint"] = sanitize_endpoint(endpoint)
    if model_profile is not None:
        details["model_profile"] = redact_diagnostic_text(model_profile, limit=120)
    if timeout_s is not None:
        details["timeout_s"] = timeout_s
    if attempts is not None:
        details["attempts"] = attempts
    if max_retries is not None:
        details["max_retries"] = max_retries
    if elapsed_ms is not None:
        details["elapsed_ms"] = elapsed_ms
    if run_id is not None:
        details["run_id"] = redact_diagnostic_text(run_id, limit=240)
    if call_id is not None:
        details["call_id"] = redact_diagnostic_text(call_id, limit=300)
    if status_code is not None:
        details["status_code"] = status_code
        details["http_status"] = status_code
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
        for key in ("status_code", "request_id", "cause_type", "failure_class")
        if details.get(key) is not None
    )
    endpoint = details.get("endpoint")
    if endpoint:
        metadata = f"endpoint={endpoint} {metadata}".strip()
    if metadata:
        metadata = f" ({metadata})"
    return (
        f"LLM provider call failed [{context}]: {details.get('error_type', 'ProviderError')}"
        f"{metadata}: {details.get('message', '')} Remediation: {details.get('remediation', '')}"
    )


_FAILURE_VERBS = {
    "transport_timeout": "stalled",
    "transport_error": "was unreachable",
    "http_rejected": "rejected the request",
    "schema_rejected": "answered but the payload was rejected by our schema",
    "output_truncated": "hit the output limit",
    "provider_error_unknown": "failed",
}


def _clip(value: Any, limit: int) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def _compact_remediation(value: Any) -> str:
    """Keep the live line actionable when the full artifact hint is verbose."""
    text = " ".join(str(value or "").split())
    lowered = text.lower()
    if any(word in lowered for word in ("quota", "balance", "credits", "billing", "insufficient")):
        return "Top up quota or switch provider profile; retrying will not succeed."
    if "timeout" in lowered or "reachability" in lowered:
        return "Check provider reachability and timeout settings, then retry."
    if any(word in lowered for word in ("credential", "authentication", "permissions")):
        return "Check provider credentials, account permissions, and model access."
    if "structured" in lowered or "schema" in lowered:
        return "Fix response schema/prompt compatibility, then retry."
    return text


def format_failure_line(failure: Mapping[str, Any], *, limit: int = 400) -> str:
    """Render one actionable, secret-free failure line with a hard size cap."""
    values: dict[str, Any] = {
        "failure_class": str(failure.get("failure_class") or "provider_error_unknown"),
        "role": _clip(failure.get("role") or "unknown", 24),
        "provider": _clip(failure.get("provider") or "unknown", 28),
        "model": _clip(failure.get("model") or "unknown", 42),
        "endpoint": _clip(failure.get("endpoint") or "unknown", 70),
        "request_id": _clip(failure.get("request_id") or "none", 28),
        "parse_status": _clip(failure.get("parse_status") or "unknown", 20),
        "run_id": _clip(failure.get("run_id") or "none", 34),
        "call_id": _clip(failure.get("call_id") or "none", 46),
        "message": _clip(failure.get("message") or "provider call failed", 80),
        "remediation": _clip(
            _compact_remediation(
                failure.get("remediation") or "Check the provider profile and retry."
            ),
            110,
        ),
    }
    verb = _FAILURE_VERBS.get(values["failure_class"], "failed")
    elapsed = failure.get("elapsed_ms")
    elapsed = elapsed if elapsed is not None else "none"
    http_status = failure.get("http_status")
    if http_status is None:
        http_status = failure.get("status_code")
    http_status = http_status if http_status is not None else "none"
    timeout = failure.get("timeout_s")
    timeout = timeout if timeout is not None else "none"
    attempts = failure.get("attempts") if failure.get("attempts") is not None else 1
    max_retries = failure.get("max_retries") if failure.get("max_retries") is not None else 0

    def render() -> str:
        return (
            f"{values['failure_class']}: {values['role']} {values['provider']}/{values['model']} "
            f"@{values['endpoint']} {verb} after {elapsed} ms "
            f"(http={http_status}, request_id={values['request_id']}, timeout={timeout}s, "
            f"attempts={attempts}/retries={max_retries}, parse={values['parse_status']}) "
            f"[run={values['run_id']} call={values['call_id']}] - {values['message']} "
            f"| remediation: {values['remediation']}"
        )

    line = render()
    # IDs and diagnostic text are useful for an artifact, but the live line
    # must remain readable. Shorten low-value tails before applying the final
    # hard cap so the remediation survives truncation.
    for field, minimum in (
        ("call_id", 20),
        ("run_id", 18),
        ("message", 28),
        ("model", 24),
        ("endpoint", 40),
        ("remediation", 60),
    ):
        while len(line) > limit:
            current = values[field]
            if len(current) <= minimum:
                break
            values[field] = _clip(current, max(minimum, len(current) - 12))
            line = render()
    if len(line) <= limit:
        return line
    suffix = f" | remediation: {values['remediation']}"
    if len(suffix) + 3 < limit:
        prefix = line[: -len(suffix)] if line.endswith(suffix) else line.split(" | remediation:", 1)[0]
        prefix_limit = max(0, limit - len(suffix) - 3)
        return prefix[:prefix_limit] + "..." + suffix
    return line[: max(0, limit - 3)] + "..."


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
    "classify_failure",
    "enrich_provider_exception",
    "format_failure_line",
    "format_provider_error",
    "provider_error_details",
    "redact_diagnostic_text",
    "sanitize_endpoint",
]
