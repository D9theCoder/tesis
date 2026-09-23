"""Secret masking and sanitization helpers for the TUI."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import fields, is_dataclass
from typing import Any

from tesis.runtime_events import redact_secrets


def _safe_config_error_text(exc: BaseException) -> str:
    """Format config-load failures without exposing YAML scalar values."""
    from tesis.doctor import sanitize_config_error

    return sanitize_config_error(exc)


def _contains_literal_secret(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    for key, item in value.items():
        if str(key).lower() in {"api_key", "secret", "token", "password"}:
            if isinstance(item, str) and item and not item.strip().startswith("${"):
                return True
        if isinstance(item, dict) and _contains_literal_secret(item):
            return True
    return False


def _mask_yaml_secrets(payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Mask literal YAML secrets while retaining restorable placeholders."""
    masked = deepcopy(payload)
    preserved: dict[str, str] = {}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in list(value.items()):
                normalized = str(key).lower().replace("-", "_")
                secret_key = any(part in normalized for part in ("api_key", "password", "secret", "token"))
                if secret_key and isinstance(item, str) and item and not item.strip().startswith("${"):
                    placeholder = f"__TESIS_PRESERVE_SECRET_{len(preserved)}__"
                    preserved[placeholder] = item
                    value[key] = placeholder
                else:
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(masked)
    return masked, preserved


def _restore_yaml_secrets(payload: Any, preserved: dict[str, str]) -> Any:
    if isinstance(payload, dict):
        for key, item in list(payload.items()):
            payload[key] = _restore_yaml_secrets(item, preserved)
    elif isinstance(value := payload, list):
        for index, item in enumerate(value):
            value[index] = _restore_yaml_secrets(item, preserved)
    elif isinstance(payload, str) and payload in preserved:
        return preserved[payload]
    return payload


def _sanitize_endpoint(value: Any) -> Any:
    """Display form for a URL: userinfo and every query/fragment *value* masked.

    Keys and their order are preserved so the URL stays readable and auditable,
    but no query or fragment value survives into a drawer, export, or
    screenshot — the canonical contract redacts all of them, not only
    credential-shaped keys.
    """

    if not isinstance(value, str) or "://" not in value:
        return value
    try:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
        parts = urlsplit(value)

        def _scrub(items: list[tuple[str, str]]) -> str:
            return urlencode([(key, "[REDACTED]") for key, _ in items], safe="[]")

        if parts.query or parts.fragment:
            query = _scrub(parse_qsl(parts.query, keep_blank_values=True)) if parts.query else ""
            fragment = parts.fragment
            if fragment:
                if "=" in fragment or "&" in fragment:
                    fragment = _scrub(parse_qsl(fragment, keep_blank_values=True))
                elif fragment.strip():
                    fragment = "[REDACTED]"
            value = urlunsplit((parts.scheme, parts.netloc, parts.path, query, fragment))
    except Exception:
        try:
            import re as _re2
            value = _re2.sub(r"([?&#][^=&#\s]*=)[^&\s#]+", r"\1[REDACTED]", value)
        except Exception:
            pass
    redacted = re.sub(r"(://[^/:\s?#]+:)[^@/\s?#]+@", r"\1[REDACTED]@", value)
    return redacted


def _safe_url(value: Any) -> str:
    """Display form for a target/endpoint URL.

    Every query/fragment value and any userinfo credential is masked by
    :func:`_sanitize_endpoint`; token-shaped text anywhere else is then
    redacted.
    """

    sanitized = _sanitize_endpoint(str(value))
    return _SECRET_TOKEN.sub("[REDACTED]", str(redact_secrets(sanitized)))


def _failure_mapping(failure: Any) -> dict[str, Any]:
    """Normalize a failure payload to a dict.

    The production state carries the slotted :class:`FailureSummary` dataclass;
    legacy callers pass mappings. Dataclass fields are read directly so a
    slotted instance is never silently dropped.
    """

    if failure is None:
        return {}
    if isinstance(failure, dict):
        return dict(failure)
    if is_dataclass(failure) and not isinstance(failure, type):
        return {spec.name: getattr(failure, spec.name) for spec in fields(failure)}
    data = getattr(failure, "__dict__", None)
    return dict(data) if isinstance(data, dict) else {}


def _mask_url_credentials(payload: Any, preserved: dict[str, str]) -> Any:
    """Display masking for URLs embedded in the settings document.

    Registers the exact sanitized spelling as a restore key so an untouched
    document still round-trips the original URL through the existing
    :func:`_restore_yaml_secrets` path.
    """

    if isinstance(payload, dict):
        for key, item in list(payload.items()):
            payload[key] = _mask_url_credentials(item, preserved)
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            payload[index] = _mask_url_credentials(item, preserved)
    elif isinstance(payload, str) and "://" in payload:
        sanitized = _sanitize_endpoint(payload)
        if isinstance(sanitized, str) and sanitized != payload:
            preserved.setdefault(sanitized, payload)
            return sanitized
    return payload


def _redact_mapping(value: Any) -> Any:
    redacted = redact_secrets(value)
    if isinstance(redacted, dict):
        redacted.pop("raw_state", None)
        redacted.pop("chain_of_thought", None)
        redacted.pop("chain-of-thought", None)
        redacted.pop("prompt", None)
        if isinstance(redacted.get("endpoint"), str):
            redacted["endpoint"] = _sanitize_endpoint(redacted["endpoint"])
    return redacted


_SECRET_TOKEN = re.compile(
    r"(?i)\b(?:thk_live|sk-live|sk-proj|xai-[A-Za-z0-9_-]*|AIza[\w-]{20,})[A-Za-z0-9_-]*"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:authorization|api[_-]?key|password|passwd|secret|token|session|cookie)"
    r"\s*[:=]\s*(?:bearer\s+)?)[^\s,;]+"
)


def _redact_text(value: Any) -> str:
    """Redact credential-shaped free text before it reaches state or widgets.

    :func:`redact_secrets` only masks known secret *values* and secret *keys*;
    a summary message embeds a token in prose, so it needs its own pass.
    """

    text = str(redact_secrets(value))
    text = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", text)
    return _SECRET_TOKEN.sub("[REDACTED]", text)
