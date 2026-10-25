"""Reasoning catalog metadata and validation, independent of provider clients."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REASONING_EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh", "max")
FALLBACK_EFFORTS = ("off", "minimal", "low", "medium", "high", "xhigh", "max")


def validate_reasoning_effort(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value.strip().lower()):
        raise ValueError("reasoning_effort must be a short effort name (letters, digits, _ or -), or null")
    return value.strip().lower()


def advertised_efforts(model: Mapping[str, Any]) -> list[str] | None:
    """Accept explicit effort lists without inventing support from a model name."""
    values = model.get("reasoning_efforts", model.get("supported_reasoning_efforts"))
    if values is None:
        return None
    if not isinstance(values, list):
        raise ValueError("reasoning_efforts must be a list")
    result = []
    for item in values:
        value = item.get("reasoning_effort", item.get("effort")) if isinstance(item, Mapping) else item
        value = validate_reasoning_effort(value)
        if value is None:
            raise ValueError("reasoning_efforts must contain nonempty effort names")
        if value not in result:
            result.append(value)
    return result


def model_efforts(config: Mapping[str, Any], model_name: str,
                  metadata: Mapping[str, Any] | None = None) -> list[str] | None:
    """Live metadata wins, then an exact-ID YAML preset; unknown stays unknown."""
    advertised = advertised_efforts(metadata or {})
    if advertised is not None:
        return advertised
    catalogs = config.get("reasoning_catalog") or {}
    if not isinstance(catalogs, Mapping):
        raise ValueError("reasoning_catalog must map exact model IDs to effort lists")
    values = catalogs.get(model_name)
    return advertised_efforts({"reasoning_efforts": values}) if values is not None else None
