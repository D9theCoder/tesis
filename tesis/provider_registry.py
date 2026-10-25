"""Reusable API-key providers expanded into the existing model-profile contract."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit


API_PROTOCOLS = {
    "openai": "OpenAI Responses",
    "openai_compatible": "OpenAI Chat Completions",
    "anthropic": "Anthropic Messages",
}
_ADAPTERS = {"openai": "openai", "openai_compatible": "openai_compatible", "anthropic": "claude"}
_PROVIDER_ID = re.compile(r"[a-z][a-z0-9_-]*\Z")


def validate_api_url(value: str) -> str:
    """Accept explicit HTTP(S) endpoints without embedded credentials."""
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme in {"http", "https"} and parsed.hostname and parsed.port != 0
                 and parsed.username is None and parsed.password is None and not parsed.fragment
                 and not any(char.isspace() or ord(char) < 32 for char in value))
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Use an absolute HTTP(S) URL without credentials, spaces, or a fragment.")
    return value


def model_profile_id(provider_id: str, model_id: str) -> str:
    """Stable, filename-safe identity, including case-sensitive gateway model IDs."""
    slug = re.sub(r"[^a-z0-9_-]+", "-", model_id.lower()).strip("-")[:48] or "model"
    digest = hashlib.sha256(model_id.encode()).hexdigest()[:12]
    return f"{provider_id}__{slug}_{digest}"


def provider_key_variable(provider_id: str) -> str:
    digest = hashlib.sha256(provider_id.encode()).hexdigest()[:8].upper()
    return f"TESIS_PROVIDER_{provider_id.upper().replace('-', '_')}_{digest}_API_KEY"


def validate_provider_entry(provider_id: str, entry: Mapping[str, Any]) -> None:
    if not _PROVIDER_ID.fullmatch(provider_id) or len(provider_id) > 64:
        raise ValueError("Provider ID must start with a lowercase letter and contain only a-z, 0-9, _ or - (max 64).")
    if provider_id == "openai_codex_auth":
        raise ValueError("openai_codex_auth uses its separate ChatGPT sign-in flow.")
    if not isinstance(entry.get("protocol"), str) or entry["protocol"] not in API_PROTOCOLS:
        raise ValueError("Choose OpenAI Responses, OpenAI Chat Completions, or Anthropic Messages.")
    validate_api_url(str(entry.get("base_url") or ""))
    if entry.get("fetch_url"):
        validate_api_url(str(entry["fetch_url"]))
    if not isinstance(entry.get("api_key"), str) or not entry["api_key"].strip():
        raise ValueError("An API key or environment reference is required.")
    models = entry.get("models")
    if not isinstance(models, list) or not models:
        raise ValueError("Select or add at least one model.")
    if any(not isinstance(model, str) or not model or any(c.isspace() or ord(c) < 32 for c in model)
           for model in models):
        raise ValueError("Model IDs must be nonempty strings without spaces or control characters.")
    if len(set(models)) != len(models):
        raise ValueError("Model IDs must be unique within a provider.")
    if entry.get("extra") is not None and not isinstance(entry["extra"], Mapping):
        raise ValueError("Provider extra settings must be a mapping.")
    if entry.get("display_name") is not None and not isinstance(entry["display_name"], str):
        raise ValueError("Provider display name must be a string.")


def expanded_model_sections(config: Mapping[str, Any]) -> dict[str, Any]:
    """Retain legacy profiles and add one profile per selected provider/model."""
    legacy = config.get("models") or {}
    if not isinstance(legacy, Mapping):
        raise ValueError("models must be a mapping")
    result = dict(legacy)
    providers = config.get("api_providers") or {}
    if not isinstance(providers, Mapping):
        raise ValueError("api_providers must be a mapping")
    for provider_id, entry in providers.items():
        if not isinstance(provider_id, str) or not isinstance(entry, Mapping):
            raise ValueError("api_providers must map provider IDs to settings")
        validate_provider_entry(provider_id, entry)
        for model_id in entry["models"]:
            name = model_profile_id(provider_id, model_id)
            if name in result:
                raise ValueError(f"Duplicate model profile: {name}")
            section = {key: entry[key] for key in (
                "temperature", "timeout", "max_tokens", "reasoning_effort", "extra",
            ) if key in entry}
            extra = dict(section.get("extra") or {})
            # A custom provider's selected wire protocol is authoritative.
            if entry["protocol"] in {"openai", "openai_compatible"}:
                extra["use_responses_api"] = entry["protocol"] == "openai"
                if entry["protocol"] == "openai":
                    extra.setdefault("store", False)
            section.update(provider=_ADAPTERS[entry["protocol"]], model_name=model_id,
                           api_key=entry["api_key"], base_url=entry["base_url"], extra=extra)
            if entry["protocol"] == "anthropic":
                parts = urlsplit(entry["base_url"])
                path = parts.path.rstrip("/")
                if path.endswith("/v1"):
                    path = path[:-3]
                section["base_url"] = urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))
            result[name] = section
    return result


def model_profile_labels(config: Mapping[str, Any]) -> dict[str, str]:
    labels = {name: name for name in expanded_model_sections(config)}
    for provider_id, entry in (config.get("api_providers") or {}).items():
        display = str(entry.get("display_name") or provider_id)
        for model_id in entry["models"]:
            labels[model_profile_id(provider_id, model_id)] = f"{display} / {model_id}"
    return labels
