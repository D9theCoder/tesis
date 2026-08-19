"""Configuration loader and validator for Stage 7 CLI."""

from __future__ import annotations

import os
import re
from dataclasses import asdict
from io import StringIO
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from dotenv import load_dotenv
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from core.state import METHODS_BY_SURFACE, SECURITY_LEVELS, SURFACES
from llm.provider import SUPPORTED_PROVIDERS
from tesis.model_config import (
    EVASION_MODES,
    LLM_CACHE_SCOPES,
    LLM_RUNTIME_ROLES,
    STRUCTURED_OUTPUT_MODES,
    EngagementConfig,
    LLMRuntimeConfig,
    ModelConfig,
    PAYLOAD_MODES,
    RoleConfig,
)
from tesis.config_fields import FORM_MATRIX, FORM_SINGLE, validate_config as validate_field_schema


class ConfigError(ValueError):
    """Raised when config parsing/validation fails."""


_VALID_EVASION_MODES: frozenset[str] = EVASION_MODES
_VALID_PAYLOAD_MODES: frozenset[str] = PAYLOAD_MODES
_VALID_EXPERIMENT_CONDITIONS: frozenset[str] = frozenset({"linear_hybrid", "akg_guided_hybrid"})

_ENV_REF_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)}")


def _round_trip_yaml() -> YAML:
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    return yaml


def mask_secret(value: str, *, unmasked_tail: int = 4) -> str:
    """Handles mask secret behavior for this module.

    Args:
        value: Value used by this function.
        unmasked_tail: Value used by this function."""
    if not value:
        return ""
    if len(value) <= unmasked_tail:
        return "*" * len(value)
    return f"****{value[-unmasked_tail:]}"


def load_yaml_config(path: str | Path) -> dict[str, Any]:
    """Loads yaml config from configured inputs.

    Args:
        path: Value used by this function."""
    config_path = Path(path)
    if not config_path.exists():
        return {}
    try:
        raw = _round_trip_yaml().load(config_path.read_text(encoding="utf-8"))
    except (YAMLError, OSError) as exc:
        raise ConfigError(f"Invalid YAML in {config_path}: {exc}") from exc
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"Config file must contain a YAML mapping: {config_path}")
    return raw


def save_yaml_config(path: str | Path, payload: Mapping[str, Any]) -> Path:
    """Handles save yaml config behavior for this module.

    Args:
        path: Value used by this function.
        payload: Value used by this function."""
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    stream = StringIO()
    _round_trip_yaml().dump(payload, stream)
    config_path.write_text(stream.getvalue(), encoding="utf-8")
    return config_path


def parse_yaml_config(raw_text: str) -> dict[str, Any]:
    """Parse editable YAML without discarding comments or mapping order."""
    try:
        raw = _round_trip_yaml().load(raw_text)
    except YAMLError as exc:
        raise ConfigError(f"Invalid YAML: {exc}") from exc
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError("Config document must contain a YAML mapping")
    return raw


def dump_yaml_config(payload: Mapping[str, Any]) -> str:
    """Serialize a round-trip YAML document for the advanced settings editor."""
    stream = StringIO()
    _round_trip_yaml().dump(payload, stream)
    return stream.getvalue()


def _resolve_env_refs(value: Any) -> Any:
    """Supports resolve env refs behavior for this module."""
    if isinstance(value, dict):
        return {k: _resolve_env_refs(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env_refs(v) for v in value]
    if not isinstance(value, str):
        return value

    def _replace(match: re.Match[str]) -> str:
        """Supports replace behavior for this module."""
        env_key = match.group(1)
        env_value = os.getenv(env_key)
        if env_value is None:
            raise ConfigError(f"Missing environment variable for config placeholder: {env_key}")
        return env_value

    return _ENV_REF_PATTERN.sub(_replace, value)


def resolve_env_references(config: dict[str, Any]) -> dict[str, Any]:
    """Handles resolve env references behavior for this module.

    Args:
        config: Value used by this function."""
    return _resolve_env_refs(config)


def _parse_bool(raw: str) -> bool:
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _coerce_bool(value: Any) -> bool:
    """Supports coerce bool behavior for this module."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return _parse_bool(value)
    if isinstance(value, (int, float)):
        return value != 0
    return bool(value)


def _parse_csv(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def load_env_overrides(prefix: str = "TESIS_") -> dict[str, Any]:
    """Loads env overrides from configured inputs.

    Args:
        prefix: Value used by this function."""
    overrides: dict[str, Any] = {}
    mapping: dict[str, str] = {
        "TARGET_URL": "target_url",
        "PROVIDER": "provider",
        "LEVEL": "level",
        "SECURITY_LEVEL": "level",
        "SURFACE": "surface",
        "PAYLOAD_MODE": "payload_mode",
        "CANDIDATE_BUDGET": "candidate_budget",
        "ITERATIONS": "iterations",
        "MAX_ITERATIONS": "iterations",
        "REPEATS": "repeats",
        "OUTPUT_DIR": "output_dir",
        "MATRIX": "matrix",
        "PROVIDERS": "providers",
        "LEVELS": "levels",
        "SURFACES": "surfaces",
        "PAYLOAD_MODES": "payload_modes",
        "FORMAT": "report_format",
        "ENRICHED_REPORTING": "enriched_reporting",
        "STOP_POLICY": "stop_policy",
        "COVERAGE_TARGET": "coverage_target",
        "DIAGNOSE": "diagnose",
        "EVASION_ENABLED": "evasion_enabled",
        "EVASION_MODE": "evasion_mode",
        "EVASION_STRATEGY": "evasion_strategy",
        "EVASION_MAX_RETRIES": "evasion_max_retries",
        "EVASION_COOLDOWN_THRESHOLD": "evasion_cooldown_threshold",
        # Canonical terminology.  Legacy EVASION_* variables remain supported
        # for existing installations and map through the same runtime fields.
        "GUARDRAIL_RETRY_ENABLED": "guardrail_retry_enabled",
        "GUARDRAIL_HANDLING": "guardrail_handling",
        "GUARDRAIL_RETRY_MODE": "guardrail_handling",
        "GUARDRAIL_RETRY_MAX": "guardrail_retry_max",
        "GUARDRAIL_RETRY_COOLDOWN_THRESHOLD": "guardrail_retry_cooldown_threshold",
        # LLM-only runtime controls.  These are intentionally kept separate
        # from provider model credentials so a run can select role overrides
        # without changing the shared model profiles.
        "LLM_MAX_CONCURRENCY": "llm_max_concurrency",
        "LLM_CACHE": "llm_cache",
        "LLM_CACHE_SCOPE": "llm_cache_scope",
        "ORCHESTRATOR_MODEL_PROFILE": "orchestrator_model_profile",
        "ORCHESTRATOR_MODEL": "orchestrator_model",
        "PAYLOAD_MODEL_PROFILE": "payload_model_profile",
        "PAYLOAD_MODEL": "payload_model",
    }

    for key, raw_value in os.environ.items():
        if not key.startswith(prefix):
            continue

        suffix = key[len(prefix):]
        if suffix.startswith("MODEL_"):
            remainder = suffix[len("MODEL_"):]
            matched_provider = None
            for candidate in sorted(SUPPORTED_PROVIDERS, key=len, reverse=True):
                prefix_candidate = f"{candidate.upper()}_"
                if remainder.startswith(prefix_candidate):
                    matched_provider = candidate
                    field_name = remainder[len(prefix_candidate):].lower()
                    break
            if not matched_provider:
                parts = suffix.split("_")
                if len(parts) < 4:
                    continue
                matched_provider = parts[1].lower()
                field_name = "_".join(parts[2:]).lower()
            if not field_name:
                continue
            models = overrides.setdefault("models", {})
            model = models.setdefault(matched_provider, {})
            model[field_name] = raw_value
            continue

        mapped = mapping.get(suffix)
        if not mapped:
            continue

        value: Any = raw_value
        if mapped in {
            "iterations", "repeats", "evasion_max_retries", "evasion_cooldown_threshold",
            "guardrail_retry_max", "guardrail_retry_cooldown_threshold", "candidate_budget",
            "llm_max_concurrency",
        }:
            try:
                value = int(raw_value)
            except ValueError as exc:
                raise ConfigError(f"Invalid integer value for {key}: {raw_value}") from exc
        elif mapped in {
            "matrix", "enriched_reporting", "diagnose", "evasion_enabled",
            "guardrail_retry_enabled", "llm_cache",
        }:
            value = _parse_bool(raw_value)
        elif mapped in {"providers", "levels", "surfaces", "payload_modes"}:
            value = _parse_csv(raw_value)
        elif mapped == "coverage_target":
            try:
                value = float(raw_value)
            except ValueError as exc:
                raise ConfigError(f"Invalid float value for {key}: {raw_value}") from exc

        overrides[mapped] = value

    return overrides


def merge_config(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    """Handles merge config behavior for this module.

    Args:
        base: Value used by this function.
        override: Value used by this function."""
    merged: dict[str, Any] = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = merge_config(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged


def _extract_cli_overrides(cli_args: Mapping[str, Any]) -> dict[str, Any]:
    """Supports extract cli overrides behavior for this module."""
    overrides: dict[str, Any] = {}
    key_mapping: dict[str, str] = {
        "target": "target_url",
        "target_url": "target_url",
        "provider": "provider",
        "level": "level",
        "surface": "surface",
        "payload_mode": "payload_mode",
        "experiment_condition": "experiment_condition",
        "target_method": "target_method",
        "log_verbosity": "log_verbosity",
        "candidate_budget": "candidate_budget",
        "iterations": "iterations",
        "repeats": "repeats",
        "matrix": "matrix",
        "output_dir": "output_dir",
        "providers": "providers",
        "levels": "levels",
        "surfaces": "surfaces",
        "payload_modes": "payload_modes",
        "format": "report_format",
        "enriched_reporting": "enriched_reporting",
        "stop_policy": "stop_policy",
        "coverage_target": "coverage_target",
        "diagnose": "diagnose",
        "evasion_enabled": "evasion_enabled",
        "evasion_mode": "evasion_mode",
        "evasion_strategy": "evasion_strategy",
        "evasion_max_retries": "evasion_max_retries",
        "evasion_cooldown_threshold": "evasion_cooldown_threshold",
        "guardrail_retry_enabled": "guardrail_retry_enabled",
        "guardrail_handling": "guardrail_handling",
        "guardrail_retry_max": "guardrail_retry_max",
        "guardrail_retry_cooldown_threshold": "guardrail_retry_cooldown_threshold",
    }

    bool_flags = {"matrix", "enriched_reporting", "diagnose", "evasion_enabled", "guardrail_retry_enabled"}

    for key, mapped in key_mapping.items():
        if key not in cli_args:
            continue
        value = cli_args.get(key)
        if value is None:
            continue
        if key in bool_flags and value is False:
            continue
        if isinstance(value, list) and not value:
            continue
        overrides[mapped] = value

    # Runtime flags are represented as a nested mapping before the normal
    # YAML/environment/CLI merge.  This keeps role settings from accidentally
    # becoming top-level engagement fields and makes CLI precedence explicit.
    runtime_override: dict[str, Any] = {}
    raw_runtime = cli_args.get("llm_runtime")
    if raw_runtime is not None:
        if not isinstance(raw_runtime, Mapping):
            raise ConfigError("llm_runtime CLI override must be a mapping")
        runtime_override = dict(raw_runtime)

    if cli_args.get("llm_max_concurrency") is not None:
        runtime_override["max_concurrency"] = cli_args["llm_max_concurrency"]
    if cli_args.get("llm_cache") is not None:
        # Unlike the historical BooleanOptionalAction fields above, an
        # explicit --no-llm-cache must override cache_scope: run from YAML.
        runtime_override["cache_scope"] = "run" if _coerce_bool(cli_args["llm_cache"]) else "none"
    if cli_args.get("llm_cache_scope") is not None:
        runtime_override["cache_scope"] = cli_args["llm_cache_scope"]

    role_overrides: dict[str, dict[str, Any]] = {}
    for role, profile_key, model_key in (
        ("orchestrator", "orchestrator_model_profile", "orchestrator_model"),
        ("payload_generator", "payload_model_profile", "payload_model"),
    ):
        role_override: dict[str, Any] = {}
        if cli_args.get(profile_key) is not None:
            role_override["model_profile"] = cli_args[profile_key]
        if cli_args.get(model_key) is not None:
            role_override["model_name"] = cli_args[model_key]
        if role_override:
            role_overrides[role] = role_override

    if role_overrides:
        existing_roles = runtime_override.get("roles")
        if existing_roles is not None and not isinstance(existing_roles, Mapping):
            raise ConfigError("llm_runtime.roles CLI override must be a mapping")
        merged_roles = dict(existing_roles or {})
        for role, role_override in role_overrides.items():
            current = merged_roles.get(role)
            if isinstance(current, Mapping):
                merged_roles[role] = {**dict(current), **role_override}
            else:
                merged_roles[role] = role_override
        runtime_override["roles"] = merged_roles

    if runtime_override:
        overrides["llm_runtime"] = runtime_override

    return overrides


def validate_target_url(url: str) -> None:
    """Validates target url according to current framework rules.

    Args:
        url: Value used by this function."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigError(f"Invalid target URL: {url}")


def validate_provider(provider: str) -> None:
    """Validates provider according to current framework rules.

    Args:
        provider: Value used by this function."""
    if provider not in SUPPORTED_PROVIDERS:
        raise ConfigError(f"Unsupported provider: {provider}")


def validate_level(level: str) -> None:
    """Validates level according to current framework rules.

    Args:
        level: Value used by this function."""
    if level not in SECURITY_LEVELS:
        raise ConfigError(f"Unsupported security level: {level}")


def validate_payload_mode(payload_mode: str) -> None:
    """Validates payload mode according to current framework rules.

    Args:
        payload_mode: Value used by this function."""
    if payload_mode not in _VALID_PAYLOAD_MODES:
        raise ConfigError(
            f"Unsupported payload mode: {payload_mode}. "
            f"Must be one of: {', '.join(sorted(_VALID_PAYLOAD_MODES))}"
        )


def _default_model_name(provider: str) -> str:
    """Supports default model name behavior for this module."""
    if provider == "gemini":
        return "gemini-3-flash-preview"
    if provider == "openai":
        return "gpt-4o-mini"
    if provider == "openai_compatible":
        return ""
    return ""


def _default_api_key(provider: str) -> str:
    """Supports default api key behavior for this module."""
    if provider == "gemini":
        return os.getenv("GOOGLE_API_KEY", "") or os.getenv("GEMINI_API_KEY", "")
    if provider == "openai":
        return os.getenv("OPENAI_API_KEY", "")
    if provider == "openai_compatible":
        return os.getenv("OPENAI_COMPATIBLE_API_KEY", "")
    return os.getenv(f"{provider.upper()}_API_KEY", "")


def _parse_model_configs(raw_models: Mapping[str, Any]) -> dict[str, ModelConfig]:
    models: dict[str, ModelConfig] = {}
    for model_key, raw_section in raw_models.items():
        if not isinstance(raw_section, Mapping):
            continue

        section = dict(raw_section)
        provider = str(section.pop("provider", model_key))
        model_name = str(section.pop("model_name", _default_model_name(provider)))
        api_key = str(section.pop("api_key", _default_api_key(provider)))
        base_url = section.pop("base_url", None)
        if base_url is not None:
            base_url = str(base_url) if base_url else None

        try:
            temperature = float(section.pop("temperature", 0.0))
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"Invalid temperature for model '{provider}'") from exc

        max_tokens_raw = section.pop("max_tokens", None)
        try:
            max_tokens = int(max_tokens_raw) if max_tokens_raw is not None else None
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"Invalid max_tokens for model '{provider}'") from exc

        try:
            timeout = int(section.pop("timeout", 60))
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"Invalid timeout for model '{provider}'") from exc

        extra = dict(section.pop("extra", {}))
        for key, value in section.items():
            extra[key] = value

        # Preserve the original YAML section name (e.g. "simulator") as the
        # dictionary key so that special entries are not overwritten when
        # their resolved provider matches another section.
        models[model_key] = ModelConfig(
            provider=provider,
            api_key=api_key,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            base_url=base_url,
            extra=extra,
        )

    return models


def _parse_llm_runtime_config(
    merged: Mapping[str, Any],
    *,
    default_profile: str,
    candidate_budget: int,
) -> LLMRuntimeConfig:
    """Parse LLM-only execution controls while preserving legacy defaults.

    Runtime controls historically did not exist in the YAML contract.  The
    loader therefore treats an absent block as a safe serial/no-cache runtime,
    while still resolving both known roles so downstream runners can consume a
    uniform settings object.
    """

    raw_runtime = merged.get("llm_runtime", {})
    if raw_runtime is None:
        raw_runtime = {}
    if not isinstance(raw_runtime, Mapping):
        raise ConfigError("llm_runtime must be a mapping")
    runtime = dict(raw_runtime)

    # Environment variables are intentionally flat for shell ergonomics.  CLI
    # overrides already arrive nested via _extract_cli_overrides.  Since env
    # values are merged after YAML, these flat values take precedence over the
    # corresponding nested YAML value.
    if merged.get("llm_max_concurrency") is not None:
        runtime["max_concurrency"] = merged["llm_max_concurrency"]
    if merged.get("llm_cache_scope") is not None:
        runtime["cache_scope"] = merged["llm_cache_scope"]
    if merged.get("llm_cache") is not None:
        runtime["cache_scope"] = "run" if _coerce_bool(merged["llm_cache"]) else "none"

    # Flat environment variables for role overrides are folded into the same
    # nested shape used by YAML and CLI inputs.
    runtime_roles = runtime.get("roles", {})
    if runtime_roles is None:
        runtime_roles = {}
    if not isinstance(runtime_roles, Mapping):
        raise ConfigError("llm_runtime.roles must be a mapping")
    runtime_roles = dict(runtime_roles)
    for role, profile_key, model_key in (
        ("orchestrator", "orchestrator_model_profile", "orchestrator_model"),
        ("payload_generator", "payload_model_profile", "payload_model"),
    ):
        role_override: dict[str, Any] = {}
        if merged.get(profile_key) is not None:
            role_override["model_profile"] = merged[profile_key]
        if merged.get(model_key) is not None:
            role_override["model_name"] = merged[model_key]
        if not role_override:
            continue
        current_role = runtime_roles.get(role)
        if current_role is not None and not isinstance(current_role, Mapping):
            raise ConfigError(f"llm_runtime.roles.{role} must be a mapping")
        runtime_roles[role] = {**dict(current_role or {}), **role_override}
    runtime["roles"] = runtime_roles

    try:
        raw_concurrency = runtime.get("max_concurrency", 1)
        if isinstance(raw_concurrency, bool) or (
            isinstance(raw_concurrency, float) and not raw_concurrency.is_integer()
        ):
            raise ValueError
        max_concurrency = int(raw_concurrency)
    except (TypeError, ValueError) as exc:
        raise ConfigError("llm_runtime.max_concurrency must be an integer between 1 and 4") from exc

    raw_cache_scope = runtime.get("cache_scope", runtime.get("cache_enabled", "none"))
    if isinstance(raw_cache_scope, bool):
        cache_scope = "run" if raw_cache_scope else "none"
    elif raw_cache_scope is None:
        cache_scope = "none"
    else:
        cache_scope = str(raw_cache_scope).strip().lower()

    raw_roles = runtime.get("roles", {})
    if raw_roles is None:
        raw_roles = {}
    if not isinstance(raw_roles, Mapping):
        raise ConfigError("llm_runtime.roles must be a mapping")

    role_names: list[str] = list(LLM_RUNTIME_ROLES)
    for role_name in raw_roles:
        normalized_role = str(role_name).strip()
        if normalized_role and normalized_role not in role_names:
            role_names.append(normalized_role)

    roles: dict[str, RoleConfig] = {}
    payload_default_tokens = min(512, 96 + 64 * candidate_budget)
    for role_name in role_names:
        raw_role = raw_roles.get(role_name, {})
        if raw_role is None:
            raw_role = {}
        if not isinstance(raw_role, Mapping):
            raise ConfigError(f"llm_runtime.roles.{role_name} must be a mapping")
        role = dict(raw_role)

        profile = role.get("model_profile", role.get("profile", default_profile))
        profile_text = str(profile).strip() if profile is not None else default_profile
        if not profile_text:
            profile_text = default_profile

        model_name_raw = role.get("model_name", role.get("model"))
        model_name = None if model_name_raw is None else str(model_name_raw).strip()
        if model_name == "":
            model_name = None

        try:
            temperature_raw = role.get("temperature", 0.0)
            if isinstance(temperature_raw, bool):
                raise ValueError
            temperature = float(temperature_raw)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"Invalid temperature for LLM role '{role_name}'") from exc

        max_tokens_raw = role.get(
            "max_tokens",
            payload_default_tokens if role_name == "payload_generator" else 96,
        )
        if max_tokens_raw is None:
            max_tokens = None
        else:
            try:
                if isinstance(max_tokens_raw, bool) or (
                    isinstance(max_tokens_raw, float) and not max_tokens_raw.is_integer()
                ):
                    raise ValueError
                max_tokens = int(max_tokens_raw)
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"Invalid max_tokens for LLM role '{role_name}'") from exc

        structured_output = str(role.get("structured_output", "auto")).strip().lower()
        roles[role_name] = RoleConfig(
            model_profile=profile_text,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
            structured_output=structured_output,
        )

    config = LLMRuntimeConfig(
        max_concurrency=max_concurrency,
        cache_scope=cache_scope,
        roles=roles,
    )
    _validate_llm_runtime_config(config)
    return config


def _validate_surface(surface: str) -> None:
    if surface not in SURFACES:
        raise ConfigError(f"Unsupported surface: {surface}. Must be one of: {', '.join(SURFACES)}")


def _validate_llm_runtime_config(config: LLMRuntimeConfig) -> None:
    """Validate concurrency, cache, and role decoding controls."""

    if not 1 <= config.max_concurrency <= 4:
        raise ConfigError("llm_runtime.max_concurrency must be between 1 and 4")
    if config.cache_scope not in LLM_CACHE_SCOPES:
        raise ConfigError(
            f"Unsupported llm_runtime.cache_scope: {config.cache_scope}. "
            f"Must be one of: {', '.join(sorted(LLM_CACHE_SCOPES))}"
        )
    for role_name, role in config.roles.items():
        if role.model_profile is not None and not str(role.model_profile).strip():
            raise ConfigError(f"llm_runtime.roles.{role_name}.model_profile must not be empty")
        if role.model_name is not None and not str(role.model_name).strip():
            raise ConfigError(f"llm_runtime.roles.{role_name}.model_name must not be empty")
        if role.temperature < 0:
            raise ConfigError(f"llm_runtime.roles.{role_name}.temperature must be >= 0")
        if role.max_tokens is not None and role.max_tokens <= 0:
            raise ConfigError(f"llm_runtime.roles.{role_name}.max_tokens must be > 0")
        if role.structured_output not in STRUCTURED_OUTPUT_MODES:
            raise ConfigError(
                f"Unsupported structured output mode for LLM role '{role_name}': "
                f"{role.structured_output}. Must be one of: "
                f"{', '.join(sorted(STRUCTURED_OUTPUT_MODES))}"
            )


def _validate_engagement_config(config: EngagementConfig) -> None:
    """Supports validate engagement config behavior for this module."""
    validate_target_url(config.target_url)
    if config.iterations <= 0:
        raise ConfigError("iterations must be > 0")
    if config.repeats <= 0:
        raise ConfigError("repeats must be > 0")
    if config.candidate_budget <= 0:
        raise ConfigError("candidate_budget must be > 0")
    if config.report_format not in {"json", "markdown", "both"}:
        raise ConfigError(f"Unsupported output format: {config.report_format}")
    if config.stop_policy not in {"impact", "coverage"}:
        raise ConfigError(f"Unsupported stop policy: {config.stop_policy}")
    if not (0.0 <= config.coverage_target <= 1.0):
        raise ConfigError("coverage_target must be between 0.0 and 1.0")

    _validate_surface(config.surface)
    validate_payload_mode(config.payload_mode)
    if config.experiment_condition not in _VALID_EXPERIMENT_CONDITIONS:
        raise ConfigError(
            f"Unsupported experiment condition: {config.experiment_condition}. "
            f"Must be one of: {', '.join(sorted(_VALID_EXPERIMENT_CONDITIONS))}"
        )

    evasion_mode = str(getattr(config, "evasion_mode", config.evasion_strategy)).strip().lower()
    if evasion_mode not in _VALID_EVASION_MODES:
        raise ConfigError(
            f"Unsupported evasion mode: {evasion_mode}. "
            f"Must be one of: {', '.join(sorted(_VALID_EVASION_MODES))}"
        )
    if config.evasion_max_retries <= 0:
        raise ConfigError("evasion_max_retries must be > 0")
    if config.evasion_cooldown_threshold <= 0:
        raise ConfigError("evasion_cooldown_threshold must be > 0")

    _validate_llm_runtime_config(config.llm_runtime)

    if config.matrix:
        if not config.providers:
            raise ConfigError("matrix mode requires at least one provider")
        if not config.levels:
            raise ConfigError("matrix mode requires at least one security level")
        for provider in config.providers:
            validate_provider(provider)
        for level in config.levels:
            validate_level(level)
        for surface in config.surfaces:
            _validate_surface(surface)
        for payload_mode in config.payload_modes:
            validate_payload_mode(payload_mode)
        if config.target_method and any(
            config.target_method not in METHODS_BY_SURFACE.get(surface, [])
            for surface in config.surfaces
        ):
            raise ConfigError(
                f"target_method {config.target_method!r} is not available for every configured matrix surface"
            )
    else:
        validate_provider(config.provider)
        validate_level(config.level)
        if config.target_method and config.target_method not in METHODS_BY_SURFACE.get(config.surface, []):
            raise ConfigError(
                f"target_method {config.target_method!r} is not available for surface {config.surface!r}"
            )


def load_and_resolve_config(*, config_path: str, cli_args: Mapping[str, Any]) -> EngagementConfig:
    """Loads and resolve config from configured inputs.

    Args:
        config_path: Value used by this function.
        cli_args: Value used by this function."""
    # Load secrets from the .env file colocated with config.yaml before model
    # defaults and ${VAR} references are resolved. Existing process variables
    # retain precedence so CI/shell overrides remain deterministic.
    config_file = Path(config_path)
    load_dotenv(dotenv_path=config_file.with_name(".env"), override=False)

    yaml_cfg = resolve_env_references(load_yaml_config(config_file))
    env_cfg = load_env_overrides(prefix="TESIS_")
    cli_cfg = _extract_cli_overrides(cli_args)

    merged = merge_config(yaml_cfg, env_cfg)
    merged = merge_config(merged, cli_cfg)

    provider = str(
        merged.get("provider")
        or merged.get("default_llm_provider")
        or (merged.get("llm_providers") or ["gemini"])[0]
    ).strip().lower()
    level = str(
        merged.get("level")
        or merged.get("security_level")
        or merged.get("default_security_level")
        or "low"
    ).strip().lower()
    surface = str(
        merged.get("surface")
        or merged.get("default_surface")
        or "sqli"
    ).strip().lower()
    payload_mode = str(merged.get("payload_mode") or "static_only").strip().lower()
    candidate_budget = int(merged.get("candidate_budget") or 5)
    llm_runtime = _parse_llm_runtime_config(
        merged,
        default_profile=provider,
        # Let the existing engagement validator report an invalid candidate
        # budget using its established error while keeping role token defaults
        # positive during this preliminary parse.
        candidate_budget=max(candidate_budget, 1),
    )

    providers = [str(p).strip().lower() for p in merged.get("providers", merged.get("llm_providers", []))]
    levels = [str(l).strip().lower() for l in merged.get("levels", merged.get("security_levels", []))]
    surfaces = [str(s).strip().lower() for s in merged.get("surfaces", [])]
    payload_modes = [str(s).strip().lower() for s in merged.get("payload_modes", [])]

    # ``guardrail_retry`` / ``guardrail_handling`` are canonical.  The older
    # ``evasion`` forms are intentionally retained as a final compatibility
    # fallback for existing configuration files and environment variables.
    guardrail_cfg = merged.get("guardrail_retry") or {}
    evasion_cfg = merged.get("evasion") or {}
    if not isinstance(guardrail_cfg, Mapping):
        raise ConfigError("guardrail_retry must be a mapping")
    if not isinstance(evasion_cfg, Mapping):
        raise ConfigError("evasion must be a mapping")

    if "guardrail_retry_enabled" in merged:
        enabled_value = merged["guardrail_retry_enabled"]
    elif "enabled" in guardrail_cfg:
        enabled_value = guardrail_cfg["enabled"]
    elif "evasion_enabled" in merged:
        enabled_value = merged["evasion_enabled"]
    else:
        enabled_value = evasion_cfg.get("enabled", False)
    evasion_enabled = _coerce_bool(enabled_value)

    mode_value = (
        merged.get("guardrail_handling")
        or guardrail_cfg.get("mode")
        or merged.get("evasion_mode")
        or merged.get("evasion_strategy")
        or evasion_cfg.get("mode")
        or evasion_cfg.get("strategy")
        or "reactive"
    )
    evasion_mode = str(mode_value).strip().lower()
    max_retries_value = (
        merged.get("guardrail_retry_max")
        or guardrail_cfg.get("max_retries")
        or merged.get("evasion_max_retries")
        or merged.get("evasion_attempts_max")
        or evasion_cfg.get("max_retries")
        or evasion_cfg.get("attempts_max")
        or 3
    )
    evasion_max_retries = int(max_retries_value)
    cooldown_value = (
        merged.get("guardrail_retry_cooldown_threshold")
        or guardrail_cfg.get("cooldown_threshold")
        or merged.get("evasion_cooldown_threshold")
        or evasion_cfg.get("cooldown_threshold")
        or 5
    )
    evasion_cooldown_threshold = int(cooldown_value)

    config = EngagementConfig(
        target_url=str(merged.get("target_url", "")).strip(),
        provider=provider,
        level=level,
        surface=surface,
        payload_mode=payload_mode,
        experiment_condition=str(merged.get("experiment_condition") or "linear_hybrid").strip().lower(),
        target_method=(str(merged.get("target_method")).strip() if merged.get("target_method") else None),
        log_verbosity=str(merged.get("log_verbosity") or "info").strip().lower(),
        candidate_budget=candidate_budget,
        iterations=int(merged.get("iterations") or merged.get("max_iterations") or merged.get("default_max_iterations") or 30),
        repeats=int(merged.get("repeats", 1)),
        output_dir=str(merged.get("output_dir", "results")).strip(),
        matrix=_coerce_bool(merged.get("matrix", False)),
        providers=providers or [provider],
        levels=levels or [level],
        surfaces=surfaces or (["sqli", "access_control", "brute_force"] if _coerce_bool(merged.get("matrix", False)) else [surface]),
        payload_modes=payload_modes or (["static_only", "hybrid"] if _coerce_bool(merged.get("matrix", False)) else [payload_mode]),
        report_format=str(merged.get("report_format") or merged.get("format") or "both").strip().lower(),
        enriched_reporting=_coerce_bool(merged.get("enriched_reporting", False)),
        stop_policy=str(merged.get("stop_policy") or "impact").strip().lower(),
        coverage_target=float(merged.get("coverage_target") or 0.70),
        diagnose=_coerce_bool(merged.get("diagnose", False)),
        evasion_enabled=evasion_enabled,
        evasion_mode=evasion_mode,
        evasion_max_retries=evasion_max_retries,
        evasion_cooldown_threshold=evasion_cooldown_threshold,
        evasion_strategy=str(merged.get("evasion_strategy") or evasion_mode).strip().lower(),
        evasion_attempts_max=int(merged.get("evasion_attempts_max", evasion_max_retries)),
        models=_parse_model_configs(merged.get("models", {})),
        llm_runtime=llm_runtime,
    )

    _validate_engagement_config(config)
    form_name = FORM_MATRIX if config.matrix else FORM_SINGLE
    field_errors = validate_field_schema(asdict(config), form=form_name)
    if field_errors:
        details = "; ".join(f"{path}: {message}" for path, message in sorted(field_errors.items()))
        raise ConfigError(f"Invalid configuration fields: {details}")
    return config
