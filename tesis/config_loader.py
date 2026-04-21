"""Configuration loader and validator for Stage 7 CLI."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

import yaml

from core.state import SECURITY_LEVELS
from llm.provider import SUPPORTED_PROVIDERS
from tesis.model_config import EngagementConfig, ModelConfig, EVASION_STRATEGIES


class ConfigError(ValueError):
    """Raised when config parsing/validation fails."""


_VALID_EVASION_STRATEGIES: frozenset[str] = EVASION_STRATEGIES

_ENV_REF_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)}")


def mask_secret(value: str, *, unmasked_tail: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= unmasked_tail:
        return "*" * len(value)
    return f"****{value[-unmasked_tail:]}"


def load_yaml_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return {}
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"Config file must contain a YAML mapping: {config_path}")
    return raw


def save_yaml_config(path: str | Path, payload: Mapping[str, Any]) -> Path:
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.safe_dump(dict(payload), sort_keys=False), encoding="utf-8")
    return config_path


def _resolve_env_refs(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _resolve_env_refs(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env_refs(v) for v in value]
    if not isinstance(value, str):
        return value

    def _replace(match: re.Match[str]) -> str:
        env_key = match.group(1)
        env_value = os.getenv(env_key)
        if env_value is None:
            raise ConfigError(f"Missing environment variable for config placeholder: {env_key}")
        return env_value

    return _ENV_REF_PATTERN.sub(_replace, value)


def resolve_env_references(config: dict[str, Any]) -> dict[str, Any]:
    return _resolve_env_refs(config)


def _parse_bool(raw: str) -> bool:
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _coerce_bool(value: Any) -> bool:
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
    overrides: dict[str, Any] = {}
    mapping: dict[str, str] = {
        "TARGET_URL": "target_url",
        "PROVIDER": "provider",
        "LEVEL": "level",
        "SECURITY_LEVEL": "level",
        "ITERATIONS": "iterations",
        "MAX_ITERATIONS": "iterations",
        "REPEATS": "repeats",
        "OUTPUT_DIR": "output_dir",
        "MATRIX": "matrix",
        "PROVIDERS": "providers",
        "LEVELS": "levels",
        "FORMAT": "report_format",
        "ENRICHED_REPORTING": "enriched_reporting",
        "STOP_POLICY": "stop_policy",
        "COVERAGE_TARGET": "coverage_target",
        "DIAGNOSE": "diagnose",
        "EVASION_ENABLED": "evasion_enabled",
        "EVASION_STRATEGY": "evasion_strategy",
    }

    for key, raw_value in os.environ.items():
        if not key.startswith(prefix):
            continue

        suffix = key[len(prefix):]
        if suffix.startswith("MODEL_"):
            parts = suffix.split("_")
            if len(parts) < 4:
                continue
            provider = parts[1].lower()
            field_name = "_".join(parts[2:]).lower()
            models = overrides.setdefault("models", {})
            model = models.setdefault(provider, {})
            model[field_name] = raw_value
            continue

        mapped = mapping.get(suffix)
        if not mapped:
            continue

        value: Any = raw_value
        if mapped in {"iterations", "repeats"}:
            try:
                value = int(raw_value)
            except ValueError as exc:
                raise ConfigError(f"Invalid integer value for {key}: {raw_value}") from exc
        elif mapped in {"matrix", "enriched_reporting", "diagnose", "evasion_enabled"}:
            value = _parse_bool(raw_value)
        elif mapped in {"providers", "levels"}:
            value = _parse_csv(raw_value)
        elif mapped == "coverage_target":
            try:
                value = float(raw_value)
            except ValueError as exc:
                raise ConfigError(f"Invalid float value for {key}: {raw_value}") from exc

        overrides[mapped] = value

    return overrides


def merge_config(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = merge_config(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged


def _extract_cli_overrides(cli_args: Mapping[str, Any]) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    key_mapping: dict[str, str] = {
        "target": "target_url",
        "target_url": "target_url",
        "provider": "provider",
        "level": "level",
        "iterations": "iterations",
        "repeats": "repeats",
        "output_dir": "output_dir",
        "providers": "providers",
        "levels": "levels",
        "format": "report_format",
        "enriched_reporting": "enriched_reporting",
        "stop_policy": "stop_policy",
        "coverage_target": "coverage_target",
        "diagnose": "diagnose",
        "evasion_enabled": "evasion_enabled",
        "evasion_strategy": "evasion_strategy",
    }

    bool_flags = {"matrix", "enriched_reporting", "diagnose", "evasion_enabled"}

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

    return overrides


def validate_target_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigError(f"Invalid target URL: {url}")


def validate_provider(provider: str) -> None:
    if provider not in SUPPORTED_PROVIDERS:
        raise ConfigError(f"Unsupported provider: {provider}")


def validate_level(level: str) -> None:
    if level not in SECURITY_LEVELS:
        raise ConfigError(f"Unsupported security level: {level}")


def _default_model_name(provider: str) -> str:
    if provider == "gemini":
        return "gemini-3-flash-preview"
    return ""


def _default_api_key(provider: str) -> str:
    if provider == "gemini":
        return os.getenv("GOOGLE_API_KEY", "") or os.getenv("GEMINI_API_KEY", "")
    return os.getenv(f"{provider.upper()}_API_KEY", "")


def _parse_model_configs(raw_models: Mapping[str, Any]) -> dict[str, ModelConfig]:
    models: dict[str, ModelConfig] = {}
    for provider, raw_section in raw_models.items():
        if not isinstance(raw_section, Mapping):
            continue

        section = dict(raw_section)
        model_name = str(section.pop("model_name", _default_model_name(provider)))
        api_key = str(section.pop("api_key", _default_api_key(provider)))

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

        models[provider] = ModelConfig(
            provider=provider,
            api_key=api_key,
            model_name=model_name,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            extra=extra,
        )

    return models


def _validate_engagement_config(config: EngagementConfig) -> None:
    validate_target_url(config.target_url)
    if config.iterations <= 0:
        raise ConfigError("iterations must be > 0")
    if config.repeats <= 0:
        raise ConfigError("repeats must be > 0")
    if config.report_format not in {"json", "markdown", "both"}:
        raise ConfigError(f"Unsupported output format: {config.report_format}")
    if config.stop_policy not in {"impact", "coverage"}:
        raise ConfigError(f"Unsupported stop policy: {config.stop_policy}")
    if not (0.0 <= config.coverage_target <= 1.0):
        raise ConfigError("coverage_target must be between 0.0 and 1.0")

    if config.evasion_enabled and config.evasion_strategy not in _VALID_EVASION_STRATEGIES:
        raise ConfigError(
            f"Unsupported evasion strategy: {config.evasion_strategy}. "
            f"Must be one of: {', '.join(sorted(_VALID_EVASION_STRATEGIES))}"
        )

    if config.matrix:
        if not config.providers:
            raise ConfigError("matrix mode requires at least one provider")
        if not config.levels:
            raise ConfigError("matrix mode requires at least one security level")
        for provider in config.providers:
            validate_provider(provider)
        for level in config.levels:
            validate_level(level)
    else:
        validate_provider(config.provider)
        validate_level(config.level)


def load_and_resolve_config(*, config_path: str, cli_args: Mapping[str, Any]) -> EngagementConfig:
    yaml_cfg = resolve_env_references(load_yaml_config(config_path))
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

    providers = [str(p).strip().lower() for p in merged.get("providers", merged.get("llm_providers", []))]
    levels = [str(l).strip().lower() for l in merged.get("levels", merged.get("security_levels", []))]

    config = EngagementConfig(
        target_url=str(merged.get("target_url", "")).strip(),
        provider=provider,
        level=level,
        iterations=int(merged.get("iterations") or merged.get("max_iterations") or merged.get("default_max_iterations") or 30),
        repeats=int(merged.get("repeats", 1)),
        output_dir=str(merged.get("output_dir", "results")).strip(),
        matrix=_coerce_bool(merged.get("matrix", False)),
        providers=providers or [provider],
        levels=levels or [level],
        report_format=str(merged.get("report_format") or merged.get("format") or "both").strip().lower(),
        enriched_reporting=_coerce_bool(merged.get("enriched_reporting", False)),
        stop_policy=str(merged.get("stop_policy") or "impact").strip().lower(),
        coverage_target=float(merged.get("coverage_target") or 0.70),
        diagnose=_coerce_bool(merged.get("diagnose", False)),
        evasion_enabled=_coerce_bool(merged.get("evasion_enabled", False)),
        evasion_strategy=str(merged.get("evasion_strategy") or "pipeline").strip().lower(),
        models=_parse_model_configs(merged.get("models", {})),
    )

    _validate_engagement_config(config)
    return config
