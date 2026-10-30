"""Focused contracts for LLM runtime configuration and headless flags."""

from __future__ import annotations

from pathlib import Path

import pytest

import tesis.cli as cli
from tesis.config_loader import ConfigError, load_and_resolve_config


def _config(path: Path, body: str = "") -> Path:
    path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai_compatible\n"
        "level: low\n"
        f"output_dir: {path.parent / 'results'}\n"
        + body,
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("value", (0, 5))
def test_runtime_concurrency_is_bounded(tmp_path: Path, value: int) -> None:
    path = _config(tmp_path / "config.yaml", f"llm_runtime:\n  max_concurrency: {value}\n")

    with pytest.raises(ConfigError, match="max_concurrency"):
        load_and_resolve_config(config_path=str(path), cli_args={})


def test_cli_runtime_flags_override_yaml_and_map_role_names(tmp_path: Path) -> None:
    path = _config(
        tmp_path / "config.yaml",
        "llm_runtime:\n  max_concurrency: 2\n  cache_scope: run\n",
    )
    namespace = cli._headless_parser().parse_args([
        "--headless",
        "--llm-max-concurrency",
        "3",
        "--no-llm-cache",
        "--orchestrator-model-profile",
        "orchestrator_profile",
        "--orchestrator-model",
        "orchestrator-model",
        "--payload-model-profile",
        "payload_profile",
        "--payload-model",
        "payload-model",
    ])

    config = load_and_resolve_config(
        config_path=str(path),
        cli_args=cli._headless_overrides(namespace),
    )

    assert config.llm_runtime.max_concurrency == 3
    assert config.llm_runtime.cache_scope == "none"
    assert config.role_configs["orchestrator"].model_profile == "orchestrator_profile"
    assert config.role_configs["orchestrator"].model_name == "orchestrator-model"
    assert config.role_configs["payload_generator"].model_profile == "payload_profile"
    assert config.role_configs["payload_generator"].model_name == "payload-model"


def test_unknown_global_model_profile_fails_with_available_profiles(tmp_path: Path) -> None:
    path = _config(
        tmp_path / "config.yaml",
        "models:\n"
        "  openai:\n"
        "    provider: openai\n"
        "    model_name: muse-model\n",
    )

    with pytest.raises(ConfigError, match="Available profiles: openai"):
        load_and_resolve_config(
            config_path=str(path),
            cli_args={"model_profile": "missing"},
        )
