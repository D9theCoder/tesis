"""Focused contracts for LLM runtime configuration and headless flags."""

from __future__ import annotations

from pathlib import Path

import pytest

import tesis.cli as cli
from tesis.config_loader import ConfigError, load_and_resolve_config
from tesis.headless import run_headless


def _config(path: Path, body: str = "") -> Path:
    path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai_compatible\n"
        "level: low\n"
        + body,
        encoding="utf-8",
    )
    return path


def test_legacy_config_uses_serial_no_cache_runtime(tmp_path: Path) -> None:
    config = load_and_resolve_config(config_path=str(_config(tmp_path / "config.yaml")), cli_args={})

    assert config.llm_runtime.max_concurrency == 1
    assert config.llm_runtime.cache_scope == "none"
    assert config.llm_runtime.cache_enabled is False


def test_runtime_roles_inherit_profile_and_default_payload_budget(tmp_path: Path) -> None:
    config = load_and_resolve_config(
        config_path=str(_config(
            tmp_path / "config.yaml",
            "candidate_budget: 3\n"
            "llm_runtime:\n"
            "  max_concurrency: 2\n"
            "  cache_scope: run\n"
            "  roles:\n"
            "    orchestrator:\n"
            "      model_profile: openai_compatible\n"
            "      model_name: fast-orchestrator\n"
            "    payload_generator:\n"
            "      structured_output: json_prompt\n",
        )),
        cli_args={},
    )

    assert config.llm_runtime.max_concurrency == 2
    assert config.llm_runtime.cache_enabled is True
    assert config.role_configs["orchestrator"].model_name == "fast-orchestrator"
    assert config.role_configs["payload_generator"].model_profile == "openai_compatible"
    assert config.role_configs["payload_generator"].max_tokens == 288
    assert config.role_configs["payload_generator"].structured_output == "json_prompt"


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


def test_global_model_profile_selects_both_runtime_roles(tmp_path: Path) -> None:
    path = _config(
        tmp_path / "config.yaml",
        "models:\n"
        "  openai:\n"
        "    provider: openai\n"
        "    model_name: muse-model\n"
        "  openai_compatible:\n"
        "    provider: openai_compatible\n"
        "    model_name: deepseek-model\n",
    )
    namespace = cli._headless_parser().parse_args([
        "--headless",
        "--model-profile",
        "openai_compatible",
    ])

    config = load_and_resolve_config(
        config_path=str(path),
        cli_args=cli._headless_overrides(namespace),
    )

    assert config.model_profile == "openai_compatible"
    assert config.role_configs["orchestrator"].model_profile == "openai_compatible"
    assert config.role_configs["payload_generator"].model_profile == "openai_compatible"


def test_role_specific_profile_overrides_global_model_profile(tmp_path: Path) -> None:
    path = _config(
        tmp_path / "config.yaml",
        "models:\n"
        "  openai:\n"
        "    provider: openai\n"
        "    model_name: muse-model\n"
        "  openai_compatible:\n"
        "    provider: openai_compatible\n"
        "    model_name: deepseek-model\n",
    )
    namespace = cli._headless_parser().parse_args([
        "--headless",
        "--model-profile",
        "openai_compatible",
        "--orchestrator-model-profile",
        "openai",
    ])

    config = load_and_resolve_config(
        config_path=str(path),
        cli_args=cli._headless_overrides(namespace),
    )

    assert config.role_configs["orchestrator"].model_profile == "openai"
    assert config.role_configs["payload_generator"].model_profile == "openai_compatible"


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


def test_environment_model_profile_selects_both_runtime_roles(tmp_path: Path, monkeypatch) -> None:
    path = _config(
        tmp_path / "config.yaml",
        "models:\n"
        "  openai:\n"
        "    provider: openai\n"
        "    model_name: muse-model\n"
        "  openai_compatible:\n"
        "    provider: openai_compatible\n"
        "    model_name: deepseek-model\n",
    )
    monkeypatch.setenv("TESIS_MODEL_PROFILE", "openai_compatible")

    config = load_and_resolve_config(config_path=str(path), cli_args={})

    assert config.model_profile == "openai_compatible"
    assert config.role_configs["orchestrator"].model_profile == "openai_compatible"
    assert config.role_configs["payload_generator"].model_profile == "openai_compatible"


def test_cli_concurrency_parser_rejects_out_of_bounds() -> None:
    with pytest.raises(SystemExit):
        cli._headless_parser().parse_args(["--llm-max-concurrency", "5"])


def test_headless_forwards_runtime_and_all_model_profiles(tmp_path: Path, monkeypatch) -> None:
    path = _config(
        tmp_path / "config.yaml",
        "llm_runtime:\n"
        "  max_concurrency: 2\n"
        "  cache_scope: run\n"
        "  roles:\n"
        "    orchestrator:\n"
        "      model_profile: orchestrator_profile\n"
        "    payload_generator:\n"
        "      model_profile: payload_profile\n"
        "models:\n"
        "  orchestrator_profile:\n"
        "    provider: openai_compatible\n"
        "    model_name: orchestrator-model\n"
        "  payload_profile:\n"
        "    provider: openai_compatible\n"
        "    model_name: payload-model\n",
    )
    captured: dict[str, object] = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        return {"status": "success", "execution_id": "test-execution"}

    monkeypatch.setattr("tesis.headless.run_single_engagement", fake_run)

    code, result, _ = run_headless(config_path=str(path), cli_args={})

    assert code == 0
    assert result["status"] == "success"
    assert captured["llm_max_concurrency"] == 2
    assert captured["llm_cache_enabled"] is True
    assert captured["llm_role_configs"]["payload_generator"]["model_profile"] == "payload_profile"
    assert captured["model_profiles"]["payload_profile"]["model_name"] == "payload-model"
