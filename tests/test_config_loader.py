"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from pathlib import Path

import pytest

from tesis.config_loader import ConfigError, _default_api_key, _default_model_name, load_and_resolve_config


def _write_yaml(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_default_model_name_openai_compatible():
    """Verifies default model name openai compatible behavior."""
    assert _default_model_name("openai_compatible") == ""


def test_default_api_key_openai_compatible(monkeypatch):
    """Verifies default api key openai compatible behavior."""
    monkeypatch.setenv("OPENAI_COMPATIBLE_API_KEY", "test-compatible-key")
    assert _default_api_key("openai_compatible") == "test-compatible-key"


def test_default_api_key_openai_compatible_fallback_empty(monkeypatch):
    """Verifies default api key openai compatible fallback empty behavior."""
    monkeypatch.delenv("OPENAI_COMPATIBLE_API_KEY", raising=False)
    assert _default_api_key("openai_compatible") == ""


def test_yaml_roundtrip_to_dataclass(tmp_path):
    """Verifies yaml roundtrip to dataclass behavior."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://localhost/dvwa
default_llm_provider: gemini
default_security_level: low
default_max_iterations: 30
llm_providers: [gemini]
security_levels: [low, medium, high]
""",
    )

    cfg = load_and_resolve_config(config_path=str(config_path), cli_args={})

    assert cfg.target_url == "http://localhost/dvwa"
    assert cfg.provider == "gemini"
    assert cfg.level == "low"
    assert cfg.iterations == 30


def test_env_override_target_url(tmp_path, monkeypatch):
    """Verifies env override target url behavior."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://yaml.local/dvwa
default_llm_provider: gemini
default_security_level: low
""",
    )

    monkeypatch.setenv("TESIS_TARGET_URL", "http://env.local/dvwa")
    cfg = load_and_resolve_config(config_path=str(config_path), cli_args={})

    assert cfg.target_url == "http://env.local/dvwa"


def test_cli_override_has_highest_priority(tmp_path, monkeypatch):
    """Verifies cli override has highest priority behavior."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://yaml.local/dvwa
default_llm_provider: gemini
default_security_level: low
""",
    )

    monkeypatch.setenv("TESIS_TARGET_URL", "http://env.local/dvwa")
    cfg = load_and_resolve_config(
        config_path=str(config_path),
        cli_args={"target": "http://cli.local/dvwa"},
    )

    assert cfg.target_url == "http://cli.local/dvwa"


def test_invalid_provider_raises_validation_error(tmp_path):
    """Verifies invalid provider raises validation error behavior."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://localhost/dvwa
provider: unknown_provider
level: low
""",
    )

    with pytest.raises(ConfigError, match="Unsupported provider"):
        load_and_resolve_config(config_path=str(config_path), cli_args={})


def test_invalid_level_raises_validation_error(tmp_path):
    """Verifies invalid level raises validation error behavior."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://localhost/dvwa
provider: gemini
level: impossible
""",
    )

    with pytest.raises(ConfigError, match="Unsupported security level"):
        load_and_resolve_config(config_path=str(config_path), cli_args={})


def test_env_reference_resolution_for_model_api_key(tmp_path, monkeypatch):
    """Verifies env reference resolution for model api key behavior."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://localhost/dvwa
provider: gemini
level: low
models:
  gemini:
    api_key: ${GEMINI_API_KEY}
    model_name: gemini-3-flash-preview
""",
    )

    monkeypatch.setenv("GEMINI_API_KEY", "secret-token-1234")
    cfg = load_and_resolve_config(config_path=str(config_path), cli_args={})

    assert cfg.models["gemini"].api_key == "secret-token-1234"


def test_payload_mode_and_candidate_budget_from_yaml(tmp_path):
    """Verifies payload mode and candidate budget from yaml behavior."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://localhost/dvwa
provider: gemini
level: low
payload_mode: hybrid
candidate_budget: 7
""",
    )

    cfg = load_and_resolve_config(config_path=str(config_path), cli_args={})

    assert cfg.payload_mode == "hybrid"
    assert cfg.candidate_budget == 7


def test_openai_compatible_model_env_override(tmp_path, monkeypatch):
    """Verifies openai compatible model env override behavior."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://localhost/dvwa
provider: openai_compatible
level: low
models:
  openai_compatible:
    base_url: http://localhost:1234/v1
""",
    )

    monkeypatch.setenv("TESIS_MODEL_OPENAI_COMPATIBLE_API_KEY", "key-from-env")
    cfg = load_and_resolve_config(config_path=str(config_path), cli_args={})

    assert cfg.models["openai_compatible"].api_key == "key-from-env"


def test_cli_omitted_bool_flags_do_not_override_yaml_true(tmp_path):
    """Verifies cli omitted bool flags do not override yaml true behavior."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://localhost/dvwa
provider: gemini
level: low
enriched_reporting: true
diagnose: true
""",
    )

    cfg = load_and_resolve_config(
        config_path=str(config_path),
        cli_args={"enriched_reporting": False, "diagnose": False},
    )

    assert cfg.enriched_reporting is True
    assert cfg.diagnose is True


def test_string_false_flags_in_yaml_are_parsed_as_false(tmp_path):
    """Verifies string false flags in yaml are parsed as false behavior."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://localhost/dvwa
provider: gemini
level: low
matrix: "false"
enriched_reporting: "false"
diagnose: "false"
""",
    )

    cfg = load_and_resolve_config(config_path=str(config_path), cli_args={})

    assert cfg.matrix is False
    assert cfg.enriched_reporting is False
    assert cfg.diagnose is False


def test_string_true_flags_in_yaml_are_parsed_as_true(tmp_path):
    """Verifies string true flags in yaml are parsed as true behavior."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://localhost/dvwa
provider: gemini
level: low
matrix: "true"
enriched_reporting: "true"
diagnose: "true"
""",
    )

    cfg = load_and_resolve_config(config_path=str(config_path), cli_args={})

    assert cfg.matrix is True
    assert cfg.enriched_reporting is True
    assert cfg.diagnose is True
