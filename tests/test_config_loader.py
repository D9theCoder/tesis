from pathlib import Path

import pytest

from tesis.config_loader import ConfigError, _default_api_key, _default_model_name, load_and_resolve_config


def _write_yaml(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_default_model_name_openai_compatible():
    assert _default_model_name("openai_compatible") == ""


def test_default_api_key_openai_compatible(monkeypatch):
    monkeypatch.setenv("OPENAI_COMPATIBLE_API_KEY", "test-compatible-key")
    assert _default_api_key("openai_compatible") == "test-compatible-key"


def test_default_api_key_openai_compatible_fallback_empty(monkeypatch):
    monkeypatch.delenv("OPENAI_COMPATIBLE_API_KEY", raising=False)
    assert _default_api_key("openai_compatible") == ""


def test_yaml_roundtrip_to_dataclass(tmp_path):
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


def test_cli_omitted_bool_flags_do_not_override_yaml_true(tmp_path):
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
