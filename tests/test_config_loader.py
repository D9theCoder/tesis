"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from pathlib import Path

import pytest

from tesis.config_loader import (
    ConfigError,
    load_and_resolve_config,
)


def _write_yaml(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


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


def test_matrix_target_method_must_match_every_selected_surface(tmp_path):
    """Reject ambiguous method-level matrices before any live work is started."""
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        """
target_url: http://localhost/dvwa
provider: gemini
level: low
matrix: true
providers: [gemini]
levels: [low]
surfaces: [sqli, access_control]
payload_modes: [static_only]
target_method: sqli_union
""",
    )

    with pytest.raises(ConfigError, match="every configured matrix surface"):
        load_and_resolve_config(config_path=str(config_path), cli_args={})
