"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from tesis.config_loader import load_and_resolve_config


class TestEvasionConfigLoading:
    """Groups regression tests for TestEvasionConfigLoading behavior."""


    def test_guardrail_retry_from_yaml_uses_canonical_names(self, tmp_path):
        """New configuration vocabulary maps to the compatibility runtime fields."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "target_url: http://localhost/dvwa\n"
            "guardrail_retry:\n"
            "  enabled: true\n"
            "  mode: proactive\n"
            "  max_retries: 2\n"
            "  cooldown_threshold: 4\n"
        )
        config = load_and_resolve_config(config_path=str(config_path), cli_args={})
        assert config.evasion_enabled is True
        assert config.evasion_mode == "proactive"
        assert config.evasion_max_retries == 2
        assert config.evasion_cooldown_threshold == 4
