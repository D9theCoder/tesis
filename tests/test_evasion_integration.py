"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import pytest
from tesis.config_loader import ConfigError, load_and_resolve_config


class TestEvasionConfigLoading:
    """Groups regression tests for TestEvasionConfigLoading behavior."""
    def test_evasion_defaults_false(self, tmp_path):
        """Verifies evasion defaults false behavior."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text("target_url: http://localhost/dvwa\n")
        config = load_and_resolve_config(config_path=str(config_path), cli_args={})
        assert config.evasion_enabled is False
        assert config.evasion_mode == "reactive"

    def test_evasion_from_yaml(self, tmp_path):
        """Verifies evasion from yaml behavior."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "target_url: http://localhost/dvwa\n"
            "evasion_enabled: true\n"
            "evasion_mode: proactive\n"
        )
        config = load_and_resolve_config(config_path=str(config_path), cli_args={})
        assert config.evasion_enabled is True
        assert config.evasion_mode == "proactive"

    def test_evasion_cli_override(self, tmp_path):
        """Verifies evasion cli override behavior."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text("target_url: http://localhost/dvwa\n")
        config = load_and_resolve_config(
            config_path=str(config_path),
            cli_args={"evasion_enabled": True, "evasion_mode": "disabled"},
        )
        assert config.evasion_enabled is True
        assert config.evasion_mode == "disabled"

    def test_invalid_evasion_mode_raises(self, tmp_path):
        """Verifies invalid evasion mode raises behavior."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "target_url: http://localhost/dvwa\n"
            "evasion_enabled: true\n"
            "evasion_mode: invalid_mode\n"
        )
        with pytest.raises(ConfigError, match="Unsupported evasion mode"):
            load_and_resolve_config(config_path=str(config_path), cli_args={})

    def test_evasion_env_overrides(self, tmp_path, monkeypatch):
        """Verifies evasion env overrides behavior."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text("target_url: http://localhost/dvwa\n")
        monkeypatch.setenv("TESIS_EVASION_ENABLED", "true")
        monkeypatch.setenv("TESIS_EVASION_STRATEGY", "proactive")
        config = load_and_resolve_config(config_path=str(config_path), cli_args={})
        assert config.evasion_enabled is True
        assert config.evasion_mode == "proactive"


class TestEvasionStatePropagation:
    """Groups regression tests for TestEvasionStatePropagation behavior."""
    def test_runner_injects_evasion_into_state(self, monkeypatch):
        """Verifies runner injects evasion into state behavior."""
        from evaluation.runner import run_single_engagement
        from core.graph_builder import build_framework

        # Mock the LangGraph framework to capture init_state
        captured_states = []

        def mock_build_framework(*, llm_provider, surface="sqli"):
            """Supports regression tests for test evasion integration."""
            class FakeApp:
                """Groups regression tests for FakeApp behavior."""
                def invoke(self, state):
                    """Supports regression tests for test evasion integration."""
                    captured_states.append(state)
                    return {
                        "iteration_count": 1,
                        "confirmed_vulns": [],
                        "achieved_outcomes": [],
                        "guardrail_activations": [],
                        "telemetry_events": [],
                        "evasion_attempts": 2,
                        "successful_evasions": 1,
                    }

                def stream(self, state, stream_mode=None):
                    """Supports regression tests for test evasion integration."""
                    captured_states.append(state)
                    yield {
                        "iteration_count": 1,
                        "confirmed_vulns": [],
                        "achieved_outcomes": [],
                        "guardrail_activations": [],
                        "telemetry_events": [],
                        "evasion_attempts": 2,
                        "successful_evasions": 1,
                    }
            return FakeApp()

        monkeypatch.setattr("evaluation.runner.build_framework", mock_build_framework)
        monkeypatch.setattr(
            "evaluation.runner.build_score_report",
            lambda state: type("R", (), {"to_dict": lambda self: {"summary": {}, "module_scores": {}}})(),
        )

        artifact = run_single_engagement(
            target_url="http://localhost/dvwa",
            security_level="low",
            llm_provider="gemini",
            evasion_enabled=True,
            evasion_mode="reactive",
        )

        assert len(captured_states) == 1
        init_state = captured_states[0]
        assert init_state["evasion_enabled"] is True
        assert init_state["evasion_mode"] == "reactive"
        assert artifact["config"]["evasion_enabled"] is True
        assert artifact["config"]["evasion_mode"] == "reactive"

    def test_runner_evasion_defaults_when_omitted(self, monkeypatch):
        """Verifies runner evasion defaults when omitted behavior."""
        from evaluation.runner import run_single_engagement

        captured_states = []

        def mock_build_framework(*, llm_provider, surface="sqli"):
            """Supports regression tests for test evasion integration."""
            class FakeApp:
                """Groups regression tests for FakeApp behavior."""
                def invoke(self, state):
                    """Supports regression tests for test evasion integration."""
                    captured_states.append(state)
                    return {
                        "iteration_count": 0,
                        "confirmed_vulns": [],
                        "achieved_outcomes": [],
                        "guardrail_activations": [],
                        "telemetry_events": [],
                        "evasion_attempts": 0,
                        "successful_evasions": 0,
                    }

                def stream(self, state, stream_mode=None):
                    """Supports regression tests for test evasion integration."""
                    captured_states.append(state)
                    yield {
                        "iteration_count": 0,
                        "confirmed_vulns": [],
                        "achieved_outcomes": [],
                        "guardrail_activations": [],
                        "telemetry_events": [],
                        "evasion_attempts": 0,
                        "successful_evasions": 0,
                    }
            return FakeApp()

        monkeypatch.setattr("evaluation.runner.build_framework", mock_build_framework)
        monkeypatch.setattr(
            "evaluation.runner.build_score_report",
            lambda state: type("R", (), {"to_dict": lambda self: {"summary": {}, "module_scores": {}}})(),
        )

        run_single_engagement(
            target_url="http://localhost/dvwa",
            security_level="low",
            llm_provider="gemini",
        )

        init_state = captured_states[0]
        assert init_state["evasion_enabled"] is False
        assert init_state["evasion_mode"] == "reactive"


class TestEvasionReportFormatting:
    """Groups regression tests for TestEvasionReportFormatting behavior."""
    def test_format_evasion_table(self):
        """Verifies format evasion table behavior."""
        from tesis.report_formatters import format_evasion_table

        data = {
            "runs": [
                {
                    "config": {"provider": "gemini", "evasion_strategy": "prompt_injection"},
                    "final_state": {"evasion_attempts": 3, "successful_evasions": 2},
                    "report": {"summary": {"guardrail_activations": 1}},
                }
            ]
        }
        table = format_evasion_table(data)
        assert "gemini" in table
        assert "prompt_injection" in table
        assert "3" in table
        assert "2" in table
        assert "66.7%" in table  # 2/3*100
        assert "0" in table       # max(1 - (3-2), 0) = 0 guardrails prevented
