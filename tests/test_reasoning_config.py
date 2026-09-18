"""Reasoning and provider-routing controls without live calls."""

from dataclasses import asdict

import pytest
from langchain_core.messages import HumanMessage

from llm.provider import get_llm, get_llm_from_model_config
from llm.runtime import LLMRuntime
from tesis.cli import _headless_overrides, _headless_parser
from tesis.config_loader import ConfigError, load_and_resolve_config
from tesis.model_config import ModelConfig


def _count_key(value, key):
    if isinstance(value, dict):
        return sum(
            (1 if item_key == key else 0) + _count_key(item_value, key)
            for item_key, item_value in value.items()
        )
    if isinstance(value, list):
        return sum(_count_key(item, key) for item in value)
    return 0


@pytest.mark.parametrize("effort", ["low", "medium", "high", "xhigh", "max"])
@pytest.mark.parametrize("responses", [False, True])
def test_effort_reaches_wire_payload(effort, responses):
    client = get_llm("openai_compatible", model_name="reasoning-model", api_key="test",
                     base_url="http://localhost:9999/v1", reasoning_effort=effort,
                     use_responses_api=responses, max_tokens=8192)
    payload = client._get_request_payload([HumanMessage(content="Return JSON")])
    if responses:
        assert payload["reasoning"]["effort"] == effort
        assert "reasoning_effort" not in payload
        assert payload["max_output_tokens"] == 8192
    else:
        assert payload["reasoning_effort"] == effort
        assert payload["max_completion_tokens"] == 8192
    assert "temperature" not in payload


@pytest.mark.parametrize("responses", [False, True])
def test_selected_effort_overrides_nested_disabled_reasoning(responses):
    client = get_llm("openai", model_name="gpt-5", api_key="test",
                     use_responses_api=responses, reasoning={"effort": "none"},
                     reasoning_effort="high")
    payload = client._get_request_payload([HumanMessage(content="Return JSON")])
    if responses:
        assert payload["reasoning"] == {"effort": "high"}
        assert "reasoning_effort" not in payload
    else:
        assert payload["reasoning_effort"] == "high"
        assert "reasoning" not in payload


@pytest.mark.parametrize("responses", [False, True])
@pytest.mark.parametrize("container_name", ["model_kwargs", "extra_body"])
def test_explicit_effort_removes_conflicting_legacy_request_fields(responses, container_name):
    conflicts = {
        "reasoning": {"effort": "low"},
        "reasoning_effort": "medium",
        "temperature": 1.0,
        "custom_option": "preserved",
    }
    client = get_llm(
        "openai_compatible",
        model_name="reasoning-model",
        api_key="test",
        base_url="http://localhost:9999/v1",
        reasoning_effort="xhigh",
        use_responses_api=responses,
        **{container_name: conflicts},
    )

    payload = client._get_request_payload([HumanMessage(content="Return JSON")])
    assert _count_key(payload, "temperature") == 0
    assert _count_key(payload, "effort") + _count_key(payload, "reasoning_effort") == 1
    assert "low" not in repr(payload)
    assert "medium" not in repr(payload)
    assert "custom_option" in repr(payload)
    if responses:
        assert payload["reasoning"]["effort"] == "xhigh"
        assert _count_key(payload, "reasoning_effort") == 0
    else:
        assert payload["reasoning_effort"] == "xhigh"
        assert _count_key(payload, "reasoning") == 0


def test_typed_config_token_budget_and_effort():
    client = get_llm_from_model_config(ModelConfig(
        provider="openai", model_name="gpt-5", api_key="test",
        max_tokens=8192, reasoning_effort="high",
        extra={"reasoning_effort": "low", "reasoning": {"effort": "low"}}))
    assert client.max_tokens == 8192
    assert client.reasoning_effort == "high"
    assert "max_output_tokens" not in client.model_kwargs
    payload = client._get_request_payload([HumanMessage(content="Return JSON")])
    assert payload["reasoning_effort"] == "high"
    assert _count_key(payload, "reasoning_effort") == 1
    assert _count_key(payload, "reasoning") == 0


def test_legacy_config_does_not_force_reasoning():
    client = get_llm("openai", model_name="gpt-4o-mini", api_key="test")
    assert client.reasoning_effort is None
    assert client.temperature == 0


def test_unpinned_roles_follow_each_coordinate_provider(tmp_path):
    """An omitted role profile resolves from the matrix coordinate provider."""
    path = tmp_path / "config.yaml"
    path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai_compatible\n"
        "models:\n"
        "  openai:\n"
        "    provider: openai\n"
        "    model_name: openai-coordinate-model\n"
        "  openai_compatible:\n"
        "    provider: openai_compatible\n"
        "    model_name: compatible-coordinate-model\n",
        encoding="utf-8",
    )

    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert all(role.model_profile is None for role in config.role_configs.values())

    role_settings = {
        role: asdict(settings)
        for role, settings in config.role_configs.items()
    }
    model_profiles = {
        profile: asdict(model)
        for profile, model in config.models.items()
    }
    runtime = LLMRuntime()
    try:
        for provider, expected_model in (
            ("openai", "openai-coordinate-model"),
            ("openai_compatible", "compatible-coordinate-model"),
        ):
            with runtime.coordinate(
                coordinate_id=f"coordinate-{provider}",
                default_provider=provider,
                default_model_config=model_profiles[provider],
                model_profiles=model_profiles,
                role_settings=role_settings,
            ) as context:
                for role in ("orchestrator", "payload_generator"):
                    resolved_provider, resolved_config, settings = context.role_config(
                        role,
                        max_tokens=128,
                    )
                    assert resolved_provider == provider
                    assert resolved_config["model_name"] == expected_model
                    assert settings.model_profile is None
    finally:
        runtime.close()


def test_pinned_role_profile_precedes_global_profile_and_coordinate(tmp_path):
    """Role pins win over a global pin, which wins over the coordinate axis."""
    path = tmp_path / "config.yaml"
    path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai_compatible\n"
        "model_profile: openai_compatible\n"
        "llm_runtime:\n"
        "  roles:\n"
        "    orchestrator:\n"
        "      model_profile: openai\n"
        "models:\n"
        "  openai:\n"
        "    provider: openai\n"
        "    model_name: pinned-role-model\n"
        "  openai_compatible:\n"
        "    provider: openai_compatible\n"
        "    model_name: pinned-global-model\n",
        encoding="utf-8",
    )

    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert config.role_configs["orchestrator"].model_profile == "openai"
    assert config.role_configs["payload_generator"].model_profile == "openai_compatible"

    model_profiles = {
        profile: asdict(model)
        for profile, model in config.models.items()
    }
    role_settings = {
        role: asdict(settings)
        for role, settings in config.role_configs.items()
    }
    runtime = LLMRuntime()
    try:
        with runtime.coordinate(
            coordinate_id="coordinate-openai",
            default_provider="openai",
            default_model_config=model_profiles["openai"],
            model_profiles=model_profiles,
            role_settings=role_settings,
        ) as context:
            orchestrator_provider, orchestrator_config, _ = context.role_config(
                "orchestrator",
                max_tokens=128,
            )
            payload_provider, payload_config, _ = context.role_config(
                "payload_generator",
                max_tokens=128,
            )
    finally:
        runtime.close()

    assert orchestrator_provider == "openai"
    assert orchestrator_config["model_name"] == "pinned-role-model"
    assert payload_provider == "openai_compatible"
    assert payload_config["model_name"] == "pinned-global-model"


@pytest.mark.parametrize("provider", ["gemini", "claude"])
def test_unmapped_effort_fails_actionably_without_downgrade(provider):
    with pytest.raises(ValueError, match=r"reasoning_effort='xhigh'.*native thinking parameters"):
        get_llm(provider, reasoning_effort="xhigh")


def test_yaml_env_cli_reasoning_precedence(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("target_url: http://localhost/dvwa\nprovider: openai\n"
                    "models:\n  openai:\n    model_name: gpt-5\n    reasoning_effort: low\n"
                    "llm_runtime:\n  roles:\n    orchestrator:\n      reasoning_effort: medium\n")
    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert config.models["openai"].reasoning_effort == "low"
    assert config.role_configs["orchestrator"].reasoning_effort == "medium"
    assert config.role_configs["payload_generator"].reasoning_effort is None
    assert all(role.max_tokens == 8192 for role in config.role_configs.values())
    monkeypatch.setenv("TESIS_REASONING_EFFORT", "xhigh")
    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert all(role.reasoning_effort == "xhigh" for role in config.role_configs.values())
    args = _headless_parser().parse_args(["--reasoning-effort", "max", "--model-profile", "openai"])
    config = load_and_resolve_config(config_path=str(path), cli_args=_headless_overrides(args))
    assert all(role.reasoning_effort == "max" for role in config.role_configs.values())


def test_explicit_profile_and_role_efforts_override_legacy_nested_values(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai\n"
        "models:\n"
        "  openai:\n"
        "    model_name: gpt-5\n"
        "    api_key: test\n"
        "    use_responses_api: true\n"
        "    reasoning:\n"
        "      effort: low\n"
        "    reasoning_effort: medium\n"
        "llm_runtime:\n"
        "  roles:\n"
        "    orchestrator:\n"
        "      reasoning:\n"
        "        effort: high\n"
        "      reasoning_effort: xhigh\n",
        encoding="utf-8",
    )

    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert config.models["openai"].reasoning_effort == "medium"
    assert config.role_configs["orchestrator"].reasoning_effort == "xhigh"
    client = get_llm_from_model_config(
        config.models["openai"],
        reasoning_effort=config.role_configs["orchestrator"].reasoning_effort,
    )
    payload = client._get_request_payload([HumanMessage(content="Return JSON")])
    assert payload["reasoning"]["effort"] == "xhigh"
    assert _count_key(payload, "effort") == 1
    assert _count_key(payload, "reasoning_effort") == 0


@pytest.mark.parametrize(
    "legacy_profile",
    [
        "    reasoning:\n      effort: high\n",
        "    model_kwargs:\n      reasoning:\n        effort: high\n",
        "    extra_body:\n      reasoning_effort: high\n",
    ],
)
def test_legacy_profile_effort_uses_reasoning_budget(legacy_profile, tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai\n"
        "candidate_budget: 3\n"
        "models:\n"
        "  openai:\n"
        "    model_name: gpt-5\n"
        f"{legacy_profile}",
        encoding="utf-8",
    )

    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert config.models["openai"].reasoning_effort == "high"
    assert config.role_configs["orchestrator"].max_tokens == 8192
    assert config.role_configs["payload_generator"].max_tokens == 8192


def test_legacy_role_effort_uses_reasoning_budget_without_changing_other_role(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai\n"
        "candidate_budget: 3\n"
        "llm_runtime:\n"
        "  roles:\n"
        "    orchestrator:\n"
        "      reasoning:\n"
        "        effort: high\n",
        encoding="utf-8",
    )

    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert config.role_configs["orchestrator"].reasoning_effort == "high"
    assert config.role_configs["orchestrator"].max_tokens == 8192
    assert config.role_configs["payload_generator"].reasoning_effort is None
    assert config.role_configs["payload_generator"].max_tokens == 288


def test_explicit_effort_defaults_budget_but_no_effort_keeps_legacy_budget(tmp_path):
    explicit_path = tmp_path / "explicit.yaml"
    explicit_path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai\n"
        "llm_runtime:\n"
        "  roles:\n"
        "    orchestrator:\n"
        "      reasoning_effort: low\n",
        encoding="utf-8",
    )
    legacy_path = tmp_path / "legacy.yaml"
    legacy_path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai\n"
        "candidate_budget: 3\n",
        encoding="utf-8",
    )

    explicit = load_and_resolve_config(config_path=str(explicit_path), cli_args={})
    legacy = load_and_resolve_config(config_path=str(legacy_path), cli_args={})
    assert explicit.role_configs["orchestrator"].max_tokens == 8192
    assert legacy.role_configs["orchestrator"].max_tokens == 96
    assert legacy.role_configs["payload_generator"].max_tokens == 288


def test_explicit_null_effort_suppresses_stale_legacy_profile_effort(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai\n"
        "candidate_budget: 3\n"
        "models:\n"
        "  openai:\n"
        "    model_name: gpt-5\n"
        "    api_key: test\n"
        "    reasoning:\n"
        "      effort: high\n"
        "    reasoning_effort: null\n",
        encoding="utf-8",
    )

    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert config.models["openai"].reasoning_effort is None
    assert "reasoning" not in config.models["openai"].extra
    assert config.role_configs["orchestrator"].max_tokens == 96
    assert config.role_configs["payload_generator"].max_tokens == 288
    client = get_llm_from_model_config(config.models["openai"])
    payload = client._get_request_payload([HumanMessage(content="Return JSON")])
    assert _count_key(payload, "reasoning") == 0
    assert _count_key(payload, "reasoning_effort") == 0


@pytest.mark.parametrize("value", ["bogus", "false", "0"])
def test_invalid_effort_rejected_before_execution(tmp_path, value):
    path = tmp_path / "config.yaml"
    path.write_text(f"target_url: http://localhost/dvwa\nmodels:\n  openai:\n    reasoning_effort: {value}\n")
    with pytest.raises(ConfigError, match="reasoning_effort"):
        load_and_resolve_config(config_path=str(path), cli_args={})
