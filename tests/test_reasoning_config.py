"""Reasoning and provider-routing controls without live calls."""


import pytest
from langchain_core.messages import HumanMessage

from llm.provider import get_llm
from tesis.config_loader import ConfigError, load_and_resolve_config


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


@pytest.mark.parametrize("provider", ["gemini", "claude"])
def test_unmapped_effort_fails_actionably_without_downgrade(provider):
    with pytest.raises(ValueError, match=r"reasoning_effort='xhigh'.*native thinking parameters"):
        get_llm(provider, reasoning_effort="xhigh")


@pytest.mark.parametrize("value", ["has spaces", "false", "0"])
def test_invalid_effort_rejected_before_execution(tmp_path, value):
    path = tmp_path / "config.yaml"
    path.write_text(f"target_url: http://localhost/dvwa\nmodels:\n  openai:\n    reasoning_effort: {value}\n")
    with pytest.raises(ConfigError, match="reasoning_effort"):
        load_and_resolve_config(config_path=str(path), cli_args={})
