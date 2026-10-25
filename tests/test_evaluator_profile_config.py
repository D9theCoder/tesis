"""Offline request serialization for the independently frozen evaluator."""

from unittest.mock import patch

import pytest
from langchain_core.messages import HumanMessage

from evaluation.thesis_scoring import evaluate_queue
from llm.provider import get_llm
from tesis.config_loader import load_and_resolve_config, save_yaml_config
from tesis.runtime_events import redact_secrets


@pytest.mark.parametrize("responses", [False, True])
def test_evaluator_uses_profile_reasoning_and_api_mode(tmp_path, responses):
    path = tmp_path / "config.yaml"
    save_yaml_config(path, {
        "target_url": "http://localhost/dvwa", "provider": "openai",
        "models": {"openai": {
            "provider": "openai", "model_name": "reasoning-model", "api_key": "test",
            "base_url": "http://localhost:9999/v1", "reasoning_effort": "high",
            "use_responses_api": responses, "temperature": 1,
        }},
        "scoring_mode": "ai", "scoring_evaluator": {
            "provider": "openai", "model": "reasoning-model", "model_profile": "openai",
            "max_attempts": 1, "max_tokens": 2048, "timeout": 20,
        },
    })
    config = load_and_resolve_config(config_path=str(path), cli_args={})
    queue = {"selection": "ai", "source_sha256": "0" * 64,
             "evaluator": redact_secrets(config.scoring_evaluator), "candidates": []}
    clients = []

    def factory(provider, **options):
        client = get_llm(provider, **options)
        clients.append(client)
        return client

    with patch("llm.provider.get_llm", side_effect=factory):
        evaluate_queue(queue, config.scoring_evaluator)
    payload = clients[0]._get_request_payload([HumanMessage(content="Return JSON")])
    assert "temperature" not in payload
    if responses:
        assert payload["reasoning"]["effort"] == "high"
        assert payload["max_output_tokens"] == 2048
    else:
        assert payload["reasoning_effort"] == "high"
        assert payload["max_completion_tokens"] == 2048


def test_evaluator_cannot_silently_change_a_historical_frozen_configuration():
    evaluator = {"provider": "openai", "model": "test", "max_attempts": 1,
                 "max_tokens": 1024, "timeout": 20, "reasoning_effort": "high"}
    historical = {key: value for key, value in evaluator.items() if key != "reasoning_effort"}
    queue = {"selection": "ai", "source_sha256": "0" * 64,
             "evaluator": historical, "candidates": []}
    with pytest.raises(ValueError, match="frozen experiment configuration"):
        evaluate_queue(queue, evaluator)
