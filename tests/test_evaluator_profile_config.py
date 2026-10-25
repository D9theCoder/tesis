"""Offline request serialization for the independently frozen evaluator."""

from unittest.mock import patch

import pytest
from langchain_core.messages import HumanMessage

from evaluation.thesis_scoring import evaluate_queue
from llm.provider import get_llm
from tesis.config_loader import ConfigError, load_and_resolve_config, save_yaml_config
from tesis.provider_registry import model_profile_id
from tesis.runtime_events import redact_secrets


@pytest.mark.parametrize("responses", [False, True])
@pytest.mark.parametrize("registry", [False, True])
@pytest.mark.parametrize("selection", ["legacy", "profile_only", "provider"])
def test_evaluator_uses_profile_reasoning_and_api_mode(tmp_path, responses, registry, selection):
    path = tmp_path / "config.yaml"
    profile_id = model_profile_id("gateway", "reasoning-model") if registry else "openai"
    adapter = "openai_compatible" if registry and not responses else "openai"
    payload = {
        "target_url": "http://localhost/dvwa", "provider": "openai",
        "models": {"openai": {
            "provider": "openai", "model_name": "reasoning-model", "api_key": "test",
            "base_url": "http://localhost:9999/v1", "reasoning_effort": "high",
            "use_responses_api": responses, "temperature": 1,
        }},
        "scoring_mode": "ai", "scoring_evaluator": {
            "provider": adapter, "model": "reasoning-model", "model_profile": profile_id,
            "max_attempts": 1, "max_tokens": 2048, "timeout": 20,
        },
    }
    if registry:
        payload["provider"] = profile_id
        payload["api_providers"] = {"gateway": {
            "protocol": adapter, "models": ["reasoning-model", "other-model"],
            "api_key": "test", "base_url": "http://localhost:9999/v1",
            "reasoning_effort": "high", "temperature": 1,
        }}
        del payload["models"]
    save_yaml_config(path, payload)
    historical = load_and_resolve_config(config_path=str(path), cli_args={}).scoring_evaluator
    if selection == "profile_only":
        del payload["scoring_evaluator"]["provider"]
        del payload["scoring_evaluator"]["model"]
        save_yaml_config(path, payload)
    elif selection == "provider":
        payload["scoring_evaluator"].update(provider=profile_id)
        del payload["scoring_evaluator"]["model_profile"]
        del payload["scoring_evaluator"]["model"]
        save_yaml_config(path, payload)
        historical = {key: value for key, value in historical.items() if key != "model_profile"}
        historical.update(provider=profile_id, adapter=adapter)
    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert config.scoring_evaluator == historical
    if registry:
        # Choosing another experiment model must preserve the frozen evaluator.
        other = load_and_resolve_config(config_path=str(path), cli_args={
            "provider": model_profile_id("gateway", "other-model"),
        })
        assert other.scoring_evaluator == config.scoring_evaluator
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


@pytest.mark.parametrize("content", ['{"score":1,"reason":"Observed signal","evidence_refs":["probe"]}', "invalid JSON"])
def test_evaluator_receipt_retains_redacted_reasoning_for_accepted_and_failed_answers(content):
    from langchain_core.messages import AIMessage
    evaluator = {"provider": "openai_compatible", "model": "judge", "max_attempts": 1,
                 "max_tokens": 1024, "timeout": 20, "api_key": "private-evaluator-credential"}
    queue = {"selection": "ai", "source_sha256": "0" * 64, "run_id": "reasoning-unit",
             "execution_id": "reasoning-unit", "rubric_version": "scoring.v4",
             "evaluator": redact_secrets(evaluator), "candidates": [{"candidate_id": "candidate",
             "status": "pending_review", "method": "sqli_union", "stage": "probe", "proof_ceiling": 1,
             "evidence_refs": ["probe"], "candidate": {}, "evidence": {}}]}
    response = AIMessage(content=content, additional_kwargs={
        "reasoning_content": "Review trace private-evaluator-credential"})
    result = evaluate_queue(queue, evaluator, invoke=lambda messages: response)
    receipt = result["telemetry"][0]
    assert receipt["reasoning_trace"] == "Review trace [REDACTED]"
    assert receipt["reasoning_summary"] is None
    assert receipt["status"] == ("abstained" if content == "invalid JSON" else "accepted")


def test_legacy_inline_evaluator_keeps_its_frozen_shape(tmp_path):
    evaluator = {"provider": "openai", "model": "historical-judge", "max_attempts": 2,
                 "max_tokens": 1024, "timeout": 60, "base_url": "https://legacy.invalid/v1"}
    path = save_yaml_config(tmp_path / "config.yaml", {
        "target_url": "http://localhost/dvwa", "provider": "openai", "scoring_evaluator": evaluator,
        "models": {"openai": {"provider": "openai", "model_name": "experiment-model"}},
    })
    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert config.scoring_evaluator == evaluator


@pytest.mark.parametrize("override", [
    {"provider": "claude"}, {"adapter": "claude"}, {"model": "different-model"},
    {"base_url": "https://other.invalid/v1"}, {"api_key": "different-secret"},
    {"use_responses_api": True},
])
def test_profile_evaluator_rejects_conflicting_connection_settings(tmp_path, override):
    profile_id = model_profile_id("gateway", "judge")
    path = save_yaml_config(tmp_path / "config.yaml", {
        "target_url": "http://localhost/dvwa", "provider": profile_id,
        "api_providers": {"gateway": {"protocol": "openai_compatible",
            "base_url": "https://gateway.invalid/v1", "api_key": "offline-key", "models": ["judge"]}},
        "scoring_evaluator": {"model_profile": profile_id, "max_attempts": 2,
            "max_tokens": 1024, "timeout": 60, **override},
    })
    with pytest.raises(ConfigError, match="must match its frozen model profile") as error:
        load_and_resolve_config(config_path=str(path), cli_args={})
    assert "different-secret" not in str(error.value)


def test_profile_evaluator_rejects_a_removed_model(tmp_path):
    path = save_yaml_config(tmp_path / "config.yaml", {
        "target_url": "http://localhost/dvwa", "provider": "openai",
        "scoring_evaluator": {"model_profile": "removed-profile", "max_attempts": 2,
            "max_tokens": 1024, "timeout": 60},
    })
    with pytest.raises(ConfigError, match="available model profile"):
        load_and_resolve_config(config_path=str(path), cli_args={})


@pytest.mark.parametrize("change", ["provider", "base_url", "protocol"])
def test_named_evaluator_cannot_replace_a_frozen_provider_model_or_protocol(tmp_path, change):
    from tesis.config_loader import load_yaml_config
    profile_id = model_profile_id("gateway", "judge")
    path = save_yaml_config(tmp_path / "config.yaml", {
        "target_url": "http://localhost/dvwa", "provider": profile_id,
        "api_providers": {"gateway": {"protocol": "openai_compatible",
            "base_url": "https://gateway.invalid/v1", "api_key": "offline-key", "models": ["judge", "other"]}},
        "scoring_evaluator": {"provider": profile_id, "max_attempts": 2, "max_tokens": 1024, "timeout": 60},
    })
    config = load_and_resolve_config(config_path=str(path), cli_args={})
    queue = {"selection": "ai", "source_sha256": "0" * 64,
             "evaluator": redact_secrets(config.scoring_evaluator), "candidates": []}
    payload = load_yaml_config(path)
    if change == "provider":
        payload["scoring_evaluator"]["provider"] = model_profile_id("gateway", "other")
    elif change == "base_url":
        payload["api_providers"]["gateway"]["base_url"] = "https://other.invalid/v1"
    else:
        payload["api_providers"]["gateway"]["protocol"] = "openai"
    save_yaml_config(path, payload)
    changed = load_and_resolve_config(config_path=str(path), cli_args={})
    with pytest.raises(ValueError, match="frozen experiment configuration"):
        evaluate_queue(queue, changed.scoring_evaluator)
