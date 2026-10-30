"""Focused registry, dotenv persistence, model discovery, and protocol contracts."""

from dataclasses import asdict
import json

import httpx
import pytest

from llm.provider import get_llm_from_model_config
from llm.runtime import LLMRuntime
from tesis.config_fields import configured_provider_choices
from tesis.config_loader import load_and_resolve_config, save_yaml_config
from tesis.provider_registry import model_profile_id


def _entry(protocol="openai_compatible", models=None, key="offline-key"):
    return {"protocol": protocol, "base_url": "https://gateway.invalid/v1", "api_key": key,
            "models": models or ["vendor/model-A", "vendor/model-a"]}


def _config(entries):
    first = next(iter(entries))
    return {"target_url": "http://localhost/dvwa", "provider": model_profile_id(first, entries[first]["models"][0]),
            "api_providers": entries}


def test_multiple_providers_and_models_resolve_without_overwriting_legacy_or_roles(tmp_path):
    payload = _config({"gateway": _entry(), "second": _entry("openai"),
                       "anthropic": _entry("anthropic")})
    payload["models"] = {"openai_codex_auth": {"provider": "openai_codex_auth", "model_name": "oauth-only"}}
    profile_ids = [model_profile_id(name, model) for name, entry in payload["api_providers"].items()
                   for model in entry["models"]]
    payload.update(matrix=True, providers=profile_ids)
    path = save_yaml_config(tmp_path / "config.yaml", payload)
    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert len(config.models) == 7
    assert set(profile_ids) <= set(configured_provider_choices(payload))
    assert "openai" not in configured_provider_choices(payload)
    assert config.models["openai_codex_auth"].model_name == "oauth-only"
    runtime = LLMRuntime()
    try:
        for profile_id in profile_ids:
            with runtime.coordinate(coordinate_id=profile_id, default_provider=profile_id,
                                    model_profiles={name: asdict(model) for name, model in config.models.items()},
                                    role_settings={role: asdict(settings) for role, settings in config.llm_runtime.roles.items()}) as context:
                adapter, settings, _ = context.role_config("payload_generator", max_tokens=32)
            assert adapter == config.models[profile_id].provider
            assert settings["model_name"] == config.models[profile_id].model_name
            assert settings["api_key"] == "offline-key"
    finally:
        runtime.close()


@pytest.mark.parametrize("protocol,expected_path", [
    ("openai", "/v1/responses"), ("openai_compatible", "/v1/chat/completions"),
    ("anthropic", "/v1/messages"),
])
def test_selected_models_send_inference_over_the_selected_wire_protocol(tmp_path, monkeypatch, protocol, expected_path):
    payload = _config({"gateway": _entry(protocol)})
    path = save_yaml_config(tmp_path / "config.yaml", payload)
    config = load_and_resolve_config(config_path=str(path), cli_args={})
    requests = []

    def handle(request):
        body = json.loads(request.content)
        requests.append(body)
        assert request.url.path == expected_path
        assert body["model"] in {"vendor/model-A", "vendor/model-a"}
        if protocol == "openai":
            assert body["store"] is False
            return httpx.Response(200, json={"id": "resp_1", "object": "response", "created_at": 1,
                "model": body["model"], "status": "completed", "output": [{"id": "msg_1", "type": "message",
                "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "ok", "annotations": []}]}],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}})
        if protocol == "anthropic":
            assert request.headers["x-api-key"] == "offline-key"
            return httpx.Response(200, json={"id": "msg_1", "type": "message", "role": "assistant", "model": body["model"],
                "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1}})
        return httpx.Response(200, json={"id": "chat_1", "object": "chat.completion", "created": 1, "model": body["model"],
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        if protocol == "anthropic":
            monkeypatch.setattr("langchain_anthropic.chat_models._get_default_httpx_client", lambda **_: client)
        for model in config.models.values():
            kwargs = {} if protocol == "anthropic" else {"http_client": client}
            llm = get_llm_from_model_config(model, **kwargs)
            result = llm.invoke("hello")
            assert "ok" in str(result.content)
    assert [body["model"] for body in requests] == ["vendor/model-A", "vendor/model-a"]
