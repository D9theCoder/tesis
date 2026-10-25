"""Focused registry, dotenv persistence, model discovery, and protocol contracts."""

from dataclasses import asdict
import json
import os

from dotenv import dotenv_values
import httpx
import pytest
from langchain_core.messages import HumanMessage

from llm.model_catalog import ModelCatalogError, catalog_url, fetch_models
from llm.provider import get_llm, get_llm_from_model_config
from llm.runtime import LLMRuntime
from tesis.config_fields import configured_provider_choices
from tesis.config_loader import ConfigError, load_and_resolve_config, load_yaml_config, save_yaml_config
from tesis.provider_registry import expanded_model_sections, model_profile_id, provider_key_variable
from tesis.provider_settings import save_provider_settings


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


@pytest.mark.parametrize("selection", ["coordinate", "global", "role"])
def test_registry_profiles_preserve_legacy_role_defaults_and_request_limits(tmp_path, selection):
    entry = {**_entry(models=["reasoning-model"]), "reasoning_effort": "high"}
    profile_id = model_profile_id("gateway", "reasoning-model")
    registry = _config({"gateway": entry})
    legacy = {key: value for key, value in registry.items() if key != "api_providers"}
    legacy["models"] = expanded_model_sections(registry)
    for payload in (legacy, registry):
        if selection == "global":
            payload["model_profile"] = profile_id
        elif selection == "role":
            payload["llm_runtime"] = {"roles": {
                "payload_generator": {"model_profile": profile_id, "max_tokens": 2048},
            }}
    configs = []
    for name, payload in (("legacy", legacy), ("registry", registry)):
        path = save_yaml_config(tmp_path / f"{name}.yaml", payload)
        configs.append(load_and_resolve_config(config_path=str(path), cli_args={}))

    assert asdict(configs[1].llm_runtime) == asdict(configs[0].llm_runtime)
    runtime = LLMRuntime()
    try:
        for role in ("orchestrator", "payload_generator"):
            requests = []
            for index, config in enumerate(configs):
                with runtime.coordinate(
                    coordinate_id=str(index), default_provider=config.provider,
                    model_profiles={name: asdict(model) for name, model in config.models.items()},
                    role_settings={name: asdict(settings) for name, settings in config.role_configs.items()},
                ) as context:
                    adapter, options, _ = context.role_config(role, max_tokens=96)
                requests.append(get_llm(adapter, **options)._get_request_payload([HumanMessage(content="Return JSON")]))
            assert requests[1] == requests[0]
            assert requests[1]["max_completion_tokens"] == (2048 if selection == "role" and role == "payload_generator" else 8192)
    finally:
        runtime.close()


@pytest.mark.parametrize("change", [
    {"protocol": "openai_codex_auth"}, {"protocol": []}, {"models": []},
    {"models": ["same", "same"]}, {"models": ["has spaces"]},
    {"base_url": "https://secret:credential@example.invalid/v1"}, {"extra": []},
])
def test_malformed_provider_entries_are_rejected(change):
    entry = _entry()
    entry.update(change)
    with pytest.raises(ValueError):
        expanded_model_sections({"api_providers": {"gateway": entry}})


@pytest.mark.parametrize("provider_id", ["has spaces", "../path", "openai_codex_auth", "UPPER"])
def test_invalid_or_oauth_provider_ids_are_rejected(provider_id):
    with pytest.raises(ValueError):
        expanded_model_sections({"api_providers": {provider_id: _entry()}})


def test_pending_keys_are_saved_only_to_private_dotenv_preserving_existing_values(tmp_path, monkeypatch):
    variable = provider_key_variable("gateway")
    monkeypatch.delenv(variable, raising=False)
    env = tmp_path / ".env"
    env.write_text("# Existing settings\nUNRELATED='keep me'\n", encoding="utf-8")
    path = tmp_path / "config.yaml"
    payload = _config({"gateway": _entry(key=f"${{{variable}}}")})
    secret = "test-'quoted'-$()\\value"
    save_provider_settings(path, payload, {variable: secret, "IGNORED_UNSAVED_KEY": "never-save"})
    assert secret not in path.read_text()
    assert dotenv_values(env)[variable] == secret
    assert dotenv_values(env)["UNRELATED"] == "keep me"
    assert "# Existing settings" in env.read_text()
    assert "IGNORED_UNSAVED_KEY" not in env.read_text()
    assert env.stat().st_mode & 0o777 == 0o600
    assert load_and_resolve_config(config_path=str(path), cli_args={}).models[payload["provider"]].api_key == secret


def test_invalid_draft_and_failed_config_replace_do_not_change_saved_files(tmp_path, monkeypatch):
    variable = provider_key_variable("gateway")
    monkeypatch.delenv(variable, raising=False)
    path, env = tmp_path / "config.yaml", tmp_path / ".env"
    path.write_text("target_url: http://localhost/dvwa\nprovider: gemini\n")
    env.write_text("# Keep\nOTHER=unchanged\n")
    original = path.read_text(), env.read_text()
    payload = _config({"gateway": _entry(key=f"${{{variable}}}")})
    invalid = {**payload, "target_url": "invalid"}
    with pytest.raises(ConfigError):
        save_provider_settings(path, invalid, {variable: "test-secret"})
    assert (path.read_text(), env.read_text()) == original
    replace = os.replace

    def fail_config(source, target):
        if target == path:
            raise OSError("simulated config failure")
        return replace(source, target)

    monkeypatch.setattr("tesis.provider_settings.os.replace", fail_config)
    with pytest.raises(OSError):
        save_provider_settings(path, payload, {variable: "test-secret"})
    assert (path.read_text(), env.read_text()) == original
    assert variable not in os.environ
    assert not list(tmp_path.glob(".config.yaml-*"))
    assert not list(tmp_path.glob("..env-*"))


@pytest.mark.parametrize("protocol", ["openai", "openai_compatible", "anthropic"])
def test_catalog_fetches_all_pages_and_uses_protocol_auth(protocol):
    requests = []

    def handle(request):
        requests.append(request)
        assert str(request.url).startswith("https://catalog.invalid/custom")
        if protocol == "anthropic":
            assert request.headers["x-api-key"] == "catalog-key"
            assert request.headers["anthropic-version"] == "2023-06-01"
            assert "authorization" not in request.headers
        else:
            assert request.headers["authorization"] == "Bearer catalog-key"
        if len(requests) == 1:
            return httpx.Response(200, json={"data": [{"id": "new-a", "display_name": "New A"}],
                                             "has_more": True, "last_id": "new-a"})
        assert request.url.params["after_id" if protocol == "anthropic" else "after"] == "new-a"
        assert request.url.params["region"] == "custom"
        return httpx.Response(200, json={"data": [{"id": "new-b"}, {"id": "new-a"}], "has_more": False})

    models = fetch_models(base_url="https://gateway.invalid/v1", protocol=protocol, api_key="catalog-key",
                          fetch_url="https://catalog.invalid/custom?region=custom", transport=httpx.MockTransport(handle))
    assert [model["id"] for model in models] == ["new-a", "new-b"]
    assert models[0]["display_name"] == "New A"
    assert len(requests) == 2


@pytest.mark.parametrize("response", [
    httpx.Response(401, text="arbitrary-secret"), httpx.Response(302, headers={"Location": "https://external.invalid"}),
    httpx.Response(200, text="not-json arbitrary-secret"), httpx.Response(200, json={"data": [None]}),
    httpx.Response(200, json={"data": [] , "has_more": True}),
])
def test_catalog_errors_are_actionable_and_do_not_echo_secrets_or_follow_redirects(response):
    requests = []

    def handle(request):
        requests.append(request)
        return response

    with pytest.raises(ModelCatalogError) as exc:
        fetch_models(base_url="https://gateway.invalid/v1", protocol="openai", api_key="arbitrary-secret",
                     transport=httpx.MockTransport(handle))
    assert "arbitrary-secret" not in str(exc.value)
    assert len(requests) == 1


def test_anthropic_listing_url_does_not_duplicate_version_and_oauth_is_excluded():
    assert catalog_url("https://api.anthropic.com", "anthropic") == "https://api.anthropic.com/v1/models"
    assert catalog_url("https://relay.invalid/v1/", "anthropic") == "https://relay.invalid/v1/models"
    with pytest.raises(ModelCatalogError):
        catalog_url("https://api.openai.com/v1", "openai_codex_auth")


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


def test_named_model_coordinates_are_executed_and_keep_separate_matrix_identity(monkeypatch):
    from evaluation.multi_llm_runner import run_provider_matrix

    profiles = expanded_model_sections({"api_providers": {"gateway": _entry(), "second": _entry()}})
    seen = []

    def fake_run(**kwargs):
        name = kwargs["llm_provider"]
        seen.append((name, kwargs["model_config"]["model_name"], kwargs["experiment_condition"],
                     kwargs["target_method"], kwargs["payload_mode"], kwargs["repeat_index"]))
        return {"status": "success", "config": {"provider": name, "surface": "sqli", "security_level": "low",
                "payload_mode": kwargs["payload_mode"], "repeat_index": kwargs["repeat_index"],
                "experiment_condition": kwargs["experiment_condition"], "target_method": kwargs["target_method"]},
                "report": {"summary": {}, "module_scores": {}},
                "llm_performance": [], "llm_performance_summary": {}}

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", fake_run)
    artifacts = run_provider_matrix(target_url="http://localhost/dvwa", providers=list(profiles), model_configs=profiles,
        security_levels=["low"], surfaces=["sqli"], payload_modes=["hybrid"], repeats=2,
        experiment_conditions=["linear_hybrid", "akg_guided_hybrid"], target_method="sqli_union")
    assert {row[0] for row in seen} == set(profiles)
    assert {row[1] for row in seen} == {"vendor/model-A", "vendor/model-a"}
    assert len(artifacts) == len(seen) == len(set(seen)) == 16
    for name in profiles:
        assert {row[2:] for row in seen if row[0] == name} == {
            (condition, "sqli_union", "hybrid", repeat)
            for condition in ("linear_hybrid", "akg_guided_hybrid") for repeat in (0, 1)
        }
    assert {artifact["config"]["provider"] for artifact in artifacts} == set(profiles)
