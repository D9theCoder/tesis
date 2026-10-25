"""Isolated reasoning controls and model-specific provider settings, all offline."""

import asyncio

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Input, Select, Static

from tesis.config_loader import load_and_resolve_config, save_yaml_config
from tesis.provider_registry import model_profile_id
from tesis.tui_reasoning import ReasoningChecked, ReasoningControl


PROFILE = {"provider": "openai_compatible", "model_name": "unknown/model", "api_key": "offline",
           "base_url": "https://gateway.invalid/v1"}


class EffortApp(App):
    CSS_PATH = "../tesis/tui.tcss"

    def compose(self) -> ComposeResult:
        yield ReasoningControl(id="effort")


@pytest.mark.parametrize("typed", [False, True])
def test_unknown_model_warns_and_requires_successful_probe_for_current_connection(monkeypatch, typed):
    calls = []
    monkeypatch.setattr("tesis.tui_reasoning.probe_reasoning", lambda profile, effort: calls.append((profile, effort)))

    async def scenario():
        async with EffortApp().run_test() as pilot:
            control = pilot.app.query_one(ReasoningControl)
            control.configure([PROFILE], None)
            await pilot.pause()
            warning = control.query_one(Static)
            assert warning.has_class("unknown-model")
            assert "Unknown model, please set your own reasoning effort" in str(warning.content)
            picker = control.query_one(Select)
            assert [value for _, value in picker._options][1:-1] == [
                "off", "minimal", "low", "medium", "high", "xhigh", "max"]
            picker.value = "custom" if typed else "off"
            if typed:
                control.query_one(Input).value = "ultra"
            await pilot.pause()
            with pytest.raises(ValueError, match="support check required"):
                control.ensure_ready()
            for _ in range(50):
                await pilot.pause(0.01)
                if control._checked:
                    break
            assert control.ensure_ready()
            assert calls[0] == (PROFILE, "ultra" if typed else "off")
            old_generation = control._generation
            changed = {**PROFILE, "base_url": "https://other.invalid/v1"}
            control.configure([changed], None)
            control.checked(ReasoningChecked(old_generation, None))
            assert not control._checked
    asyncio.run(scenario())


def test_known_catalog_uses_only_its_choices_and_rejected_custom_value_cannot_proceed(monkeypatch):
    def reject(*_):
        raise ValueError("private provider error that must not be displayed")

    monkeypatch.setattr("tesis.tui_reasoning.probe_reasoning", reject)

    async def scenario():
        async with EffortApp().run_test() as pilot:
            control = pilot.app.query_one(ReasoningControl)
            control.configure([PROFILE], ["low", "high", "xhigh"])
            await pilot.pause()
            picker = control.query_one(Select)
            assert "off" not in [value for _, value in picker._options]
            picker.value = "high"
            await pilot.pause()
            assert control.ensure_ready()
            picker.value = "custom"
            control.query_one(Input).value = "off"
            await pilot.pause()
            with pytest.raises(ValueError):
                control.ensure_ready()
            await pilot.pause(0.1)
            assert not control._checked
            assert "Could not confirm" in str(control.query_one(Static).content)
            assert "private provider" not in str(control.query_one(Static).content)
    asyncio.run(scenario())


def test_model_efforts_stay_separate_and_metadata_never_reaches_inference(tmp_path):
    from langchain_core.messages import HumanMessage
    from llm.provider import get_llm_from_model_config

    entry = {"protocol": "openai_compatible", "api_key": "offline", "base_url": PROFILE["base_url"],
             "models": ["glm", "deepseek"], "model_options": {
                 "glm": {"reasoning_effort": "xhigh", "reasoning_efforts": ["low", "high", "xhigh"]},
                 "deepseek": {"reasoning_effort": "off", "reasoning_efforts": ["off", "low", "high", "xhigh"]}}}
    path = save_yaml_config(tmp_path / "config.yaml", {"target_url": "http://localhost/dvwa",
        "provider": model_profile_id("gateway", "glm"), "providers": None,
        "levels": None, "surfaces": None, "payload_modes": None,
        "api_providers": {"gateway": entry}})
    config = load_and_resolve_config(config_path=str(path), cli_args={})
    assert config.providers == [model_profile_id("gateway", "glm")]
    for name, expected in (("glm", "xhigh"), ("deepseek", "off")):
        model = config.models[model_profile_id("gateway", name)]
        wire = get_llm_from_model_config(model)._get_request_payload([HumanMessage(content="OK")])
        assert wire["reasoning_effort"] == expected
        assert "reasoning_efforts" not in wire


def test_unknown_default_reports_available_profiles_after_provider_removal(tmp_path):
    path = save_yaml_config(tmp_path / "config.yaml", {"target_url": "http://localhost/dvwa",
        "provider": "removed", "providers": None,
        "models": {"saved": {"provider": "openai", "model_name": "available"}}})
    with pytest.raises(ValueError, match="It may have been removed.*Available: saved"):
        load_and_resolve_config(config_path=str(path), cli_args={})


@pytest.mark.parametrize("responses", [False, True])
def test_support_probe_sends_custom_effort_through_effective_wire_protocol(responses):
    import json
    import httpx
    from tesis.tui_reasoning import probe_reasoning

    requests = []

    def handle(request):
        requests.append(request)
        if responses:
            return httpx.Response(200, json={"id": "resp_probe", "object": "response", "status": "completed",
                "created_at": 1, "model": "unknown/model", "output": [{"id": "msg_probe", "type": "message",
                "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "OK", "annotations": []}]}]})
        return httpx.Response(200, json={"id": "chatcmpl_probe", "object": "chat.completion", "created": 1,
            "model": "unknown/model", "choices": [{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "OK"}}]})

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        profile = {**PROFILE, "provider": "openai" if responses else "openai_compatible",
                   "use_responses_api": responses, "extra": {"http_client": client}}
        probe_reasoning(profile, "ultra")
    assert len(requests) == 1
    assert requests[0].url.path == ("/v1/responses" if responses else "/v1/chat/completions")
    body = json.loads(requests[0].content)
    assert body["model"] == "unknown/model"
    assert (body["reasoning"]["effort"] if responses else body["reasoning_effort"]) == "ultra"
    assert "temperature" not in body
    assert "reasoning_efforts" not in body
