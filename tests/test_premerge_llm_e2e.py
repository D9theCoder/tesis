"""Focused offline launch, runtime, session, and artifact acceptance."""

import asyncio
import json
import os
from types import SimpleNamespace

import pytest
from textual.widgets import Select
from textual.widgets._select import InvalidSelectValueError

from evaluation.reporter import write_json_report
from foundation.session_manager import DVWASession
from llm.runtime import current_call_context
from tesis import tui, tui_state
from tesis.config_loader import save_yaml_config
from tesis.tui_forms import LaunchDrawer


@pytest.mark.parametrize("mode", ["single", "matrix"])
def test_configured_roles_and_credentials_reach_saved_execution(tmp_path, monkeypatch, mode):
    """Use real launchers/runners with local substitutes for graph and transports."""
    for key in list(os.environ):
        if key.startswith("TESIS_"):
            monkeypatch.delenv(key)
    path = tmp_path / "config.yaml"
    save_yaml_config(path, {
        "target_url": "http://localhost/dvwa", "provider": "openai_compatible",
        "providers": ["openai_compatible"], "level": "low", "levels": ["low"],
        "surface": "sqli", "surfaces": ["sqli"], "payload_mode": "hybrid",
        "payload_modes": ["hybrid"], "target_method": "sqli_union",
        "output_dir": str(tmp_path / "artifacts"), "enriched_reporting": True,
        "dvwa_username": "configured-admin", "dvwa_password": "configured-private-password",
        "models": {"openai_compatible": {
            "provider": "openai_compatible", "model_name": "offline-reasoning-model",
            "api_key": "offline-private-key", "base_url": "http://localhost:9999/v1",
        }},
        "llm_runtime": {"max_concurrency": 1, "cache_scope": "none", "roles": {
            "orchestrator": {"reasoning_effort": "high"},
            "payload_generator": {"reasoning_effort": "low"},
        }},
    })
    monkeypatch.setattr(tui_state, "CONFIG_PATH", path)
    calls, logins = [], []

    class Unsupported(RuntimeError):
        status_code = 400

    class Client:
        def __init__(self, provider, options):
            self.provider, self.options, self.native = provider, options, False

        def with_structured_output(self, *args, **kwargs):
            self.native = True
            return self

        def invoke(self, messages):
            calls.append({"provider": self.provider, "effort": self.options["reasoning_effort"],
                          "max_tokens": self.options["max_tokens"]})
            if self.native:
                self.native = False
                raise Unsupported("unsupported tool_choice parameter")
            return SimpleNamespace(content='{"status":"ok"}', response_metadata={}, usage_metadata={})

    monkeypatch.setattr("llm.runtime.get_llm", lambda provider, **options: Client(provider, options))

    class HTTP:
        def __init__(self, base_url):
            self.base_url = base_url

        def get(self, path):
            return SimpleNamespace(text="<form></form>")

        def post(self, path, *, data):
            logins.append((data["username"], data["password"]))
            return SimpleNamespace(text='<a href="logout.php">Logout</a>',
                                   url="http://localhost/dvwa/index.php")

        def close(self):
            pass

        def set_cookie(self, *args, **kwargs):
            pass

    monkeypatch.setattr("foundation.session_manager.HTTPClient", HTTP)

    class Graph:
        def stream(self, state, **kwargs):
            with DVWASession(state["target_url"]) as session:
                assert session.login()
            context = current_call_context()
            for role in ("orchestrator", "payload_generator"):
                context.runtime.invoke(context=context, role=role, system_message="Health JSON",
                    user_message='Return {"status":"ok"}',
                    schema={"title": "OfflineProbe", "type": "object",
                            "properties": {"status": {"type": "string"}}, "required": ["status"]},
                    schema_version="offline-health.v1", validator=lambda value: value, max_tokens=96)
            yield {**state, "task_result": "INCOMPLETE", "incomplete_reason": "MODEL_STOPPED_WITHOUT_FINDING"}

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **kwargs: Graph())

    async def scenario():
        app = tui.TesisApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            mission = app.screen
            await app.push_screen(LaunchDrawer(mode=mode))
            await pilot.pause()
            drawer = app.screen
            reasoning_control = drawer.query_one("#launch-reasoning-effort", Select)
            assert reasoning_control.value == "preserve"
            reasoning_control.value = "inherit"
            assert all(role.reasoning_effort is None for role in drawer._resolved_config().role_configs.values())
            reasoning_control.value = "preserve"
            provider_control = drawer.query_one("#launch-field-provider", Select)
            with pytest.raises(InvalidSelectValueError):
                provider_control.value = "gemini"
            assert "reasoning_effort" not in drawer._cli_args()
            drawer._goto_step(len(drawer.STEPS) - 1)
            drawer.start_from_review()
            for _ in range(500):
                await pilot.pause(0.01)
                if not mission.run_active:
                    break
            assert not mission.run_active
            assert mission.state.status == "succeeded"

    asyncio.run(asyncio.wait_for(scenario(), timeout=20))
    assert logins == [("configured-admin", "configured-private-password")]
    assert [call["effort"] for call in calls] == ["high", "high", "low", "low"]
    assert all(call["provider"] == "openai_compatible" and call["max_tokens"] == 8192 for call in calls)
    primaries = []
    for artifact_path in (tmp_path / "artifacts").rglob("*.json"):
        text = artifact_path.read_text()
        assert "configured-private-password" not in text
        assert "offline-private-key" not in text
        record = json.loads(text)
        if record.get("schema_version") == "tui.v1":
            primaries.append(record)
    assert len(primaries) == 1
    assert primaries[0]["llm_performance_summary"]["provider_requests"] == 4
    assert primaries[0]["llm_performance_summary"]["calls"] == 2
    assert [row["reasoning_effort_requested"] for row in primaries[0]["llm_performance"]] == ["high", "low"]
    write_json_report(tmp_path / "acceptance.json", {
        "status": "passed", "mode": mode, "provider": "openai_compatible",
        "role_efforts": ["high", "low"], "actual_provider_dispatches": len(calls),
        "primary_execution_id": primaries[0]["execution_id"], "configured_credentials_used": True,
        "transports": "local substitutes; zero provider/DVWA requests",
    })
