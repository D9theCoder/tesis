"""Keyboard and screen smoke tests for the Textual application."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from tesis import tui
from tesis.model_config import EngagementConfig, ModelConfig
from tesis.runtime_events import RunEvent


def test_main_menu_keyboard_navigation_opens_single_setup():
    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, tui.MainMenuScreen)
            assert app.screen.query_one("#main-menu").option_count == 7
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, tui.RunSetupScreen)
            assert not app.screen.matrix
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, tui.MainMenuScreen)

    asyncio.run(scenario())


def test_matrix_screen_calculates_total_and_uses_compact_layout():
    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(90, 44)) as pilot:
            await pilot.pause()
            await pilot.press("down", "enter")
            await pilot.pause()
            assert isinstance(app.screen, tui.RunSetupScreen)
            assert app.screen.matrix
            assert "36 runs" in str(app.screen.query_one("#run-total").render())
            assert app.screen.has_class("compact")

    asyncio.run(scenario())


def test_run_setup_round_trips_llm_runtime_controls(monkeypatch):
    config = EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="openai_compatible",
        level="low",
        models={
            "openai_compatible": ModelConfig(
                "openai_compatible", "", "baseline-model"
            ),
        },
    )
    config.llm_runtime = {
        "max_concurrency": 2,
        "cache_scope": "run",
        "roles": {
            "orchestrator": {"model_profile": "orchestrator-profile", "model_name": "orch-model"},
            "payload_generator": {"model_profile": "payload-profile", "model_name": "payload-model"},
        },
    }
    monkeypatch.setattr(tui, "load_and_resolve_config", lambda **_kwargs: config)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 44)) as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            setup = app.screen
            assert isinstance(setup, tui.RunSetupScreen)
            assert setup.query_one("#llm-max-concurrency").value == "2"
            assert setup.query_one("#llm-cache-scope").value == "run"
            assert "orchestrator-profile/orch-model" in str(
                setup.query_one("#setup-summary").render()
            )

            setup.query_one("#llm-max-concurrency").value = "1"
            setup.query_one("#llm-cache-scope").value = "none"
            setup.query_one("#orchestrator-model-profile").value = "new-orch-profile"
            setup.query_one("#orchestrator-model").value = "new-orch-model"
            resolved = setup.resolved_config()
            assert resolved.llm_runtime["max_concurrency"] == 1
            assert resolved.llm_runtime["cache_scope"] == "none"
            assert resolved.llm_runtime["roles"]["orchestrator"]["model_profile"] == "new-orch-profile"
            assert resolved.llm_runtime["roles"]["orchestrator"]["model_name"] == "new-orch-model"

    asyncio.run(scenario())


def test_run_setup_reasoning_slider_applies_global_role_override(monkeypatch):
    config = EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="openai_compatible",
        level="low",
        models={
            "openai_compatible": ModelConfig(
                "openai_compatible", "", "reasoning-model"
            ),
        },
    )
    config.llm_runtime = {
        "max_concurrency": 1,
        "cache_scope": "none",
        "roles": {"orchestrator": {}, "payload_generator": {}},
    }
    captured: dict[str, object] = {}

    def load_config(**kwargs):
        captured.update(kwargs.get("cli_args", {}))
        return config

    monkeypatch.setattr(tui, "load_and_resolve_config", load_config)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 44)) as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            setup = app.screen
            assert isinstance(setup, tui.RunSetupScreen)
            slider = setup.query_one("#reasoning-effort", tui.ReasoningEffortSlider)
            assert slider.effort is None

            slider.focus()
            await pilot.press("right", "right", "right")
            assert slider.effort == "high"

            resolved = setup.resolved_config()
            assert captured["reasoning_effort"] == "high"
            assert resolved.llm_runtime["roles"]["orchestrator"]["reasoning_effort"] == "high"
            assert resolved.llm_runtime["roles"]["payload_generator"]["reasoning_effort"] == "high"

            await pilot.press("home")
            assert slider.effort is None
            inherited = setup.resolved_config()
            assert "reasoning_effort" not in inherited.llm_runtime["roles"]["orchestrator"]
            assert "reasoning_effort" not in inherited.llm_runtime["roles"]["payload_generator"]

    asyncio.run(scenario())

@pytest.mark.parametrize(
    ("loaded_roles", "payload_effort"),
    [
        (
            {
                "orchestrator": {"reasoning_effort": "xhigh"},
                "payload_generator": {"reasoning_effort": "high"},
            },
            "high",
        ),
        (
            {
                "orchestrator": {"reasoning_effort": "xhigh"},
                "payload_generator": {},
            },
            None,
        ),
    ],
)
def test_run_setup_preserves_mixed_role_efforts_until_global_control_changes(
    monkeypatch, loaded_roles, payload_effort
):
    config = EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="openai_compatible",
        level="low",
        models={
            "openai_compatible": ModelConfig(
                "openai_compatible", "", "reasoning-model"
            ),
        },
    )
    config.llm_runtime = {
        "max_concurrency": 1,
        "cache_scope": "none",
        "roles": loaded_roles,
    }
    monkeypatch.setattr(tui, "load_and_resolve_config", lambda **_kwargs: config)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 44)) as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            setup = app.screen
            assert isinstance(setup, tui.RunSetupScreen)
            slider = setup.query_one("#reasoning-effort", tui.ReasoningEffortSlider)
            assert slider.effort is None
            assert slider.mixed
            rendered = str(slider.render())
            assert "orchestrator=xhigh" in rendered
            assert f"payload_generator={payload_effort or 'inherit'}" in rendered

            resolved = setup.resolved_config()
            roles = resolved.llm_runtime["roles"]
            assert roles["orchestrator"]["reasoning_effort"] == "xhigh"
            if payload_effort is None:
                assert "reasoning_effort" not in roles["payload_generator"]
            else:
                assert roles["payload_generator"]["reasoning_effort"] == payload_effort

            slider.focus()
            await pilot.press("right")
            assert slider.effort == "low"
            assert not slider.mixed
            overridden = setup.resolved_config()
            assert overridden.llm_runtime["roles"]["orchestrator"]["reasoning_effort"] == "low"
            assert overridden.llm_runtime["roles"]["payload_generator"]["reasoning_effort"] == "low"

    asyncio.run(scenario())


def test_reasoning_slider_pointer_uses_rendered_track_and_keyboard_still_steps(
    monkeypatch,
):
    config = EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="openai_compatible",
        level="low",
        models={
            "openai_compatible": ModelConfig(
                "openai_compatible", "", "reasoning-model"
            ),
        },
    )
    monkeypatch.setattr(tui, "load_and_resolve_config", lambda **_kwargs: config)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 44)) as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            slider = app.screen.query_one(
                "#reasoning-effort", tui.ReasoningEffortSlider
            )
            slider.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            content_x = slider.content_region.x - slider.region.x
            content_y = slider.content_region.y - slider.region.y

            assert await pilot.click(
                slider,
                offset=(content_x + slider.track_width - 1, content_y),
            )
            assert slider.effort == "max"

            assert await pilot.click(
                slider,
                offset=(content_x + slider.track_width, content_y),
            )
            assert slider.effort == "max"

            assert await pilot.click(slider, offset=(content_x + 4, content_y))
            assert slider.effort == "medium"
            await pilot.press("left")
            assert slider.effort == "low"
            await pilot.press("right")
            assert slider.effort == "medium"
            await pilot.press("home")
            assert slider.effort is None

    asyncio.run(scenario())


def test_reasoning_slider_narrow_track_selects_the_rendered_marker(monkeypatch):
    config = EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="openai_compatible",
        level="low",
        models={
            "openai_compatible": ModelConfig(
                "openai_compatible", "", "reasoning-model"
            ),
        },
    )
    monkeypatch.setattr(tui, "load_and_resolve_config", lambda **_kwargs: config)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(20, 30)) as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            slider = app.screen.query_one(
                "#reasoning-effort", tui.ReasoningEffortSlider
            )
            slider.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            # Narrow terminals clip the track, so some markers are unreachable.
            assert slider.content_region.width < slider.track_width
            content_x = slider.content_region.x - slider.region.x
            content_y = slider.content_region.y - slider.region.y
            visible_cells = min(slider.content_region.width, slider.track_width)

            for x in range(visible_cells):
                previous = slider.effort
                await pilot.click(slider, offset=(content_x + x, content_y))
                track = slider.marker_track
                if x % 2 == 0:
                    assert slider.effort == slider.VALUES[x // 2]
                    assert track[x] == "●"
                else:
                    assert slider.effort == previous
                    assert track[x] == "─"

            settled = slider.effort
            await pilot.click(slider, offset=(content_x + visible_cells, content_y))
            assert slider.effort == settled

    asyncio.run(scenario())


def test_run_setup_global_model_profile_switches_both_roles(monkeypatch):
    config = EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="openai",
        level="low",
        models={
            "openai": ModelConfig("openai", "", "muse-model"),
            "openai_compatible": ModelConfig(
                "openai_compatible", "", "deepseek-model"
            ),
        },
    )
    config.llm_runtime = {
        "max_concurrency": 1,
        "cache_scope": "none",
        "roles": {
            "orchestrator": {"model_profile": "openai"},
            "payload_generator": {"model_profile": "openai"},
        },
    }
    monkeypatch.setattr(tui, "load_and_resolve_config", lambda **_kwargs: config)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 44)) as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            setup = app.screen
            assert isinstance(setup, tui.RunSetupScreen)
            assert setup.query_one("#model-profile").value == "openai"

            setup.query_one("#model-profile").value = "openai_compatible"
            await pilot.pause()

            assert setup.query_one("#orchestrator-model-profile").value == "openai_compatible"
            assert setup.query_one("#payload-model-profile").value == "openai_compatible"
            assert setup.query_one("#model").value == "deepseek-model"

    asyncio.run(scenario())


def test_settings_saves_llm_runtime_controls(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        "models:\n  gemini:\n    model_name: baseline-model\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(tui, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 44)) as pilot:
            await pilot.pause()
            await pilot.press("down", "down", "enter")
            await pilot.pause()
            settings = app.screen
            assert isinstance(settings, tui.SettingsScreen)
            settings.query_one("#settings-llm-max-concurrency").value = "2"
            settings.query_one("#settings-llm-cache-scope").value = "run"
            settings.query_one("#settings-orchestrator-model-profile").value = "orch-profile"
            settings.query_one("#settings-orchestrator-model").value = "orch-model"
            settings.query_one("#settings-payload-model-profile").value = "payload-profile"
            settings.query_one("#settings-payload-model").value = "payload-model"
            settings.query_one(
                "#settings-model-reasoning-effort", tui.ReasoningEffortSlider
            ).effort = "xhigh"
            settings.query_one(
                "#settings-reasoning-effort", tui.ReasoningEffortSlider
            ).effort = "high"
            settings.query_one("#settings-save").press()
            await pilot.pause()
            saved = config_path.read_text(encoding="utf-8")
            assert "max_concurrency: 2" in saved
            assert "cache_scope: run" in saved
            assert "model_profile: orch-profile" in saved
            assert "model_name: payload-model" in saved
            assert "reasoning_effort: xhigh" in saved
            assert saved.count("reasoning_effort: high") == 2

    asyncio.run(scenario())


def test_settings_preserves_mixed_roles_and_profile_effort_until_changed(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai_compatible\n"
        "level: low\n"
        "models:\n"
        "  openai_compatible:\n"
        "    model_name: reasoning-model\n"
        "    reasoning_effort: xhigh\n"
        "llm_runtime:\n"
        "  max_concurrency: 1\n"
        "  cache_scope: none\n"
        "  roles:\n"
        "    orchestrator:\n"
        "      reasoning_effort: xhigh\n"
        "    payload_generator:\n"
        "      reasoning_effort: high\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(tui, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 44)) as pilot:
            await pilot.pause()
            await pilot.press("down", "down", "enter")
            await pilot.pause()
            settings = app.screen
            assert isinstance(settings, tui.SettingsScreen)
            role_slider = settings.query_one(
                "#settings-reasoning-effort", tui.ReasoningEffortSlider
            )
            model_slider = settings.query_one(
                "#settings-model-reasoning-effort", tui.ReasoningEffortSlider
            )
            assert role_slider.effort is None
            assert role_slider.mixed
            assert "orchestrator=xhigh" in str(role_slider.render())
            assert "payload_generator=high" in str(role_slider.render())
            assert model_slider.effort == "xhigh"

            settings.query_one("#settings-llm-max-concurrency").value = "2"
            settings.query_one("#settings-save").press()
            await pilot.pause()
            saved = tui.load_yaml_config(config_path)
            assert saved["models"]["openai_compatible"]["reasoning_effort"] == "xhigh"
            assert (
                saved["llm_runtime"]["roles"]["orchestrator"]["reasoning_effort"]
                == "xhigh"
            )
            assert (
                saved["llm_runtime"]["roles"]["payload_generator"]["reasoning_effort"]
                == "high"
            )

            model_slider.effort = "max"
            settings.query_one("#settings-save").press()
            await pilot.pause()
            saved = tui.load_yaml_config(config_path)
            assert saved["models"]["openai_compatible"]["reasoning_effort"] == "max"
            assert (
                saved["llm_runtime"]["roles"]["orchestrator"]["reasoning_effort"]
                == "xhigh"
            )
            assert (
                saved["llm_runtime"]["roles"]["payload_generator"]["reasoning_effort"]
                == "high"
            )

            role_slider.focus()
            await pilot.press("right")
            assert role_slider.effort == "low"
            settings.query_one("#settings-save").press()
            await pilot.pause()
            saved = tui.load_yaml_config(config_path)
            assert saved["models"]["openai_compatible"]["reasoning_effort"] == "max"
            assert (
                saved["llm_runtime"]["roles"]["orchestrator"]["reasoning_effort"]
                == "low"
            )
            assert (
                saved["llm_runtime"]["roles"]["payload_generator"]["reasoning_effort"]
                == "low"
            )

    asyncio.run(scenario())


def test_validation_screen_runs_structured_offline_doctor(monkeypatch):
    calls: list[bool] = []

    def fake_doctor(_config, *, live=False):
        calls.append(live)
        return {
            "status": "failed",
            "summary": {"passed": 1, "failed": 1, "skipped": 0, "total": 2},
            "checks": [
                {
                    "id": "akg",
                    "category": "graph",
                    "status": "passed",
                    "summary": "AKG topology is valid",
                    "details": "9 methods covered",
                },
                {
                    "id": "provider",
                    "category": "llm",
                    "status": "failed",
                    "summary": "Provider configuration is incomplete",
                    "remediation": "Set the provider API key",
                },
            ],
        }

    import tesis.doctor

    monkeypatch.setattr(tesis.doctor, "run_doctor", fake_doctor)
    monkeypatch.setattr(
        tui,
        "load_and_resolve_config",
        lambda **_kwargs: EngagementConfig(
            target_url="http://localhost/dvwa", provider="gemini", level="low"
        ),
    )

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 42)) as pilot:
            app.push_screen(tui.ValidationScreen())
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, tui.ValidationScreen)
            screen._run_validation(screen._validation_generation, "doctor-offline")
            await pilot.pause()
            rendered = "\n".join(
                str(line) for line in screen.query_one("#validation-log").lines
            )
            assert calls == [False]
            assert "AKG topology is valid" in rendered
            assert "Set the provider API key" in rendered
            assert "1 passed, 1 failed" in rendered

    asyncio.run(scenario())


def test_settings_loads_round_trip_yaml_editor(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "# keep me\ntarget_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\nfuture_key: yes\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(tui, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause()
            await pilot.press("down", "down", "enter")
            await pilot.pause()
            assert isinstance(app.screen, tui.SettingsScreen)
            raw = app.screen.query_one("#yaml-editor").text
            assert "# keep me" in raw
            assert "future_key" in raw

    asyncio.run(scenario())


def test_settings_rejects_invalid_yaml_without_overwriting(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    original = "# keep\ntarget_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
    config_path.write_text(original, encoding="utf-8")
    monkeypatch.setattr(tui, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause()
            await pilot.press("down", "down", "enter")
            await pilot.pause()
            app.screen.query_one("#yaml-editor").text = "key: [unterminated"
            app.screen.query_one("#settings-save").press()
            await pilot.pause()
            assert config_path.read_text(encoding="utf-8") == original
            assert "Not saved" in str(app.screen.query_one("#settings-status").render())

    asyncio.run(scenario())


def test_settings_masks_literal_secret_in_raw_editor(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\n"
        "models:\n  gemini:\n    model_name: test-model\n    api_key: literal-secret-value\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(tui, "CONFIG_PATH", config_path)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause()
            await pilot.press("down", "down", "enter")
            await pilot.pause()
            raw = app.screen.query_one("#yaml-editor").text
            assert "literal-secret-value" not in raw
            assert "__TESIS_PRESERVE_SECRET_" in raw
            assert app.screen.query_one("#settings-api-key").value == ""

    asyncio.run(scenario())


def _dashboard_config(tmp_path: Path) -> EngagementConfig:
    return EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="gemini",
        level="low",
        output_dir=str(tmp_path / "results"),
        models={"gemini": ModelConfig("gemini", "provider-secret-key", "test-model")},
    )


def test_tui_run_experiment_multiplexes_journal_writes_descriptor_and_akg(
    tmp_path: Path, monkeypatch
) -> None:
    config = _dashboard_config(tmp_path)
    screen = tui.RuntimeDashboardScreen(
        config,
        matrix=False,
        condition="linear_hybrid",
        target_method=None,
    )
    emitted: list[RunEvent] = []
    monkeypatch.setattr(screen, "_post_event", emitted.append)
    monkeypatch.setattr(screen, "_tesis_closing", True)

    def fake_single(**kwargs):
        execution_id = kwargs["execution_id"]
        sink = kwargs["event_sink"]
        sink.emit(RunEvent("run.started", execution_id=execution_id, run_id="run-t", data={"n": 1}))
        sink.emit(RunEvent("graph.node.started", data={"node": "sqli"}))
        return {"execution_id": execution_id, "run_id": "run-t", "status": "success", "config": {}}

    monkeypatch.setattr(tui, "run_single_engagement", fake_single)

    screen.run_experiment()

    runs_root = Path(tmp_path) / "results" / "runs"
    run_dir = max(runs_root.iterdir(), key=lambda p: p.stat().st_ctime)

    # Terminal descriptor carries result identity.
    desc = json.loads((run_dir / "runtime.json").read_text(encoding="utf-8"))
    assert desc["status"] == "finished"
    assert desc["execution_id"]
    assert desc["run_id"] == "run-t"

    # Journal contains each event once; UI callback received them too.
    journal_text = (run_dir / "runtime.events.jsonl").read_text(encoding="utf-8")
    assert "run.started" in journal_text
    assert "graph.node.started" in journal_text
    assert "provider-secret-key" not in journal_text
    assert [event.event_type for event in emitted] == ["run.started", "graph.node.started"]

    # Deterministic AKG snapshot exported for frontend fallback.
    akg_path = run_dir / "akg.snapshot.json"
    assert akg_path.exists()
    akg = json.loads(akg_path.read_text(encoding="utf-8"))
    assert akg["schema_version"] == "akg-snapshot.v1"
    assert len(akg["nodes"]) == akg["node_count"]


def test_dashboard_stream_and_tab_trace_toggle(monkeypatch):
    monkeypatch.setattr(tui.RuntimeDashboardScreen, "run_experiment", lambda self: None)

    async def scenario() -> None:
        app = tui.TesisApp()
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            setup = app.screen
            setup.query_one("#start-run").press()
            await pilot.pause()
            await pilot.pause()
            assert isinstance(app.screen, tui.RuntimeDashboardScreen)
            assert app.screen._runtime_thread is not None
            assert app.screen._runtime_thread.daemon is True
            app.screen.post_message(tui.DashboardEvent(
                RunEvent(event_type="llm.token", message="hello", data={"streaming": True})
            ))
            await pilot.pause()
            assert app.screen.query_one("#trace-log").has_class("hidden")
            await pilot.press("tab")
            await pilot.pause()
            assert not app.screen.query_one("#trace-log").has_class("hidden")
            assert app.screen.query_one("#stream-log").has_class("hidden")

    asyncio.run(scenario())
