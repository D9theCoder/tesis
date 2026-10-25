"""Offline launcher controls; provider and DVWA calls are deliberately replaced."""

import asyncio
import dataclasses
import json
from pathlib import Path

import pytest

from tesis import tui, tui_mission, tui_state
from tesis.model_config import EngagementConfig, ModelConfig
from tesis.runtime_events import RunEvent


@pytest.mark.parametrize("mode", ["single", "matrix"])
@pytest.mark.parametrize("status", ["success", "error", "cancelled"])
def test_launcher_runtime_lifecycle(tmp_path, monkeypatch, mode, status):
    """Exercise the mounted screen, worker, observer files, and terminal outcome."""
    config = EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="openai_compatible",
        level="low",
        models={"openai_compatible": ModelConfig(
            "openai_compatible", "offline-secret", "offline-model",
            base_url="http://localhost:9999/v1",
        )},
        output_dir=str(tmp_path / "results"),
    )
    config.iterations = 4
    config.candidate_budget = 5
    config.experiment_condition = "akg_guided_hybrid"
    config.target_method = "sqli_union"
    config.providers = [config.provider]
    config.levels = ["low"]
    config.surfaces = ["sqli"]
    config.payload_modes = ["hybrid", "llm_mutation_only"]
    captured = {}
    events = []
    active_descriptors = []
    parent_checks = []

    def runner(**kwargs):
        captured.update(kwargs)
        from tesis.live_runtime import descriptor_path
        descriptor = json.loads(descriptor_path(kwargs["output_dir"]).read_text())
        active_descriptors.append(descriptor)
        sink = kwargs["event_sink"]
        parent_id = kwargs["execution_id"]
        result = {"status": status, "execution_id": parent_id, "run_id": "offline-parent"}
        if mode == "matrix":
            sink.emit(RunEvent("matrix.started", execution_id=parent_id,
                               timestamp=100.0, data={"total": 2}))
            for index in range(2):
                child_id = f"offline-child-{index}"
                sink.emit(RunEvent("matrix.run.started", execution_id=parent_id,
                    timestamp=101.0 + index * 10,
                    data={"coordinate_index": index, "coordinate_execution_id": child_id,
                          "payload_mode": config.payload_modes[index], "total": 2}))
                sink.emit(RunEvent("run.started", execution_id=child_id,
                                  timestamp=102.0 + index * 10))
                sink.emit(RunEvent("run.failed" if status == "error" else "run.finished",
                    execution_id=child_id, timestamp=103.0 + index * 10,
                    data={"status": "error" if status == "error" else "success"}))
                parent_checks.append((observed_state.execution_id, observed_state.status,
                                      observed_state.started_at))
                sink.emit(RunEvent("matrix.run.finished", execution_id=parent_id,
                    timestamp=104.0 + index * 10,
                    data={"coordinate_index": index, "coordinate_execution_id": child_id,
                          "completed": index + 1, "total": 2,
                          "status": "error" if status == "error" else "success"}))
            result.update(totals={"total_runs": 2, "error_runs": 2 if status == "error" else 0},
                          cancellation={"completed_runs": 2, "total_runs": 2, "not_started_runs": 0})
            return [], result
        # A result is authoritative even when the runner emits no terminal event.
        sink.emit(RunEvent("run.started", execution_id=parent_id, timestamp=100.0))
        return result

    monkeypatch.setattr(tui_mission, "run_provider_matrix" if mode == "matrix"
                        else "run_single_engagement", runner)

    async def scenario():
        nonlocal screen
        app = tui.TesisApp()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            original_post = screen._post_event

            def record(event):
                events.append(event.as_dict())
                # Inspect model state at the event boundary without touching widgets.
                tui_state.apply_run_event(observed_state, event)
                original_post(event)

            screen._post_event = record
            screen.start_run(config, mode=mode)
            deadline = asyncio.get_running_loop().time() + 10
            while screen._runtime_thread.is_alive():
                assert asyncio.get_running_loop().time() < deadline, "worker did not stop"
                await pilot.pause(0.01)
            screen._drain_runtime_events()
            await pilot.pause()
            expected = {"success": "succeeded", "error": "failed", "cancelled": "cancelled"}[status]
            evidence_dir = Path("results/validation/tui-model-matrix-fix-2026-10-10/offline") / f"{mode}-{status}"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            (evidence_dir / "events.json").write_text(json.dumps(events, indent=2))
            (evidence_dir / "screen.svg").write_text(app.export_screenshot())
            (evidence_dir / "state.json").write_text(json.dumps(dataclasses.asdict(screen.state), indent=2))
            assert screen.state.status == expected
            assert not screen.run_active
            assert screen.state.execution_id == captured["execution_id"]
            if mode == "matrix":
                assert len(screen.state.coordinates) == 2
                assert screen.state.completed == screen.state.total == 2
                assert observed_state.started_at == 100.0
            assert screen._journal_path.is_file()
            journal = screen._journal_path.read_text()
            assert "offline-secret" not in journal
            journal_events = [json.loads(line) for line in journal.splitlines()]
            assert journal_events[-1]["execution_id"] == captured["execution_id"]
            assert journal_events[-1]["data"]["status"] == status
            from tesis.live_runtime import descriptor_path
            terminal = json.loads(descriptor_path(captured["output_dir"]).read_text())
            assert terminal["execution_id"] == captured["execution_id"]
            assert terminal["run_id"] == ("offline-parent" if mode == "single" else None)
            assert terminal["status"] == {"success": "finished", "error": "failed", "cancelled": "cancelled"}[status]

    screen = None
    observed_state = tui_state.TuiRunState(run_mode=mode)
    asyncio.run(asyncio.wait_for(scenario(), timeout=15))
    assert active_descriptors[0]["status"] == "active"
    assert captured["max_iterations"] == 4
    assert captured["candidate_budget"] == 5
    assert captured["experiment_condition"] == "akg_guided_hybrid"
    assert captured["target_method"] == "sqli_union"
    assert captured["stop_policy"] == config.stop_policy
    assert captured["coverage_target"] == config.coverage_target
    assert captured["llm_runtime_config"] == dataclasses.asdict(config.llm_runtime)
    assert captured["scoring_profile"] == config.scoring_profile
    model = captured["model_configs"][config.provider] if mode == "matrix" else captured["model_config"]
    assert model["base_url"] == "http://localhost:9999/v1"
    if mode == "matrix":
        assert captured["include_aggregate"] is True
        # The parent must remain active across child terminal events.
        child_terminals = [event for event in events if event["event_type"] in {"run.finished", "run.failed"}
                           and event.get("execution_id", "").startswith("offline-child-")]
        assert len(child_terminals) == 2
        assert all(identity == captured["execution_id"] and state in {"running", "degraded"}
                   and started == 100.0 for identity, state, started in parent_checks)


@pytest.mark.parametrize("outcome", ["error", "cancelled"])
def test_real_matrix_partial_artifacts(tmp_path, monkeypatch, outcome):
    """Use the real matrix scheduler with controlled child results, offline."""
    import evaluation.multi_llm_runner as matrix_runner
    from evaluation.reporter import write_json_report

    config = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai_compatible", level="low",
        models={"openai_compatible": ModelConfig("openai_compatible", "", "offline-model",
                                                base_url="http://localhost:9999/v1")},
        output_dir=str(tmp_path / "results"),
        providers=["openai_compatible"], levels=["low"], surfaces=["sqli"],
        payload_modes=["hybrid", "llm_mutation_only"], target_method="sqli_union",
    )
    child_artifacts = []

    def child(**kwargs):
        sink = kwargs["event_sink"]
        execution_id = kwargs["execution_id"]
        sink.emit(RunEvent("run.started", execution_id=execution_id))
        if outcome == "cancelled":
            kwargs["cancellation_token"].cancel("offline control")
        artifact = {
            "execution_id": execution_id, "run_id": execution_id,
            "status": outcome, "config": {
                "provider": kwargs["llm_provider"], "security_level": kwargs["security_level"],
                "surface": kwargs["surface"], "payload_mode": kwargs["payload_mode"],
                "target_method": kwargs["target_method"], "repeat_index": kwargs["repeat_index"],
            },
            "final_state": {}, "report": {},
        }
        write_json_report(Path(kwargs["output_dir"]) / f"{execution_id}.json", artifact)
        child_artifacts.append(artifact)
        sink.emit(RunEvent("run.failed" if outcome == "error" else "run.cancelled",
                           execution_id=execution_id, data={"status": outcome}))
        return artifact

    monkeypatch.setattr(matrix_runner, "run_single_engagement", child)
    monkeypatch.setattr(tui_mission, "run_provider_matrix", matrix_runner.run_provider_matrix)
    screen = tui_mission.MissionControlScreen()
    screen.state.run_mode = "matrix"
    events = []

    def record(event):
        events.append(event.as_dict())
        tui_state.apply_run_event(screen.state, event)

    monkeypatch.setattr(screen, "_post_event", record)
    screen._run_blocking(config, "matrix")
    expected = "failed" if outcome == "error" else "cancelled"
    evidence_dir = Path("results/validation/tui-model-matrix-fix-2026-10-10/offline") / f"real-matrix-{outcome}"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "events.json").write_text(json.dumps(events, indent=2))
    (evidence_dir / "children.json").write_text(json.dumps(child_artifacts, indent=2))
    aggregates = list(Path(config.output_dir).rglob("*.matrix.json"))
    assert len(aggregates) == 1
    aggregate = json.loads(aggregates[0].read_text())
    (evidence_dir / "aggregate.json").write_text(json.dumps(aggregate, indent=2))
    assert screen.state.status == expected
    assert aggregate["status"] == outcome
    assert screen.state.execution_id == aggregate["execution_id"]
    assert len(screen.state.coordinates) == len(child_artifacts)
    assert screen.state.completed == len(child_artifacts)
    assert screen.state.total == 2
    assert aggregate["cancellation"]["completed_runs"] == len(child_artifacts)
    assert aggregate["cancellation"]["not_started_runs"] == 2 - len(child_artifacts)
    if outcome == "cancelled":
        assert len(child_artifacts) == 1
    else:
        assert len(child_artifacts) == 2
        assert aggregate['execution_reason']['code'] == 'CHILD_EXECUTION_UNKNOWN'
        assert aggregate['totals']['execution_unknown_runs'] == 2
        assert all(artifact.get('execution_status') is None for artifact in child_artifacts)
