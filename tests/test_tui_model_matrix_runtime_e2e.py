"""Offline launcher controls; provider and DVWA calls are deliberately replaced."""

import json
from pathlib import Path

import pytest

from tesis import tui_mission, tui_state
from tesis.model_config import EngagementConfig, ModelConfig
from tesis.runtime_events import RunEvent


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
