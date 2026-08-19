"""Regression tests for dated experiment artifact directories."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from tesis.artifact_layout import ExperimentArtifactLayout, allocate_artifact_layout
from tesis.artifact_repository import ArtifactRepository
from evaluation.multi_llm_runner import run_provider_matrix


def test_layout_uses_date_and_only_numbers_colliding_same_day(tmp_path: Path) -> None:
    now = datetime(2026, 8, 19, 12, 30)

    first = allocate_artifact_layout(tmp_path, "matrix", now=now)
    single = allocate_artifact_layout(tmp_path, "single-run", now=now)
    second = allocate_artifact_layout(tmp_path, "matrix", now=now)

    assert first.root.name == "matrix-2026-08-19"
    assert single.root.name == "single-run-2026-08-19-2"
    assert second.root.name == "matrix-2026-08-19-3"


def test_matrix_child_name_contains_sequence_and_coordinate(tmp_path: Path) -> None:
    layout = ExperimentArtifactLayout.allocate(tmp_path, "matrix", now=datetime(2026, 8, 19))

    child = layout.child_directory(
        {
            "provider": "openai_compatible",
            "surface": "access_control",
            "security_level": "high",
            "payload_mode": "llm_mutation_only",
        },
        0,
    )

    assert child.name == "run-001-openai_compatible-access_control-high-llm_mutation_only"
    assert child.is_dir()


def test_manifest_indexes_runs_and_repository_skips_manifest(tmp_path: Path) -> None:
    layout = ExperimentArtifactLayout.allocate(tmp_path, "matrix", now=datetime(2026, 8, 19))
    child = layout.child_directory(
        {
            "provider": "gemini",
            "surface": "sqli",
            "security_level": "low",
            "payload_mode": "hybrid",
        },
        0,
    )
    (child / "exec-1.json").write_text(
        json.dumps({"execution_id": "exec-1", "run_id": "run-1", "status": "success"}),
        encoding="utf-8",
    )
    manifest = layout.write_manifest(
        config={"provider": "gemini", "api_key": "secret"},
        artifacts=[{
            "execution_id": "exec-1",
            "run_id": "run-1",
            "status": "success",
            "provider": "gemini",
            "surface": "sqli",
            "security_level": "low",
            "payload_mode": "hybrid",
        }],
        aggregate={
            "execution_id": "matrix-1",
            "run_id": "matrix-run-1",
            "status": "success",
            "totals": {"total_runs": 1},
        },
    )

    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "artifact-manifest.v1"
    assert payload["config"]["api_key"] == "[REDACTED]"
    assert payload["runs"][0]["artifact"] == "run-001-gemini-sqli-low-hybrid/exec-1.json"
    assert payload["aggregate"]["artifact"] == "matrix-1.matrix.json"

    discovered = ArtifactRepository(layout.root).scan()
    assert {item.run_id for item in discovered} == {"run-1"}
    assert all(item.path.name != "experiment.manifest.json" for item in discovered)


def test_matrix_runner_can_route_each_coordinate_to_a_child_directory(monkeypatch, tmp_path: Path) -> None:
    seen: list[Path] = []

    def fake_run(**kwargs):
        seen.append(Path(kwargs["output_dir"]))
        return {
            "execution_id": "exec-child",
            "run_id": "gemini-sqli-low-hybrid-0",
            "status": "success",
            "provider": "gemini",
            "surface": "sqli",
            "security_level": "low",
            "payload_mode": "hybrid",
            "config": {
                "provider": "gemini",
                "surface": "sqli",
                "security_level": "low",
                "payload_mode": "hybrid",
            },
            "report": {"summary": {}, "module_scores": {}},
            "final_state": {},
        }

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", fake_run)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])
    layout = ExperimentArtifactLayout.allocate(tmp_path, "matrix", now=datetime(2026, 8, 19))

    artifacts, _ = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low"],
        surfaces=["sqli"],
        payload_modes=["hybrid"],
        output_dir=str(layout.root),
        run_output_dir_factory=layout.child_directory,
        include_aggregate=True,
    )

    assert len(artifacts) == 1
    assert seen == [layout.root / "run-001-gemini-sqli-low-hybrid"]
