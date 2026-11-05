"""Regression tests for dated experiment artifact directories."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from tesis.artifact_layout import allocate_artifact_layout


def test_layout_uses_date_and_only_numbers_colliding_same_day(tmp_path: Path) -> None:
    now = datetime(2026, 8, 19, 12, 30)

    first = allocate_artifact_layout(tmp_path, "matrix", now=now)
    single = allocate_artifact_layout(tmp_path, "single-run", now=now)
    second = allocate_artifact_layout(tmp_path, "matrix", now=now)

    assert first.root.name == "matrix-2026-08-19"
    assert single.root.name == "single-run-2026-08-19-2"
    assert second.root.name == "matrix-2026-08-19-3"


def test_manifest_aggregate_reference_is_relative_to_layout_root(tmp_path: Path) -> None:
    layout = allocate_artifact_layout(tmp_path, "matrix", now=datetime(2026, 8, 19, 12, 30))
    block = layout.root / "selection"
    block.mkdir()
    aggregate = block / "epoch-selection.matrix.json"
    aggregate.write_text(
        json.dumps({"execution_id": "epoch-selection", "status": "completed"}),
        encoding="utf-8",
    )

    manifest_path = layout.write_manifest(
        aggregate={"execution_id": "epoch-selection", "status": "completed"},
        aggregate_artifact=aggregate,
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["aggregate"]["artifact"] == "selection/epoch-selection.matrix.json"
    assert manifest["aggregate"]["execution_id"] == "epoch-selection"
    assert (manifest_path.parent / manifest["aggregate"]["artifact"]).resolve() == aggregate.resolve()


def test_manifest_default_aggregate_stays_at_layout_root(tmp_path: Path) -> None:
    layout = allocate_artifact_layout(tmp_path, "matrix", now=datetime(2026, 8, 19, 12, 30))

    manifest_path = layout.write_manifest(
        aggregate={"execution_id": "epoch-matrix", "status": "completed"},
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["aggregate"]["artifact"] == "epoch-matrix.matrix.json"


def test_manifest_rejects_aggregate_outside_layout_root(tmp_path: Path) -> None:
    layout = allocate_artifact_layout(tmp_path, "matrix", now=datetime(2026, 8, 19, 12, 30))
    outside = tmp_path / "outside.matrix.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="outside the layout root"):
        layout.write_manifest(
            aggregate={"execution_id": "epoch-selection", "status": "completed"},
            aggregate_artifact=outside,
        )


def test_manifest_rejects_missing_explicit_aggregate(tmp_path: Path) -> None:
    layout = allocate_artifact_layout(tmp_path, "matrix", now=datetime(2026, 8, 19, 12, 30))

    with pytest.raises(ValueError, match="does not exist under the layout root"):
        layout.write_manifest(
            aggregate={"execution_id": "epoch-selection", "status": "completed"},
            aggregate_artifact="selection/epoch-selection.matrix.json",
        )
