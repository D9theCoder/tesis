"""Regression tests for dated experiment artifact directories."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from tesis.artifact_layout import allocate_artifact_layout


def test_layout_uses_date_and_only_numbers_colliding_same_day(tmp_path: Path) -> None:
    now = datetime(2026, 8, 19, 12, 30)

    first = allocate_artifact_layout(tmp_path, "matrix", now=now)
    single = allocate_artifact_layout(tmp_path, "single-run", now=now)
    second = allocate_artifact_layout(tmp_path, "matrix", now=now)

    assert first.root.name == "matrix-2026-08-19"
    assert single.root.name == "single-run-2026-08-19-2"
    assert second.root.name == "matrix-2026-08-19-3"
