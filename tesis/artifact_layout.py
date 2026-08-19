"""Collision-safe, human-readable experiment artifact layouts.

The evaluation runners continue to support their historical flat ``output_dir``
API.  This module is an opt-in layout layer used by the TUI and headless
terminal runner so old integrations and existing artifacts remain readable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from evaluation.reporter import write_json_report
from tesis.runtime_events import redact_secrets


_MODES = frozenset({"single-run", "matrix"})


def _slug(value: object) -> str:
    """Convert a coordinate value into a short, filename-safe component."""

    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value).strip())
    return text.strip("-._") or "unknown"


def _local_date(now: datetime | None = None) -> str:
    current = now or datetime.now().astimezone()
    if current.tzinfo is None:
        current = current.astimezone()
    return current.date().isoformat()


@dataclass(slots=True)
class ExperimentArtifactLayout:
    """Allocated directory and manifest state for one experiment invocation."""

    root: Path
    mode: str
    created_at: str
    sequence: int | None = None
    _children: list[Path] = field(default_factory=list, repr=False)

    @classmethod
    def allocate(
        cls,
        base_dir: str | Path,
        mode: str,
        *,
        now: datetime | None = None,
    ) -> "ExperimentArtifactLayout":
        """Reserve ``<mode>-YYYY-MM-DD[-N]`` atomically.

        The first experiment of a mode on a day has no suffix.  A numeric
        suffix is added only when that name already exists, which keeps the
        common path short while making repeated same-day runs unambiguous.
        """

        normalized_mode = str(mode).strip().lower()
        if normalized_mode not in _MODES:
            raise ValueError(f"unsupported experiment artifact mode: {mode!r}")
        base = Path(base_dir)
        base.mkdir(parents=True, exist_ok=True)
        date_text = _local_date(now)
        prefix = f"{normalized_mode}-{date_text}"
        # Number experiments globally per day, while retaining the mode in
        # each directory name.  Thus a first matrix and first single run on
        # the same day become ``matrix-DATE`` and ``single-run-DATE-2``.
        day_pattern = re.compile(rf"^(?:single-run|matrix)-{re.escape(date_text)}(?:-(\d+))?$")
        existing_ordinals = {
            int(match.group(1) or 1)
            for item in base.iterdir()
            if item.is_dir()
            for match in [day_pattern.match(item.name)]
            if match is not None
        }
        suffix = max(existing_ordinals, default=0) + 1
        while True:
            name = prefix if suffix == 1 else f"{prefix}-{suffix}"
            candidate = base / name
            try:
                candidate.mkdir()
            except FileExistsError:
                suffix += 1
                continue
            return cls(
                root=candidate,
                mode=normalized_mode,
                created_at=(now or datetime.now().astimezone()).isoformat(),
                sequence=None if suffix == 1 else suffix,
            )

    def child_directory(
        self,
        coordinate: Mapping[str, Any] | None = None,
        index: int = 0,
    ) -> Path:
        """Reserve a matrix child directory named by sequence and coordinate."""

        if self.mode != "matrix":
            raise ValueError("child directories are only available for matrix layouts")
        coordinate = coordinate or {}
        provider = _slug(coordinate.get("provider", "provider"))
        surface = _slug(coordinate.get("surface", "surface"))
        level = _slug(coordinate.get("security_level", "level"))
        payload_mode = _slug(coordinate.get("payload_mode", "payload"))
        name = f"run-{int(index) + 1:03d}-{provider}-{surface}-{level}-{payload_mode}"
        candidate = self.root / name
        candidate.mkdir(parents=False, exist_ok=False)
        self._children.append(candidate)
        return candidate

    @property
    def manifest_path(self) -> Path:
        return self.root / "experiment.manifest.json"

    def write_manifest(
        self,
        *,
        config: Mapping[str, Any] | None = None,
        artifacts: Sequence[Mapping[str, Any]] = (),
        aggregate: Mapping[str, Any] | None = None,
        status: str | None = None,
    ) -> Path:
        """Write a compact index while keeping full evidence in run JSON files."""

        safe_config = redact_secrets(dict(config or {}))
        runs: list[dict[str, Any]] = []
        for index, artifact in enumerate(artifacts):
            artifact_config = artifact.get("config", {})
            if not isinstance(artifact_config, Mapping):
                artifact_config = {}
            child = self._children[index] if index < len(self._children) else self.root
            execution_id = artifact.get("execution_id")
            primary_name = f"{execution_id}.json" if execution_id else None
            runs.append({
                "index": index + 1,
                "directory": str(child.relative_to(self.root)),
                "artifact": str((child / primary_name).relative_to(self.root)) if primary_name else None,
                "execution_id": execution_id,
                "run_id": artifact.get("run_id"),
                "status": artifact.get("status", "unknown"),
                "provider": artifact.get("provider", artifact_config.get("provider")),
                "surface": artifact.get("surface", artifact_config.get("surface")),
                "security_level": artifact.get("security_level", artifact_config.get("security_level")),
                "payload_mode": artifact.get("payload_mode", artifact_config.get("payload_mode")),
                "experiment_condition": artifact.get(
                    "experiment_condition", artifact_config.get("experiment_condition")
                ),
                "target_method": artifact.get("target_method", artifact_config.get("target_method")),
            })

        aggregate_info: dict[str, Any] | None = None
        if aggregate is not None:
            aggregate_execution_id = aggregate.get("execution_id")
            aggregate_info = {
                "artifact": (
                    f"{aggregate_execution_id}.matrix.json"
                    if aggregate_execution_id
                    else None
                ),
                "execution_id": aggregate_execution_id,
                "run_id": aggregate.get("run_id"),
                "status": aggregate.get("status"),
                "totals": aggregate.get("totals", {}),
            }

        payload = {
            "schema_version": "artifact-manifest.v1",
            "artifact_type": "experiment_manifest",
            "mode": self.mode,
            "directory": self.root.name,
            "created_at": self.created_at,
            "status": status or (aggregate or {}).get("status") or (
                artifacts[-1].get("status") if artifacts else "unknown"
            ),
            "config": safe_config,
            "aggregate": aggregate_info,
            "runs": runs,
        }
        return write_json_report(self.manifest_path, payload)


def allocate_artifact_layout(
    output_dir: str | Path,
    mode: str,
    *,
    now: datetime | None = None,
) -> ExperimentArtifactLayout:
    """Allocate an experiment layout below the normal ``results/runs`` root."""

    return ExperimentArtifactLayout.allocate(Path(output_dir) / "runs", mode, now=now)


__all__ = ["ExperimentArtifactLayout", "allocate_artifact_layout"]
