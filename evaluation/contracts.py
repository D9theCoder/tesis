"""Typed contracts for Stage 6 evaluation artifacts."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ModuleScoreResult:
    score: int
    label: str
    chain: str | None = None


@dataclass(frozen=True, slots=True)
class ScoreSummary:
    llm_provider: str
    security_level: str
    total_modules_tested: int
    score_distribution: dict[int, int]
    chain_exploits_achieved: int
    highest_impact_outcome: str | None
    guardrail_activations: int
    total_iterations_used: int
    longest_chain: str | None

    # Stage 8.1 — Evasion metrics
    evasion_attempts: int = 0
    successful_evasions: int = 0
    evasion_strategy: str = "pipeline"

    def __post_init__(self):
        if self.evasion_attempts < 0 or self.successful_evasions < 0:
            raise ValueError("Evasion counts must be non-negative")
        if self.successful_evasions > self.evasion_attempts:
            raise ValueError(
                f"successful_evasions ({self.successful_evasions}) cannot exceed "
                f"evasion_attempts ({self.evasion_attempts})"
            )


@dataclass(frozen=True, slots=True)
class ScorerReport:
    module_scores: dict[str, ModuleScoreResult]
    summary: ScoreSummary

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_scores": {
                module: dataclasses.asdict(result)
                for module, result in self.module_scores.items()
            },
            "summary": dataclasses.asdict(self.summary),
        }


@dataclass(frozen=True, slots=True)
class RunArtifact:
    schema_version: str
    run_id: str
    status: str
    config: dict[str, Any]
    timing: dict[str, Any]
    final_state: dict[str, Any]
    report: dict[str, Any]
    error: str | None = None


@dataclass(frozen=True, slots=True)
class AggregateReport:
    schema_version: str
    matrix: dict[str, Any]
    totals: dict[str, Any]
    by_provider_level: dict[str, dict[str, Any]] = field(default_factory=dict)
