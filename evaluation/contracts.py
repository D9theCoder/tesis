"""Typed contracts for Stage 6 evaluation artifacts."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ModuleScoreResult:
    """Score contract for one evaluated module or vulnerability surface."""
    score: int
    label: str
    chain: str | None = None


@dataclass(frozen=True, slots=True)
class ScoreSummary:
    """Aggregated score summary emitted by the Evaluation Layer."""
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

    # Stage 6 — Method selection & adaptation metrics (computed by scorer)
    method_selection_accuracy: float = 0.0
    adaptation_rate: float = 0.0
    mean_attempts_to_success: float = 0.0
    payload_validity_rate: float = 0.0
    payload_execution_success_rate: float = 0.0
    payload_improvement_rate: float = 0.0
    guardrail_activation_rate: float = 0.0
    payload_guardrail_activations: int = 0
    consistency_score: float = 0.0
    token_cost: float = 0.0
    token_cost_per_success: float = 0.0

    # Thesis §7.1 — output quality & composite run score
    output_validity_score: float = 0.0
    composite_score: float = 0.0
    invalid_json_rate: float = 0.0
    fallback_rate: float = 0.0

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
    """Structured report containing per-run evaluation scores and metadata."""
    module_scores: dict[str, ModuleScoreResult]
    summary: ScoreSummary

    def to_dict(self) -> dict[str, Any]:
        """Handles to dict behavior for this module."""
        return {
            "module_scores": {
                module: dataclasses.asdict(result)
                for module, result in self.module_scores.items()
            },
            "summary": dataclasses.asdict(self.summary),
        }


@dataclass(frozen=True, slots=True)
class RunArtifact:
    """Serializable artifact produced by one framework run."""
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
    """Aggregate report across multiple framework runs or model configurations."""
    schema_version: str
    matrix: dict[str, Any]
    totals: dict[str, Any]
    by_provider_level: dict[str, dict[str, Any]] = field(default_factory=dict)
