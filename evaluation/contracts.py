"""Typed contracts for Stage 6 evaluation artifacts."""

from __future__ import annotations

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


@dataclass(frozen=True, slots=True)
class ScorerReport:
    module_scores: dict[str, ModuleScoreResult]
    summary: ScoreSummary

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_scores": {
                module: {
                    "score": result.score,
                    "label": result.label,
                    "chain": result.chain,
                }
                for module, result in self.module_scores.items()
            },
            "summary": {
                "llm_provider": self.summary.llm_provider,
                "security_level": self.summary.security_level,
                "total_modules_tested": self.summary.total_modules_tested,
                "score_distribution": dict(self.summary.score_distribution),
                "chain_exploits_achieved": self.summary.chain_exploits_achieved,
                "highest_impact_outcome": self.summary.highest_impact_outcome,
                "guardrail_activations": self.summary.guardrail_activations,
                "total_iterations_used": self.summary.total_iterations_used,
                "longest_chain": self.summary.longest_chain,
            },
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
