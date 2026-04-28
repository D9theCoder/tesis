"""Typed configuration models for Stage 7 CLI and runtime wiring."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

EVASION_STRATEGIES: frozenset[str] = frozenset(
    {"pipeline", "prompt_injection", "roleplay"}
)


@dataclass(slots=True)
class ModelConfig:
    provider: str
    api_key: str
    model_name: str
    temperature: float = 0.0
    max_tokens: int | None = None
    timeout: int = 60
    base_url: str | None = None
    system_prompt: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EngagementConfig:
    target_url: str
    provider: str
    level: str
    iterations: int = 30
    repeats: int = 1
    output_dir: str = "results"
    matrix: bool = False
    providers: list[str] = field(default_factory=list)
    levels: list[str] = field(default_factory=list)
    report_format: str = "both"
    enriched_reporting: bool = False
    stop_policy: str = "impact"
    coverage_target: float = 0.70
    diagnose: bool = False
    models: dict[str, ModelConfig] = field(default_factory=dict)

    # Stage 8.1 — Evasion integration
    evasion_enabled: bool = False
    evasion_strategy: str = "pipeline"  # see EVASION_STRATEGIES
    evasion_attempts_max: int = 3


__all__ = ["ModelConfig", "EngagementConfig"]
