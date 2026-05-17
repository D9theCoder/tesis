"""Typed configuration models for Stage 7 CLI and runtime wiring."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

EVASION_MODES: frozenset[str] = frozenset({"reactive", "proactive", "disabled"})
PAYLOAD_MODES: frozenset[str] = frozenset({"static_only", "hybrid", "llm_mutation_only"})

# Backward-compatible alias
EVASION_STRATEGIES = EVASION_MODES


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
    surface: str = "sqli"
    payload_mode: str = "static_only"
    candidate_budget: int = 5
    iterations: int = 30
    repeats: int = 1
    output_dir: str = "results"
    matrix: bool = False
    providers: list[str] = field(default_factory=list)
    levels: list[str] = field(default_factory=list)
    surfaces: list[str] = field(default_factory=list)
    payload_modes: list[str] = field(default_factory=list)
    report_format: str = "both"
    enriched_reporting: bool = False
    stop_policy: str = "impact"
    coverage_target: float = 0.70
    diagnose: bool = False
    models: dict[str, ModelConfig] = field(default_factory=dict)

    # Stage 8.1 — Evasion integration (refactored to mode-based)
    evasion_enabled: bool = False
    evasion_mode: str = "reactive"  # see EVASION_MODES
    evasion_max_retries: int = 3
    evasion_cooldown_threshold: int = 5

    # Legacy fields preserved for backward compatibility
    evasion_strategy: str = "reactive"
    evasion_attempts_max: int = 3


__all__ = ["ModelConfig", "EngagementConfig", "PAYLOAD_MODES"]
