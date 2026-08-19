"""Typed configuration models for Stage 7 CLI and runtime wiring."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

EVASION_MODES: frozenset[str] = frozenset({"reactive", "proactive", "disabled"})
PAYLOAD_MODES: frozenset[str] = frozenset({"static_only", "hybrid", "llm_mutation_only"})
LLM_CACHE_SCOPES: frozenset[str] = frozenset({"none", "run"})
STRUCTURED_OUTPUT_MODES: frozenset[str] = frozenset({"auto", "native", "json_prompt"})
LLM_RUNTIME_ROLES: tuple[str, ...] = ("orchestrator", "payload_generator")

# Backward-compatible alias
EVASION_STRATEGIES = EVASION_MODES


@dataclass(slots=True)
class ModelConfig:
    """Model provider configuration resolved from CLI and config files."""
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
class RoleConfig:
    """Role-specific LLM settings layered over a provider model profile.

    ``model_profile`` is a key in :attr:`EngagementConfig.models`.  Leaving it
    unset makes the runtime use the engagement's primary provider profile.
    Provider credentials and endpoint settings intentionally stay in
    :class:`ModelConfig`; keeping them out of this object prevents role
    overrides from duplicating secrets in configuration and artifacts.
    """

    model_profile: str | None = None
    model_name: str | None = None
    temperature: float = 0.0
    max_tokens: int | None = None
    structured_output: str = "auto"


# More explicit name for callers that do not use the shorter role terminology.
LLMRoleConfig = RoleConfig


@dataclass(slots=True)
class LLMRuntimeConfig:
    """Execution controls for the matrix-scoped LLM runtime.

    Legacy configuration files resolve to ``max_concurrency=1`` and
    ``cache_scope='none'``.  ``roles`` contains only role-level decoding and
    profile overrides; provider credentials remain in ``models``.
    """

    max_concurrency: int = 1
    cache_scope: str = "none"
    roles: dict[str, RoleConfig] = field(default_factory=dict)

    @property
    def cache_enabled(self) -> bool:
        """Whether successful responses may be reused within one run."""

        return self.cache_scope == "run"


@dataclass(slots=True)
class EngagementConfig:
    """Target and execution configuration for one DVWA engagement."""
    target_url: str
    provider: str
    level: str
    surface: str = "sqli"
    payload_mode: str = "static_only"
    experiment_condition: str = "linear_hybrid"
    target_method: str | None = None
    log_verbosity: str = "info"
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

    # LLM-only acceleration controls.  Placed after the historical fields so
    # existing positional EngagementConfig callers retain their ordering.
    llm_runtime: LLMRuntimeConfig = field(default_factory=LLMRuntimeConfig)

    @property
    def llm_max_concurrency(self) -> int:
        """Compatibility accessor used by execution runners."""

        return self.llm_runtime.max_concurrency

    @property
    def llm_cache(self) -> bool:
        """Compatibility accessor for the boolean CLI/cache contract."""

        return self.llm_runtime.cache_enabled

    @property
    def role_configs(self) -> dict[str, RoleConfig]:
        """Return the resolved role settings without exposing provider keys."""

        return self.llm_runtime.roles


__all__ = [
    "EngagementConfig",
    "LLMRoleConfig",
    "LLMRuntimeConfig",
    "LLM_CACHE_SCOPES",
    "LLM_RUNTIME_ROLES",
    "ModelConfig",
    "PAYLOAD_MODES",
    "RoleConfig",
    "STRUCTURED_OUTPUT_MODES",
]
