"""Prompt builders for AKG-constrained payload candidate generation."""

from __future__ import annotations

import json
from typing import Any


_EXECUTION_STAGES = {"exploit", "bypass"}


def _execution_ready_seeds(static_seeds: list[dict]) -> list[dict]:
    """Prefer exploit-ready seeds over detection-only probes for mutation."""
    execution_seeds = [
        seed
        for seed in static_seeds
        if str(seed.get("stage", "")).strip().lower() in _EXECUTION_STAGES
    ]
    return execution_seeds or static_seeds[:1]


def build_payload_generation_prompt(
    *,
    method: str,
    security_level: str,
    observations: dict[str, Any],
    static_seeds: list[dict],
    payload_profile: dict,
    candidate_budget: int,
) -> str:
    """Build the strict JSON prompt used for hybrid payload generation."""
    applicable_observations = {
        key: value
        for key, value in observations.items()
        if isinstance(value, (bool, int, float, str)) and "credential" not in key.lower()
    }
    # Expose only execution-ready seeds. The first static seed is often a
    # detection probe, which must not be mutated and then executed as Stage 2.
    # Validation still sees the full local seed list and rejects any generated
    # provenance outside that list.
    generation_seeds = _execution_ready_seeds(static_seeds)
    compact_seeds = [
        {
            "source_seed_id": seed.get("source_seed_id") or seed.get("candidate_id"),
            "payload_or_logic": seed.get("payload_or_logic"),
            "stage": seed.get("stage"),
            "target_param": seed.get("target_param"),
            "expected_signal": seed.get("expected_signal"),
        }
        for seed in generation_seeds
    ]
    capsule = {
        "method": method,
        "security_level": security_level,
        "observations": applicable_observations,
        "static_seeds": compact_seeds,
        "allowed_mutation_types": payload_profile.get("allowed_mutation_types", []),
        "forbidden_mutation_types": payload_profile.get("forbidden_mutation_types", []),
        "expected_signals": payload_profile.get("expected_success_signals", []),
        "candidate_budget": candidate_budget,
    }
    return (
        f"Context: {json.dumps(capsule, sort_keys=True, separators=(',', ':'))}\n"
        "Choose an exploit or bypass seed above and generate exactly one constrained "
        "Stage 2 variant. Preserve the method, target parameter, and expected success "
        "signal; do not return a probe, baseline, false-only condition, or no-delay "
        "candidate. Return only "
        '{"variants":[{"source_seed_id":"seed-id","mutation_type":"allowed-type",'
        '"payload_or_logic":"value"}]}.'
    )
