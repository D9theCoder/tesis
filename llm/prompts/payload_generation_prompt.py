"""Prompt builders for AKG-constrained payload candidate generation."""

from __future__ import annotations

import json
from typing import Any


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
    # A deterministic representative seed keeps a reasoning-capable provider
    # inside the fixed output ceiling.  Validation still sees the full local
    # seed list and rejects any generated provenance outside that list.
    compact_seeds = [
        {
            "source_seed_id": seed.get("source_seed_id") or seed.get("candidate_id"),
            "payload_or_logic": seed.get("payload_or_logic"),
            "target_param": seed.get("target_param"),
            "expected_signal": seed.get("expected_signal"),
        }
        for seed in static_seeds[:1]
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
        "Generate exactly one constrained variant. Return only "
        '{"variants":[{"source_seed_id":"seed-id","mutation_type":"allowed-type",'
        '"payload_or_logic":"value"}]}.'
    )
