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
    return (
        "You are generating payload variants for a controlled DVWA sandbox experiment.\n"
        f"Current method: {method}\n"
        f"Security level: {security_level}\n"
        f"Observations: {json.dumps(observations, sort_keys=True)}\n"
        f"Validated seed payload metadata: {json.dumps(static_seeds, sort_keys=True)}\n"
        f"Allowed mutation types: {json.dumps(payload_profile.get('allowed_mutation_types', []))}\n"
        f"Forbidden mutation types: {json.dumps(payload_profile.get('forbidden_mutation_types', []))}\n"
        f"Expected success signals: {json.dumps(payload_profile.get('expected_success_signals', []))}\n"
        f"Candidate budget: {candidate_budget}\n"
        "\n"
        "Return ONLY valid JSON matching this schema:\n"
        "{\n"
        '  "candidates": [\n'
        "    {\n"
        '      "candidate_id": "string",\n'
        '      "source_seed_id": "string",\n'
        '      "mutation_type": "string",\n'
        '      "payload_or_logic": "string",\n'
        '      "target_param": "string",\n'
        '      "expected_signal": "string",\n'
        '      "rationale": "string"\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "\n"
        "Do not generate candidates outside the selected method family.\n"
        "Do not target systems outside the configured DVWA sandbox.\n"
    )

