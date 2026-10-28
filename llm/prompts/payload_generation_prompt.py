"""Prompt builders for AKG-constrained payload candidate generation."""

from __future__ import annotations

from typing import Any

from core.payload_policy import TEMPLATE_OBSERVATION_ALLOWLIST
from llm.prompts.context import context_json

_EXECUTION_STAGES = {"exploit", "bypass"}


def payload_generation_prompt_seeds(static_seeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the exact compact seed rows the mutation prompt will render.

    Only execution-ready seeds are ever shown; when none exist the prompt shows
    no seed at all and the caller must not call the model.  This is the single
    source of truth for ``prompt_visible_seed_ids`` and copy evidence.
    """
    return [
        {
            "source_seed_id": str(seed.get("source_seed_id") or seed.get("candidate_id")),
            "payload_or_logic": seed.get("payload_or_logic"),
            "stage": seed.get("stage"),
            "target_param": seed.get("target_param"),
            "expected_signal": seed.get("expected_signal"),
        }
        for seed in static_seeds
        if str(seed.get("stage", "")).strip().lower() in _EXECUTION_STAGES
    ]


def _execution_ready_seeds(static_seeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deprecated alias kept for readers of the historical helper name."""
    return payload_generation_prompt_seeds(static_seeds)


def sanitized_template_observations(
    observations: dict[str, Any] | None,
) -> dict[str, bool]:
    """Return only allowlisted, boolean fixture/session observations.

    The allowlist is closed by name and type.  Payload text, raw control
    responses, credentials, prior successes, profile helper fields, and history
    cannot reach a Template prompt through this function.
    """
    if not isinstance(observations, dict):
        return {}
    return {
        key: value
        for key, value in observations.items()
        if key in TEMPLATE_OBSERVATION_ALLOWLIST and isinstance(value, bool)
    }


def build_payload_generation_prompt(
    *,
    method: str,
    security_level: str,
    observations: dict[str, Any],
    static_seeds: list[dict[str, Any]],
    payload_profile: dict[str, Any],
    candidate_budget: int,
) -> str:
    """Build the strict JSON prompt used for hybrid payload generation."""
    applicable_observations = {
        key: value
        for key, value in observations.items()
        if isinstance(value, (bool, int, float, str)) and "credential" not in key.lower()
    }
    # Expose only execution-ready seeds through the single projection helper.
    # The first static seed is often a detection probe, which must not be
    # mutated and then executed as Stage 2; a probe is never rendered.
    compact_seeds = payload_generation_prompt_seeds(static_seeds)
    stable = {
        "method": method,
        "security_level": security_level,
        "allowed_mutation_types": payload_profile.get("allowed_mutation_types", []),
        "forbidden_mutation_types": payload_profile.get("forbidden_mutation_types", []),
        "expected_signals": payload_profile.get("expected_success_signals", []),
        "candidate_budget": candidate_budget,
        "static_seeds": compact_seeds,
    }
    return (
        "Choose an exploit or bypass seed from the context and generate exactly one constrained "
        "Stage 2 variant. Preserve the method, target parameter, and expected success "
        "signal; do not return a probe, baseline, false-only condition, or no-delay "
        "candidate. Return only "
        '{"variants":[{"source_seed_id":"seed-id","mutation_type":"allowed-type",'
        '"payload_or_logic":"value"}]}.\n'
        f"Context: {context_json(stable, {'observations': applicable_observations})}"
    )


def build_template_generation_prompt(
    *,
    template: dict[str, Any],
    observations: dict[str, Any] | None = None,
    candidate_budget: int = 1,
) -> str:
    """Build the closed-allowlist prompt for Template payload construction.

    The prompt exposes only the neutral template, the fixed method/level/
    parameter/expected-signal contract, the authorized bounds, and allowlisted
    boolean fixture/session observations.  It has no parameter for seeds,
    credentials, control results, profiles, history, or prior successes, so a
    working payload cannot enter through this builder.
    """
    feasibility = template.get("feasibility")
    feasibility_row = feasibility if isinstance(feasibility, dict) else {}
    stable = {
        "task": "construct_from_neutral_template",
        "method": template.get("method"),
        "security_level": template.get("security_level"),
        "surface": template.get("surface"),
        "template_id": template.get("template_id"),
        "template_version": template.get("template_version"),
        "template_sha256": template.get("template_sha256"),
        "objective": template.get("objective"),
        "format": template.get("format"),
        "constraints": template.get("constraints"),
        "allowed_parameters": template.get("allowed_parameters"),
        "target_param": template.get("target_param"),
        "expected_signal": template.get("expected_signal"),
        "level_context": template.get("level_context"),
        "feasibility": {
            "status": feasibility_row.get("status"),
            "reason": feasibility_row.get("reason"),
        },
        "candidate_budget": max(0, int(candidate_budget)),
    }
    changing = {"observations": sanitized_template_observations(observations)}
    return (
        "Construct exactly one exploit or bypass candidate from the neutral template in "
        "the context. The template is inert: it is not a payload, so use it as a task "
        "description and never echo its fields as a payload. Emit only the value for the "
        "allowed parameter, in the stated format, for the stated method, security level, "
        "and expected success signal. Do not return a detection probe, a baseline, a "
        "false-only condition, or a no-delay candidate, and do not include URLs, hosts, "
        "credentials you were not given, or anything outside the stated bounds. Return "
        'only {"candidates":[{"payload_or_logic":"value","target_param":"parameter",'
        '"expected_signal":"signal"}]}.\n'
        f"Context: {context_json(stable, changing)}"
    )
