"""Versioned prompt manifests for orchestrator and payload generation.

Each manifest records the current template (system message + fixed user
instruction suffix), builder input schema, output schema hash, validator
version, and eval suite version. Importing this module never changes prompt
text, output, or runtime behavior.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from typing import Any, TypedDict

MANIFEST_VERSION = "1.0.0"
VALIDATOR_VERSION = "validator.v1"
EVAL_SUITE_VERSION = "prompt-eval.v1"

ORCHESTRATOR_PROMPT_ID = "orchestrator.method_selection"
PAYLOAD_PROMPT_ID = "payload_generation.constrained_variant"

Mapping_like = Any  # subscriptable input mapping; kept loose to avoid new deps.


def _sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_hash(payload: Any) -> str:
    return _sha256_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def _instruction_suffix(prompt: str) -> str:
    """Split the fixed instruction suffix off a ``"Context: {...}\\n..."`` prompt."""
    _, sep, suffix = prompt.partition("\n")
    return suffix if sep else prompt


def _input_schema(builder: Any) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for name, param in inspect.signature(builder).parameters.items():
        annotation = param.annotation
        params[name] = {
            "type": getattr(annotation, "__name__", str(annotation)),
            "required": param.default is inspect.Parameter.empty,
            "default": None if param.default is inspect.Parameter.empty else repr(param.default),
        }
    return {"parameters": params}


class OrchestratorPromptInput(TypedDict, total=False):
    """Typed builder input for orchestrator method selection."""

    current_surface: str
    viable_methods: list[str]
    observations: dict[str, bool]
    attempted_agents: list[str]
    blocked_agents: list[str]
    failure_agents: list[str]
    scores: dict[str, int]
    method_scores: dict[str, int] | None
    confirmed_vulns: list[str]
    achieved_outcomes: list[str]
    security_level: str
    payload_mode: str
    iteration_count: int
    max_iterations: int


class PayloadPromptInput(TypedDict, total=False):
    """Typed builder input for constrained payload generation."""

    method: str
    security_level: str
    observations: dict[str, Any]
    static_seeds: list[dict]
    payload_profile: dict
    candidate_budget: int


def _require(mapping: Mapping_like, key: str) -> Any:
    try:
        return mapping[key]
    except (TypeError, KeyError):
        raise KeyError(f"missing required prompt input: {key!r}") from None


def _bounded_int(value: Any, *, minimum: int = 0) -> int:
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        number = minimum
    return max(minimum, number)


def build_orchestrator_prompt_typed(inputs: OrchestratorPromptInput) -> str:
    """Typed, bounded wrapper around :func:`build_orchestrator_prompt`.

    Delegates to the canonical builder, so valid inputs render byte-identical
    prompts. Out-of-range budgets are clamped instead of raising.
    """
    from llm.prompts.orchestrator_prompt import build_orchestrator_prompt

    return build_orchestrator_prompt(
        current_surface=str(_require(inputs, "current_surface")),
        viable_methods=list(_require(inputs, "viable_methods")),
        observations=dict(_require(inputs, "observations")),
        attempted_agents=list(inputs.get("attempted_agents", [])),
        blocked_agents=list(inputs.get("blocked_agents", [])),
        failure_agents=list(inputs.get("failure_agents", [])),
        scores=dict(inputs.get("scores", {})),
        method_scores=inputs.get("method_scores"),
        confirmed_vulns=list(_require(inputs, "confirmed_vulns")),
        achieved_outcomes=list(_require(inputs, "achieved_outcomes")),
        security_level=str(inputs.get("security_level", "low")),
        payload_mode=str(inputs.get("payload_mode", "static_only")),
        iteration_count=_bounded_int(inputs.get("iteration_count", 0)),
        max_iterations=_bounded_int(inputs.get("max_iterations", 0)),
    )


def build_payload_generation_prompt_typed(inputs: PayloadPromptInput) -> str:
    """Typed, bounded wrapper around :func:`build_payload_generation_prompt`."""
    from llm.prompts.payload_generation_prompt import build_payload_generation_prompt

    return build_payload_generation_prompt(
        method=str(_require(inputs, "method")),
        security_level=str(inputs.get("security_level", "low")),
        observations=dict(inputs.get("observations", {})),
        static_seeds=list(_require(inputs, "static_seeds")),
        payload_profile=dict(_require(inputs, "payload_profile")),
        candidate_budget=_bounded_int(inputs.get("candidate_budget", 1)),
    )


def _manifest(prompt_id: str, parts: dict[str, Any]) -> dict[str, Any]:
    input_schema = _input_schema(parts["builder"])
    return {
        "prompt_id": prompt_id,
        "version": MANIFEST_VERSION,
        "template_hash": _sha256_text(
            parts["system_message"] + "\n\n" + parts["instruction_suffix"]
        ),
        "input_schema": input_schema,
        "input_schema_hash": _canonical_hash(input_schema),
        "output_schema_hash": _canonical_hash(parts["output_schema"]),
        "output_schema_version": parts["output_schema_version"],
        "validator_version": VALIDATOR_VERSION,
        "validator_hash": _sha256_text(parts["validator_source"]),
        "eval_suite_version": EVAL_SUITE_VERSION,
    }


def _orchestrator_parts() -> dict[str, Any]:
    from agents.orchestrator import (
        _ORCHESTRATOR_SCHEMA,
        _ORCHESTRATOR_SYSTEM_MESSAGE,
        _validate_decision_payload,
    )
    from llm.prompts.orchestrator_prompt import build_orchestrator_prompt
    from llm.runtime import ORCHESTRATOR_SCHEMA_VERSION

    exemplar = build_orchestrator_prompt(
        current_surface="sqli",
        viable_methods=["sqli_union"],
        observations={"sqli_endpoint_present": True},
        attempted_agents=[],
        blocked_agents=[],
        failure_agents=[],
        scores={},
        confirmed_vulns=[],
        achieved_outcomes=[],
        security_level="low",
        payload_mode="static_only",
        iteration_count=0,
        max_iterations=5,
    )
    return {
        "builder": build_orchestrator_prompt,
        "system_message": _ORCHESTRATOR_SYSTEM_MESSAGE,
        "instruction_suffix": _instruction_suffix(exemplar),
        "output_schema": _ORCHESTRATOR_SCHEMA,
        "output_schema_version": ORCHESTRATOR_SCHEMA_VERSION,
        "validator_source": inspect.getsource(_validate_decision_payload),
    }


def _payload_parts() -> dict[str, Any]:
    from foundation.payload_generator import (
        _PAYLOAD_SCHEMA,
        _PAYLOAD_SYSTEM_MESSAGE,
        _validate_variants_payload,
    )
    from llm.prompts.payload_generation_prompt import build_payload_generation_prompt
    from llm.runtime import PAYLOAD_SCHEMA_VERSION

    exemplar = build_payload_generation_prompt(
        method="sqli_union",
        security_level="low",
        observations={"sqli_endpoint_present": True},
        static_seeds=[{
            "source_seed_id": "seed-1",
            "payload_or_logic": "seed",
            "stage": "exploit",
            "target_param": "id",
            "expected_signal": "rows",
        }],
        payload_profile={
            "allowed_mutation_types": ["case_variant"],
            "forbidden_mutation_types": ["external_target"],
            "expected_success_signals": ["rows"],
        },
        candidate_budget=1,
    )
    return {
        "builder": build_payload_generation_prompt,
        "system_message": _PAYLOAD_SYSTEM_MESSAGE,
        "instruction_suffix": _instruction_suffix(exemplar),
        "output_schema": _PAYLOAD_SCHEMA,
        "output_schema_version": PAYLOAD_SCHEMA_VERSION,
        "validator_source": inspect.getsource(_validate_variants_payload),
    }


ORCHESTRATOR_MANIFEST: dict[str, Any] = _manifest(ORCHESTRATOR_PROMPT_ID, _orchestrator_parts())
PAYLOAD_MANIFEST: dict[str, Any] = _manifest(PAYLOAD_PROMPT_ID, _payload_parts())

PROMPT_MANIFESTS: dict[str, dict[str, Any]] = {
    ORCHESTRATOR_PROMPT_ID: ORCHESTRATOR_MANIFEST,
    PAYLOAD_PROMPT_ID: PAYLOAD_MANIFEST,
}


__all__ = [
    "EVAL_SUITE_VERSION",
    "MANIFEST_VERSION",
    "ORCHESTRATOR_MANIFEST",
    "ORCHESTRATOR_PROMPT_ID",
    "PAYLOAD_MANIFEST",
    "PAYLOAD_PROMPT_ID",
    "PROMPT_MANIFESTS",
    "VALIDATOR_VERSION",
    "OrchestratorPromptInput",
    "PayloadPromptInput",
    "build_orchestrator_prompt_typed",
    "build_payload_generation_prompt_typed",
]
