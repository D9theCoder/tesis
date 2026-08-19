"""Payload candidate builder for static-only and hybrid modes."""

from __future__ import annotations

import json
import logging
import hashlib
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from core.knowledge_graph import AttackKnowledgeGraph
from foundation.payload_library import PayloadLibrary
from llm.guardrail_monitor import is_guardrail_refusal, make_guardrail_event
from llm.prompts.payload_generation_prompt import build_payload_generation_prompt
from llm.provider import get_llm
from llm.runtime import (
    LLMOutputError,
    PAYLOAD_SCHEMA_VERSION,
    current_call_context,
)

logger = logging.getLogger(__name__)

_VALID_MODES = {"static_only", "hybrid", "llm_mutation_only"}
# Payload mutation is a structured JSON response.  Keep its streamed model
# call bounded even when a provider configuration leaves max_tokens unset;
# malformed or truncated output is handled by the existing static-seed
# fallback and is recorded in the artifact.
_DEFAULT_MUTATION_MAX_TOKENS = 256
_PAYLOAD_SYSTEM_MESSAGE = (
    "You generate constrained payload variants only for an authorized DVWA sandbox. "
    "Stay within the selected method, preserve seed provenance, never introduce external "
    f"targets, and follow JSON schema {PAYLOAD_SCHEMA_VERSION}."
)
_PAYLOAD_SCHEMA = {
    "title": "dvwa_payload_variants",
    "description": "Constrained variants of supplied DVWA payload seeds.",
    "type": "object",
    "properties": {
        "variants": {
            "type": "array",
            "maxItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "source_seed_id": {"type": "string"},
                    "mutation_type": {"type": "string"},
                    "payload_or_logic": {"type": "string"},
                },
                "required": ["source_seed_id", "mutation_type", "payload_or_logic"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["variants"],
    "additionalProperties": False,
}


def _extract_text(raw_content: Any) -> str:
    if isinstance(raw_content, str):
        return raw_content
    if isinstance(raw_content, list):
        parts = []
        for item in raw_content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        if parts:
            return "\n".join(parts)
    return str(raw_content)


def _validate_variants_payload(
    payload: dict[str, Any],
    *,
    seeds: list[dict],
    profile: dict[str, Any],
) -> dict[str, Any]:
    rows = payload.get("variants", payload.get("candidates"))
    if not isinstance(rows, list) or not rows:
        raise ValueError("variants must be a non-empty list")
    seed_ids = {
        str(seed.get("source_seed_id") or seed.get("candidate_id"))
        for seed in seeds
    }
    allowed = set(str(value) for value in profile.get("allowed_mutation_types", []))
    normalized: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("each variant must be an object")
        source_seed_id = str(row.get("source_seed_id") or "")
        mutation_type = str(row.get("mutation_type") or "")
        payload_or_logic = row.get("payload_or_logic")
        if source_seed_id not in seed_ids:
            raise ValueError("variant references an unknown source seed")
        if mutation_type not in allowed:
            raise ValueError("variant uses a disallowed mutation type")
        if not isinstance(payload_or_logic, str) or not payload_or_logic:
            raise ValueError("variant payload_or_logic must be a non-empty string")
        normalized.append({
            "source_seed_id": source_seed_id,
            "mutation_type": mutation_type,
            "payload_or_logic": payload_or_logic,
        })
    return {"variants": normalized}


def _parse_candidates(
    raw_text: str,
    method: str,
    *,
    seeds: list[dict] | None = None,
    profile: dict[str, Any] | None = None,
) -> tuple[list[dict], str]:
    """Parse generated candidates and retain a machine-auditable parse status."""
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start == -1 or end <= start:
            return [], "invalid_json"
        try:
            payload = json.loads(raw_text[start : end + 1])
        except json.JSONDecodeError:
            return [], "invalid_json"
    if not isinstance(payload, dict):
        return [], "invalid_schema"
    rows = payload.get("variants", payload.get("candidates"))
    if not isinstance(rows, list):
        return [], "invalid_schema"
    candidates = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        candidate = dict(row)
        seed = next(
            (
                item for item in (seeds or [])
                if str(item.get("source_seed_id") or item.get("candidate_id"))
                == str(candidate.get("source_seed_id") or "")
            ),
            {},
        )
        digest_src = json.dumps(
            {
                "index": index,
                "method": method,
                "payload_or_logic": candidate.get("payload_or_logic", ""),
                "source_seed_id": candidate.get("source_seed_id", ""),
                "target_param": candidate.get("target_param", ""),
                "expected_signal": candidate.get("expected_signal", ""),
                "mutation_type": candidate.get("mutation_type", ""),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha1(digest_src.encode("utf-8")).hexdigest()[:8]
        candidate.setdefault("candidate_id", f"{method}_llm_{index}_{digest}")
        candidate.setdefault("mutation_type", "llm_variant")
        candidate.setdefault("source", "llm_generated")
        candidate.setdefault("method", method)
        candidate.setdefault("stage", "exploit")
        candidate["target_param"] = seed.get("target_param") or candidate.get("target_param")
        candidate["expected_signal"] = seed.get("expected_signal") or candidate.get("expected_signal")
        candidate.setdefault("rationale", "constrained model mutation")
        candidates.append(candidate)
    if not rows:
        return [], "empty_candidates"
    return candidates, "ok" if candidates else "invalid_schema"


def _build_llm(provider_name: str, model_config: dict[str, Any]):
    if model_config:
        kwargs = {k: v for k, v in model_config.items() if k != "provider"}
        extra = kwargs.pop("extra", {})
        if isinstance(extra, dict):
            kwargs.update(extra)
        if kwargs.get("max_tokens") is None:
            kwargs["max_tokens"] = _DEFAULT_MUTATION_MAX_TOKENS
        return get_llm(provider_name, **kwargs)
    return get_llm(provider_name, max_tokens=_DEFAULT_MUTATION_MAX_TOKENS)


def generate_llm_variants(
    *,
    state: dict[str, Any],
    method: str,
    seeds: list[dict],
    profile: dict[str, Any],
    budget: int,
) -> tuple[list[dict], dict[str, Any] | None, list[dict]]:
    """Generates constrained LLM payload variants from AKG-linked seed candidates."""
    # Keep the provider request deliberately small.  ``budget`` remains the
    # execution candidate budget, while one model-produced variant is enough
    # to exercise constrained mutation; static seeds still supply coverage.
    model_budget = min(1, budget)
    prompt = build_payload_generation_prompt(
        method=method,
        security_level=str(state.get("security_level", "low")),
        observations=dict(state.get("observations", {})),
        static_seeds=seeds,
        payload_profile=profile,
        candidate_budget=model_budget,
    )
    prompt_event = {
        "method": method,
        "provider": state.get("llm_provider", "gemini"),
        "prompt": prompt,
        "candidate_budget": budget,
        "model_candidate_budget": model_budget,
    }
    try:
        context = current_call_context()
        if context is not None:
            max_tokens = min(512, 96 + 64 * budget)
            result = context.runtime.invoke(
                context=context,
                role="payload_generator",
                system_message=_PAYLOAD_SYSTEM_MESSAGE,
                user_message=prompt,
                schema=_PAYLOAD_SCHEMA,
                schema_version=PAYLOAD_SCHEMA_VERSION,
                validator=lambda value: _validate_variants_payload(
                    value, seeds=seeds, profile=profile
                ),
                max_tokens=max_tokens,
            )
            text = result.text
            parsed_payload = result.parsed
            prompt_event["performance"] = result.performance
        else:
            llm = _build_llm(str(state.get("llm_provider", "gemini")), dict(state.get("model_config", {})))
            response = llm.invoke([
                SystemMessage(content=_PAYLOAD_SYSTEM_MESSAGE),
                HumanMessage(content=prompt),
            ])
            text = _extract_text(getattr(response, "content", ""))
            parsed_payload = None
    except LLMOutputError as exc:
        text = exc.text
        prompt_event["performance"] = exc.performance
        prompt_event["response"] = text
        if is_guardrail_refusal(text):
            prompt_event["fallback_reason"] = "guardrail_refusal"
            return [], prompt_event, [make_guardrail_event(
                provider=str(state.get("llm_provider", "gemini")),
                context="payload_generation",
                response=text,
            )]
        runtime_status = str(exc.performance.get("parse_status") or "invalid")
        parse_status = "incomplete_response" if runtime_status == "incomplete" else "invalid_json"
        prompt_event["parse_status"] = parse_status
        prompt_event["fallback_reason"] = parse_status
        return [], prompt_event, []
    except Exception as exc:
        logger.warning("Payload generation failed; falling back to static seeds: %s", exc)
        prompt_event["error"] = f"{type(exc).__name__}: {exc}"
        prompt_event["fallback_reason"] = "llm_error"
        return [], prompt_event, []

    prompt_event["response"] = text
    if is_guardrail_refusal(text):
        prompt_event["fallback_reason"] = "guardrail_refusal"
        return [], prompt_event, [
            make_guardrail_event(
                provider=str(state.get("llm_provider", "gemini")),
                context="payload_generation",
                response=text,
            )
        ]
    if parsed_payload is not None:
        text = json.dumps(parsed_payload, sort_keys=True, separators=(",", ":"))
    candidates, parse_status = _parse_candidates(
        text, method, seeds=seeds, profile=profile
    )
    prompt_event["parse_status"] = parse_status
    if parse_status != "ok":
        prompt_event["fallback_reason"] = parse_status
    return candidates[:budget], prompt_event, []


def build_payload_candidates(state: dict[str, Any]) -> dict[str, Any]:
    """Builds static and optional generated payload candidates for one method."""
    method = str(state.get("selected_method") or state.get("next_agent") or "")
    if not method:
        return {"payload_candidates": {}}

    kg = AttackKnowledgeGraph()
    profile = kg.get_payload_profile(method)
    level = str(state.get("security_level", "low"))
    mode = str(state.get("payload_mode", "static_only")).strip().lower()
    if mode not in _VALID_MODES:
        mode = "static_only"

    seed_candidates = PayloadLibrary().load_seed_candidates(method, level)
    budget = min(int(state.get("candidate_budget", 5) or 5), int(profile.get("max_generated_candidates", 5) or 5))

    generated: list[dict] = []
    prompt_event: dict[str, Any] | None = None
    guardrails: list[dict] = []
    invalid_json_events: list[dict] = []
    fallback_events: list[dict] = []
    if mode in {"hybrid", "llm_mutation_only"}:
        generated, prompt_event, guardrails = generate_llm_variants(
            state=state,
            method=method,
            seeds=seed_candidates,
            profile=profile,
            budget=budget,
        )

    if prompt_event and not generated:
        fallback_reason = str(prompt_event.get("fallback_reason") or "empty_candidates")
        fallback_events.append({
            "event": "payload_generation.static_seed_fallback",
            "method": method,
            "payload_mode": mode,
            "reason": fallback_reason,
        })
        if fallback_reason == "invalid_json":
            invalid_json_events.append({
                "event": "payload_generation.invalid_json",
                "method": method,
                "provider": state.get("llm_provider", "gemini"),
            })

    # `llm_mutation_only` is a preferred generation mode, not permission to
    # execute an unvalidated empty workflow.  A provider failure, refusal, or
    # malformed response uses the documented deterministic static-seed fallback
    # and records it in the run artifact.
    candidates = (
        generated or seed_candidates
        if mode == "llm_mutation_only"
        else [*seed_candidates, *generated]
    )
    return {
        "payload_candidates": {method: candidates},
        "generated_payloads": {method: generated},
        "generation_prompts": [prompt_event] if prompt_event else [],
        "payload_guardrail_activations": guardrails,
        "guardrail_activations": guardrails,
        "invalid_json_events": invalid_json_events,
        "fallback_events": fallback_events,
        "payload_provenance": {
            str(candidate["candidate_id"]): {
                "source": candidate.get("source", "llm_generated"),
                "source_seed_id": candidate.get("source_seed_id"),
                "mutation_type": candidate.get("mutation_type"),
                "method": method,
                "target_param": candidate.get("target_param"),
                "expected_signal": candidate.get("expected_signal"),
            }
            for candidate in candidates
            if candidate.get("candidate_id")
        },
    }


def payload_candidate_builder_node(state: dict[str, Any]) -> dict[str, Any]:
    """Executes payload candidate construction in the LangGraph workflow.

    Reads:
        Selected method, payload mode, LLM provider, model config, AKG payload
        profile, and candidate budget fields.

    Writes:
        Payload candidates, generated payloads, prompt artifacts, provenance, and
        guardrail activation records.

    Side Effects:
        May call an LLM provider when payload mode allows generated candidates.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update with candidate and provenance fields."""
    return build_payload_candidates(state)
