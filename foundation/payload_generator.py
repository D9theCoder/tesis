"""Payload candidate builder for static-only and hybrid modes."""

from __future__ import annotations

import json
import logging
import hashlib
from typing import Any

from langchain_core.messages import HumanMessage

from core.knowledge_graph import AttackKnowledgeGraph
from foundation.payload_library import PayloadLibrary
from llm.guardrail_monitor import is_guardrail_refusal, make_guardrail_event
from llm.prompts.payload_generation_prompt import build_payload_generation_prompt
from llm.provider import get_llm

logger = logging.getLogger(__name__)

_VALID_MODES = {"static_only", "hybrid", "llm_mutation_only"}


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


def _parse_candidates(raw_text: str, method: str) -> tuple[list[dict], str]:
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
    rows = payload.get("candidates")
    if not isinstance(rows, list):
        return [], "invalid_schema"
    candidates = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        candidate = dict(row)
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
        return get_llm(provider_name, **kwargs)
    return get_llm(provider_name)


def generate_llm_variants(
    *,
    state: dict[str, Any],
    method: str,
    seeds: list[dict],
    profile: dict[str, Any],
    budget: int,
) -> tuple[list[dict], dict[str, Any] | None, list[dict]]:
    """Generates constrained LLM payload variants from AKG-linked seed candidates."""
    prompt = build_payload_generation_prompt(
        method=method,
        security_level=str(state.get("security_level", "low")),
        observations=dict(state.get("observations", {})),
        static_seeds=seeds,
        payload_profile=profile,
        candidate_budget=budget,
    )
    prompt_event = {
        "method": method,
        "provider": state.get("llm_provider", "gemini"),
        "prompt": prompt,
        "candidate_budget": budget,
    }
    try:
        llm = _build_llm(str(state.get("llm_provider", "gemini")), dict(state.get("model_config", {})))
        response = llm.invoke([HumanMessage(content=prompt)])
        text = _extract_text(getattr(response, "content", ""))
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
    candidates, parse_status = _parse_candidates(text, method)
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
