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


def _parse_candidates(raw_text: str, method: str) -> list[dict]:
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start == -1 or end <= start:
            return []
        try:
            payload = json.loads(raw_text[start : end + 1])
        except json.JSONDecodeError:
            return []
    rows = payload.get("candidates", []) if isinstance(payload, dict) else []
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
    return candidates


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
        return [], prompt_event, []

    prompt_event["response"] = text
    if is_guardrail_refusal(text):
        return [], prompt_event, [
            make_guardrail_event(
                provider=str(state.get("llm_provider", "gemini")),
                context="payload_generation",
                response=text,
            )
        ]
    return _parse_candidates(text, method)[:budget], prompt_event, []


def build_payload_candidates(state: dict[str, Any]) -> dict[str, Any]:
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
    if mode in {"hybrid", "llm_mutation_only"}:
        generated, prompt_event, guardrails = generate_llm_variants(
            state=state,
            method=method,
            seeds=seed_candidates,
            profile=profile,
            budget=budget,
        )

    candidates = generated if mode == "llm_mutation_only" else [*seed_candidates, *generated]
    return {
        "payload_candidates": {method: candidates},
        "generated_payloads": {method: generated},
        "generation_prompts": [prompt_event] if prompt_event else [],
        "payload_guardrail_activations": guardrails,
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
    return build_payload_candidates(state)
