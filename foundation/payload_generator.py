"""Payload candidate builder for static, hybrid, strict mutation, and Template modes.

Mode contract (``core.payload_policy``):

* ``static_only`` — validated static seeds only; no payload-generation call.
* ``hybrid`` — validated static seeds plus any valid model seed mutation.
* ``llm_mutation_only`` — validated model seed mutations only.  A refusal,
  empty response, malformed JSON, schema violation, provider error, rejected
  candidate, zero budget, or stale candidate queues nothing; a static seed, a
  chain-derived candidate, or an earlier visit never substitutes.
* ``llm_template`` — validated model candidates constructed from a neutral,
  non-executable template only.  The template is never queued or executed and
  the candidate carries template provenance instead of a seed id.

The trusted origin of every generated candidate is assigned here, from the
runtime call identity and the frozen mode policy, never from model output.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from core.knowledge_graph import get_attack_knowledge_graph
from core.payload_policy import (
    DEFAULT_CANDIDATE_BUDGET,
    EVENT_NO_SUPPLIED_SEED,
    EVENT_PROVIDER_FAILURE,
    EVENT_STRICT_NO_CANDIDATE,
    EVENT_TEMPLATE_UNAVAILABLE,
    EXPLOIT_STAGES,
    MODEL_PAYLOAD_MODES,
    MUTATION_PROMPT_ID,
    PAYLOAD_POLICY_VERSION,
    PAYLOAD_SCHEMA_VERSION,
    PAYLOAD_TEMPLATE_SCHEMA_VERSION,
    REASON_NO_SUPPLIED_SEED,
    REASON_SEED_NOT_SUPPLIED,
    TEMPLATE_MUTATION_TYPE,
    TEMPLATE_PROMPT_ID,
    allows_chain_derived,
    allows_static_candidates,
    coerce_budget,
    expected_origin_kind,
    generation_budget,
    generation_opportunity,
    is_model_output_failure_reason,
    lifecycle_fact,
    require_payload_mode,
    requires_model_candidate,
)
from evaluation.scoring_evidence import evidence_hash
from foundation.payload_library import PayloadLibrary
from foundation.payload_templates import (
    TemplateError,
    load_template,
    template_feasibility,
    template_reference,
)
from llm.guardrail_monitor import is_guardrail_refusal, make_guardrail_event
from llm.prompts.payload_generation_prompt import (
    build_payload_generation_prompt,
    build_template_generation_prompt,
    payload_generation_prompt_seeds,
    sanitized_template_observations,
)
from llm.provider import get_llm
from llm.runtime import (
    LLMOutputError,
    current_call_context,
    output_failure_kind,
)

logger = logging.getLogger(__name__)

# Payload responses are small structured JSON objects.  Keep the streamed model
# call bounded even when a provider configuration leaves max_tokens unset.
# Malformed or truncated output is a recorded generation failure; it never
# becomes a static candidate.
_DEFAULT_MUTATION_MAX_TOKENS = 256
_EXECUTION_STAGES = EXPLOIT_STAGES
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
# Template construction has no seed field at all: a template candidate cannot
# name — or fabricate — a source seed.
_TEMPLATE_SYSTEM_MESSAGE = (
    "You construct one exploit or bypass value from a neutral, inert template for an "
    "authorized DVWA sandbox. The template is not a payload and must never be treated as "
    "one. Stay within the selected method, parameter, and authorized bounds, never "
    f"introduce external targets, and follow JSON schema {PAYLOAD_TEMPLATE_SCHEMA_VERSION}."
)
_TEMPLATE_SCHEMA = {
    "title": "dvwa_template_payload_construction",
    "description": "One candidate constructed from a neutral, non-executable template.",
    "type": "object",
    "properties": {
        "candidates": {
            "type": "array",
            "maxItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "payload_or_logic": {"type": "string"},
                    "target_param": {"type": "string"},
                    "expected_signal": {"type": "string"},
                },
                "required": ["payload_or_logic", "target_param", "expected_signal"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["candidates"],
    "additionalProperties": False,
}

_MUTATION_CANDIDATE_FIELDS = ("source_seed_id", "mutation_type", "payload_or_logic")
_TEMPLATE_CANDIDATE_FIELDS = ("payload_or_logic", "target_param", "expected_signal")


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


def _decode_json_object(raw_text: str) -> tuple[dict[str, Any] | None, str | None]:
    """Decode a JSON object, tolerating a fenced/embedded object in the text."""
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start == -1 or end <= start:
            return None, "invalid_json"
        try:
            payload = json.loads(raw_text[start : end + 1])
        except json.JSONDecodeError:
            return None, "invalid_json"
    if not isinstance(payload, dict):
        return None, "invalid_schema"
    return payload, None


def _validate_variants_payload(
    payload: dict[str, Any],
    *,
    seeds: list[dict],
    profile: dict[str, Any],
) -> dict[str, Any]:
    if set(payload) != {"variants"}:
        raise ValueError("response must contain only variants")
    rows = payload["variants"]
    if not isinstance(rows, list) or len(rows) != 1:
        raise ValueError("variants must contain exactly one candidate")
    seed_ids = {
        str(seed.get("source_seed_id") or seed.get("candidate_id"))
        for seed in seeds
    }
    allowed = set(str(value) for value in profile.get("allowed_mutation_types", []))
    normalized: list[dict[str, str]] = []
    for row in rows:
        if (not isinstance(row, dict) or set(row) != set(_MUTATION_CANDIDATE_FIELDS)
                or any(not isinstance(row[key], str) or not row[key].strip()
                       for key in _MUTATION_CANDIDATE_FIELDS)):
            raise ValueError("variant must contain exactly the required non-empty string fields")
        source_seed_id = row["source_seed_id"]
        mutation_type = row["mutation_type"]
        payload_or_logic = row["payload_or_logic"]
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


def _validate_template_payload(
    payload: dict[str, Any],
    *,
    template: dict[str, Any],
) -> dict[str, Any]:
    """Validate a template-construction response against the neutral template."""
    if set(payload) != {"candidates"}:
        raise ValueError("response must contain only candidates")
    rows = payload["candidates"]
    if not isinstance(rows, list) or len(rows) != 1:
        raise ValueError("candidates must contain exactly one candidate")
    target_param = str(template.get("target_param") or "")
    expected_signal = str(template.get("expected_signal") or "")
    normalized: list[dict[str, str]] = []
    for row in rows:
        if (not isinstance(row, dict) or set(row) != set(_TEMPLATE_CANDIDATE_FIELDS)
                or any(not isinstance(row[key], str) or not row[key].strip()
                       for key in _TEMPLATE_CANDIDATE_FIELDS)):
            raise ValueError("candidate must contain exactly the required non-empty string fields")
        value = row.get("payload_or_logic")
        if not isinstance(value, str) or not value.strip():
            raise ValueError("candidate payload_or_logic must be a non-empty string")
        if str(row.get("target_param") or "") != target_param:
            raise ValueError("candidate does not target the template parameter")
        if str(row.get("expected_signal") or "") != expected_signal:
            raise ValueError("candidate does not claim the template signal")
        normalized.append({
            "payload_or_logic": value,
            "target_param": target_param,
            "expected_signal": expected_signal,
        })
    return {"candidates": normalized}


def _parse_candidates(
    raw_text: str,
    method: str,
    *,
    seeds: list[dict] | None = None,
    profile: dict[str, Any] | None = None,
) -> tuple[list[dict], str]:
    """Parse generated seed mutations and retain a machine-auditable status.

    Only the three schema fields are copied from model output.  Identity,
    stage, provenance, and origin are assigned by the runtime afterwards, so a
    model cannot label its own output as a static seed or a probe.
    """
    payload, parse_error = _decode_json_object(raw_text)
    if parse_error:
        return [], parse_error
    assert payload is not None
    rows = payload.get("variants", payload.get("candidates"))
    if not isinstance(rows, list):
        return [], "invalid_schema"
    candidates = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        source_seed_id = str(row.get("source_seed_id") or "")
        mutation_type = str(row.get("mutation_type") or "")
        payload_or_logic = row.get("payload_or_logic")
        if not isinstance(payload_or_logic, str) or not payload_or_logic:
            continue
        candidate = {
            "source_seed_id": source_seed_id,
            "mutation_type": mutation_type,
            "payload_or_logic": payload_or_logic,
        }
        seed = next(
            (
                item for item in (seeds or [])
                if str(item.get("source_seed_id") or item.get("candidate_id"))
                == source_seed_id
            ),
            {},
        )
        digest_src = json.dumps(
            {
                "index": index,
                "method": method,
                "payload_or_logic": payload_or_logic,
                "source_seed_id": source_seed_id,
                "target_param": candidate.get("target_param", ""),
                "expected_signal": candidate.get("expected_signal", ""),
                "mutation_type": mutation_type,
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


def _parse_template_candidates(
    raw_text: str,
    method: str,
    template: dict[str, Any],
) -> tuple[list[dict], str, list[dict]]:
    """Parse template-construction output into trusted candidate skeletons.

    Returns ``(candidates, parse_status, rejections)``.  A response that echoes a
    different parameter or signal is rejected explicitly instead of being
    coerced into the template contract.
    """
    payload, parse_error = _decode_json_object(raw_text)
    if parse_error:
        return [], parse_error, []
    assert payload is not None
    rows = payload.get("candidates", payload.get("variants"))
    if not isinstance(rows, list):
        return [], "invalid_schema", []
    if not rows:
        return [], "empty_candidates", []
    target_param = str(template.get("target_param") or "")
    expected_signal = str(template.get("expected_signal") or "")
    template_id = str(template.get("template_id") or "")
    candidates: list[dict] = []
    rejections: list[dict] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            rejections.append({"reason": "invalid_schema"})
            continue
        unexpected = sorted(set(row) - set(_TEMPLATE_CANDIDATE_FIELDS))
        if unexpected:
            # The template schema forbids extra fields; a response carrying (for
            # example) a source_seed_id is a schema violation, not provenance.
            rejections.append(
                {"reason": "unexpected_candidate_field", "detail": unexpected}
            )
            continue
        value = row.get("payload_or_logic")
        if not isinstance(value, str) or not value.strip():
            rejections.append({"reason": "empty_payload"})
            continue
        if str(row.get("target_param") or "") != target_param:
            rejections.append({"reason": "template_parameter_mismatch"})
            continue
        if str(row.get("expected_signal") or "") != expected_signal:
            rejections.append({"reason": "template_signal_mismatch"})
            continue
        digest_src = json.dumps(
            {
                "index": index,
                "method": method,
                "template_id": template_id,
                "payload_or_logic": value,
                "target_param": target_param,
                "expected_signal": expected_signal,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha1(digest_src.encode("utf-8")).hexdigest()[:8]
        candidates.append({
            "candidate_id": f"{method}_template_{index}_{digest}",
            "method": method,
            "stage": "exploit",
            "mutation_type": TEMPLATE_MUTATION_TYPE,
            "payload_or_logic": value,
            "target_param": target_param,
            "expected_signal": expected_signal,
            "rationale": "neutral template construction",
        })
    if candidates:
        return candidates, "ok", rejections
    if rejections:
        return [], str(rejections[0].get("reason") or "invalid_schema"), rejections
    return [], "invalid_schema", rejections


def _filter_execution_ready_variants(
    candidates: list[dict],
    seeds: list[dict],
) -> tuple[list[dict], int]:
    """Keep only variants bound to a seed the prompt actually showed.

    ``seeds`` is the exact prompt-visible execution-seed set.  A candidate
    referencing a probe seed or any canonical seed that was not rendered is
    rejected here; the validator enforces the same boundary with the recorded
    ``prompt_visible_seed_ids`` receipt.
    """
    visible_ids = {
        str(seed.get("source_seed_id") or seed.get("candidate_id"))
        for seed in seeds
        if str(seed.get("stage", "")).strip().lower() in _EXECUTION_STAGES
    }
    accepted = [
        candidate
        for candidate in candidates
        if str(candidate.get("source_seed_id", "")) in visible_ids
    ]
    return accepted, len(candidates) - len(accepted)


def _canonical_seed_payloads(method: str, security_level: str) -> dict[str, str]:
    """Return canonical seed id -> payload for the method/level."""
    return {
        str(candidate.get("candidate_id")): str(candidate.get("payload_or_logic", ""))
        for candidate in PayloadLibrary().load_seed_candidates(method, security_level)
        if isinstance(candidate, dict) and candidate.get("candidate_id")
    }


def _copy_evidence(
    payload_value: str,
    *,
    supplied: dict[str, str],
    canonical: dict[str, str],
    exclude: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Record exact seed copies without implying novelty.

    ``copy_of_supplied_seed`` compares against the seeds actually present in
    this call's input.  ``equals_canonical_seed_id`` records equality to another
    local canonical seed that was not supplied.  Neither field proves a new
    technique; a changed string is not proof either.
    """
    matched_supplied = sorted(
        seed_id
        for seed_id, seed_payload in supplied.items()
        if seed_payload and seed_payload == payload_value
    )
    canonical_matches = sorted(
        seed_id
        for seed_id, seed_payload in canonical.items()
        if seed_payload and seed_payload == payload_value and seed_id not in exclude
    )
    return {
        "copy_of_supplied_seed": bool(matched_supplied),
        "supplied_seed_matches": matched_supplied,
        "equals_canonical_seed_id": canonical_matches[0] if canonical_matches else None,
    }


def _supplied_seed_payloads(seeds: list[dict]) -> dict[str, str]:
    """Return the seed rows actually supplied to the model call."""
    supplied: dict[str, str] = {}
    for seed in seeds:
        seed_id = str(seed.get("source_seed_id") or seed.get("candidate_id") or "")
        if seed_id:
            supplied[seed_id] = str(seed.get("payload_or_logic", ""))
    return supplied


def _trusted_candidate_id(
    candidate: dict[str, Any],
    *,
    method: str,
    origin_kind: str,
    index: int,
    visit_id: str | None,
) -> str:
    """Return a runtime-assigned, visit-scoped candidate identity.

    The model can never choose its own candidate id, so a repeated payload on a
    later visit gets a distinct identity instead of overwriting earlier
    provenance.  The id stays deterministic for the same visit and output.
    """
    stem = "template" if origin_kind == "template_generation" else "llm"
    digest_src = json.dumps(
        {
            "method": method,
            "origin_kind": origin_kind,
            "index": index,
            "visit_id": visit_id,
            "payload_or_logic": str(candidate.get("payload_or_logic") or ""),
            "target_param": str(candidate.get("target_param") or ""),
            "expected_signal": str(candidate.get("expected_signal") or ""),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha1(digest_src.encode("utf-8")).hexdigest()[:8]
    return f"{method}_{stem}_{index}_{digest}"


def _normalize_generated_candidates(
    candidates: list[dict],
    *,
    mode: str,
    method: str,
    security_level: str,
    visit_id: str | None,
    prompt_event: dict[str, Any] | None,
    seeds: list[dict],
) -> list[dict]:
    """Assign the trusted origin of every generated candidate.

    The mode fixes the origin kind; the runtime call identity fixes the call
    binding.  Model output cannot choose either, and no candidate keeps a
    model-supplied ``source`` label.
    """
    origin_kind = expected_origin_kind(mode) or "seed_mutation"
    event = prompt_event or {}
    call_id = event.get("call_id")
    prompt_id = str(event.get("prompt_id") or MUTATION_PROMPT_ID)
    schema_version = str(event.get("schema_version") or PAYLOAD_SCHEMA_VERSION)
    template_ref = event.get("template_reference")
    visible_ids = {str(value) for value in (event.get("prompt_visible_seed_ids") or [])}
    # Copy evidence must describe the seeds the prompt actually rendered.  Kept
    # callers may pass the full canonical library here (the builder normalizes a
    # second time); the recorded prompt-visible rows are the supplied set, so an
    # unrendered probe is never called a supplied seed.
    visible_rows = event.get("prompt_visible_seeds")
    supplied_rows = (
        [row for row in visible_rows if isinstance(row, dict)]
        if isinstance(visible_rows, list)
        else seeds
    )
    supplied = _supplied_seed_payloads(supplied_rows)
    canonical = _canonical_seed_payloads(method, security_level)
    normalized: list[dict] = []
    for index, candidate in enumerate(candidates):
        row = dict(candidate)
        payload_value = str(row.get("payload_or_logic") or "")
        row["source"] = "llm_generated"
        row["origin_kind"] = origin_kind
        row["method"] = method
        # A model candidate is an exploit/bypass candidate by contract; model
        # output cannot relabel itself as a detection probe.  Identity is also
        # runtime-assigned and visit-scoped so a repeated output on a later
        # visit cannot impersonate or overwrite the earlier candidate.
        row["stage"] = "exploit"
        row["visit_id"] = visit_id
        row["candidate_id"] = _trusted_candidate_id(
            row,
            method=method,
            origin_kind=origin_kind,
            index=index,
            visit_id=visit_id,
        )
        row["model_call_id"] = call_id
        row["prompt_id"] = prompt_id
        row["schema_version"] = schema_version
        row["policy_version"] = PAYLOAD_POLICY_VERSION
        if origin_kind == "template_generation":
            row.pop("source_seed_id", None)
            row["mutation_type"] = TEMPLATE_MUTATION_TYPE
            row["origin_ref"] = dict(template_ref or {})
            feasibility = dict(event.get("template_feasibility") or {})
            row["feasibility"] = {
                "status": feasibility.get("status"),
                "reason": feasibility.get("reason"),
            }
            row.update(
                _copy_evidence(payload_value, supplied={}, canonical=canonical)
            )
        else:
            seed_id = str(row.get("source_seed_id") or "")
            row["origin_ref"] = {"seed_id": seed_id}
            row["seed_supplied"] = bool(seed_id and seed_id in visible_ids)
            row.update(
                _copy_evidence(
                    payload_value,
                    supplied=supplied,
                    canonical=canonical,
                    exclude=frozenset(visible_ids),
                )
            )
        normalized.append(row)
    return normalized


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


def _generation_failure(
    prompt_event: dict[str, Any],
    *,
    reason: str,
    provider: str,
    text: str = "",
    performance: dict[str, Any] | None = None,
    error: str | None = None,
    receipt_binding: str | None = None,
) -> tuple[list[dict], dict[str, Any], list[dict]]:
    """Record one failed generation opportunity without any candidate revival."""
    prompt_event["failure_reason"] = reason
    prompt_event["failure_reasons"] = [reason]
    # Call identity is always present: an actual retained runtime receipt or an
    # explicit null when no dispatch happened.  Never invent an id.
    prompt_event.setdefault("call_id", None)
    if receipt_binding:
        prompt_event["receipt_binding"] = receipt_binding
    if performance:
        prompt_event["performance"] = performance
        prompt_event["call_id"] = performance.get("call_id", prompt_event.get("call_id"))
        prompt_event["parse_status"] = performance.get("parse_status", "invalid")
    if text:
        prompt_event["response"] = text
    if error:
        prompt_event["error"] = error
    prompt_event["parsed_candidate_ids"] = []
    guardrails: list[dict] = []
    if reason == "guardrail_refusal":
        guardrails.append(
            make_guardrail_event(
                provider=provider,
                context="payload_generation",
                response=text,
            )
        )
    return [], prompt_event, guardrails


def generate_llm_variants(
    *,
    state: dict[str, Any],
    method: str,
    seeds: list[dict],
    profile: dict[str, Any],
    budget: int,
) -> tuple[list[dict], dict[str, Any] | None, list[dict]]:
    """Generate at most one constrained model candidate for the current visit.

    Returns ``(generated, prompt_event, guardrail_events)``.  In strict modes a
    refusal, invalid output, rejected candidate, provider failure, or zero
    budget returns no candidate; the caller never substitutes a static seed.
    """
    mode = require_payload_mode(state.get("payload_mode"))
    if mode not in MODEL_PAYLOAD_MODES:
        return [], None, []
    security_level = str(state.get("security_level", "low"))
    visit_id = state.get("selected_visit_id")
    model_budget = min(1, max(0, int(budget)))
    provider = str(state.get("llm_provider", "gemini"))
    visible_seeds = (
        [] if mode == "llm_template" else payload_generation_prompt_seeds(seeds)
    )
    visible_ids = [str(seed["source_seed_id"]) for seed in visible_seeds]
    prompt_event: dict[str, Any] = {
        "method": method,
        "payload_mode": mode,
        "visit_id": visit_id,
        "provider": provider,
        "origin_kind": expected_origin_kind(mode),
        "policy_version": PAYLOAD_POLICY_VERSION,
        "candidate_budget": int(budget),
        "model_candidate_budget": model_budget,
        "prompt_visible_seed_ids": visible_ids,
        "prompt_visible_seeds": visible_seeds,
        "prompt_visible_seeds_sha256": evidence_hash(visible_seeds),
    }
    if model_budget <= 0:
        prompt_event["skipped"] = "candidate_budget_zero"
        prompt_event["failure_reason"] = "candidate_budget_zero"
        prompt_event["parsed_candidate_ids"] = []
        return [], prompt_event, []
    if mode != "llm_template" and not visible_seeds:
        # No execution-ready seed exists, so no honest mutation prompt can be
        # built.  This is an absence outcome, never a model-output failure.
        prompt_event["skipped"] = REASON_NO_SUPPLIED_SEED
        prompt_event["failure_reason"] = REASON_NO_SUPPLIED_SEED
        prompt_event["parsed_candidate_ids"] = []
        return [], prompt_event, []

    template: dict[str, Any] | None = None
    if mode == "llm_template":
        try:
            template = load_template(method, security_level)
        except TemplateError as exc:
            prompt_event["failure_reason"] = "template_unavailable"
            prompt_event["template_error"] = exc.reason
            prompt_event["parsed_candidate_ids"] = []
            return [], prompt_event, []
        prompt = build_template_generation_prompt(
            template=template,
            observations=dict(state.get("observations", {})),
            candidate_budget=model_budget,
        )
        prompt_event.update({
            "template_id": template["template_id"],
            "template_version": template["template_version"],
            "template_sha256": template["template_sha256"],
            "template_reference": template_reference(template),
            "template_feasibility": template_feasibility(template),
            "prompt_id": TEMPLATE_PROMPT_ID,
            "schema_version": PAYLOAD_TEMPLATE_SCHEMA_VERSION,
        })
        evidence_input = {
            "template": {
                key: template[key]
                for key in (
                    "template_id",
                    "template_version",
                    "template_sha256",
                    "method",
                    "security_level",
                    "target_param",
                    "expected_signal",
                    "objective",
                    "format",
                    "constraints",
                    "allowed_parameters",
                )
            },
            "observations": sanitized_template_observations(state.get("observations")),
        }
        schema = _TEMPLATE_SCHEMA
        system_message = _TEMPLATE_SYSTEM_MESSAGE
        schema_version = PAYLOAD_TEMPLATE_SCHEMA_VERSION

        def validator(value: dict[str, Any]) -> dict[str, Any]:
            return _validate_template_payload(value, template=template)
    else:
        prompt = build_payload_generation_prompt(
            method=method,
            security_level=security_level,
            observations=dict(state.get("observations", {})),
            static_seeds=seeds,
            payload_profile=profile,
            candidate_budget=model_budget,
        )
        prompt_event.update({
            "prompt_id": MUTATION_PROMPT_ID,
            "schema_version": PAYLOAD_SCHEMA_VERSION,
        })
        evidence_input = {
            "observations": dict(state.get("observations", {})),
            "seeds": seeds,
            "prompt_visible_seed_ids": visible_ids,
            "prompt_visible_seeds": visible_seeds,
            "prompt_visible_seeds_sha256": evidence_hash(visible_seeds),
            "profile": profile,
        }
        schema = _PAYLOAD_SCHEMA
        system_message = _PAYLOAD_SYSTEM_MESSAGE
        schema_version = PAYLOAD_SCHEMA_VERSION

        def validator(value: dict[str, Any]) -> dict[str, Any]:
            return _validate_variants_payload(value, seeds=visible_seeds, profile=profile)

    prompt_event["prompt"] = prompt
    text = ""
    parsed_payload: dict[str, Any] | None = None
    try:
        context = current_call_context()
        if context is not None:
            max_tokens = min(512, 96 + 64 * int(budget))
            result = context.runtime.invoke(
                context=context,
                role="payload_generator",
                system_message=system_message,
                user_message=prompt,
                schema=schema,
                schema_version=schema_version,
                validator=validator,
                max_tokens=max_tokens,
                evidence_context={
                    "method": method,
                    "visit_id": visit_id,
                    "input": evidence_input,
                },
            )
            text = result.text
            parsed_payload = result.parsed
            prompt_event["performance"] = result.performance
            prompt_event["call_id"] = result.performance.get("call_id")
        else:
            llm = _build_llm(
                provider, dict(state.get("model_config", {}))
            )
            response = llm.invoke([
                SystemMessage(content=system_message),
                HumanMessage(content=prompt),
            ])
            text = _extract_text(getattr(response, "content", ""))
            parsed_payload = None
    except LLMOutputError as exc:
        text = exc.text
        if is_guardrail_refusal(text):
            return _generation_failure(
                prompt_event,
                reason="guardrail_refusal",
                provider=provider,
                text=text,
                performance=exc.performance,
            )
        reason = output_failure_kind(exc.performance, text)
        return _generation_failure(
            prompt_event,
            reason=reason,
            provider=provider,
            text=text,
            performance=exc.performance,
        )
    except Exception as exc:  # noqa: BLE001 - provider/transport boundary
        logger.warning("Payload generation failed in %s mode: %s", mode, exc)
        retained = getattr(exc, "performance", None)
        if not isinstance(retained, dict):
            retained = getattr(exc, "provider_failure", None)
        if not isinstance(retained, dict):
            retained = None
        return _generation_failure(
            prompt_event,
            reason="llm_error",
            provider=provider,
            error=f"{type(exc).__name__}: {exc}",
            performance=retained,
            receipt_binding="runtime_receipt" if retained else "unavailable_no_dispatch",
        )

    prompt_event["response"] = text
    if is_guardrail_refusal(text):
        return _generation_failure(
            prompt_event,
            reason="guardrail_refusal",
            provider=provider,
            text=text,
        )
    if parsed_payload is None:
        value, parse_error = _decode_json_object(text)
        if parse_error:
            return _generation_failure(
                prompt_event, reason=parse_error, provider=provider, text=text)
        assert value is not None
        try:
            parsed_payload = validator(value)
        except ValueError as exc:
            return _generation_failure(
                prompt_event, reason="invalid_schema", provider=provider,
                text=text, error=str(exc))
    text = json.dumps(parsed_payload, sort_keys=True, separators=(",", ":"))

    rejections: list[dict] = []
    if mode == "llm_template" and template is not None:
        candidates, parse_status, rejections = _parse_template_candidates(
            text, method, template
        )
    else:
        candidates, parse_status = _parse_candidates(
            text, method, seeds=visible_seeds, profile=profile
        )
    prompt_event["parse_status"] = parse_status
    prompt_event["parsed_candidate_ids"] = [
        str(candidate.get("candidate_id")) for candidate in candidates
    ]
    if parse_status != "ok":
        prompt_event["candidate_rejections"] = rejections
        return _generation_failure(
            prompt_event,
            reason=parse_status,
            provider=provider,
            text=text,
        )

    rejected_probe_variants = 0
    if mode != "llm_template":
        visible_id_set = set(visible_ids)
        rejected_candidates = [
            candidate for candidate in candidates
            if str(candidate.get("source_seed_id") or "") not in visible_id_set
        ]
        candidates, rejected_probe_variants = _filter_execution_ready_variants(
            candidates, visible_seeds
        )
        if rejected_probe_variants:
            stage_by_id = {
                str(seed.get("candidate_id")): str(seed.get("stage") or "")
                for seed in PayloadLibrary().load_seed_candidates(method, security_level)
            }
            rejections = []
            for candidate in rejected_candidates:
                seed_id = str(candidate.get("source_seed_id") or "")
                rejections.append({
                    "reason": (
                        "probe_seed_for_exploit"
                        if stage_by_id.get(seed_id) == "probe" else REASON_SEED_NOT_SUPPLIED
                    ),
                    "source_seed_id": seed_id,
                })
            prompt_event["rejected_probe_seed_variants"] = rejected_probe_variants
            prompt_event["candidate_rejections"] = rejections
        if not candidates:
            reason = str((prompt_event.get("candidate_rejections") or [{}])[0].get("reason")
                         or REASON_SEED_NOT_SUPPLIED)
            return _generation_failure(
                prompt_event,
                reason=reason,
                provider=provider,
                text=text,
            )

    generated = _normalize_generated_candidates(
        candidates,
        mode=mode,
        method=method,
        security_level=security_level,
        visit_id=visit_id,
        prompt_event=prompt_event,
        seeds=visible_seeds,
    )
    prompt_event["parsed_candidate_ids"] = [
        str(candidate.get("candidate_id")) for candidate in generated
    ]
    return generated[:model_budget], prompt_event, []


def _static_exploit_candidates(
    method: str, security_level: str
) -> list[dict]:
    """Return static exploit/bypass seeds; probe seeds are detection controls."""
    return [
        candidate
        for candidate in PayloadLibrary().load_seed_candidates(method, security_level)
        if str(candidate.get("stage", "")).strip().lower() in _EXECUTION_STAGES
    ]


def _visit_token(visit_id: str | None) -> str:
    """Return a short deterministic token that makes queue ids visit-scoped."""
    raw = str(visit_id or "legacy")
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]
    readable = "".join(ch if ch.isalnum() else "_" for ch in raw)[:24].strip("_") or "visit"
    return f"{readable}_{digest}"


def _stamp_static_candidates(
    method: str,
    security_level: str,
    visit_id: str | None,
    seed_candidates: list[dict],
) -> list[dict]:
    """Give canonical seeds a visit-scoped execution id.

    ``source_seed_id`` stays the canonical origin reference; the execution id is
    unique per visit so a revisit cannot inherit or drop another visit's queue
    row, and C's candidate+visit binding is always satisfied.
    """
    token = _visit_token(visit_id)
    stamped: list[dict] = []
    for index, seed in enumerate(seed_candidates):
        seed_id = str(seed.get("candidate_id") or seed.get("source_seed_id") or "")
        payload = str(seed.get("payload_or_logic", ""))
        canonical = {
            str(row.get("candidate_id")): str(row.get("payload_or_logic", ""))
            for row in PayloadLibrary().load_seed_candidates(method, security_level)
        }
        stamped.append({
            **seed,
            "candidate_id": f"{method}_static_{token}_{index}",
            "source_seed_id": seed_id,
            "source": "static_seed",
            "origin_kind": "static_seed",
            "origin_ref": {"seed_id": seed_id},
            "visit_id": visit_id,
            "policy_version": PAYLOAD_POLICY_VERSION,
            "copy_of_supplied_seed": False,
            "equals_canonical_seed_id": seed_id if canonical.get(seed_id) == payload else None,
        })
    return stamped


def _chain_derived_candidates(
    state: dict[str, Any],
    method: str,
    seed_candidates: list[dict],
) -> list[dict]:
    """Build the route-bound plaintext credential candidate for static/hybrid."""
    route = state.get("active_chain_route") or {}
    if not (
        method == "bf_dictionary"
        and route.get("source") == "credentials_extracted"
        and route.get("target_agent") == method
    ):
        return []
    seed = next(
        (
            row
            for row in seed_candidates
            if row.get("stage") in _EXECUTION_STAGES
        ),
        None,
    )
    if not seed:
        return []
    derived: list[dict] = []
    for credential in state.get("found_credentials", []):
        if (
            credential.get("representation") != "plaintext"
            or credential.get("source_evidence_id")
            not in route.get("source_evidence_ids", [])
            or not credential.get("username")
            or not credential.get("password")
        ):
            continue
        pair = f"{credential['username']}:{credential['password']}"
        digest = hashlib.sha256(
            (credential["source_evidence_id"] + pair).encode()
        ).hexdigest()[:16]
        derived.append({
            **seed,
            "candidate_id": f"{method}_chain_{_visit_token(state.get('selected_visit_id'))}_{digest}",
            "source": "chain_derived",
            "origin_kind": "chain_derived",
            "origin_ref": {
                "seed_id": str(seed.get("candidate_id") or ""),
                "source_evidence_ids": list(route.get("source_evidence_ids", [])),
            },
            "visit_id": state.get("selected_visit_id"),
            "policy_version": PAYLOAD_POLICY_VERSION,
            "mutation_type": "credential_ordering",
            "stage": "exploit",
            "payload_or_logic": pair,
            "rationale": "route-bound plaintext credential",
        })
    return derived


def _provenance_row(candidate: dict[str, Any], method: str) -> dict[str, Any]:
    """Build the durable provenance record for one queued candidate."""
    origin_kind = str(candidate.get("origin_kind") or candidate.get("source") or "")
    row = {
        "source": candidate.get("source", "llm_generated"),
        "origin_kind": origin_kind,
        "origin_ref": dict(candidate.get("origin_ref") or {}),
        "source_seed_id": candidate.get("source_seed_id"),
        "mutation_type": candidate.get("mutation_type"),
        "method": method,
        "target_param": candidate.get("target_param"),
        "expected_signal": candidate.get("expected_signal"),
        "visit_id": candidate.get("visit_id"),
        "model_call_id": candidate.get("model_call_id"),
        "prompt_id": candidate.get("prompt_id"),
        "schema_version": candidate.get("schema_version"),
        "policy_version": candidate.get("policy_version") or PAYLOAD_POLICY_VERSION,
        "copy_of_supplied_seed": bool(candidate.get("copy_of_supplied_seed")),
        "equals_canonical_seed_id": candidate.get("equals_canonical_seed_id"),
    }
    if origin_kind != "template_generation":
        row["seed_supplied"] = bool(candidate.get("seed_supplied"))
    if origin_kind == "template_generation":
        row.pop("source_seed_id", None)
        row["feasibility"] = dict(candidate.get("feasibility") or {})
    return row


def build_payload_candidates(state: dict[str, Any]) -> dict[str, Any]:
    """Build the current visit's exploit/bypass candidates for one method.

    Static and hybrid modes keep their intended seeds plus any valid model
    candidate.  Strict modes queue model candidates only, and every no-usable
    -candidate case produces an explicit status instead of a substitute.
    """
    method = str(state.get("selected_method") or state.get("next_agent") or "")
    if not method:
        return {"payload_candidates": {}}

    kg = get_attack_knowledge_graph()
    profile = kg.get_payload_profile(method)
    security_level = str(state.get("security_level", "low"))
    mode = require_payload_mode(state.get("payload_mode"))
    visit_id = state.get("selected_visit_id")
    configured_budget = coerce_budget(
        state.get("candidate_budget", DEFAULT_CANDIDATE_BUDGET)
    )
    model_limit = generation_budget(configured_budget, profile)

    seed_candidates = _static_exploit_candidates(method, security_level)
    generation_seeds = PayloadLibrary().load_seed_candidates(method, security_level)
    generated: list[dict] = []
    prompt_event: dict[str, Any] | None = None
    guardrails: list[dict] = []
    fallback_events: list[dict] = []
    invalid_json_events: list[dict] = []
    output_failure_events: list[dict] = []
    provider = str(state.get("llm_provider", "gemini"))
    opportunities: list[dict] = []
    lifecycle: list[dict] = []
    model_required = requires_model_candidate(mode)

    if model_required and model_limit > 0 and mode in MODEL_PAYLOAD_MODES:
        generated, prompt_event, guardrails = generate_llm_variants(
            state=state,
            method=method,
            seeds=generation_seeds if mode != "llm_template" else [],
            profile=profile,
            budget=model_limit,
        )
    elif model_required:
        prompt_event = {
            "method": method,
            "payload_mode": mode,
            "visit_id": visit_id,
            "origin_kind": expected_origin_kind(mode),
            "policy_version": PAYLOAD_POLICY_VERSION,
            "candidate_budget": configured_budget,
            "model_candidate_budget": 0,
            "skipped": "candidate_budget_zero",
            "failure_reason": "candidate_budget_zero",
            "parsed_candidate_ids": [],
            "prompt_visible_seed_ids": [],
            "prompt_visible_seeds": [],
            "prompt_visible_seeds_sha256": evidence_hash([]),
        }
    else:
        # static_only is an intentional zero-call payload ablation: record the
        # not-required decision so the role's absence stays auditable.
        opportunities.append(generation_opportunity(
            method=method,
            visit_id=visit_id,
            mode=mode,
            required=False,
            status="not_required",
            reason="static_payload_mode",
            prompt_id=MUTATION_PROMPT_ID,
            schema_version=PAYLOAD_SCHEMA_VERSION,
            origin_kind=None,
        ))

    if prompt_event is not None:
        generated = _normalize_generated_candidates(
            generated,
            mode=mode,
            method=method,
            security_level=security_level,
            visit_id=visit_id,
            prompt_event=prompt_event,
            # The supplied set is the prompt-visible rows recorded on this call,
            # never the full canonical library (which includes probes).
            seeds=list(prompt_event.get("prompt_visible_seeds") or []),
        )
        prompt_event["parsed_candidate_ids"] = [
            str(candidate.get("candidate_id")) for candidate in generated
        ] or list(prompt_event.get("parsed_candidate_ids") or [])
        failure_reason = str(prompt_event.get("failure_reason") or "")
        if generated:
            opportunity_status = "completed"
            opportunity_reason = None
        elif failure_reason in {
            "candidate_budget_zero", REASON_NO_SUPPLIED_SEED, "template_unavailable",
        }:
            opportunity_status = "not_run"
            opportunity_reason = failure_reason
        else:
            opportunity_status = "failed"
            opportunity_reason = failure_reason or "empty_candidates"
        opportunities.append(generation_opportunity(
            method=method,
            visit_id=visit_id,
            mode=mode,
            required=model_required,
            status=opportunity_status,
            reason=opportunity_reason,
            call_id=prompt_event.get("call_id"),
            prompt_id=str(prompt_event.get("prompt_id") or MUTATION_PROMPT_ID),
            schema_version=str(
                prompt_event.get("schema_version") or PAYLOAD_SCHEMA_VERSION
            ),
            origin_kind=expected_origin_kind(mode),
            parsed_candidate_ids=list(prompt_event.get("parsed_candidate_ids") or []),
            failure_reason_detail=(
                str(prompt_event.get("failure_reason") or "")
                or None
            ),
        ))
        if failure_reason and not generated:
            failure_row = {
                "method": method,
                "payload_mode": mode,
                "visit_id": visit_id,
                "reason": failure_reason,
                "origin_kind": expected_origin_kind(mode),
                "role": "payload_generator",
                "call_id": prompt_event.get("call_id"),
                "parse_status": prompt_event.get("parse_status"),
                "policy_version": PAYLOAD_POLICY_VERSION,
            }
            if failure_reason in {"llm_error", "provider_error"}:
                fallback_events.append(
                    {**failure_row, "event": EVENT_PROVIDER_FAILURE}
                )
            elif failure_reason == "template_unavailable":
                fallback_events.append(
                    {**failure_row, "event": EVENT_TEMPLATE_UNAVAILABLE}
                )
            elif failure_reason == REASON_NO_SUPPLIED_SEED:
                fallback_events.append(
                    {**failure_row, "event": EVENT_NO_SUPPLIED_SEED}
                )
            elif failure_reason not in {"candidate_budget_zero"} and mode not in {"hybrid", "static_only"}:
                fallback_events.append(
                    {**failure_row, "event": EVENT_STRICT_NO_CANDIDATE}
                )
            # Role/visit/call-bound output events stay available to existing
            # output-grade readers; a provider failure is never recorded here.
            if failure_reason == "invalid_json":
                invalid_json_events.append({
                    "event": "payload_generation.invalid_json",
                    "method": method,
                    "provider": prompt_event.get("provider", provider),
                    "visit_id": visit_id,
                    "role": "payload_generator",
                    "call_id": prompt_event.get("call_id"),
                    "failure_kind": failure_reason,
                    "policy_version": PAYLOAD_POLICY_VERSION,
                })
            elif (
                is_model_output_failure_reason(failure_reason)
                and failure_reason != "guardrail_refusal"
            ):
                # A refusal is a model act with its own guardrail activation, not
                # a schema/output rejection; it must not be double counted.
                output_failure_events.append({
                    "event": "payload_generation.output_rejected",
                    "method": method,
                    "failure_kind": failure_reason,
                    "performance": prompt_event.get("performance", {}),
                    "visit_id": visit_id,
                    "role": "payload_generator",
                    "call_id": prompt_event.get("call_id"),
                    "policy_version": PAYLOAD_POLICY_VERSION,
                })

    candidates: list[dict] = []
    if allows_static_candidates(mode):
        candidates.extend(
            _stamp_static_candidates(method, security_level, visit_id, seed_candidates)
        )
    candidates.extend(generated)
    if allows_chain_derived(mode):
        candidates.extend(_chain_derived_candidates(state, method, seed_candidates))

    # Generation never exceeds the queue budget; the validator applies the
    # single per-visit budget to the merged origins and records every excluded
    # candidate with its reason, so no origin can silently reserve a slot.

    for candidate in candidates:
        candidate.setdefault("method", method)
        candidate["visit_id"] = visit_id
        candidate.setdefault("policy_version", PAYLOAD_POLICY_VERSION)
        if candidate.get("origin_kind") is None:
            candidate["origin_kind"] = (
                "static_seed" if candidate.get("source") == "static_seed" else "seed_mutation"
            )
        lifecycle.append(lifecycle_fact(
            method=method,
            visit_id=visit_id,
            candidate_id=str(candidate.get("candidate_id") or "") or None,
            origin_kind=str(candidate["origin_kind"]),
            status="generated",
            reason=None,
        ))
    if prompt_event is not None:
        for rejection in prompt_event.get("candidate_rejections") or []:
            lifecycle.append(lifecycle_fact(
                method=method,
                visit_id=visit_id,
                candidate_id=None,
                origin_kind=expected_origin_kind(mode) or "seed_mutation",
                status="rejected",
                reason=str(rejection.get("reason") or "invalid_candidate"),
            ))

    return {
        "payload_candidates": {method: candidates},
        "active_payload_candidates": {method: {"visit_id": visit_id,
            "candidate_ids": [row["candidate_id"] for row in candidates], "status": "pending"}},
        "generated_payloads": {method: generated},
        "generation_prompts": [prompt_event] if prompt_event else [],
        "payload_guardrail_activations": guardrails,
        "guardrail_activations": guardrails,
        "fallback_events": fallback_events,
        "invalid_json_events": invalid_json_events,
        "output_failure_events": output_failure_events,
        "model_call_requirements": opportunities,
        "candidate_lifecycle": lifecycle,
        "payload_provenance": {
            str(candidate["candidate_id"]): _provenance_row(candidate, method)
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
        Payload candidates, generated payloads, prompt artifacts, provenance,
        generation opportunities, and candidate lifecycle facts.

    Side Effects:
        May call an LLM provider when payload mode allows generated candidates.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update with candidate and provenance fields."""
    update = build_payload_candidates(state)
    for field in (
        "invalid_json_events",
        "output_failure_events",
        "guardrail_activations",
        "payload_guardrail_activations",
        "fallback_events",
    ):
        update[field] = [{**event, "method": state.get("selected_method"),
            "visit_id": state.get("selected_visit_id"), "origin": "payload_generator", "scope": "method"}
            for event in update.get(field, [])]
    return update
