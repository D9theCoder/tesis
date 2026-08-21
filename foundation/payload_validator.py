"""Payload candidate validation for AKG-constrained hybrid execution."""

from __future__ import annotations

import math
import re
from typing import Any
from urllib.parse import unquote, urlparse

from core.knowledge_graph import AttackKnowledgeGraph
from foundation.payload_library import PayloadLibrary
from foundation.payload_ranker import rank_candidates


_REQUIRED_FIELDS = {
    "candidate_id",
    "source_seed_id",
    "mutation_type",
    "payload_or_logic",
    "target_param",
    "expected_signal",
}

_OUT_OF_SCOPE_MARKERS = (
    "http://",
    "https://",
    "169.254.169.254",
    "/etc/passwd",
    "xp_cmdshell",
    "curl ",
    "wget ",
    "nc ",
    "bash -",
    "powershell",
)
_CREDENTIAL_PREFIX = re.compile(r"^\s*[^:,;\s]+\s*:\s*[^,;\s]+")
_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_BENCHMARK_CALL = re.compile(r"\bbenchmark\s*\(", re.IGNORECASE)
_SLEEP_CALL = re.compile(r"\bsleep\s*\(\s*([^,)]*)", re.IGNORECASE)
_MAX_SAFE_DELAY_SECONDS = 5.0


def allowed_target_params(method: str) -> set[str]:
    """Returns target parameters allowed by the AKG payload profile for a method."""
    profile = AttackKnowledgeGraph().get_payload_profile(method)
    target_params = profile.get("target_params", [])
    allowed = {str(item) for item in target_params if item}
    if method.startswith("bf_"):
        allowed.add("credential_pair")
    return allowed


def _is_out_of_scope(payload: str) -> bool:
    lowered = payload.lower()
    if any(marker in lowered for marker in _OUT_OF_SCOPE_MARKERS):
        return True
    stripped = payload.strip()
    # A backslash is legitimate in SQL syntax (for example an escaped quote),
    # so only reject it when it forms a UNC target or traversal sequence.
    if stripped.startswith(("//", "\\\\")):
        return True
    if "../" in stripped or "..\\" in stripped or "/.." in stripped:
        return True
    parsed = urlparse(stripped)
    return bool(parsed.scheme and parsed.netloc)


def _unsafe_resource_reason(payload: str) -> str | None:
    """Reject delay mutations that can consume unbounded target resources.

    Model mutations can insert SQL block comments or percent-encode function
    names.  Normalize those representations before inspecting delay calls so
    that the validator remains a hard boundary before the HTTP client.  A
    SLEEP call is accepted only when its first argument is a finite decimal
    value within the bounded delay used by the handwritten DVWA seeds; opaque
    expressions are rejected conservatively.
    """
    normalized = payload
    for _ in range(2):
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    normalized = _SQL_BLOCK_COMMENT.sub("", normalized)

    if _BENCHMARK_CALL.search(normalized):
        return "unsafe_resource_cost"

    for match in _SLEEP_CALL.finditer(normalized):
        try:
            seconds = float(match.group(1).strip())
        except (TypeError, ValueError):
            return "unsafe_resource_cost"
        if not math.isfinite(seconds) or not 0 <= seconds <= _MAX_SAFE_DELAY_SECONDS:
            return "unsafe_resource_cost"
    return None


def validate_candidate(candidate: dict[str, Any], method: str, profile: dict[str, Any]) -> dict[str, Any]:
    """Validates one payload candidate against method profile and provenance rules.

    Args:
        candidate: Candidate payload metadata to validate.
        method: Selected static method agent.
        profile: AKG payload profile for the method.

    Returns:
        Validation result describing whether the candidate is accepted and why."""
    if not isinstance(candidate, dict):
        return {"valid": False, "reason": "not_a_dict", "candidate": candidate}

    missing = sorted(_REQUIRED_FIELDS - set(candidate))
    if missing:
        return {"valid": False, "reason": f"missing_fields:{missing}", "candidate_id": candidate.get("candidate_id")}

    candidate_method = str(candidate.get("method") or method)
    if candidate_method != method:
        return {
            "valid": False,
            "reason": "wrong_method_family",
            "candidate_id": candidate.get("candidate_id"),
        }

    target_param = str(candidate.get("target_param", ""))
    if target_param not in allowed_target_params(method):
        return {
            "valid": False,
            "reason": "wrong_target_param",
            "candidate_id": candidate.get("candidate_id"),
        }

    payload = str(candidate.get("payload_or_logic", ""))
    if not payload.strip():
        return {"valid": False, "reason": "empty_payload", "candidate_id": candidate.get("candidate_id")}
    unsafe_resource_reason = _unsafe_resource_reason(payload)
    if unsafe_resource_reason:
        return {
            "valid": False,
            "reason": unsafe_resource_reason,
            "candidate_id": candidate.get("candidate_id"),
        }
    if _is_out_of_scope(payload):
        return {
            "valid": False,
            "reason": "out_of_scope_target",
            "candidate_id": candidate.get("candidate_id"),
        }
    if method.startswith("bf_") and target_param == "credential_pair" and not _CREDENTIAL_PREFIX.match(payload):
        return {
            "valid": False,
            "reason": "invalid_credential_pair",
            "candidate_id": candidate.get("candidate_id"),
        }

    source = str(candidate.get("source", "llm_generated"))
    source_seed_id = str(candidate.get("source_seed_id", "")).strip()
    if not source_seed_id:
        return {
            "valid": False,
            "reason": "missing_source_seed_id",
            "candidate_id": candidate.get("candidate_id"),
        }

    mutation = str(candidate.get("mutation_type", ""))
    if mutation in set(profile.get("forbidden_mutation_types", [])):
        return {
            "valid": False,
            "reason": "forbidden_mutation_type",
            "candidate_id": candidate.get("candidate_id"),
        }
    if source != "static_seed" and mutation not in set(profile.get("allowed_mutation_types", [])):
        return {
            "valid": False,
            "reason": "mutation_type_not_allowed",
            "candidate_id": candidate.get("candidate_id"),
        }

    expected_signal = str(candidate.get("expected_signal", ""))
    if expected_signal not in set(profile.get("expected_success_signals", [])):
        return {
            "valid": False,
            "reason": "wrong_expected_signal",
            "candidate_id": candidate.get("candidate_id"),
        }

    if str(candidate.get("stage", "exploit")) not in {"probe", "exploit", "bypass"}:
        return {
            "valid": False,
            "reason": "invalid_stage",
            "candidate_id": candidate.get("candidate_id"),
        }

    return {"valid": True, "reason": "ok", "candidate_id": candidate.get("candidate_id")}


def validate_payload_candidates(state: dict[str, Any]) -> dict[str, Any]:
    """Validates, deduplicates, and ranks candidates for the selected method.

    Args:
        state: Current shared LangGraph state containing the selected method,
            payload candidate map, generated candidate map, and provenance map.

    Returns:
        Partial state update with validation results, accepted payload
        candidates, and provenance records for ranked candidates."""
    method = str(state.get("selected_method") or state.get("next_agent") or "")
    if not method:
        return {"payload_validation_results": {"unknown": [{"valid": False, "reason": "missing_method"}]}}

    kg = AttackKnowledgeGraph()
    profile = kg.get_payload_profile(method)
    raw_candidates = list(state.get("payload_candidates", {}).get(method, []))
    canonical_seed_candidates = PayloadLibrary().load_seed_candidates(
        method,
        str(state.get("security_level", "low")),
    )
    static_seed_ids = {
        str(candidate.get("candidate_id"))
        for candidate in canonical_seed_candidates
        if isinstance(candidate, dict) and str(candidate.get("source", "")) == "static_seed" and candidate.get("candidate_id")
    }
    canonical_static_payloads = {
        str(candidate.get("candidate_id")): str(candidate.get("payload_or_logic", ""))
        for candidate in canonical_seed_candidates
        if isinstance(candidate, dict) and candidate.get("candidate_id")
    }
    def _collect_candidates(candidates: list[dict]) -> tuple[list[dict], list[dict]]:
        seen_payloads: set[str] = set()
        seen: set[str] = set()
        valid: list[dict] = []
        rejected: list[dict] = []

        for raw_candidate in candidates:
            candidate = dict(raw_candidate)
            candidate.setdefault("method", method)
            candidate_id = str(candidate.get("candidate_id", ""))
            if not candidate_id or candidate_id in seen:
                rejected.append({
                    "candidate_id": candidate_id or None,
                    "valid": False,
                    "reason": "duplicate_or_missing_candidate_id",
                })
                continue
            seen.add(candidate_id)
            result = validate_candidate(candidate, method, profile)
            payload_value = str(candidate.get("payload_or_logic", ""))
            if result["valid"] and payload_value in seen_payloads:
                result = {
                    "valid": False,
                    "reason": "duplicate_payload_or_logic",
                    "candidate_id": candidate_id,
                }
            if result["valid"]:
                seed_id = str(candidate.get("source_seed_id", "")).strip()
                if seed_id not in static_seed_ids:
                    result = {
                        "valid": False,
                        "reason": "unknown_source_seed_id",
                        "candidate_id": candidate_id,
                    }
                elif str(candidate.get("source", "llm_generated")) == "static_seed" and (
                    candidate_id != seed_id
                    or payload_value != canonical_static_payloads.get(seed_id)
                ):
                    result = {
                        "valid": False,
                        "reason": "invalid_static_seed_provenance",
                        "candidate_id": candidate_id,
                    }
            if result["valid"]:
                seen_payloads.add(payload_value)
                candidate["validation"] = result
                valid.append(candidate)
            else:
                rejected.append(result)
        return valid, rejected

    valid, rejected = _collect_candidates(raw_candidates)
    generated_attempted = (
        str(state.get("payload_mode", "static_only")).strip().lower()
        in {"hybrid", "llm_mutation_only"}
        and any(
            str(candidate.get("source", "llm_generated")) != "static_seed"
            for candidate in raw_candidates
            if isinstance(candidate, dict)
        )
    )
    fallback_used = False
    if not valid and generated_attempted:
        fallback_valid, fallback_rejected = _collect_candidates(canonical_seed_candidates)
        if fallback_valid:
            valid = fallback_valid
            rejected.extend(fallback_rejected)
            fallback_used = True

    max_total = int(profile.get("max_total_candidates", state.get("candidate_budget", 5)) or 5)
    ranked = rank_candidates(valid, max_total)
    update = {
        "payload_candidates": {method: ranked},
        "payload_validation_results": {method: [*rejected, *[c["validation"] for c in ranked]]},
        "payload_provenance": {
            str(candidate["candidate_id"]): {
                "source": candidate.get("source", "llm_generated"),
                "source_seed_id": candidate.get("source_seed_id"),
                "mutation_type": candidate.get("mutation_type"),
                "method": method,
                "target_param": candidate.get("target_param"),
                "expected_signal": candidate.get("expected_signal"),
            }
            for candidate in ranked
        },
    }
    if fallback_used:
        update["fallback_events"] = [{
            "event": "payload_validation.static_seed_fallback",
            "method": method,
            "payload_mode": str(state.get("payload_mode", "static_only")),
            "reason": "no_valid_generated_candidates",
        }]
    if not ranked and state.get("target_method") == method:
        update.update({
            "next_agent": "scorer",
            "task_result": "INCOMPLETE",
            "incomplete_reason": "NO_VALID_PAYLOADS",
            "fallback_events": [{
                "event": "target_method.no_valid_payloads",
                "target_method": method,
            }],
        })
    return update


def payload_validator_node(state: dict[str, Any]) -> dict[str, Any]:
    """Executes payload validation in the LangGraph workflow.

    Reads:
        Selected method, payload candidates, generated payloads, payload provenance,
        AKG payload profile, and candidate budget fields.

    Writes:
        Payload validation results and ranked valid candidates for the selected
        method.

    Routing:
        Downstream graph routing sends valid candidates to the method agent or no
        valid candidates to the chaining router.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update with validation results."""
    return validate_payload_candidates(state)
