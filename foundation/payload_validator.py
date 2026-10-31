"""Payload candidate validation, origin containment, and exploit-queue budgeting.

The validator is the hard boundary between a generated or static candidate and
the HTTP queue.  It enforces, in one place:

* method/parameter/scope/resource/schema containment;
* the trusted origin contract: a seed-origin candidate binds a real supplied
  canonical seed, a Template candidate binds a real neutral template id/version/
  hash and never a fabricated seed id;
* one versioned per-visit budget for distinct exploit/bypass candidate IDs
  across all origins, independent of detection and verification controls;
* explicit lifecycle facts for valid/queued/rejected/budget-excluded candidates;
* a strict-mode no-candidate outcome that never revives a seed, a stale visit
  candidate, or a chain-derived substitute.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote, urlparse

from core.knowledge_graph import get_attack_knowledge_graph
from core.payload_policy import (
    BUDGET_EXCLUSION_REASON,
    CONTROL_POLICY_VERSION,
    EVENT_MODEL_BUDGET_EXCLUDED,
    EVENT_STATIC_FALLBACK,
    EVENT_TARGET_NO_VALID_PAYLOADS,
    EVENT_VALIDATION_NO_USABLE,
    EVENT_VALIDATION_STRICT_NO_CANDIDATE,
    EXPLOIT_STAGES,
    LEGACY_CONTROL_POLICY_VERSION,
    MUTATION_PROMPT_ID,
    ORIGIN_KINDS,
    PAYLOAD_POLICY_BASIS_HISTORICAL,
    PAYLOAD_POLICY_BASIS_LIVE,
    PAYLOAD_POLICY_BASIS_STATE_KEY,
    PAYLOAD_POLICY_VERSION,
    PAYLOAD_SCHEMA_VERSION,
    QUEUE_ROLE_DETECTION,
    QUEUE_ROLE_EXPLOIT,
    REASON_BUDGET_EXCLUDED_MODEL,
    REASON_MISSING_POLICY_IDENTITY,
    REASON_MISSING_PROMPT_SEEDS,
    REASON_NO_SUPPLIED_SEED,
    REASON_PROBE_SEED_PROVENANCE,
    REASON_SEED_NOT_SUPPLIED,
    RECORDED_POLICY_STATE_KEY,
    TEMPLATE_MUTATION_TYPE,
    control_snapshot_policy_version,
    expected_origin_kind,
    exploit_queue_limit,
    generation_opportunity,
    is_exploit_stage,
    is_provider_failure_reason,
    is_strict_mode,
    lifecycle_fact,
    origin_kind_permitted,
    require_payload_mode,
    requires_model_candidate,
    resolve_policy_basis,
)
from evaluation.scoring_evidence import evidence_hash
from foundation.payload_library import PayloadLibrary
from foundation.payload_ranker import rank_candidates
from foundation.payload_templates import TEMPLATE_REGISTRY, validate_template_reference


_BASE_REQUIRED_FIELDS = {
    "candidate_id",
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
_CREDENTIAL_PREFIX = re.compile(r"^\s*([^:,;\s]+)\s*:\s*([^,;\s]+)")
_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_BENCHMARK_CALL = re.compile(r"\bbenchmark\s*\(", re.IGNORECASE)
_SLEEP_CALL = re.compile(r"\bsleep\s*\(\s*([^,)]*)", re.IGNORECASE)
_MAX_SAFE_DELAY_SECONDS = 5.0


def allowed_target_params(method: str, profile: dict | None = None) -> set[str]:
    """Returns target parameters allowed by the AKG payload profile for a method."""
    profile = profile if profile is not None else get_attack_knowledge_graph().get_payload_profile(method)
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


def bounded_sleep_delays(payload: str) -> list[float]:
    """Parse bounded delay calls, raising ValueError for unsafe resource cost.

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
    normalized = _SQL_BLOCK_COMMENT.sub(" ", normalized)

    if _BENCHMARK_CALL.search(normalized):
        raise ValueError("unsafe_resource_cost")

    delays: list[float] = []
    for match in _SLEEP_CALL.finditer(normalized):
        try:
            seconds = float(match.group(1).strip())
        except (TypeError, ValueError) as exc:
            raise ValueError("unsafe_resource_cost") from exc
        if not math.isfinite(seconds) or not 0 <= seconds <= _MAX_SAFE_DELAY_SECONDS:
            raise ValueError("unsafe_resource_cost")
        delays.append(seconds)
    return delays


def _unsafe_resource_reason(payload: str) -> str | None:
    try:
        bounded_sleep_delays(payload)
    except ValueError:
        return "unsafe_resource_cost"
    return None


def declared_origin_kind(candidate: dict[str, Any]) -> str:
    """Return the candidate's origin kind, deriving it for legacy rows only.

    New candidates always carry ``origin_kind`` assigned by the runtime.  A
    legacy artifact row is read from its recorded ``source`` string so old
    evidence keeps a documented meaning instead of being reinterpreted.
    """
    kind = str(candidate.get("origin_kind") or "").strip()
    if kind:
        return kind
    source = str(candidate.get("source") or "")
    if source == "static_seed":
        return "static_seed"
    if source == "chain_derived":
        return "chain_derived"
    if source in {"derived_control", "control"}:
        return "derived_control"
    return "seed_mutation"


def _template_feasibility(method: str, security_level: str) -> dict[str, Any]:
    template = TEMPLATE_REGISTRY.get((method, str(security_level).lower()))
    if not template:
        return {}
    return dict(template.get("feasibility") or {})


def _validate_origin(
    candidate: dict[str, Any],
    *,
    method: str,
    security_level: str,
    mode: str | None,
    visit_id: str | None,
    basis: str,
    enforce_current_identity: bool,
    canonical_seed_payloads: dict[str, str],
    canonical_stage_by_id: dict[str, str],
    visible_seed_ids: list[str] | None,
    recorded_policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate trusted origin, template/seed provenance, and policy identity.

    ``basis="live"`` is fail-closed: origin kind, current policy version, current
    visit identity and the recorded prompt-visible seed set are required.
    ``basis="historical"`` is available only when a reader passes the recorded
    policy explicitly; it validates against the recorded template registry and
    the canonical seed stage, and never infers history from missing fields.
    """
    historical = basis == PAYLOAD_POLICY_BASIS_HISTORICAL
    kind = str(candidate.get("origin_kind") or "").strip()
    if not kind:
        if not historical and enforce_current_identity:
            return {"valid": False, "reason": REASON_MISSING_POLICY_IDENTITY}
        kind = declared_origin_kind(candidate)
    if kind not in ORIGIN_KINDS:
        return {"valid": False, "reason": "unknown_origin_kind"}
    if mode is not None and not origin_kind_permitted(mode, kind):
        return {"valid": False, "reason": "origin_not_permitted_for_mode"}
    if historical:
        recorded_version = str(recorded_policy.get("policy_version") or "")
        declared_version = str(candidate.get("policy_version") or "")
        if recorded_version and declared_version and declared_version != recorded_version:
            return {"valid": False, "reason": "stale_payload_policy_version"}
    elif enforce_current_identity:
        if str(candidate.get("policy_version") or "") != PAYLOAD_POLICY_VERSION:
            return {"valid": False, "reason": "stale_payload_policy_version"}
        if visit_id is not None and candidate.get("visit_id") != visit_id:
            return {"valid": False, "reason": "stale_visit_candidate"}
    if kind == "template_generation":
        if str(candidate.get("source_seed_id") or "").strip():
            return {"valid": False, "reason": "fabricated_source_seed_id"}
        registry = recorded_policy.get("template_registry") if historical else None
        issues = validate_template_reference(
            candidate.get("origin_ref"),
            method,
            security_level,
            registry=registry,
            recorded_registry_required=historical,
        )
        if issues:
            return {"valid": False, "reason": str(issues[0].get("reason"))}
        if not historical:
            feasibility = _template_feasibility(method, security_level)
            if feasibility.get("status") == "unsupported":
                return {"valid": False, "reason": "template_infeasible"}
        return {"valid": True, "reason": "ok"}
    seed_id = str(candidate.get("source_seed_id") or "").strip()
    if not seed_id:
        return {"valid": False, "reason": "missing_source_seed_id"}
    if seed_id not in canonical_seed_payloads:
        return {"valid": False, "reason": "unknown_source_seed_id"}
    if canonical_stage_by_id.get(seed_id) not in EXPLOIT_STAGES:
        return {"valid": False, "reason": REASON_PROBE_SEED_PROVENANCE}
    if kind == "static_seed":
        if str(candidate.get("payload_or_logic", "")) != canonical_seed_payloads.get(seed_id):
            return {"valid": False, "reason": "invalid_static_seed_provenance"}
    elif kind == "seed_mutation" and not historical:
        if visible_seed_ids is None:
            return {"valid": False, "reason": REASON_MISSING_PROMPT_SEEDS}
        if seed_id not in set(visible_seed_ids):
            return {"valid": False, "reason": REASON_SEED_NOT_SUPPLIED}
    canonical_id = candidate.get("equals_canonical_seed_id")
    if canonical_id is not None and str(canonical_id) not in canonical_seed_payloads:
        return {"valid": False, "reason": "invalid_canonical_seed_reference"}
    if "copy_of_supplied_seed" in candidate and not isinstance(
        candidate.get("copy_of_supplied_seed"), bool
    ):
        return {"valid": False, "reason": "invalid_copy_evidence"}
    return {"valid": True, "reason": "ok"}


def validate_candidate(
    candidate: dict[str, Any],
    method: str,
    profile: dict[str, Any],
    *,
    mode: str | None = None,
    security_level: str = "low",
    visit_id: str | None = None,
    basis: str = PAYLOAD_POLICY_BASIS_LIVE,
    enforce_current_identity: bool = False,
    canonical_seed_payloads: dict[str, str] | None = None,
    canonical_stage_by_id: dict[str, str] | None = None,
    visible_seed_ids: list[str] | None = None,
    recorded_policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validates one payload candidate against method profile and origin rules.

    Args:
        candidate: Candidate payload metadata to validate.
        method: Selected static method agent.
        profile: AKG payload profile for the method.
        mode: Payload mode when the caller has one; enables the mode/origin gate.
        security_level: Fixture level used for template and canonical-seed scope.
        visit_id: Current visit identity for the live stale-candidate gate.
        basis: ``live`` (default) or explicit ``historical`` replay contract.
        enforce_current_identity: Require current policy/visit identity (queue path).
        canonical_seed_payloads: Canonical seed id -> payload for the method/level.
        canonical_stage_by_id: Canonical seed id -> recorded stage.
        visible_seed_ids: Exact prompt-visible seed ids for this visit, if recorded.
        recorded_policy: Recorded policy/template snapshot for historical replay.

    Returns:
        Validation result describing whether the candidate is accepted and why."""
    if not isinstance(candidate, dict):
        return {"valid": False, "reason": "not_a_dict", "candidate": candidate}

    missing = sorted(_BASE_REQUIRED_FIELDS - set(candidate))
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
    if target_param not in allowed_target_params(method, profile):
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

    if canonical_seed_payloads is None or canonical_stage_by_id is None:
        canonical_rows = PayloadLibrary().load_seed_candidates(method, security_level)
        if canonical_seed_payloads is None:
            canonical_seed_payloads = {
                str(row.get("candidate_id")): str(row.get("payload_or_logic", ""))
                for row in canonical_rows
                if isinstance(row, dict) and row.get("candidate_id")
            }
        if canonical_stage_by_id is None:
            canonical_stage_by_id = {
                str(row.get("candidate_id")): str(row.get("stage") or "")
                for row in canonical_rows
                if isinstance(row, dict) and row.get("candidate_id")
            }
    origin_result = _validate_origin(
        candidate,
        method=method,
        security_level=security_level,
        mode=mode,
        visit_id=visit_id,
        basis=basis,
        enforce_current_identity=enforce_current_identity,
        canonical_seed_payloads=canonical_seed_payloads,
        canonical_stage_by_id=canonical_stage_by_id,
        visible_seed_ids=visible_seed_ids,
        recorded_policy=recorded_policy or {},
    )
    if origin_result["valid"] is not True:
        return {
            "valid": False,
            "reason": origin_result["reason"],
            "candidate_id": candidate.get("candidate_id"),
            "origin_kind": declared_origin_kind(candidate),
        }

    mutation = str(candidate.get("mutation_type", ""))
    origin_kind = declared_origin_kind(candidate)
    if mutation in set(profile.get("forbidden_mutation_types", [])):
        return {
            "valid": False,
            "reason": "forbidden_mutation_type",
            "candidate_id": candidate.get("candidate_id"),
        }
    if origin_kind == "template_generation":
        # A template candidate is a construction, not a seed mutation, so the
        # seed-mutation allowlist does not apply; its label is fixed instead.
        if mutation != TEMPLATE_MUTATION_TYPE:
            return {
                "valid": False,
                "reason": "invalid_template_mutation_type",
                "candidate_id": candidate.get("candidate_id"),
            }
    elif origin_kind != "static_seed" and mutation not in set(profile.get("allowed_mutation_types", [])):
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

    result: dict[str, Any] = {"valid": True, "reason": "ok", "candidate_id": candidate.get("candidate_id")}
    if declared_origin_kind(candidate) == "template_generation":
        result["template_feasibility"] = _template_feasibility(method, security_level)
    return result


def _rejection_row(
    candidate: dict[str, Any], result: dict[str, Any], method: str
) -> dict[str, Any]:
    """Return a validation row that keeps origin evidence on rejections."""
    row = {
        "candidate_id": result.get("candidate_id") or candidate.get("candidate_id"),
        "valid": False,
        "reason": str(result.get("reason") or "rejected"),
        "method": method,
        "origin_kind": candidate.get("origin_kind") or declared_origin_kind(candidate),
        "copy_of_supplied_seed": bool(candidate.get("copy_of_supplied_seed")),
        "equals_canonical_seed_id": candidate.get("equals_canonical_seed_id"),
    }
    if candidate.get("origin_ref"):
        row["origin_ref"] = dict(candidate.get("origin_ref") or {})
    if candidate.get("feasibility"):
        row["feasibility"] = dict(candidate.get("feasibility") or {})
    return row


def _provenance_update(
    candidate: dict[str, Any], method: str, *, validation: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Merge durable provenance for one candidate (never drops origin fields)."""
    kind = candidate.get("origin_kind") or declared_origin_kind(candidate)
    row = {
        "source": candidate.get("source", "llm_generated"),
        "origin_kind": kind,
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
    # Preserve the builder's frozen ordering identity; a historical artifact
    # without it stays without it rather than claiming today's policy.
    for order_field in ("candidate_order_policy", "candidate_order_policy_version"):
        order_value = candidate.get(order_field)
        if order_value:
            row[order_field] = order_value
    if kind == "template_generation":
        row.pop("source_seed_id", None)
        row["feasibility"] = dict(candidate.get("feasibility") or {})
    if validation is not None:
        row["validation"] = dict(validation)
    return row


def _generation_prompt_for_visit(
    state: dict[str, Any], method: str, visit_id: str | None
) -> dict[str, Any]:
    """Return the latest payload-generation prompt event for this visit."""
    for event in reversed(state.get("generation_prompts", []) or []):
        if not isinstance(event, dict):
            continue
        if event.get("method") == method and event.get("visit_id") == visit_id:
            return event
    return {}


def _generation_opportunity_for_visit(
    state: dict[str, Any], method: str, visit_id: str | None
) -> dict[str, Any]:
    """Return the generation receipt for this visit, if one was recorded."""
    for row in reversed(state.get("model_call_requirements", []) or []):
        if not isinstance(row, dict):
            continue
        if (
            row.get("role") != "payload_generator"
            or str(row.get("receipt_stage") or "generation") != "generation"
        ):
            continue
        if row.get("method") == method and row.get("visit_id") == visit_id:
            return row
    return {}


def validate_payload_candidates(
    state: dict[str, Any], *, policy_basis: str | None = None
) -> dict[str, Any]:
    """Validates, deduplicates, budgets, and ranks exploit candidates.

    ``policy_basis`` is explicit: live runs validate against the current epoch,
    and only a replay reader may pass ``"historical"`` (plus the recorded policy
    in state) to use the artifact's frozen contract.  Missing fields are never
    treated as evidence that a queue is historical.

    Args:
        state: Current shared LangGraph state containing the selected method,
            payload mode, payload candidate map, provenance, and budget.
        policy_basis: Explicit validation basis supplied by a replay reader.

    Returns:
        Partial state update with validation results, the ranked exploit queue,
        provenance, lifecycle facts, generation validation receipts, and
        explicit failure events."""
    method = str(state.get("selected_method") or state.get("next_agent") or "")
    if not method:
        return {"payload_validation_results": {"unknown": [{"valid": False, "reason": "missing_method"}]}}

    kg = get_attack_knowledge_graph()
    profile = kg.get_payload_profile(method)
    mode = require_payload_mode(state.get("payload_mode"))
    basis = resolve_policy_basis(
        policy_basis if policy_basis is not None else state.get(PAYLOAD_POLICY_BASIS_STATE_KEY)
    )
    historical = basis == PAYLOAD_POLICY_BASIS_HISTORICAL
    recorded_policy = state.get(RECORDED_POLICY_STATE_KEY)
    recorded_policy = recorded_policy if isinstance(recorded_policy, Mapping) else {}
    security_level = str(state.get("security_level", "low"))
    visit_id = state.get("selected_visit_id")
    queue_limit = exploit_queue_limit(state.get("candidate_budget"), profile)
    raw_candidates = [
        dict(candidate)
        for candidate in state.get("payload_candidates", {}).get(method, [])
        if isinstance(candidate, dict)
    ]
    active = state.get("active_payload_candidates", {}).get(method)
    if active is not None:
        pending_ids = set(active.get("candidate_ids", [])) if active.get("visit_id") == visit_id else set()
        raw_candidates = [candidate for candidate in raw_candidates if candidate.get("candidate_id") in pending_ids]

    canonical_rows = PayloadLibrary().load_seed_candidates(method, security_level)
    canonical_payloads = {
        str(row.get("candidate_id")): str(row.get("payload_or_logic", ""))
        for row in canonical_rows
        if isinstance(row, dict) and row.get("candidate_id")
    }
    canonical_stage_by_id = {
        str(row.get("candidate_id")): str(row.get("stage") or "")
        for row in canonical_rows
        if isinstance(row, dict) and row.get("candidate_id")
    }
    strict_mode = is_strict_mode(mode)
    opportunity = _generation_opportunity_for_visit(state, method, visit_id)
    prompt_event = _generation_prompt_for_visit(state, method, visit_id)
    expected_call_id = opportunity.get("call_id")
    visible_seed_ids = (
        None if historical
        else [str(value) for value in (prompt_event.get("prompt_visible_seed_ids") or [])]
    )

    valid: list[dict] = []
    rejected: list[dict] = []
    detection_rows: list[dict] = []
    seen_ids: set[str] = set()
    seen_payloads: set[str] = set()
    for candidate in raw_candidates:
        candidate.setdefault("method", method)
        candidate_id = str(candidate.get("candidate_id", ""))
        if not candidate_id or candidate_id in seen_ids:
            rejected.append({
                "candidate_id": candidate_id or None,
                "valid": False,
                "reason": "duplicate_or_missing_candidate_id",
                "method": method,
            })
            continue
        seen_ids.add(candidate_id)
        if not is_exploit_stage(candidate.get("stage", "exploit")):
            # Detection probes are controls, not exploit candidates.  They never
            # consume the exploit budget and never enter its denominator.
            detection_rows.append({
                "candidate_id": candidate_id,
                "valid": False,
                "reason": "probe_is_detection_control",
                "queue_role": QUEUE_ROLE_DETECTION,
                "method": method,
                # Canonical probe rows are trusted static detection controls;
                # never label them as model mutations in the lifecycle fact.
                "origin_kind": declared_origin_kind(candidate),
            })
            continue
        result = validate_candidate(
            candidate,
            method,
            profile,
            mode=mode,
            security_level=security_level,
            visit_id=visit_id,
            basis=basis,
            enforce_current_identity=not historical,
            canonical_seed_payloads=canonical_payloads,
            canonical_stage_by_id=canonical_stage_by_id,
            visible_seed_ids=visible_seed_ids,
            recorded_policy=recorded_policy,
        )
        payload_value = str(candidate.get("payload_or_logic", ""))
        if result["valid"] and payload_value in seen_payloads:
            result = {
                "valid": False,
                "reason": "duplicate_payload_or_logic",
                "candidate_id": candidate_id,
            }
        if (result["valid"] and not historical
                and declared_origin_kind(candidate) in {"seed_mutation", "template_generation"}):
            bound_call = candidate.get("model_call_id")
            if not expected_call_id:
                result = {
                    "valid": False,
                    "reason": "model_call_receipt_missing",
                    "candidate_id": candidate_id,
                }
            elif bound_call != expected_call_id:
                result = {
                    "valid": False,
                    "reason": "model_call_mismatch",
                    "candidate_id": candidate_id,
                }
        if result["valid"]:
            seen_payloads.add(payload_value)
            candidate["validation"] = result
            valid.append(candidate)
        else:
            rejected.append(_rejection_row(candidate, result, method))

    ranked = rank_candidates(valid, queue_limit, mode=mode)
    ranked_ids = {str(candidate.get("candidate_id")) for candidate in ranked}
    budget_excluded = [
        candidate for candidate in valid
        if str(candidate.get("candidate_id")) not in ranked_ids
    ]
    rejected.extend(
        {
            "candidate_id": candidate.get("candidate_id"),
            "valid": False,
            "reason": BUDGET_EXCLUSION_REASON,
            "method": method,
            "queue_role": QUEUE_ROLE_EXPLOIT,
            "origin_kind": candidate.get("origin_kind") or declared_origin_kind(candidate),
        }
        for candidate in budget_excluded
    )

    lifecycle: list[dict] = []
    for candidate in valid:
        lifecycle.append(lifecycle_fact(
            method=method,
            visit_id=visit_id,
            candidate_id=str(candidate.get("candidate_id")),
            origin_kind=declared_origin_kind(candidate),
            status="valid",
            reason="ok",
        ))
    for candidate in ranked:
        lifecycle.append(lifecycle_fact(
            method=method,
            visit_id=visit_id,
            candidate_id=str(candidate.get("candidate_id")),
            origin_kind=declared_origin_kind(candidate),
            status="queued",
            reason=None,
        ))
    for candidate in budget_excluded:
        lifecycle.append(lifecycle_fact(
            method=method,
            visit_id=visit_id,
            candidate_id=str(candidate.get("candidate_id")),
            origin_kind=declared_origin_kind(candidate),
            status="budget_excluded",
            reason=BUDGET_EXCLUSION_REASON,
        ))
    for row in [*rejected, *detection_rows]:
        candidate_id = row.get("candidate_id")
        if not candidate_id:
            continue
        if row.get("reason") == BUDGET_EXCLUSION_REASON:
            # Budget exclusion already emitted its own lifecycle fact.
            continue
        origin_kind = str(row.get("origin_kind") or "")
        if origin_kind not in ORIGIN_KINDS:
            origin_kind = expected_origin_kind(mode) or "seed_mutation"
        lifecycle.append(lifecycle_fact(
            method=method,
            visit_id=visit_id,
            candidate_id=str(candidate_id),
            origin_kind=origin_kind,
            status="rejected",
            reason=str(row.get("reason") or "rejected"),
        ))

    update: dict[str, Any] = {
        "payload_candidates": {method: ranked},
        "payload_validation_results": {
            method: [
                {**row, "visit_id": visit_id, "queue_role": row.get("queue_role", QUEUE_ROLE_EXPLOIT)}
                for row in [*rejected, *[candidate["validation"] for candidate in ranked]]
            ]
        },
        "payload_provenance": {
            str(candidate["candidate_id"]): _provenance_update(
                {**state.get("payload_provenance", {}).get(str(candidate["candidate_id"]), {}), **candidate},
                method,
                validation=candidate.get("validation"),
            )
            for candidate in ranked
        },
        "candidate_lifecycle": lifecycle,
    }

    model_candidate_ids = {
        str(candidate.get("candidate_id"))
        for candidate in ranked
        if declared_origin_kind(candidate) in {"seed_mutation", "template_generation"}
    }
    # Validity is recorded separately from queueing: a model candidate can be
    # valid yet budget-excluded, and that must not look like an invalid output.
    validated_model_ids = sorted(
        str(candidate.get("candidate_id"))
        for candidate in valid
        if declared_origin_kind(candidate) in {"seed_mutation", "template_generation"}
    )
    if opportunity and requires_model_candidate(mode):
        generation_event = prompt_event
        update.setdefault("model_call_requirements", []).append(
            generation_opportunity(
                method=method,
                visit_id=visit_id,
                mode=mode,
                required=bool(opportunity.get("required", True)),
                status=str(opportunity.get("status") or "completed"),
                reason=opportunity.get("reason"),
                call_id=expected_call_id,
                prompt_id=str(
                    generation_event.get("prompt_id")
                    or opportunity.get("prompt_id")
                    or MUTATION_PROMPT_ID
                ),
                schema_version=str(
                    generation_event.get("schema_version")
                    or opportunity.get("schema_version")
                    or PAYLOAD_SCHEMA_VERSION
                ),
                origin_kind=expected_origin_kind(mode),
                opportunity_id=str(opportunity.get("opportunity_id") or "") or None,
                receipt_stage="validation",
                parsed_candidate_ids=list(opportunity.get("parsed_candidate_ids") or []),
                valid_candidate_ids=validated_model_ids,
                failure_reason_detail=opportunity.get("failure_reason_detail"),
            )
        )

    fallback_events: list[dict] = []
    strict_no_candidate = False
    absence_reasons = {REASON_NO_SUPPLIED_SEED, "candidate_budget_zero", "template_unavailable"}
    if not ranked:
        generation_reason = str(
            prompt_event.get("failure_reason")
            or opportunity.get("reason")
            or ""
        ).strip()
        provider_failure = is_provider_failure_reason(generation_reason)
        absence = generation_reason in absence_reasons
        if strict_mode and not absence and not provider_failure:
            # Strict, but the model returned something unusable: graded output
            # failure, with the call identity that produced it.
            strict_no_candidate = True
            fallback_events.append({
                "event": EVENT_VALIDATION_STRICT_NO_CANDIDATE,
                "method": method,
                "payload_mode": mode,
                "visit_id": visit_id,
                "reason": generation_reason or (
                    "no_candidates_generated" if not raw_candidates else "no_valid_generated_candidates"
                ),
                "origin_kind": expected_origin_kind(mode),
                "role": "payload_generator",
                "call_id": expected_call_id,
            })
        else:
            # Absence/infeasibility or an operational provider failure: null,
            # never an unusable-model-output zero.
            fallback_events.append({
                "event": EVENT_VALIDATION_NO_USABLE,
                "method": method,
                "payload_mode": mode,
                "visit_id": visit_id,
                "reason": generation_reason or "no_usable_candidate",
                "origin_kind": None,
                "provider_failure": provider_failure,
                "absence": absence,
            })
    elif mode == "hybrid" and not model_candidate_ids:
        generation_reason = str(
            prompt_event.get("failure_reason")
            or opportunity.get("reason")
            or ""
        ).strip()
        if validated_model_ids:
            # A valid model candidate exists but the per-visit budget kept it
            # out of the queue: that is not a generation failure and earns no
            # static-fallback credit.
            fallback_events.append({
                "event": EVENT_MODEL_BUDGET_EXCLUDED,
                "method": method,
                "payload_mode": mode,
                "visit_id": visit_id,
                "reason": REASON_BUDGET_EXCLUDED_MODEL,
                "role": "payload_generator",
                "origin_kind": "seed_mutation",
                "candidate_ids": list(validated_model_ids),
                "provider_failure": False,
            })
        else:
            generated_ids = {
                str(candidate.get("candidate_id"))
                for candidate in state.get("generated_payloads", {}).get(method, []) or []
                if isinstance(candidate, dict) and candidate.get("candidate_id")
            }
            if not generation_reason:
                generation_reason = (
                    "no_valid_generated_candidates" if generated_ids else "static_coverage"
                )
            fallback_events.append({
                "event": EVENT_STATIC_FALLBACK,
                "method": method,
                "payload_mode": mode,
                "visit_id": visit_id,
                "reason": generation_reason,
                "role": "payload_generator",
                "origin_kind": "static_seed",
                "candidate_ids": [str(candidate.get("candidate_id")) for candidate in ranked],
                "provider_failure": is_provider_failure_reason(generation_reason),
            })

    scope_rejections = [row for row in rejected if row.get("reason") == "out_of_scope_target"]
    if scope_rejections:
        update["containment_events"] = [{**row, "kind": "payload",
            "classification": "scope_violation", "origin": "payload_validator", "scope": "method",
            "method": method, "visit_id": visit_id} for row in scope_rejections]
    if fallback_events:
        update["fallback_events"] = [{**row, "origin": "payload_validator", "scope": "method",
            "visit_id": visit_id} for row in fallback_events]
    if not ranked and state.get("target_method") == method:
        update.update({
            "next_agent": "scorer",
            "task_result": "INCOMPLETE",
            "incomplete_reason": "NO_VALID_PAYLOADS",
            "fallback_events": [*update.get("fallback_events", []), {
                "event": EVENT_TARGET_NO_VALID_PAYLOADS,
                "target_method": method,
                "method": method,
                "visit_id": visit_id,
                "payload_mode": mode,
                "reason": "NO_VALID_PAYLOADS",
                "role": "payload_generator",
                "origin": "payload_validator",
                "scope": "method",
                "origin_kind": expected_origin_kind(mode),
                "strict_no_candidate": strict_no_candidate,
            }],
        })
    return update


def freeze_probe_controls(
    state: dict[str, Any], method: str, visit_id: str | None = None
) -> dict[str, Any]:
    """Freeze this visit's detection controls through the versioned catalog.

    Fail closed: an unfreezable catalog yields an empty, explicitly invalid
    control snapshot so the visit makes no detection requests and never falls
    back to an implicit static probe list.
    """
    from foundation.control_catalog import freeze_detection_controls

    try:
        return freeze_detection_controls(state, method, visit_id)
    except Exception as exc:  # noqa: BLE001 - fail closed on catalog failure
        return {
            "visit_id": visit_id,
            "method": method,
            "policy_version": CONTROL_POLICY_VERSION,
            "candidates": [],
            "sha256": evidence_hash([]),
            "validation_results": [{
                "valid": False,
                "reason": "detection_control_freeze_failed",
                "detail": f"{type(exc).__name__}: {exc}",
            }],
            "quarantined": False,
            "quarantine_reason": "detection_control_freeze_failed",
        }


def validate_probe_controls(state: dict[str, Any], controls: dict) -> list[dict]:
    """Validate saved detection controls without restoring missing local seeds.

    Dispatch is by the snapshot's recorded policy version.  Legacy snapshots
    must still be the complete ordered canonical probe set; versioned catalog
    snapshots are validated by the control catalog itself, which owns request
    budgets and quarantine.  Controls never consume the exploit candidate
    budget or enter its denominator.
    """
    method = str(state.get("selected_method") or "")
    if not method:
        return [{"valid": False, "reason": "probe_control_missing_method"}]
    if not isinstance(controls, dict) or controls.get("visit_id") != state.get("selected_visit_id"):
        return [{"valid": False, "reason": "probe_control_visit_mismatch"}]
    policy_version = control_snapshot_policy_version(controls)
    if policy_version != LEGACY_CONTROL_POLICY_VERSION:
        from foundation.control_catalog import validate_detection_controls

        try:
            return validate_detection_controls(state, method, controls)
        except Exception as exc:  # noqa: BLE001 - fail closed on catalog failure
            return [{
                "valid": False,
                "reason": "detection_control_validation_failed",
                "detail": f"{type(exc).__name__}: {exc}",
            }]
    rows = controls.get("candidates")
    if not isinstance(rows, list) or controls.get("sha256") != evidence_hash(rows):
        return [{"valid": False, "reason": "probe_control_hash_mismatch"}]
    canonical = [c for c in PayloadLibrary().load_seed_candidates(method, state.get("security_level", "low"))
                 if c.get("stage") == "probe"]
    if rows != canonical:
        return [{"valid": False, "reason": "probe_control_catalog_mismatch"}]
    profile = get_attack_knowledge_graph().get_payload_profile(method)
    return [_validate_legacy_probe_control(c, method, profile) for c in rows]


def _validate_legacy_probe_control(
    candidate: dict[str, Any],
    method: str,
    profile: dict[str, Any],
) -> dict[str, Any]:
    """Validate one canonical probe row of a complete legacy control snapshot.

    Legacy snapshots predate policy/origin identity and carry the full ordered
    canonical probe set.  They are detection controls, not exploit candidates,
    so the exploit-only seed-stage gate must not reject them; structural
    containment and method/profile fit still apply.
    """
    candidate_id = candidate.get("candidate_id")
    if not isinstance(candidate, dict) or str(candidate.get("stage")) != "probe":
        return {"valid": False, "reason": "probe_control_stage_invalid",
                "candidate_id": candidate_id}
    if str(candidate.get("method") or method) != method:
        return {"valid": False, "reason": "probe_control_method_mismatch",
                "candidate_id": candidate_id}
    payload = str(candidate.get("payload_or_logic") or "")
    if not payload.strip():
        return {"valid": False, "reason": "empty_payload", "candidate_id": candidate_id}
    unsafe = _unsafe_resource_reason(payload)
    if unsafe:
        return {"valid": False, "reason": unsafe, "candidate_id": candidate_id}
    if _is_out_of_scope(payload):
        return {"valid": False, "reason": "out_of_scope_target", "candidate_id": candidate_id}
    target_param = str(candidate.get("target_param", ""))
    if target_param not in allowed_target_params(method, profile):
        return {"valid": False, "reason": "wrong_target_param", "candidate_id": candidate_id}
    if method.startswith("bf_") and target_param == "credential_pair" and not _CREDENTIAL_PREFIX.match(payload):
        return {"valid": False, "reason": "invalid_credential_pair", "candidate_id": candidate_id}
    expected_signal = str(candidate.get("expected_signal", ""))
    if expected_signal not in set(profile.get("expected_success_signals", [])):
        return {"valid": False, "reason": "wrong_expected_signal", "candidate_id": candidate_id}
    return {"valid": True, "reason": "legacy_probe_control", "candidate_id": candidate_id}


def payload_validator_node(state: dict[str, Any]) -> dict[str, Any]:
    """Executes payload validation in the LangGraph workflow.

    Reads:
        Selected method, payload candidates, generated payloads, payload provenance,
        AKG payload profile, and candidate budget fields.

    Writes:
        Payload validation results, the ranked exploit queue, lifecycle facts,
        generation validation receipts, and this visit's frozen detection controls.

    Routing:
        Downstream graph routing sends valid candidates to the method agent or no
        valid candidates to the chaining router.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update with validation results."""
    update = validate_payload_candidates(state, policy_basis=PAYLOAD_POLICY_BASIS_LIVE)
    method = state.get("selected_method")
    queue = update.get("payload_candidates", {}).get(method, [])
    visit_id = state.get("selected_visit_id")
    update["payload_validation_results"] = {key: [dict(row, visit_id=visit_id) for row in rows]
        for key, rows in update.get("payload_validation_results", {}).items()}
    update["active_payload_candidates"] = {method: {"visit_id": visit_id,
        "candidate_ids": [candidate["candidate_id"] for candidate in queue], "status": "validated"}}
    if not queue:
        update["preparation_failures"] = [{"method": method, "visit_id": visit_id,
            "reason": "NO_VALID_PAYLOADS"}]
    # Freeze this visit's detection controls from the versioned catalog.  A
    # graph visit with no executable candidate never receives probe controls.
    controls = freeze_probe_controls(state, str(method), visit_id) if queue else {
        "visit_id": visit_id,
        "method": method,
        "policy_version": CONTROL_POLICY_VERSION,
        "candidates": [],
        "sha256": evidence_hash([]),
        "validation_results": [],
    }
    if controls.get("candidates") and not controls.get("validation_results"):
        controls["validation_results"] = validate_probe_controls(state, controls)
    update["probe_controls"] = {method: controls}
    route = state.get("active_chain_route") or {}
    if route.get("target_agent") == state.get("selected_method") == "bf_dictionary" and route.get("source") == "credentials_extracted":
        bindings = []
        for candidate in update.get("payload_candidates", {}).get("bf_dictionary", []):
            if candidate.get("stage") not in EXPLOIT_STAGES:
                continue
            parsed = _CREDENTIAL_PREFIX.match(str(candidate.get("payload_or_logic", "")))
            if not parsed:
                continue
            source = next((c for c in state.get("found_credentials", [])
                if c.get("representation") == "plaintext"
                and c.get("source_evidence_id") in route.get("source_evidence_ids", [])
                and c.get("source_candidate_id") and c.get("source_visit_id")
                and any(row.get("evidence_id") == c["source_evidence_id"]
                    and row.get("candidate_id") == c["source_candidate_id"]
                    and row.get("visit_id") == c["source_visit_id"]
                    for row in state.get("response_evidence", []))
                and (c.get("username"), c.get("password")) == parsed.groups()), None)
            if source:
                bindings.append({"candidate_id": candidate["candidate_id"],
                    "source_evidence_id": source["source_evidence_id"],
                    "source_visit_id": source["source_visit_id"], "representation": "plaintext"})
        update["active_chain_route"] = {**route, "source_bindings": bindings}
    update["telemetry_events"] = [{
        "node": "payload_validator",
        "event": "payload.validation.completed",
        "status": "ok",
        "payload": {"method": state.get("selected_method")},
    }]
    return update
