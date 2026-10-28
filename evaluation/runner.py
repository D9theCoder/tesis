"""Single-engagement Stage 6 evaluation runner."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections import Counter
from collections.abc import Mapping
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from traceback import format_exc
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler
from core.checkpoint_store import (
    ExperimentCheckpointStore,
    coordinate_fingerprint,
    default_graph_store_path,
    default_store_path,
    stable_thread_id,
    validate_checkpoint_identity,
    validate_resume,
)
from core.graph_builder import GRAPH_BUILD_VERSION, build_framework
from core.payload_policy import (
    BUDGET_POLICY_VERSION,
    CONTROL_POLICY_VERSION,
    EVENT_PROVIDER_FAILURE,
    EVENT_STATIC_FALLBACK,
    EXPERIMENT_POLICY_VERSION,
    PAYLOAD_POLICY_VERSION,
    is_provider_failure_reason,
    mode_display_label,
    normalize_payload_mode,
    is_supported_payload_mode,
    requires_model_candidate,
)
from core.workflow_policy import WORKFLOW_PROTOCOL_VERSION, workflow_progress
from agents.state_utils import candidate_budget_receipt, validated_payload_candidates
from foundation.session_manager import dvwa_credentials
from foundation.http_client import http_request_accounting, snapshot_http_request_counters
from core.knowledge_graph import AttackKnowledgeGraph, get_attack_knowledge_graph
from core.scorer import build_score_report
from core.state import (
    CHECKPOINT_SCHEMA_VERSION,
    STATE_SCHEMA_VERSION,
    new_default_state,
)
from evaluation.diagnostics import diagnose_quality
from evaluation.failure_logger import write_failure_artifact
from core.run_status import terminal_status, lifecycle_alias, reason as status_reason, FAILURE_REASONS
from evaluation.manual_scoring_sheet import manual_scoring_rows
from evaluation.reporter import (
    build_candidate_dispositions,
    link_exported_request_evidence,
    write_events_jsonl,
    write_json_report,
)
from evaluation.telemetry import RunTelemetry, stable_sha256
from llm.diagnostics import format_failure_line
from llm.runtime import (
    LLMRuntime,
    RoleSettings,
    build_failure_envelope,
    model_fingerprint,
)
from tesis.artifact_repository import config_fingerprint, new_execution_id
from tesis.runtime_events import (
    CancellationRequested,
    CancellationToken,
    RunEvent,
    RuntimeEventSink,
    normalize_stream_chunk,
    redact_secrets,
)


LLM_TOKEN_BATCH_INTERVAL = 0.05
LLM_TOKEN_BATCH_CHARS = 256

# Partial graph resume may only continue past pure internal nodes. Anything
# else (recon, orchestrator, payload_candidate_builder, method agents) may
# have external target/provider effects and must fail closed.
SAFE_RESUME_NODES = frozenset({"payload_validator", "chaining_router", "scorer"})


class _ResumeFailed(RuntimeError):
    """Internal fail-closed resume signal; converted to an error artifact."""


class _RuntimeCallbackHandler(BaseCallbackHandler):
    """Translate provider-independent LangChain callbacks into run events."""

    def __init__(self, emit, *, provider: str) -> None:
        self._emit = emit
        self._provider = provider
        self._streamed_runs: set[str] = set()
        self._chain_nodes: dict[str, str] = {}
        self._token_buffers: dict[str, list[str]] = {}
        self._token_buffer_chars: dict[str, int] = {}
        self._last_token_emit: dict[str, float] = {}

    def _emit_token_batch(self, call_id: str) -> None:
        parts = self._token_buffers.pop(call_id, [])
        self._token_buffer_chars.pop(call_id, None)
        if not parts:
            return
        self._emit("llm.token", message="".join(parts), data={
            "provider": self._provider,
            "call_id": call_id,
            "streaming": True,
            "chunk_count": len(parts),
        })
        self._last_token_emit[call_id] = perf_counter()

    @staticmethod
    def _chain_name(serialized: Any, kwargs: dict[str, Any]) -> str:
        name = kwargs.get("name")
        if not name and isinstance(serialized, dict):
            name = serialized.get("name") or serialized.get("id", [""])[-1]
        return str(name or "chain")

    def on_chain_start(self, serialized, inputs, *, run_id, **kwargs) -> None:
        node = self._chain_name(serialized, kwargs)
        self._chain_nodes[str(run_id)] = node
        self._emit("graph.node.started", node=node, message=f"{node} started", data={})

    def on_chain_end(self, outputs, *, run_id, **kwargs) -> None:
        node = self._chain_nodes.pop(str(run_id), str(kwargs.get("name") or "chain"))
        self._emit("graph.node.completed", node=node, message=f"{node} completed", data={})

    def on_chain_error(self, error: BaseException, *, run_id, **kwargs) -> None:
        node = self._chain_nodes.pop(str(run_id), str(kwargs.get("name") or "chain"))
        self._emit("graph.node.failed", node=node, message=str(error), data={
            "error_type": type(error).__name__,
        })

    def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs) -> None:
        prompts = [
            [getattr(message, "content", str(message)) for message in batch]
            for batch in messages
        ]
        self._emit("llm.started", message="Model call started", data={
            "provider": self._provider,
            "call_id": str(run_id),
            "prompts": prompts,
        })

    def on_llm_new_token(self, token: str, *, run_id, chunk=None, **kwargs) -> None:
        text = normalize_stream_chunk(chunk if chunk is not None else token)
        if not text:
            return
        call_id = str(run_id)
        self._streamed_runs.add(call_id)
        now = perf_counter()
        if call_id not in self._last_token_emit:
            # Show the first token immediately, then batch subsequent chunks to
            # avoid flooding event sinks and terminal renderers.
            self._emit("llm.token", message=text, data={
                "provider": self._provider,
                "call_id": call_id,
                "streaming": True,
                "chunk_count": 1,
            })
            self._last_token_emit[call_id] = now
            return

        self._token_buffers.setdefault(call_id, []).append(text)
        buffered_chars = self._token_buffer_chars.get(call_id, 0) + len(text)
        self._token_buffer_chars[call_id] = buffered_chars
        if (
            buffered_chars >= LLM_TOKEN_BATCH_CHARS
            or now - self._last_token_emit[call_id] >= LLM_TOKEN_BATCH_INTERVAL
        ):
            self._emit_token_batch(call_id)

    def on_llm_end(self, response, *, run_id, **kwargs) -> None:
        call_id = str(run_id)
        self._emit_token_batch(call_id)
        text = normalize_stream_chunk(response)
        self._emit("llm.completed", message=text or "Model call completed", data={
            "provider": self._provider,
            "call_id": call_id,
            "streaming": call_id in self._streamed_runs,
            "response": text,
        })
        self._streamed_runs.discard(call_id)
        self._last_token_emit.pop(call_id, None)

    def on_llm_error(self, error: BaseException, *, run_id, **kwargs) -> None:
        call_id = str(run_id)
        self._emit_token_batch(call_id)
        self._emit("llm.failed", message=str(error), data={
            "provider": self._provider,
            "call_id": call_id,
            "error_type": type(error).__name__,
        })
        self._streamed_runs.discard(call_id)
        self._last_token_emit.pop(call_id, None)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@lru_cache(maxsize=None)
def _akg_generated_candidate_limit(method: str) -> int | None:
    try:
        profile = get_attack_knowledge_graph().get_payload_profile(method) or {}
        return int(profile["max_generated_candidates"])
    except (KeyError, TypeError, ValueError):
        return None


def _candidate_event_data(state: dict[str, Any], configured_budget: int) -> dict[str, Any]:
    """Build dashboard counters without changing graph state."""
    method = str(state.get("selected_method") or "")
    generated = (state.get("generated_payloads", {}).get(method, ()) or ()) if method else ()
    accepted = validated_payload_candidates(state, method) if method else ()
    tried = (state.get("tried_payloads", {}).get(method, ()) or ()) if method else ()
    validation = (state.get("payload_validation_results", {}).get(method, ()) or ()) if method else ()
    reasons = Counter(
        str(row.get("reason") or row.get("rejection_reason") or "unspecified")
        for row in validation
        if isinstance(row, dict) and row.get("valid") is not True
    )
    akg_limit = _akg_generated_candidate_limit(method) if method else None
    akg_limit = akg_limit or configured_budget
    effective = min(configured_budget, akg_limit)
    return {
        "generated_candidates": len(generated),
        "generation_budget": effective,
        "generation_remaining": max(0, effective - len(generated)),
        "accepted_candidates": len(accepted),
        "tried_candidates": len({str(item) for item in tried}),
        "validation_failures": dict(reasons),
    }


def _llm_activity(events: list[dict[str, Any]], restored_receipts: list[dict] | None = None) -> dict[str, int]:
    """Summarize provider/runtime callback activity captured by the runner."""
    counts = Counter(str(event.get("event_type") or "") for event in events)
    runtime_events = [
        event
        for event in events
        if isinstance(event.get("data"), dict)
        and event["data"].get("source") == "llm_runtime"
        and event.get("event_type") in {"llm.started", "llm.completed", "llm.failed"}
    ]
    expected_output_failures = sum(
        1
        for event in runtime_events
        if event.get("event_type") == "llm.failed"
        and str(event["data"].get("parse_status")) in {"invalid", "incomplete"}
    )
    if runtime_events:
        # A runtime lifecycle event and a LangChain callback describe the same
        # provider call. Prefer the runtime stream as authoritative so one
        # call is not mistaken for a retry. Invalid/incomplete responses count
        # as completed attempts for activity accounting, but not as failures.
        started = sum(event.get("event_type") == "llm.started" for event in runtime_events)
        completed = sum(event.get("event_type") == "llm.completed" for event in runtime_events)
        failed = sum(event.get("event_type") == "llm.failed" for event in runtime_events)
        completed += expected_output_failures
        failed = max(0, failed - expected_output_failures)
    else:
        # Legacy/direct callers may expose only provider callbacks.
        started = counts["llm.started"]
        completed = counts["llm.completed"]
        failed = counts["llm.failed"]
    observed_ids = {event.get("data", {}).get("call_id") for event in runtime_events}
    restored = [row for row in restored_receipts or [] if row.get("call_id") not in observed_ids]
    started += len(restored)
    completed += sum(row.get("parse_status") in {"ok", "invalid", "incomplete"} for row in restored)
    failed += sum(row.get("parse_status") not in {"ok", "invalid", "incomplete"} for row in restored)
    return {
        "started": started,
        "completed": completed,
        # Invalid/incomplete structured output is an expected deterministic
        # fallback path. Provider/network failures remain authoritative.
        "failed": failed,
        "tokens": counts["llm.token"],
    }


def _effective_llm_runtime_config(
    context,
    *,
    candidate_budget: int,
) -> dict[str, Any]:
    """Describe the resolved, non-secret runtime settings for one coordinate."""
    role_defaults = {
        "orchestrator": 96,
        "payload_generator": min(512, 96 + 64 * int(candidate_budget)),
    }
    roles: dict[str, dict[str, Any]] = {}
    for role, default_tokens in role_defaults.items():
        provider, resolved, settings = context.role_config(role, max_tokens=default_tokens)
        roles[role] = {
            "model_profile": settings.model_profile or context.default_provider,
            "provider": provider,
            "model_name": resolved.get("model_name"),
            "temperature": resolved.get("temperature", 0),
            "max_tokens": int(resolved.get("max_tokens", default_tokens)),
            "structured_output": settings.structured_output,
            "reasoning_effort": resolved.get("reasoning_effort"),
            "rate_limit_retries": resolved.get("rate_limit_retries"),
            "rate_limit_retry_budget_s": resolved.get("rate_limit_retry_budget_s"),
            "model_fingerprint": model_fingerprint({"provider": provider, **resolved}),
        }
    return {
        "max_concurrency": int(context.runtime.max_concurrency),
        "rate_limit_retries": context.runtime.rate_limit_policy.retries,
        "rate_limit_retry_budget_s": context.runtime.rate_limit_policy.budget_s,
        "cache_scope": "run" if context.cache_enabled else "none",
        "roles": roles,
    }


def _orchestrator_failure(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the first model/runtime exception hidden by deterministic fallback."""
    for event in events:
        if event.get("event_type") != "orchestrator.fallback.applied":
            continue
        data = event.get("data")
        if isinstance(data, dict) and data.get("error_type"):
            return data
    return None


def _failure_for_run(
    records: list[Mapping[str, Any]],
    *,
    run_id: str,
    fallback: Mapping[str, Any] | None = None,
    provider: str,
    model_config: Mapping[str, Any] | None,
    coordinate_id: str,
) -> dict[str, Any] | None:
    """Return one canonical failure envelope for a provider-backed run."""
    for row in records:
        candidate = row.get("failure") if isinstance(row, Mapping) else None
        if isinstance(candidate, Mapping):
            return build_failure_envelope({**dict(row), **dict(candidate)}, run_id=run_id)
        parse_status = str(row.get("parse_status") or "").lower() if isinstance(row, Mapping) else ""
        if parse_status in {"provider_error", "invalid", "incomplete"}:
            return build_failure_envelope(row, run_id=run_id)

    if fallback is None:
        return None
    candidate = fallback.get("failure") if isinstance(fallback, Mapping) else None
    if isinstance(candidate, Mapping):
        envelope = dict(candidate)
        envelope["run_id"] = run_id
        return envelope

    config = dict(model_config or {})
    role = str(fallback.get("role") or "orchestrator")
    error_type = str(fallback.get("error_type") or "ProviderError")
    synthetic = {
        "provider": provider,
        "model": config.get("model_name") or config.get("model") or "unknown",
        "model_profile": config.get("model_profile") or provider,
        "role": role,
        "coordinate_id": coordinate_id,
        "call_id": fallback.get("call_id") or f"{coordinate_id}:{role}:1",
        "endpoint": config.get("base_url") or config.get("endpoint"),
        "timeout_s": config.get("timeout", config.get("request_timeout")),
        "attempts": fallback.get("attempts", 1),
        "max_retries": config.get("max_retries", fallback.get("max_retries", 0)),
        "elapsed_ms": fallback.get("elapsed_ms", 0),
        "error_type": error_type,
        "cause_type": fallback.get("cause_type"),
        "status_code": fallback.get("status_code"),
        "request_id": fallback.get("request_id"),
        "parse_status": fallback.get("parse_status") or "provider_error",
        "error_message": fallback.get("message") or fallback.get("error_message") or error_type,
        "remediation": fallback.get("remediation"),
        "failure_class": fallback.get("failure_class"),
    }
    return build_failure_envelope(synthetic, run_id=run_id)


def _canonical_hash(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


@lru_cache(maxsize=1)
def default_source_identity() -> dict[str, Any]:
    """Return the shared chapter3 source identity for runner artifacts."""
    from evaluation.research_plan import source_identity

    root = Path(__file__).resolve().parents[1]
    return dict(source_identity(
        repository_root=root,
        config_path=root / "config.yaml" if (root / "config.yaml").is_file() else None,
    ))


def default_source_hashes_sha256() -> str:
    return str(default_source_identity()["source_hashes_sha256"])


def fixture_documents(evidence: Any) -> dict[str, dict[str, Any]]:
    """Project any supported fixture-evidence input into raw documents per level.

    Accepts one raw ``fixture-restoration.v1`` document, a list of documents, or
    a ``by_level`` envelope. Plan/identity metadata is rejected inside the
    document; the shared projection keeps it in the caller's envelope.
    """
    from tesis.config_fields import normalize_fixture_documents

    return normalize_fixture_documents(evidence)


def fixture_evidence_for_level(evidence: Any, security_level: str) -> dict[str, Any]:
    """Select the raw operator attestation for one matrix level.

    Missing or mismatched levels stay empty (unknown); nothing is synthesized.
    """
    from tesis.config_fields import fixture_document_for_level

    return fixture_document_for_level(evidence, security_level)


def recorded_payload_policy_snapshot() -> dict[str, Any]:
    """Return the immutable payload policy/template/prompt identity snapshot.

    Delegates to A's producer; the snapshot is JSON-safe and hash-pinned so a
    replay reader can validate a historical Template reference against the
    registry/manifests that produced it rather than today's module state.
    """
    from foundation.payload_snapshot import payload_policy_snapshot

    return payload_policy_snapshot()


def resolve_recorded_payload_policy(snapshot: Any) -> dict[str, Any] | None:
    """Validate a frozen snapshot, or capture the live run's own identity.

    A supplied snapshot is verified for self-digest/completeness and persisted
    unchanged; no live registry comparison happens here. Without a frozen input
    the live process identity is the truthful recorded identity of this run.
    """
    if snapshot is None:
        return recorded_payload_policy_snapshot()
    from foundation.payload_snapshot import verify_payload_policy_snapshot

    issues = [issue for issue in verify_payload_policy_snapshot(snapshot) if issue.get("valid") is not True]
    if issues:
        raise ValueError(
            "payload_policy_snapshot invalid: "
            + ", ".join(str(issue.get("reason")) for issue in issues)
        )
    return deepcopy(snapshot)


def _unique_opportunities(
    rows: Any, *, stage: str, role: str | None = None
) -> list[dict[str, Any]]:
    """Return one row per opportunity id for one role/receipt stage.

    A generator and the validator can both record the same opportunity id;
    only the generation-stage row belongs in the generation denominator, and
    orchestrator selection rows never belong in the payload populations.
    """
    if not isinstance(rows, list):
        return []
    seen: set[str] = set()
    selected: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        if role is not None and str(row.get("role") or "") != role:
            continue
        receipt_stage = str(row.get("receipt_stage") or "generation")
        if receipt_stage != stage:
            continue
        identifier = str(row.get("opportunity_id") or "")
        if identifier:
            if identifier in seen:
                continue
            seen.add(identifier)
        selected.append(dict(row))
    return selected


def generation_opportunity_coverage(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Describe whether the exported generation population is complete.

    A validation-only population is coverage-unavailable, never a measured zero
    generation count.
    """
    generation = artifact.get("payload_generation_opportunities")
    validation = artifact.get("payload_validation_opportunities")
    state = artifact.get("final_state")
    if isinstance(state, Mapping):
        if not isinstance(generation, list):
            generation = state.get("payload_generation_opportunities")
        if not isinstance(validation, list):
            validation = state.get("payload_validation_opportunities")
    generation_rows = generation if isinstance(generation, list) else []
    validation_rows = validation if isinstance(validation, list) else []
    mode = str((artifact.get("config") or {}).get("payload_mode") or "")
    if generation_rows:
        return {"status": "recorded", "generation_rows": len(generation_rows),
                "validation_rows": len(validation_rows), "reason": None}
    if validation_rows:
        return {"status": "unavailable", "generation_rows": 0,
                "validation_rows": len(validation_rows),
                "reason": "generation_receipt_missing"}
    if requires_model_candidate(mode) or mode in {"hybrid", "llm_mutation_only", "llm_template"}:
        return {"status": "unavailable", "generation_rows": 0, "validation_rows": 0,
                "reason": "no_payload_generation_opportunity_recorded"}
    return {"status": "not_applicable", "generation_rows": 0, "validation_rows": 0,
            "reason": "static_payload_mode"}


def _candidate_budget_receipts(final_state: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive one receipt per observed method visit from append-only facts."""
    visits: list[tuple[str, str]] = []
    for row in final_state.get("candidate_lifecycle", []) or []:
        if not isinstance(row, Mapping):
            continue
        method = str(row.get("method") or "")
        visit_id = str(row.get("visit_id") or "")
        if method and visit_id and (method, visit_id) not in visits:
            visits.append((method, visit_id))
    receipts: list[dict[str, Any]] = []
    for method, visit_id in visits:
        try:
            receipts.append(candidate_budget_receipt(final_state, method, visit_id))
        except Exception:
            continue
    return receipts


def _payload_generation_failure(final_state: dict[str, Any]) -> dict[str, Any] | None:
    """Return a provider-error payload failure recorded by the graph.

    Dispatch uses the policy event identity and reason taxonomy. A strict-mode
    no-candidate event, a model refusal, or a Template infeasibility is not a
    provider/transport failure and must not be relabelled as one.
    """
    for event in final_state.get("fallback_events", []) or []:
        if not isinstance(event, dict):
            continue
        event_name = str(event.get("event") or event.get("event_type") or "")
        reason = event.get("reason")
        if event_name == EVENT_PROVIDER_FAILURE:
            return event
        if event_name == EVENT_STATIC_FALLBACK and is_provider_failure_reason(reason):
            return event
    return None


def _preserve_evidence_backed_fixture_limit(
    status_fields: Mapping[str, Any], final_state: Mapping[str, Any]
) -> dict[str, Any]:
    """Keep an evidence-backed environment limitation through finalization.

    ``terminal_status(classify=True)`` reclassifies a readiness/quarantine stop
    as ``unconfirmed``; that erases the actual operational cause. A confirmed
    candidate outcome always wins, and an unexplained ``fixture_limited`` label
    never overrides positive proof.
    """
    fields = dict(status_fields)
    if fields.get("security_outcome") == "confirmed":
        return fields
    prior_reason = final_state.get("security_outcome_reason")
    if final_state.get("security_outcome") != "fixture_limited":
        return fields
    if not (isinstance(prior_reason, Mapping) and str(prior_reason.get("code") or "").strip()):
        return fields
    fields["security_outcome"] = "fixture_limited"
    fields["security_outcome_reason"] = dict(prior_reason)
    return fields


def _environment_no_call_outcome(final_state: Mapping[str, Any]) -> bool:
    """Whether a zero-call terminal state is an environment/control outcome."""
    return (
        final_state.get("execution_status") == "failed"
        or final_state.get("security_outcome") == "fixture_limited"
        or final_state.get("llm_skip_reason") in {"READINESS_NOT_READY", "RUN_QUARANTINED"}
    )


def _final_candidate_request_rows(final_state: dict[str, Any]) -> list[dict[str, Any]]:
    """Return only the final visit's own executed candidate requests."""
    method = str(final_state.get("selected_method") or "")
    visit_id = str(final_state.get("selected_visit_id") or "")
    if not method or not visit_id:
        return []
    rows = []
    for row in final_state.get("response_evidence", []) or []:
        if not isinstance(row, Mapping):
            continue
        if str(row.get("method") or row.get("agent_id") or "") != method:
            continue
        if str(row.get("visit_id") or "") != visit_id:
            continue
        if str(row.get("identity_kind") or "") != "candidate":
            continue
        if str(row.get("stage") or "") not in {"exploit", "bypass"}:
            continue
        if row.get("control_id") or row.get("source_candidate_id"):
            continue
        rows.append(dict(row))
    return rows


def _terminal_incomplete_reason(final_state: dict[str, Any]) -> str | None:
    """Read terminal aliases; only known execution errors fail the run."""
    if final_state.get("execution_status") == "failed":
        return (final_state.get("execution_reason") or {}).get("code") or "RUNTIME_FAILURE"
    if any(row.get("status_code") is None for row in _final_candidate_request_rows(final_state)):
        return "TARGET_REQUEST_FAILURE"
    result = str(final_state.get("task_result") or "").strip().upper()
    reason = str(final_state.get("incomplete_reason") or "").strip()
    if result == "SUCCESS":
        return None
    if result == "INCOMPLETE":
        return reason or "NO_CANDIDATE_CONFIRMATION"
    if result:
        # Unknown terminal values (FAILED, ERROR, or malformed values) must
        # never fall through to the success branch.
        return reason or f"INVALID_TASK_RESULT:{result}"
    if reason:
        return reason
    return None


def run_single_engagement(
    *,
    target_url: str,
    security_level: str,
    llm_provider: str,
    surface: str = "sqli",
    payload_mode: str = "static_only",
    max_iterations: int = 30,
    candidate_budget: int = 5,
    repeat_index: int = 0,
    stop_policy: str = "impact",
    coverage_target: float = 0.70,
    enriched_reporting: bool = False,
    diagnose: bool = False,
    output_dir: str | None = None,
    evasion_enabled: bool = False,
    evasion_mode: str = "reactive",
    evasion_max_retries: int = 3,
    evasion_cooldown_threshold: int = 5,
    live_display: bool = False,
    model_config: dict[str, Any] | None = None,
    event_sink: RuntimeEventSink | None = None,
    cancellation_token: CancellationToken | None = None,
    execution_id: str | None = None,
    experiment_condition: str = "linear_hybrid",
    target_method: str | None = None,
    experiment_block: str | None = None,
    llm_runtime: LLMRuntime | None = None,
    llm_role_configs: dict[str, RoleSettings | dict[str, Any]] | None = None,
    model_profiles: dict[str, dict[str, Any]] | None = None,
    llm_cache_enabled: bool = False,
    llm_max_concurrency: int = 1,
    llm_cache: bool | None = None,
    llm_cache_scope: str | None = None,
    role_configs: dict[str, RoleSettings | dict[str, Any]] | None = None,
    llm_runtime_config: dict[str, Any] | None = None,
    resume: bool = False,
    checkpoint_dir: str | None = None,
    experiment_id: str | None = None,
    scoring_mode: str = "human",
    scoring_evaluator: dict[str, Any] | None = None,
    scoring_rubric_version: str = "scoring.v3",
    scoring_profile: dict[str, Any] | None = None,
    scoring_oracles: list[dict[str, Any]] | None = None,
    scoring_policy_epoch: dict[str, Any] | None = None,
    token_price_schedule: dict[str, Any] | None = None,
    fixture_restoration_evidence: dict[str, Any] | None = None,
    payload_policy_snapshot: dict[str, Any] | None = None,
    source_hashes_sha256: str | None = None,
    fixture_id: str | None = None,
    protocol_version: str | None = None,
    dvwa_username: str = "admin",
    dvwa_password: str = "password",
) -> dict:
    """Run one configured DVWA framework engagement and write evaluation artifacts.

    The runner builds an initial `ExploitationState`, compiles the LangGraph
    workflow, invokes it, computes score reports, records telemetry, and writes
    JSONL/report artifacts. Exceptions are captured into failure artifacts so a
    matrix run can continue.

    Args:
        target_url: DVWA base URL for the engagement.
        security_level: DVWA security level to configure.
        llm_provider: Provider identifier passed into framework state.
        surface: Vulnerability surface selected for the run.
        payload_mode: Payload candidate mode for the run.
        max_iterations: Maximum LangGraph method iterations.
        candidate_budget: Maximum generated-candidate budget per method.
        repeat_index: Matrix repeat index used in artifact IDs.
        stop_policy: Stop on high impact or fixed configured method coverage.
        coverage_target: Fraction of configured methods entered before stopping.
        enriched_reporting: Whether to emit richer text reports.
        diagnose: Whether to add diagnostic quality analysis.
        output_dir: Optional directory for written run artifacts.
        evasion_enabled: Whether guardrail retry behavior is enabled.
        evasion_mode: Evasion retry mode stored in state.
        evasion_max_retries: Maximum retry attempts for guardrail false positives.
        evasion_cooldown_threshold: Clean-response threshold for cooldown logic.
        live_display: Whether to run the terminal progress reporter.
        model_config: Optional provider model configuration.

    Returns:
        Run artifact containing final state, report, telemetry, paths, and
        failure details when execution fails.
    """
    run_id = f"{llm_provider}-{surface}-{security_level}-{payload_mode}-{repeat_index}"
    from tesis.model_config import EXPERIMENT_BLOCKS

    payload_mode = normalize_payload_mode(payload_mode)
    if not is_supported_payload_mode(payload_mode):
        raise ValueError(f"unsupported payload mode: {payload_mode!r}")
    block = str(experiment_block or ("forced" if target_method else "selection")).strip().lower()
    if block not in EXPERIMENT_BLOCKS:
        raise ValueError(f"experiment_block must be one of {EXPERIMENT_BLOCKS}")
    if block == "selection" and target_method:
        raise ValueError("a selection-block run must not declare target_method")
    if block == "forced" and not target_method:
        raise ValueError("a forced-method run requires target_method")
    scoring_policy_epoch = deepcopy(scoring_policy_epoch or {})
    token_price_schedule = deepcopy(token_price_schedule or {})
    fixture_restoration_evidence = fixture_evidence_for_level(
        fixture_restoration_evidence, security_level,
    )
    if source_hashes_sha256 is None:
        source_hashes_sha256 = default_source_hashes_sha256()
    fixture_restoration_sha256 = None
    if fixture_restoration_evidence:
        from foundation.readiness import validate_fixture_restoration_evidence

        validate_fixture_restoration_evidence(
            fixture_restoration_evidence,
            fixture_id=fixture_id,
            protocol_version=protocol_version,
            security_level=security_level,
            epoch_id=scoring_policy_epoch.get("epoch_id"),
            source_hashes_sha256=source_hashes_sha256,
        )
        fixture_restoration_sha256 = _canonical_hash(fixture_restoration_evidence)
    recorded_payload_policy = resolve_recorded_payload_policy(payload_policy_snapshot)
    policy_epoch = {
        "epoch_id": scoring_policy_epoch.get("epoch_id"),
        "policy_version": EXPERIMENT_POLICY_VERSION,
        "payload_policy_version": PAYLOAD_POLICY_VERSION,
        "control_policy_version": CONTROL_POLICY_VERSION,
        "budget_policy_version": BUDGET_POLICY_VERSION,
        "workflow_protocol_version": WORKFLOW_PROTOCOL_VERSION,
        "graph_build_version": GRAPH_BUILD_VERSION,
        "state_schema_version": STATE_SCHEMA_VERSION,
        "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
        "scoring_rubric_version": scoring_rubric_version,
        "scoring_policy": scoring_policy_epoch,
        "source_hashes_sha256": source_hashes_sha256,
        "fixture_restoration_sha256": fixture_restoration_sha256,
        "recorded_payload_policy_sha256": (
            recorded_payload_policy.get("snapshot_sha256")
            if isinstance(recorded_payload_policy, Mapping)
            and isinstance(recorded_payload_policy.get("snapshot_sha256"), str)
            and recorded_payload_policy.get("snapshot_sha256")
            else _canonical_hash(recorded_payload_policy)
        ),
    }
    from evaluation.thesis_scoring import validate_scoring_config
    validate_scoring_config(scoring_mode, scoring_evaluator or {})
    from evaluation.scoring_evidence import validate_evidence_config
    scoring_profile, scoring_oracles = deepcopy(scoring_profile or {}), deepcopy(scoring_oracles or [])
    validate_evidence_config(scoring_rubric_version, scoring_profile, scoring_oracles)
    execution_id = execution_id or new_execution_id()
    cancellation_token = cancellation_token or CancellationToken()
    runtime_events: list[dict[str, Any]] = []
    restored_receipts: list[dict[str, Any]] = []
    method_execution_inputs: list[dict[str, Any]] = []
    candidate_disposition_inputs: list[dict[str, Any]] = []
    captured_inputs: set[tuple[str, str]] = set()
    captured_disposition_inputs: set[tuple[str, str]] = set()
    if llm_role_configs is None:
        llm_role_configs = role_configs
    if llm_runtime_config and not llm_role_configs:
        raw_roles = llm_runtime_config.get("roles")
        if isinstance(raw_roles, dict):
            llm_role_configs = raw_roles
    if llm_cache_scope is None and llm_cache is None and llm_runtime_config:
        llm_cache_scope = llm_runtime_config.get("cache_scope")
    if llm_cache is not None:
        llm_cache_enabled = bool(llm_cache)
    if llm_cache_scope is not None:
        llm_cache_enabled = str(llm_cache_scope).strip().lower() == "run"
    identity_runtime = llm_runtime or LLMRuntime(max_concurrency=1, rate_limit_config=llm_runtime_config)
    try:
        with identity_runtime.coordinate(coordinate_id=execution_id, default_provider=llm_provider,
                default_model_config=model_config or {}, model_profiles=model_profiles or {llm_provider: model_config or {}},
                role_settings=llm_role_configs or {}, cache_enabled=llm_cache_enabled) as identity_context:
            effective_identity = _effective_llm_runtime_config(identity_context, candidate_budget=candidate_budget)
    finally:
        if llm_runtime is None:
            identity_runtime.close()
    resume_request_execution_id = execution_id if resume else None
    # Opt-in durable resume (handoff slice 2). Defaults are unchanged: without
    # resume/checkpoint flags the run uses a random execution_id thread on the
    # process-local MemorySaver and never touches SQLite.
    coordinate = {
        "scoring_rubric_version": scoring_rubric_version,
        "scoring_profile": scoring_profile, "scoring_oracles": scoring_oracles,
        "scoring_policy_epoch": scoring_policy_epoch, "token_price_schedule": token_price_schedule,
        "policy_epoch": policy_epoch,
        "recorded_payload_policy": recorded_payload_policy,
        "fixture_restoration_evidence": fixture_restoration_evidence,
        "fixture_restoration_sha256": fixture_restoration_sha256,
        "source_hashes_sha256": source_hashes_sha256,
        "source_identity_version": default_source_identity().get("identity_version"),
        "fixture_id": fixture_id, "protocol_version": protocol_version,
        "scoring_mode": scoring_mode,
        "scoring_evaluator": redact_secrets(scoring_evaluator or {}),
        "target_url": target_url,
        "provider": llm_provider,
        "surface": surface,
        "security_level": security_level,
        "payload_mode": payload_mode,
        "experiment_condition": experiment_condition,
        "experiment_block": block,
        "target_method": target_method,
        "repeat_index": repeat_index,
        "stop_policy": stop_policy,
        "coverage_target": coverage_target,
        "candidate_budget": candidate_budget,
        "max_iterations": max_iterations,
        "model_name": (model_config or {}).get("model_name") if isinstance(model_config, Mapping) else None,
        "evasion_enabled": evasion_enabled,
        "evasion_mode": evasion_mode,
        "evasion_max_retries": evasion_max_retries,
        "evasion_cooldown_threshold": evasion_cooldown_threshold,
        "effective_llm_runtime": effective_identity,
        "workflow_protocol_version": WORKFLOW_PROTOCOL_VERSION,
    }
    checkpoint_experiment = str(experiment_id or "experiment")
    checkpoint_thread_id = stable_thread_id(checkpoint_experiment, coordinate)
    checkpoint_store_path = default_store_path(checkpoint_dir, output_dir) if (checkpoint_dir is not None or experiment_id is not None) else None
    graph_store_path = default_graph_store_path(checkpoint_dir, output_dir) if checkpoint_store_path is not None else None
    graph_thread_id = execution_id
    partial_graph_resume = False

    def _resume_error(reason: str) -> dict:
        return {
            "schema_version": "tui.v1",
            "execution_id": execution_id,
            "run_id": run_id,
            "status": "error",
            **terminal_status({}, execution_status="failed", execution_reason={"code": "RESUME_REFUSED", "detail": reason, "evidence_refs": []}),
            "error": reason,
            "resumed_from_checkpoint": False,
            "resumed": False,
            "checkpoint_thread_id": checkpoint_thread_id,
            "state_schema_version": STATE_SCHEMA_VERSION,
            "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
            "graph_build_version": GRAPH_BUILD_VERSION,
        }

    if checkpoint_store_path is not None:
        # Single opt-in availability probe, before any metadata write,
        # runtime setup, or graph work: explicit checkpointing without the
        # sqlite-saver package fails once with a 'uv sync' remediation.
        try:
            from langgraph.checkpoint.sqlite import SqliteSaver  # noqa: F401
        except ImportError as exc:
            return _resume_error(
                "checkpointing requires the 'langgraph-checkpoint-sqlite' package; "
                f"run 'uv sync' to install it ({type(exc).__name__}: {exc}); refusing run"
            )

    if resume:
        lookup_path = checkpoint_store_path or default_store_path(None, None)
        if not lookup_path.exists():
            return _resume_error(
                f"no checkpoint metadata at {lookup_path}; re-run without --resume; refusing resume"
            )
        try:
            store = ExperimentCheckpointStore(lookup_path, experiment_id=checkpoint_experiment)
            try:
                stored = store.load(checkpoint_thread_id)
            finally:
                store.close()
        except (sqlite3.Error, ValueError) as exc:
            return _resume_error(
                f"checkpoint metadata at {lookup_path} is unreadable or corrupt "
                f"({type(exc).__name__}: {exc}); delete the checkpoint file and "
                "re-run without --resume; refusing resume"
            )
        if stored is None:
            return _resume_error(
                f"no checkpoint for thread {checkpoint_thread_id!r} at {lookup_path}; "
                "re-run without --resume; refusing resume"
            )
        ok, reason = validate_checkpoint_identity(
            stored, coordinate=coordinate, experiment_id=checkpoint_experiment
        )
        if not ok:
            return _resume_error(reason)
        try:
            _receipt = int(stored.get("completion_receipt", 0) or 0)
        except (TypeError, ValueError):
            return _resume_error(
                f"checkpoint for thread {checkpoint_thread_id!r} has an unreadable completion receipt; "
                "delete the checkpoint and re-run without --resume; refusing resume"
            )
        if _receipt == 1:
            ok, reason = validate_resume(stored, coordinate=coordinate)
            if not ok:
                return _resume_error(reason)
            resumed = dict(stored["artifact"])
            resumed.update(terminal_status(resumed))
            if resumed["execution_status"]:
                resumed["status"] = lifecycle_alias(resumed["execution_status"])
            resumed["resumed_from_checkpoint"] = True
            resumed["resumed"] = True
            resumed["resume_thread_id"] = checkpoint_thread_id
            resumed["resume_request_execution_id"] = execution_id
            if graph_store_path is not None:
                resumed["graph_checkpoint_store"] = str(graph_store_path)
            if output_dir:
                try:
                    # A replay request is a receipt, not another primary run
                    # with the original execution ID and different source bytes.
                    write_json_report(Path(output_dir) / f"{execution_id}.resume.json", {
                        "schema_version": "checkpoint-resume.v1", "artifact_type": "checkpoint_resume_receipt",
                        "request_execution_id": execution_id,
                        "source_execution_id": resumed.get("execution_id"),
                        "checkpoint_thread_id": checkpoint_thread_id,
                        "graph_thread_id": stored["state"].get("graph_thread_id"),
                        "replayed_nodes": 0, "fresh_provider_calls": 0,
                    })
                except Exception as exc:
                    resumed["artifact_write_warning"] = f"{type(exc).__name__}: {exc}"
            return resumed
        graph_thread_id = stored["state"].get("graph_thread_id") or checkpoint_thread_id
        execution_id = stored["state"].get("execution_id") or execution_id
        run_id = stored["state"].get("run_id") or run_id
        partial_graph_resume = True
        if graph_store_path is None or not graph_store_path.exists():
            return _resume_error(
                f"checkpoint for thread {checkpoint_thread_id!r} has no completion receipt "
                f"and no graph checkpoint at {graph_store_path}; re-run without --resume; "
                "refusing resume"
            )
    elif checkpoint_store_path is not None:
        # Fail closed before any external action: without a start-of-run
        # identity row, a later --resume could misattribute this run's graph
        # checkpoints to a different coordinate. Never warn-and-continue.
        try:
            _start_store = ExperimentCheckpointStore(
                checkpoint_store_path, experiment_id=checkpoint_experiment
            )
            try:
                _start_store.save_started(
                    thread_id=checkpoint_thread_id, coordinate=coordinate,
                    graph_thread_id=graph_thread_id, execution_id=execution_id, run_id=run_id,
                )
            finally:
                _start_store.close()
        except Exception as exc:
            return _resume_error(
                f"cannot record checkpoint identity at {checkpoint_store_path} "
                f"({type(exc).__name__}: {exc}); refusing run"
            )
    runtime_service = llm_runtime or LLMRuntime(max_concurrency=1, rate_limit_config=llm_runtime_config)
    owns_runtime = llm_runtime is None
    runtime_event_emitter = None

    def forward_runtime_activity(event_type: str, data: dict[str, Any]) -> None:
        if runtime_event_emitter is not None:
            runtime_event_emitter(event_type, data)

    runtime_stack = ExitStack()
    http_accounting_stack = ExitStack()
    live_http_counter: dict[str, Any] | None = None
    try:
        live_http_counter = http_accounting_stack.enter_context(http_request_accounting())
    except Exception as exc:  # noqa: BLE001 - accounting must not block execution
        runtime_events.append({
            "event_type": "runner.http_accounting.unavailable",
            "timestamp": _now_iso(), "execution_id": execution_id, "run_id": run_id,
            "node": "runner", "method": None, "candidate": None,
            "message": "HTTP request accounting unavailable",
            "data": {"error_type": type(exc).__name__},
        })
    runtime_stack.enter_context(dvwa_credentials(dvwa_username, dvwa_password))
    call_context = runtime_stack.enter_context(runtime_service.coordinate(
        coordinate_id=execution_id,
        default_provider=llm_provider,
        default_model_config=model_config or {},
        model_profiles=model_profiles or {llm_provider: model_config or {}},
        role_settings=llm_role_configs or {},
        cache_enabled=llm_cache_enabled,
        activity_callback=forward_runtime_activity,
    ))
    # Automatic method selection is model-backed for every payload mode; an
    # explicit target plus static_only is the intentional zero-call ablation.
    # Mutation and Template additionally require a model-generated candidate.
    llm_required = block == "selection" or requires_model_candidate(payload_mode)
    configured_profiles: list[Mapping[str, Any]] = []
    if isinstance(model_config, Mapping):
        configured_profiles.append(model_config)
    for profile in (model_profiles or {}).values():
        if isinstance(profile, Mapping):
            configured_profiles.append(profile)
    known_secrets = [
        value
        for profile in configured_profiles
        for key, value in profile.items()
        if "key" in str(key).lower()
        or "secret" in str(key).lower()
        or "token" in str(key).lower()
    ]

    def emit(
        event_type: str,
        *,
        message: str | None = None,
        node: str | None = None,
        method: str | None = None,
        candidate: Any = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        safe_data = redact_secrets(data or {}, known_secrets)
        safe_message = redact_secrets(message, known_secrets) if message else message
        event = RunEvent(
            event_type=event_type,
            execution_id=execution_id,
            run_id=run_id,
            node=node,
            method=method,
            candidate=candidate,
            message=safe_message,
            data=safe_data,
        )
        runtime_events.append({
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "execution_id": execution_id,
            "run_id": run_id,
            "node": node,
            "method": method,
            "candidate": candidate,
            "message": safe_message,
            "data": safe_data,
        })
        if event_sink is not None:
            event_sink.emit(event)

    def emit_runtime_activity(event_type: str, data: dict[str, Any]) -> None:
        # Runtime events contain hashes and timing only; prompts and responses
        # remain available only through the existing callback/audit path.
        emit(event_type, data=data)

    runtime_event_emitter = emit_runtime_activity

    started_at = _now_iso()
    started_clock = perf_counter()
    telemetry = RunTelemetry(run_id=run_id)
    reporter = None
    if live_display:
        try:
            from tesis.progress_reporter import EngagementProgressReporter
            reporter = EngagementProgressReporter(
                max_iterations=max_iterations,
                provider=llm_provider,
                level=security_level,
            )
            reporter.start()
        except Exception as exc:
            LOGGER = logging.getLogger(__name__)
            LOGGER.warning("Live display initialization failed: %s", exc)
    telemetry.emit(
        iteration=0,
        node="runner",
        event_type="run.started",
        status="ok",
        payload={
            "target_url": target_url,
            "provider": llm_provider,
            "security_level": security_level,
            "surface": surface,
            "payload_mode": payload_mode,
        },
    )
    emit("run.started", message="Experiment started", data={
        "target_url": target_url,
        "provider": llm_provider,
        "security_level": security_level,
        "surface": surface,
        "payload_mode": payload_mode,
        "experiment_condition": experiment_condition,
        "target_method": target_method,
    })

    init_state: dict[str, Any] | None = None
    final_state: dict[str, Any] | None = None
    provider_failure: dict[str, Any] | None = None
    saver_conn = None
    resumed_from_graph_checkpoint = False
    try:
        cancellation_token.check()
        evasion_enabled = bool(evasion_enabled)
        saver = None
        if checkpoint_store_path is not None:
            # Availability already probed before runtime setup; plain import here.
            from langgraph.checkpoint.sqlite import SqliteSaver
            from core.checkpoint_audit import AuditCheckpointSerializer
            graph_store_path.parent.mkdir(parents=True, exist_ok=True)
            saver_conn = sqlite3.connect(str(graph_store_path), check_same_thread=False)
            saver = SqliteSaver(saver_conn,
                serde=AuditCheckpointSerializer(graph_store_path.parent / "checkpoint-audit"))
            try:
                saver.setup()
            except Exception as exc:
                raise _ResumeFailed(
                    f"cannot initialize graph checkpoint store at {graph_store_path} "
                    f"({type(exc).__name__}: {exc}); refusing run"
                )
        if checkpoint_store_path is not None:
            app = build_framework(llm_provider=llm_provider, surface=surface, checkpointer=saver)
        else:
            # Default path keeps the legacy call shape so test doubles patching
            # build_framework without a checkpointer kwarg keep working.
            app = build_framework(llm_provider=llm_provider, surface=surface)
        init_state = {
            **new_default_state(),
            "scoring_rubric_version": scoring_rubric_version, "scoring_profile": scoring_profile,
            "scoring_oracles": scoring_oracles, "fixture_id": fixture_id, "protocol_version": protocol_version,
            "run_id": run_id, "execution_id": execution_id,
            "target_url": target_url,
            "security_level": security_level,
            "llm_provider": llm_provider,
            "current_surface": surface,
            "payload_mode": payload_mode,
            "payload_policy_version": PAYLOAD_POLICY_VERSION,
            "control_policy_version": CONTROL_POLICY_VERSION,
            "budget_policy_version": BUDGET_POLICY_VERSION,
            "experiment_policy_version": EXPERIMENT_POLICY_VERSION,
            "experiment_block": block,
            "fixture_restoration_evidence": fixture_restoration_evidence,
            "policy_epoch": policy_epoch,
            "recorded_payload_policy": recorded_payload_policy,
            "source_identity": {
                key: default_source_identity().get(key)
                for key in ("identity_version", "source_hashes_sha256", "config_sha256")
            },
            "source_hashes_sha256": source_hashes_sha256,
            "candidate_budget": candidate_budget,
            "max_iterations": max_iterations,
            "stop_policy": stop_policy,
            "coverage_target": coverage_target,
            "evasion_enabled": evasion_enabled,
            "evasion_mode": evasion_mode,
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
            "model_config": model_config or {},
            "experiment_condition": experiment_condition,
            "target_method": target_method, "repeat_index": repeat_index,
            "workflow_protocol_version": WORKFLOW_PROTOCOL_VERSION,
        }

        if event_sink is not None:
            init_state["model_config"] = {**(model_config or {}), "streaming": True}

        seen_events = 0
        callback_handler = _RuntimeCallbackHandler(emit, provider=llm_provider)
        graph_config = {
            "recursion_limit": max(32, 8 * max_iterations + 16),
            "callbacks": [callback_handler],
            "configurable": {
                "thread_id": graph_thread_id,
            }
        }
        if partial_graph_resume:
            snapshot = app.get_state(graph_config)
            if snapshot is None or getattr(snapshot, "values", None) is None:
                raise _ResumeFailed(
                    f"no graph checkpoint for thread {graph_thread_id!r} at {graph_store_path}; "
                    "re-run without --resume; refusing resume"
                )
            # The resumed initial snapshot includes receipts for completed work.
            # Only newly appended validation events can freeze a method input.
            seen_events = len(snapshot.values.get("telemetry_events", []))
            restored_receipts = list(snapshot.values.get("llm_call_receipts", []))
            try:
                call_context.restore_receipts(restored_receipts)
            except (TypeError, ValueError) as exc:
                raise _ResumeFailed(str(exc)) from exc
            emit("run.resumed", data={"restored_provider_calls": len(restored_receipts),
                "resume_request_execution_id": resume_request_execution_id})
            pending = set(getattr(snapshot, "next", None) or ())
            unsafe = sorted(n for n in pending if n not in SAFE_RESUME_NODES)
            if unsafe:
                raise _ResumeFailed(
                    f"graph checkpoint for thread {graph_thread_id!r} is paused before "
                    f"{', '.join(unsafe)}; resuming could duplicate external target/provider "
                    "effects (recon, orchestrator, candidate builder, method agents); "
                    "re-run without --resume; refusing resume"
                )
            if not pending:
                final_state = dict(snapshot.values)
                resumed_from_graph_checkpoint = True
                stream_iter = iter(())
            else:
                resumed_from_graph_checkpoint = True
                try:
                    stream_iter = app.stream(None, stream_mode="values", config=graph_config)
                except TypeError:
                    stream_iter = app.stream(None, stream_mode="values")
        else:
            try:
                stream_iter = app.stream(init_state, stream_mode="values", config=graph_config)
            except TypeError:
                # Lightweight test doubles may not accept LangGraph's config kwarg.
                stream_iter = app.stream(init_state, stream_mode="values")
        try:
            for state_snapshot in stream_iter:
                final_state = state_snapshot
                events = final_state.get("telemetry_events", [])
                new_events = events[seen_events:]
                seen_events = len(events)
                method = final_state.get("selected_method")
                queue = validated_payload_candidates(final_state, str(method))
                visit_id = str(final_state.get("selected_visit_id") or "")
                identity = (str(method), visit_id or str(final_state.get("iteration_count", 0)))
                for event in new_events:
                    event_name = str(event.get("event") or event.get("event_type") or "")
                    if event_name != "payload.validation.completed":
                        continue
                    event_payload = event.get("payload")
                    if not isinstance(event_payload, dict):
                        event_payload = {}
                    event_method = str(event_payload.get("method") or method or "")
                    if not event_method:
                        continue
                    event_visit = str(
                        final_state.get("selected_visit_id")
                        or event_payload.get("visit_id")
                        or f"{event_method}:legacy:{final_state.get('iteration_count', 0)}"
                    )
                    disposition_identity = (event_method, event_visit)
                    if disposition_identity in captured_disposition_inputs:
                        continue
                    catalog = final_state.get("payload_candidates", {}).get(event_method, [])
                    validations = final_state.get("payload_validation_results", {}).get(event_method, [])
                    candidate_ids = {
                        str(candidate.get("candidate_id"))
                        for candidate in catalog
                        if isinstance(candidate, dict) and candidate.get("candidate_id") is not None
                    } if isinstance(catalog, list) else set()
                    previously_tried = {
                        str(value)
                        for value in final_state.get("tried_payloads", {}).get(event_method, [])
                    }
                    provenance = final_state.get("payload_provenance", {})
                    frozen_disposition = {
                        "method": event_method,
                        "visit_id": event_visit,
                        "iteration_count": final_state.get("iteration_count", 0),
                        "candidate_catalog": deepcopy(catalog) if isinstance(catalog, list) else [],
                        "validated_queue": deepcopy(validated_payload_candidates(final_state, event_method)),
                        "validation_results": deepcopy(validations) if isinstance(validations, list) else [],
                        "previously_tried_candidate_ids": [
                            str(candidate.get("candidate_id"))
                            for candidate in catalog
                            if isinstance(candidate, dict)
                            and candidate.get("candidate_id") is not None
                            and str(candidate.get("payload_or_logic")) in previously_tried
                        ] if isinstance(catalog, list) else [],
                        "payload_provenance": {
                            candidate_id: deepcopy(provenance[candidate_id])
                            for candidate_id in candidate_ids
                            if isinstance(provenance, dict) and candidate_id in provenance
                        },
                    }
                    candidate_disposition_inputs.append(redact_secrets(frozen_disposition, known_secrets))
                    captured_disposition_inputs.add(disposition_identity)
                if (queue and identity not in captured_inputs
                        and any(event.get("event") == "payload.validation.completed"
                                and event.get("payload", {}).get("method") == method
                                for event in new_events)):
                    # Save the validated queue before execution, without tokens
                    # or message objects, for diagnostic replay without a model.
                    # State snapshots are immutable partial-update inputs. Share
                    # prior immutable audit rows until the artifact is serialized.
                    frozen = {key: value for key, value in final_state.items()
                              if key not in {"messages", "model_config", "endpoints"}}
                    frozen["payload_candidates"] = {str(method): deepcopy(queue)}
                    frozen["recorded_payload_policy"] = deepcopy(recorded_payload_policy)
                    method_execution_inputs.append({"method": method, "state": redact_secrets(frozen, known_secrets)})
                    captured_inputs.add(identity)
                for event in new_events:
                    event_name = str(event.get("event") or event.get("event_type") or "runtime.event")
                    emit(
                        event_name,
                        node=str(event.get("node") or "") or None,
                        method=str(event.get("method") or "") or None,
                        message=str(event.get("status") or event_name),
                        data=dict(event.get("payload") or {}),
                    )
                    if reporter:
                        reporter.update(event)
                emit("graph.state", message="State updated", data={
                    "workflow": workflow_progress(final_state),
                    "iteration_count": final_state.get("iteration_count", 0),
                    "max_iterations": max_iterations,
                    "selected_method": final_state.get("selected_method"),
                    "confirmed_vulns": list(final_state.get("confirmed_vulns", [])),
                    "achieved_outcomes": list(final_state.get("achieved_outcomes", [])),
                    "akg_path": list(final_state.get("akg_path", [])),
                    **_candidate_event_data(final_state, candidate_budget),
                    "guardrail_count": len(final_state.get("guardrail_activations", [])),
                    "fallback_count": len(final_state.get("fallback_events", [])),
                    "latest_verifier": final_state.get("verifier_decision"),
                })
                cancellation_token.check()
        finally:
            if cancellation_token.is_cancelled and hasattr(stream_iter, "close"):
                stream_iter.close()
        if final_state is None and not partial_graph_resume:
            cancellation_token.check()
            try:
                final_state = app.invoke(init_state, config=graph_config)
            except TypeError:
                final_state = app.invoke(init_state)
        if final_state is None:
            raise _ResumeFailed(
                f"graph resume for thread {graph_thread_id!r} produced no state; "
                "re-run without --resume; refusing resume"
            )
        telemetry.extend_from_state_events(list(final_state.get("telemetry_events", [])))
        llm_activity = _llm_activity(runtime_events, restored_receipts)
        hidden_failure = _orchestrator_failure(runtime_events)
        terminal_incomplete_reason = _terminal_incomplete_reason(final_state)
        payload_generation_failure = _payload_generation_failure(final_state)
        failure_seed: Mapping[str, Any] | None = hidden_failure
        if failure_seed is None:
            for runtime_event in runtime_events:
                if runtime_event.get("event_type") != "llm.failed":
                    continue
                event_data = runtime_event.get("data")
                if isinstance(event_data, Mapping) and event_data.get("source") == "llm_runtime":
                    failure_seed = event_data
                    break
        provider_failure = _failure_for_run(
            call_context.records,
            run_id=run_id,
            fallback=failure_seed,
            provider=llm_provider,
            model_config=model_config,
            coordinate_id=execution_id,
        )
        if provider_failure is None and payload_generation_failure is not None:
            provider_failure = _failure_for_run(
                call_context.records,
                run_id=run_id,
                fallback=payload_generation_failure,
                provider=llm_provider,
                model_config=model_config,
                coordinate_id=execution_id,
            )
        if hidden_failure is not None:
            # Deterministic fallback may preserve a partial execution artifact,
            # but an experiment whose orchestrator model failed is not a
            # successful experimental run. Mark it explicitly so the TUI and
            # matrix aggregate cannot report a false positive.
            final_state = dict(final_state)
            final_state["task_result"] = "INCOMPLETE"
            final_state["incomplete_reason"] = "LLM_RUNTIME_FAILURE"
            error_type = str(hidden_failure.get("error_type") or "LLMError")
            error = (
                format_failure_line(provider_failure)
                if provider_failure is not None
                else (
                    f"{error_type}: orchestrator model call failed; "
                    "deterministic fallback output was retained for audit only"
                )
            )
            status = "error"
            failure_payload = {
                "error_type": error_type,
                "reason": "LLM_RUNTIME_FAILURE",
            }
            if provider_failure is not None:
                failure_payload.update({
                    "failure_class": provider_failure.get("failure_class"),
                    "failure": provider_failure,
                })
            telemetry.emit(
                iteration=int(final_state.get("iteration_count", 0) or 0),
                node="orchestrator",
                event_type="run.failed",
                status="error",
                payload=failure_payload,
            )
            emit(
                "run.failed",
                node="orchestrator",
                message=error,
                data=failure_payload,
            )
        elif (
            terminal_incomplete_reason is not None
            and (terminal_incomplete_reason in FAILURE_REASONS or terminal_incomplete_reason.startswith("INVALID_TASK_RESULT:"))
            and not llm_activity["failed"]
            and payload_generation_failure is None
        ):
            # Only explicit execution failures enter this branch. A missing
            # confirmed security finding cannot make a normal completion fail.
            final_state = dict(final_state)
            final_state["task_result"] = "INCOMPLETE"
            final_state["incomplete_reason"] = terminal_incomplete_reason
            error = f"Execution failed: {terminal_incomplete_reason}"
            status = "error"
            telemetry.emit(
                iteration=int(final_state.get("iteration_count", 0) or 0),
                node="runner",
                event_type="run.failed",
                status="error",
                payload={
                    "task_result": "INCOMPLETE",
                    "reason": terminal_incomplete_reason,
                },
            )
            emit(
                "run.failed",
                node="runner",
                message=error,
                data={
                    "task_result": "INCOMPLETE",
                    "reason": terminal_incomplete_reason,
                },
            )
        elif llm_activity["failed"]:
            # A provider callback failure is authoritative even when a graph
            # node catches it and continues with a deterministic fallback.
            # Keeping such a run successful would make a partial experiment
            # indistinguishable from a completed model-backed run.
            final_state = dict(final_state)
            final_state["task_result"] = "INCOMPLETE"
            final_state["incomplete_reason"] = "LLM_RUNTIME_FAILURE"
            error = (
                format_failure_line(provider_failure)
                if provider_failure is not None
                else "LLM runtime failure: at least one provider call failed"
            )
            status = "error"
            failure_payload = {"error_type": "LLM_RUNTIME_FAILURE", "reason": "LLM_RUNTIME_FAILURE"}
            if provider_failure is not None:
                failure_payload.update({
                    "failure_class": provider_failure.get("failure_class"),
                    "failure": provider_failure,
                })
            telemetry.emit(
                iteration=int(final_state.get("iteration_count", 0) or 0),
                node="runner",
                event_type="run.failed",
                status="error",
                payload=failure_payload,
            )
            emit(
                "run.failed",
                node="runner",
                message=error,
                data=failure_payload,
            )
        elif payload_generation_failure is not None:
            # Payload generation currently retains static seeds after a
            # provider exception.  That fallback is useful for auditability,
            # but it is not a successful hybrid experiment because the model
            # requested by the coordinate did not complete its call.
            final_state = dict(final_state)
            final_state["task_result"] = "INCOMPLETE"
            final_state["incomplete_reason"] = "LLM_RUNTIME_FAILURE"
            error = (
                format_failure_line(provider_failure)
                if provider_failure is not None
                else "LLM runtime failure: payload generation fell back to static seeds"
            )
            status = "error"
            failure_payload = {"error_type": "LLM_RUNTIME_FAILURE", "reason": "LLM_RUNTIME_FAILURE"}
            if provider_failure is not None:
                failure_payload.update({
                    "failure_class": provider_failure.get("failure_class"),
                    "failure": provider_failure,
                })
            telemetry.emit(
                iteration=int(final_state.get("iteration_count", 0) or 0),
                node="payload_candidate_builder",
                event_type="run.failed",
                status="error",
                payload=failure_payload,
            )
            emit(
                "run.failed",
                node="payload_candidate_builder",
                message=error,
                data=failure_payload,
            )
        elif llm_required and llm_activity["started"] == 0 and not _environment_no_call_outcome(final_state) \
                and final_state.get("llm_skip_reason") not in {
            "NO_VIABLE_METHODS", "ALL_METHODS_EXHAUSTED", "TARGET_METHOD_INFEASIBLE",
            "WORKFLOW_STOPPED_BEFORE_SELECTION",
        }:
            # Automatic selection and hybrid/mutation coordinates are
            # model-backed by contract. A graph that reaches a terminal state
            # without a callback is the original false-success failure mode.
            final_state = dict(final_state)
            final_state["task_result"] = "INCOMPLETE"
            final_state["incomplete_reason"] = "LLM_NOT_CALLED"
            error = "LLM call required by payload mode but no provider call was observed"
            status = "error"
            telemetry.emit(
                iteration=int(final_state.get("iteration_count", 0) or 0),
                node="runner",
                event_type="run.failed",
                status="error",
                payload={"error_type": "LLM_NOT_CALLED", "reason": "LLM_NOT_CALLED"},
            )
            emit(
                "run.failed",
                node="runner",
                message=error,
                data={"error_type": "LLM_NOT_CALLED", "reason": "LLM_NOT_CALLED"},
            )
        elif llm_required and llm_activity["completed"] < llm_activity["started"]:
            # Every observed provider start must have a matching completion.
            # A missing completion is incomplete telemetry even when no
            # explicit failure callback was emitted, and must not be shown as
            # a successful model-backed run.
            final_state = dict(final_state)
            final_state["task_result"] = "INCOMPLETE"
            final_state["incomplete_reason"] = "LLM_ACTIVITY_INCOMPLETE"
            error = "LLM provider activity started but did not complete"
            status = "error"
            telemetry.emit(
                iteration=int(final_state.get("iteration_count", 0) or 0),
                node="runner",
                event_type="run.failed",
                status="error",
                payload={"error_type": "LLM_ACTIVITY_INCOMPLETE", "reason": "LLM_ACTIVITY_INCOMPLETE"},
            )
            emit(
                "run.failed",
                node="runner",
                message=error,
                data={"error_type": "LLM_ACTIVITY_INCOMPLETE", "reason": "LLM_ACTIVITY_INCOMPLETE"},
            )
        else:
            status = "success"
            error = None
            if terminal_incomplete_reason:
                final_state = {**final_state, "task_result": "INCOMPLETE",
                    "incomplete_reason": terminal_incomplete_reason}
        report = build_score_report(final_state).to_dict()
        report["summary"].update(final_state.get("summary", {}))
        report["surface_scores"] = final_state.get("surface_scores", {})
        if reporter:
            reporter.finalize(report)
    except CancellationRequested:
        final_state = final_state or init_state or new_default_state()
        report = build_score_report(final_state).to_dict()
        status = "cancelled"
        error = None
        emit("run.cancelled", message="Cancellation requested; latest safe state retained")
    except _ResumeFailed as exc:
        final_state = dict(final_state or new_default_state())
        final_state.update({"task_result": "INCOMPLETE", "incomplete_reason": "RESUME_REFUSED"})
        report = build_score_report(final_state).to_dict()
        status = "error"
        error = f"{type(exc).__name__}: {exc}"
        emit("run.failed", node="runner", message=str(exc), data={"error_type": "_ResumeFailed"})
    except Exception as exc:
        final_state = dict(final_state or init_state or new_default_state())
        final_state.update({
            "target_url": target_url,
            "security_level": security_level,
            "llm_provider": llm_provider,
            "current_surface": surface,
            "payload_mode": payload_mode,
            "candidate_budget": candidate_budget,
            "max_iterations": max_iterations,
            "stop_policy": stop_policy,
            "coverage_target": coverage_target,
            "evasion_enabled": evasion_enabled,
            "evasion_mode": evasion_mode,
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
            "task_result": "INCOMPLETE",
            "incomplete_reason": "TARGET_TRANSPORT_FAILURE" if type(exc).__name__ in {"TransportError", "RequestTimeoutError"} else "RUNNER_EXCEPTION",
        })
        report = build_score_report(final_state).to_dict()
        status = "error"
        error = f"{type(exc).__name__}: {exc}\n{format_exc()}"
        telemetry.emit(
            iteration=0,
            node="runner",
            event_type="run.failed",
            status="error",
            payload={"error_type": type(exc).__name__},
        )
        emit(
            "run.failed",
            node="runner",
            message=f"{type(exc).__name__}: {exc}",
            data={"error_type": type(exc).__name__},
        )

    runtime_stack.close()

    if reporter:
        reporter.stop()

    ended_at = _now_iso()
    duration_ms = int((perf_counter() - started_clock) * 1000)
    if diagnose:
        summary = report.get("summary", {}) if isinstance(report, dict) else {}
        module_scores = report.get("module_scores", {}) if isinstance(report, dict) else {}
        score_map = {
            name: int(payload.get("score", 0))
            for name, payload in module_scores.items()
            if isinstance(payload, dict)
        }
        diagnostics = diagnose_quality(
            scores=score_map,
            total_iterations_used=int(summary.get("total_iterations_used", 0) or 0),
            highest_outcome=summary.get("highest_impact_outcome"),
        )
        if isinstance(summary, dict):
            summary["diagnostics"] = diagnostics

    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    method_scores = dict(final_state.get("method_scores", {}))
    payload_scores = dict(final_state.get("payload_scores", {}))
    exploitation_scores = dict(final_state.get("exploitation_scores", {}))
    chain_scores = dict(final_state.get("chain_scores", {}))
    selected_method = final_state.get("selected_method")
    method_score = method_scores.get(selected_method, 0)
    exploitation_score = exploitation_scores.get(selected_method, 0)
    chain_score = chain_scores.get(selected_method, 0)
    llm_activity = _llm_activity(runtime_events, restored_receipts)
    llm_performance = [dict(row) for row in call_context.records]
    llm_performance_summary = call_context.performance_summary()
    effective_llm_runtime_config = _effective_llm_runtime_config(
        call_context,
        candidate_budget=candidate_budget,
    )
    effective_profiles = {
        str(settings.get("model_profile") or "").strip()
        for settings in effective_llm_runtime_config["roles"].values()
        if str(settings.get("model_profile") or "").strip()
    }
    selected_model_profile = next(iter(effective_profiles)) if len(effective_profiles) == 1 else None
    readiness = final_state.get("readiness")
    candidate_lifecycle = list(final_state.get("candidate_lifecycle", []) or [])
    budget_receipts = _candidate_budget_receipts(final_state)
    model_call_requirements = list(final_state.get("model_call_requirements", []) or [])
    generation_opportunities = _unique_opportunities(
        final_state.get("payload_generation_opportunities")
        if isinstance(final_state.get("payload_generation_opportunities"), list)
        else model_call_requirements,
        stage="generation",
        role="payload_generator",
    )
    validation_opportunities = _unique_opportunities(
        model_call_requirements, stage="validation", role="payload_generator"
    )
    state_receipts = {
        "readiness": readiness,
        "selection_rejections": list(final_state.get("selection_rejections", []) or []),
        "observation_facts": list(final_state.get("observation_facts", []) or []),
        "precondition_status": dict(final_state.get("precondition_status", {}) or {}),
        "candidate_lifecycle": candidate_lifecycle,
        "candidate_budget_receipts": budget_receipts,
        "model_call_requirements": model_call_requirements,
        "chain_assessment": final_state.get("chain_assessment"),
        "control_events": list(final_state.get("control_events", []) or []),
        "quarantined_visits": list(final_state.get("quarantined_visits", []) or []),
        "payload_generation_opportunities": generation_opportunities,
        "payload_validation_opportunities": validation_opportunities,
        "payload_generation_opportunity_coverage": generation_opportunity_coverage({
            "payload_generation_opportunities": generation_opportunities,
            "payload_validation_opportunities": validation_opportunities,
            "config": {"payload_mode": payload_mode},
        }),
        "recorded_payload_policy": recorded_payload_policy,
    }
    summed_call_duration_ms = sum(
        int(row.get("call_duration_ms", 0) or 0)
        for row in llm_performance
        if isinstance(row, dict)
    )

    artifact = {
        "schema_version": "tui.v1",
        "workflow": workflow_progress(final_state),
        "execution_id": execution_id,
        "run_id": run_id,
        "status": status,
        "repeat_index": repeat_index,
        "failure": provider_failure,
        "experiment_condition": experiment_condition,
        "experiment_block": block,
        "target_method": target_method,
        "policy_epoch": policy_epoch,
        "recorded_payload_policy": recorded_payload_policy,
        "source_identity": {
            key: default_source_identity().get(key)
            for key in ("identity_version", "source_hashes", "source_hashes_sha256", "config_sha256")
        },
        "source_hashes_sha256": source_hashes_sha256,
        "fixture_restoration_evidence": fixture_restoration_evidence,
        "fixture_restoration_sha256": fixture_restoration_sha256,
        "payload_policy_version": PAYLOAD_POLICY_VERSION,
        "control_policy_version": CONTROL_POLICY_VERSION,
        "budget_policy_version": BUDGET_POLICY_VERSION,
        "experiment_policy_version": EXPERIMENT_POLICY_VERSION,
        "payload_mode_label": mode_display_label(payload_mode),
        **state_receipts,
        "provider": llm_provider,
        "model": (model_config or {}).get("model_name"),
        "model_profile": selected_model_profile,
        "surface": surface,
        "security_level": security_level,
        "payload_mode": payload_mode,
        "llm_required": llm_required,
        "llm_activity": llm_activity,
        "llm_performance": llm_performance,
        "llm_performance_summary": llm_performance_summary,
        "llm_runtime_config": effective_llm_runtime_config,
        "llm_max_concurrency": effective_llm_runtime_config["max_concurrency"],
        "llm_cache_scope": effective_llm_runtime_config["cache_scope"],
        "task_result": final_state.get("task_result"),
        "incomplete_reason": final_state.get("incomplete_reason"),
        "selected_method": selected_method,
        "viable_methods": list(final_state.get("viable_methods", [])),
        "akg_path": list(final_state.get("akg_path", [])),
        "method_score": method_score,
        "payload_scores": payload_scores,
        "exploitation_score": exploitation_score,
        "chain_score": chain_score,
        "payload_validity_rate": summary.get("payload_validity_rate", 0.0),
        "payload_execution_success_rate": summary.get("payload_execution_success_rate", 0.0),
        "payload_improvement_rate": summary.get("payload_improvement_rate", 0.0),
        "consistency_score": summary.get("consistency_score"),
        "metric_availability": summary.get("metric_availability", {}),
        "metric_unavailable_reason": summary.get("metric_unavailable_reason", {}),
        "guardrail_activations": list(final_state.get("guardrail_activations", [])),
        "guardrail_activation_count": len(final_state.get("guardrail_activations", [])),
        "payload_guardrail_activations": len(final_state.get("payload_guardrail_activations", [])),
        "attempts_to_success": int(round(summary.get("mean_attempts_to_success", 0.0) or 0.0)),
        "token_cost": summary.get("token_cost"),
        "token_cost_per_success": summary.get("token_cost_per_success"),
        "config": {
            "target_url": target_url,
            "provider": llm_provider,
            "model": (model_config or {}).get("model_name"),
            "model_profile": selected_model_profile,
            "model_config": redact_secrets(model_config or {}),
            "security_level": security_level,
            "surface": surface,
            "payload_mode": payload_mode,
            "llm_required": llm_required,
            "llm_cache_enabled": llm_cache_enabled,
            "llm_cache_scope": effective_llm_runtime_config["cache_scope"],
            "llm_max_concurrency": effective_llm_runtime_config["max_concurrency"],
            "llm_runtime": effective_llm_runtime_config,
            "llm_role_configs": {
                role: {
                    key: settings[key]
                    for key in (
                        "model_profile",
                        "model_name",
                        "temperature",
                        "max_tokens",
                        "structured_output",
                    )
                }
                for role, settings in effective_llm_runtime_config["roles"].items()
            },
            "max_iterations": max_iterations,
            "iteration_unit": "method_visit", "workflow_protocol_version": WORKFLOW_PROTOCOL_VERSION,
            "stop_policy": stop_policy, "coverage_target": coverage_target,
            "candidate_budget": candidate_budget,
            "repeat_index": repeat_index,
            "experiment_condition": experiment_condition,
            "experiment_block": block,
            "target_method": target_method,
            "payload_mode_label": mode_display_label(payload_mode),
            "payload_policy_version": PAYLOAD_POLICY_VERSION,
            "control_policy_version": CONTROL_POLICY_VERSION,
            "budget_policy_version": BUDGET_POLICY_VERSION,
            "experiment_policy_version": EXPERIMENT_POLICY_VERSION,
            "policy_epoch": policy_epoch,
            "scoring_policy_epoch": scoring_policy_epoch,
            "token_price_schedule": token_price_schedule,
            "source_hashes_sha256": source_hashes_sha256,
            "source_identity_version": default_source_identity().get("identity_version"),
            "source_config_sha256": default_source_identity().get("config_sha256"),
            "fixture_restoration_sha256": fixture_restoration_sha256,
            "evasion_enabled": evasion_enabled,
            "evasion_mode": evasion_mode,
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
        },
        "timing": {
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_ms": duration_ms,
            "wall_time_ms": duration_ms,
            "summed_role_call_duration_ms": summed_call_duration_ms,
            "non_call_overhead_ms": max(0, duration_ms - summed_call_duration_ms),
        },
        "final_state": {
            **state_receipts,
            "fixture_restoration_evidence": fixture_restoration_evidence,
            "source_hashes_sha256": source_hashes_sha256,
            "workflow_protocol_version": WORKFLOW_PROTOCOL_VERSION,
            "workflow_stop_reason": final_state.get("workflow_stop_reason"),
            "stop_policy": stop_policy, "coverage_target": coverage_target,
            "max_iterations": max_iterations, "llm_skip_reason": final_state.get("llm_skip_reason"),
            "active_payload_candidates": final_state.get("active_payload_candidates", {}),
            "preparation_failures": final_state.get("preparation_failures", []),
            "llm_call_receipts": redact_secrets(final_state.get("llm_call_receipts", [])),
            "summary": final_state.get("summary", {}), "surface_scores": final_state.get("surface_scores", {}),
            "observations": dict(final_state.get("observations", {})),
            "iteration_count": final_state.get("iteration_count", 0),
            "task_result": final_state.get("task_result"),
            "incomplete_reason": final_state.get("incomplete_reason"),
            "llm_activity": llm_activity,
            "llm_required": llm_required,
            "llm_performance": llm_performance,
            "llm_performance_summary": llm_performance_summary,
            "confirmed_vulns": list(final_state.get("confirmed_vulns", [])),
            "achieved_outcomes": list(final_state.get("achieved_outcomes", [])),
            "guardrail_activations": list(final_state.get("guardrail_activations", [])),
            "payload_guardrail_activations": list(final_state.get("payload_guardrail_activations", [])),
            "selected_method": selected_method,
            "viable_methods": list(final_state.get("viable_methods", [])),
            "akg_path": list(final_state.get("akg_path", [])),
            "payload_candidates": dict(final_state.get("payload_candidates", {})),
            "generated_payloads": dict(final_state.get("generated_payloads", {})),
            "payload_validation_results": dict(final_state.get("payload_validation_results", {})),
            "probe_controls": dict(final_state.get("probe_controls", {})),
            "payload_scores": payload_scores,
            "payload_provenance": dict(final_state.get("payload_provenance", {})),
            "method_scores": method_scores,
            "exploitation_scores": exploitation_scores,
            "chain_scores": chain_scores,
            "output_scores": dict(final_state.get("output_scores", {})),
            "composite_scores": dict(final_state.get("composite_scores", {})),
            "scores": dict(final_state.get("scores", {})),
            "selected_visit_id": final_state.get("selected_visit_id"),
            "scoring_decisions": list(final_state.get("scoring_decisions", [])),
            "verifier_history": list(final_state.get("verifier_history", [])),
            "verifier_decision": final_state.get("verifier_decision"),
            "chain_history": list(final_state.get("chain_history", [])),
            "current_chain": list(final_state.get("current_chain", [])),
            "active_chain_route": final_state.get("active_chain_route"),
            "chain_consumption": list(final_state.get("chain_consumption", [])),
            "weak_chain_opportunities": list(final_state.get("weak_chain_opportunities", [])),
            "found_credentials": redact_secrets(final_state.get("found_credentials", [])),
            "attempted_agents": list(final_state.get("attempted_agents", [])),
            "tried_payloads": dict(final_state.get("tried_payloads", {})),
            "current_surface": final_state.get("current_surface"),
            "experiment_condition": experiment_condition,
            "experiment_block": block,
            "target_method": target_method,
            "payload_mode": payload_mode,
            "repeat_index": repeat_index,
            "target_url": target_url,
            "response_evidence": redact_secrets(final_state.get("response_evidence", [])),
            "timing_evidence": list(final_state.get("timing_evidence", [])),
            "output_failure_events": list(final_state.get("output_failure_events", [])),
            "fallback_events": list(final_state.get("fallback_events", [])),
            "containment_events": list(final_state.get("containment_events", [])),
            "invalid_json_events": list(final_state.get("invalid_json_events", [])),
            "evasion_enabled": final_state.get("evasion_enabled", False),
            "evasion_mode": final_state.get("evasion_mode", "reactive"),
            "evasion_max_retries": final_state.get("evasion_max_retries", 3),
            "evasion_cooldown_threshold": final_state.get("evasion_cooldown_threshold", 5),
        },
        "report": report,
        "payload_candidates": dict(final_state.get("payload_candidates", {})),
        "payload_validation_results": dict(final_state.get("payload_validation_results", {})),
        "probe_controls": dict(final_state.get("probe_controls", {})),
        "payload_provenance": dict(final_state.get("payload_provenance", {})),
        "confirmed_vulns": list(final_state.get("confirmed_vulns", [])),
        "achieved_outcomes": list(final_state.get("achieved_outcomes", [])),
        "invalid_json_events": list(final_state.get("invalid_json_events", [])),
        "fallback_events": list(final_state.get("fallback_events", [])),
        "containment_events": list(final_state.get("containment_events", [])),
        "execution_log": runtime_events,
        "response_evidence": redact_secrets(final_state.get("response_evidence", [])),
        "timing_evidence": list(final_state.get("timing_evidence", [])),
        "verifier_decision": final_state.get("verifier_decision"),
        "scoring_decisions": list(final_state.get("scoring_decisions", [])),
        "method_execution_inputs": method_execution_inputs,
        "candidate_disposition_inputs": candidate_disposition_inputs,
        "output_score": dict(final_state.get("output_scores", {})).get(selected_method, 0),
        "composite_score": dict(final_state.get("composite_scores", {})).get(selected_method, 0),
        "error": error,
    }
    artifact["state_schema_version"] = STATE_SCHEMA_VERSION
    artifact["config"].update(scoring_rubric_version=scoring_rubric_version, scoring_profile=scoring_profile,
        scoring_oracles=scoring_oracles, fixture_id=fixture_id, protocol_version=protocol_version)
    try:
        if scoring_rubric_version == 'scoring.v4' and scoring_oracles:
            from evaluation.session_oracle import collect_session_oracles
            from evaluation.scoring_evidence import attach_oracle_evidence
            from foundation.http_client import request_scope
            with dvwa_credentials(dvwa_username, dvwa_password):
                with request_scope(phase="verification", role="candidate_verification"):
                    artifact = collect_session_oracles(artifact, final_state)
                from evaluation.permission_oracle import collect_permission_oracles
                with request_scope(phase="verification", role="independent_control"):
                    artifact = collect_permission_oracles(artifact, final_state)
                attach_oracle_evidence(artifact)
                from evaluation.dependency_oracle import collect_dependency_oracles
                with request_scope(phase="verification", role="independent_control"):
                    artifact = collect_dependency_oracles(artifact, final_state)
                attach_oracle_evidence(artifact)
            artifact['response_evidence'] = artifact['final_state']['response_evidence']
    except Exception as exc:
        status = "error"
        error = f"{type(exc).__name__}: {exc}"
        final_state = {**final_state, "incomplete_reason": "ARTIFACT_PROCESSING_FAILURE"}
        artifact.update(status=status, error=error)
        emit("run.failed", node="runner", message=error, data={"reason": "ARTIFACT_PROCESSING_FAILURE"})
    http_counters = snapshot_http_request_counters(live_http_counter)
    artifact["http_request_counters"] = http_counters
    artifact["final_state"]["http_request_counters"] = http_counters
    http_accounting_stack.close()
    status_fields = terminal_status(artifact,
        execution_status={"success": "completed", "error": "failed", "cancelled": "interrupted"}[status],
        execution_reason=((final_state.get("execution_reason")
            if (final_state.get("execution_reason") or {}).get("code") == final_state.get("incomplete_reason")
            else status_reason(final_state.get("incomplete_reason") or "RUNTIME_FAILURE", error or ""))
            if status == "error" else status_reason("CANCELLED", cancellation_token.reason or "") if status == "cancelled" else None),
        classify=True)
    status_fields = _preserve_evidence_backed_fixture_limit(status_fields, final_state)
    artifact.update(status_fields)
    artifact["final_state"].update(status_fields)
    artifact["final_state"].setdefault("summary", {}).update(status_fields)
    final_state = {**final_state, **status_fields}
    report = artifact.setdefault("report", {})
    report.setdefault("summary", {}).update(status_fields)
    link_exported_request_evidence(artifact)
    build_candidate_dispositions(artifact)
    artifact["payload_generation_opportunity_coverage"] = generation_opportunity_coverage(artifact)
    artifact["config"]["scoring_mode"] = scoring_mode
    artifact["config"]["scoring_evaluator"] = redact_secrets(scoring_evaluator or {})
    artifact["scoring_mode"] = scoring_mode
    artifact["thesis_scoring_status"] = "pending_review"
    artifact["composite_score_status"] = "runtime_provisional_scoring.v2"
    from evaluation.research_metrics import scoring_policy as _scoring_policy

    canonical_policy = _scoring_policy(artifact)
    artifact["scoring_policy"] = canonical_policy
    artifact["score_epoch"] = {
        "runtime_provisional": "scoring.v2",
        "thesis_final": scoring_rubric_version,
        "final_status": "pending_review",
        "scoring_policy_epoch": scoring_policy_epoch,
        "scoring_policy_version": canonical_policy.get("policy_version"),
        "metrics_epoch": canonical_policy.get("metrics_epoch"),
        "scoring_rule_sha256": canonical_policy.get("scoring_rule_sha256"),
    }
    artifact["config"]["scoring_policy_version"] = canonical_policy.get("policy_version")
    artifact["config"]["metrics_epoch"] = canonical_policy.get("metrics_epoch")
    artifact["checkpoint_schema_version"] = CHECKPOINT_SCHEMA_VERSION
    artifact["graph_build_version"] = GRAPH_BUILD_VERSION
    artifact["config_fingerprint"] = config_fingerprint(artifact["config"])
    artifact["checkpoint_thread_id"] = checkpoint_thread_id
    artifact["graph_thread_id"] = graph_thread_id
    artifact["resume_request_execution_id"] = resume_request_execution_id
    artifact["checkpoint_store"] = str(checkpoint_store_path) if checkpoint_store_path else None
    artifact["graph_checkpoint_store"] = str(graph_store_path) if graph_store_path else None
    resumed_ok = bool(partial_graph_resume and resumed_from_graph_checkpoint and status != "error")
    artifact["resumed_from_checkpoint"] = resumed_ok
    artifact["resumed"] = resumed_ok
    artifact["manual_scoring_evidence"] = manual_scoring_rows(artifact)
    telemetry.emit(
        iteration=int(final_state.get("iteration_count", 0) or 0),
        node="runner",
        event_type="run.finished",
        status=status,
        payload={"duration_ms": duration_ms, **status_fields},
    )
    emit(
        "run.finished",
        message=f"Experiment {status}",
        data={"status": status, "duration_ms": duration_ms, "workflow": workflow_progress(final_state), **status_fields},
    )

    base_dir = Path(output_dir) if output_dir else Path("results") / "runs"
    # The user-facing sidecar must contain the complete runtime trace,
    # including provider callbacks. The previous telemetry-only sidecar
    # omitted llm.started/completed/failed and made real calls impossible
    # to audit even though they were present in the primary artifact.
    events = list(runtime_events)
    if enriched_reporting:
        rich_payload = {
            "schema_version": "stage7.rich.v1",
            "run_id": run_id,
            "execution_id": execution_id,
            "status": status,
            **status_fields,
            "prompt_response_hashes": [
                {
                    "event_type": event.get("event_type"),
                    "hash": stable_sha256(
                        json.dumps(event.get("data", {}), sort_keys=True, separators=(",", ":"))
                    ),
                }
                for event in events
                if isinstance(event, dict)
                and str(event.get("event_type", "")).startswith(("orchestrator", "llm."))
            ],
            "events_count": len(events),
        }
        try:
            write_events_jsonl(base_dir / f"{execution_id}.events.jsonl", events)
            write_json_report(base_dir / f"{execution_id}.rich.json", rich_payload)
        except Exception as exc:
            # Sidecar generation must never break primary artifact generation.
            summary = report.get("summary") if isinstance(report, dict) else None
            if isinstance(summary, dict):
                summary["sidecar_warning"] = f"{type(exc).__name__}: {exc}"

    # Failure evidence is useful even when rich reporting is disabled. Keep
    # this sidecar independent so a TUI/default run cannot lose the exact
    # terminal reason and provider activity that caused an error.
    if status == "error" and (output_dir or enriched_reporting):
        try:
            write_failure_artifact(
                output_dir=base_dir,
                run_id=execution_id,
                error=error or "unknown_error",
                failure=provider_failure,
                final_state={
                    **status_fields,
                    "iteration_count": final_state.get("iteration_count", 0),
                    "task_result": final_state.get("task_result"),
                    "incomplete_reason": final_state.get("incomplete_reason"),
                    "provider": llm_provider,
                    "model": (model_config or {}).get("model_name"),
                    "payload_mode": payload_mode,
                    "llm_required": llm_required,
                    "llm_activity": _llm_activity(events),
                    "confirmed_vulns": list(final_state.get("confirmed_vulns", [])),
                    "achieved_outcomes": list(final_state.get("achieved_outcomes", [])),
                    "fallback_events": list(final_state.get("fallback_events", [])),
                    "invalid_json_events": list(final_state.get("invalid_json_events", [])),
                    "containment_events": list(final_state.get("containment_events", [])),
                    "evasion_enabled": final_state.get("evasion_enabled", False),
                    "evasion_mode": final_state.get("evasion_mode", "reactive"),
                    "evasion_max_retries": final_state.get("evasion_max_retries", 3),
                    "evasion_cooldown_threshold": final_state.get("evasion_cooldown_threshold", 5),
                },
                recent_events=events[-20:],
            )
        except Exception as exc:
            summary = report.get("summary") if isinstance(report, dict) else None
            if isinstance(summary, dict):
                summary["failure_sidecar_warning"] = f"{type(exc).__name__}: {exc}"

    artifact["execution_log"] = list(runtime_events)
    if output_dir:
        try:
            write_json_report(Path(output_dir) / f"{execution_id}.json", artifact)
        except Exception as exc:
            artifact["artifact_write_warning"] = f"{type(exc).__name__}: {exc}"
            status = "error"
            artifact.update(status="error", error=artifact["artifact_write_warning"], execution_status="failed",
                execution_reason=status_reason("ARTIFACT_WRITE_FAILURE", artifact["artifact_write_warning"]))
            artifact["final_state"].update({k: artifact[k] for k in status_fields})
            report["summary"].update({k: artifact[k] for k in status_fields})
            status_fields = {k: artifact[k] for k in status_fields}
            emit("run.failed", node="runner", message=artifact["error"], data={"status": "error", **status_fields})
            artifact["execution_log"] = list(runtime_events)
            try:
                write_failure_artifact(output_dir=base_dir, run_id=execution_id,
                    error=artifact["error"], failure=provider_failure,
                    final_state=artifact["final_state"], recent_events=runtime_events[-20:])
                if enriched_reporting:
                    write_events_jsonl(base_dir / f"{execution_id}.events.jsonl", runtime_events)
                    rich_payload.update(status="error", **status_fields)
                    write_json_report(base_dir / f"{execution_id}.rich.json", rich_payload)
            except Exception as sidecar_exc:
                report["summary"]["failure_sidecar_warning"] = f"{type(sidecar_exc).__name__}: {sidecar_exc}"
    # Completed successful fast-path runs are the only safe checkpoint receipts.
    # Partial/error/cancelled runs are never stored, so resume cannot replay
    # externally acting nodes. Opt-in: only when checkpoint flags are set.
    if checkpoint_store_path is not None and status == "success" and error is None and final_state:
        try:
            store = ExperimentCheckpointStore(checkpoint_store_path, experiment_id=checkpoint_experiment)
            try:
                store.save_completed(
                    thread_id=checkpoint_thread_id,
                    final_state=final_state,
                    artifact=artifact,
                    coordinate=coordinate, graph_thread_id=graph_thread_id,
                )
            finally:
                store.close()
        except Exception as exc:
            artifact["checkpoint_write_warning"] = f"{type(exc).__name__}: {exc}"
    try:
        runtime_stack.close()
    finally:
        if saver_conn is not None:
            try:
                saver_conn.close()
            except Exception:
                pass
    if owns_runtime:
        runtime_service.close()
    return artifact
