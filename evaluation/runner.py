"""Single-engagement Stage 6 evaluation runner."""

from __future__ import annotations

import json
import logging
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from time import perf_counter
from traceback import format_exc
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler

from core.graph_builder import build_framework
from core.knowledge_graph import AttackKnowledgeGraph
from core.scorer import build_score_report
from core.state import new_default_state
from evaluation.diagnostics import diagnose_quality
from evaluation.failure_logger import write_failure_artifact
from evaluation.manual_scoring_sheet import manual_scoring_rows
from evaluation.reporter import write_events_jsonl, write_json_report, write_rich_report
from evaluation.telemetry import RunTelemetry, stable_sha256
from llm.runtime import LLMRuntime, RoleSettings, model_fingerprint
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
        profile = AttackKnowledgeGraph().get_payload_profile(method) or {}
        return int(profile["max_generated_candidates"])
    except (KeyError, TypeError, ValueError):
        return None


def _candidate_event_data(state: dict[str, Any], configured_budget: int) -> dict[str, Any]:
    """Build dashboard counters without changing graph state."""
    method = str(state.get("selected_method") or "")
    generated = (state.get("generated_payloads", {}).get(method, ()) or ()) if method else ()
    accepted = (state.get("payload_candidates", {}).get(method, ()) or ()) if method else ()
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


def _llm_activity(events: list[dict[str, Any]]) -> dict[str, int]:
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
            "model_fingerprint": model_fingerprint({"provider": provider, **resolved}),
        }
    return {
        "max_concurrency": int(context.runtime.max_concurrency),
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


def _payload_generation_failure(final_state: dict[str, Any]) -> dict[str, Any] | None:
    """Return a provider-error payload fallback recorded by the graph."""
    for event in final_state.get("fallback_events", []) or []:
        if not isinstance(event, dict):
            continue
        if (
            event.get("event") == "payload_generation.static_seed_fallback"
            and str(event.get("reason", "")).strip().lower() == "llm_error"
        ):
            return event
    return None


def _terminal_incomplete_reason(final_state: dict[str, Any]) -> str | None:
    """Return a normalized terminal failure reason, if one is present."""
    result = str(final_state.get("task_result") or "").strip().upper()
    reason = str(final_state.get("incomplete_reason") or "").strip()
    if result == "SUCCESS":
        return None
    if result == "INCOMPLETE":
        return reason or "UNSPECIFIED"
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
    llm_runtime: LLMRuntime | None = None,
    llm_role_configs: dict[str, RoleSettings | dict[str, Any]] | None = None,
    model_profiles: dict[str, dict[str, Any]] | None = None,
    llm_cache_enabled: bool = False,
    llm_max_concurrency: int = 1,
    llm_cache: bool | None = None,
    llm_cache_scope: str | None = None,
    role_configs: dict[str, RoleSettings | dict[str, Any]] | None = None,
    llm_runtime_config: dict[str, Any] | None = None,
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
        stop_policy: Evaluation stop policy recorded in artifacts.
        coverage_target: Coverage threshold recorded for diagnostics.
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
    execution_id = execution_id or new_execution_id()
    cancellation_token = cancellation_token or CancellationToken()
    runtime_events: list[dict[str, Any]] = []
    del llm_max_concurrency  # Single-run mode is intentionally fixed at one coordinate.
    if llm_role_configs is None:
        llm_role_configs = role_configs
    if llm_runtime_config and not llm_role_configs:
        raw_roles = llm_runtime_config.get("roles")
        if isinstance(raw_roles, dict):
            llm_role_configs = raw_roles
    if llm_cache is not None:
        llm_cache_enabled = bool(llm_cache)
    if llm_cache_scope is not None:
        llm_cache_enabled = str(llm_cache_scope).strip().lower() == "run"
    runtime_service = llm_runtime or LLMRuntime(max_concurrency=1)
    owns_runtime = llm_runtime is None
    runtime_event_emitter = None

    def forward_runtime_activity(event_type: str, data: dict[str, Any]) -> None:
        if runtime_event_emitter is not None:
            runtime_event_emitter(event_type, data)

    runtime_stack = ExitStack()
    call_context = runtime_stack.enter_context(runtime_service.coordinate(
        coordinate_id=execution_id,
        default_provider=llm_provider,
        default_model_config=model_config or {},
        model_profiles=model_profiles or {llm_provider: model_config or {}},
        role_settings=llm_role_configs or {},
        cache_enabled=llm_cache_enabled,
        activity_callback=forward_runtime_activity,
    ))
    # Automatic method selection is model-backed even for static payloads;
    # explicit target_method + static_only is the only intentional zero-call
    # ablation. Hybrid/mutation modes additionally require payload generation.
    llm_required = (
        target_method is None
        or str(payload_mode).strip().lower() in {"hybrid", "llm_mutation_only"}
    )
    known_secrets = [
        value for key, value in (model_config or {}).items()
        if "key" in key.lower() or "secret" in key.lower() or "token" in key.lower()
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
    try:
        cancellation_token.check()
        evasion_enabled = bool(evasion_enabled)
        app = build_framework(llm_provider=llm_provider, surface=surface)
        init_state = {
            **new_default_state(),
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
            "model_config": model_config or {},
            "experiment_condition": experiment_condition,
            "target_method": target_method,
        }

        if event_sink is not None:
            init_state["model_config"] = {**(model_config or {}), "streaming": True}

        seen_events = 0
        callback_handler = _RuntimeCallbackHandler(emit, provider=llm_provider)
        graph_config = {
            "callbacks": [callback_handler],
            "configurable": {
                "thread_id": execution_id,
            }
        }
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
                    "iteration_count": final_state.get("iteration_count", 0),
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
        if final_state is None:
            cancellation_token.check()
            try:
                final_state = app.invoke(init_state, config=graph_config)
            except TypeError:
                final_state = app.invoke(init_state)
        telemetry.extend_from_state_events(list(final_state.get("telemetry_events", [])))
        llm_activity = _llm_activity(runtime_events)
        hidden_failure = _orchestrator_failure(runtime_events)
        terminal_incomplete_reason = _terminal_incomplete_reason(final_state)
        payload_generation_failure = _payload_generation_failure(final_state)
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
                f"{error_type}: orchestrator model call failed; "
                "deterministic fallback output was retained for audit only"
            )
            status = "error"
            telemetry.emit(
                iteration=int(final_state.get("iteration_count", 0) or 0),
                node="orchestrator",
                event_type="run.failed",
                status="error",
                payload={"error_type": error_type, "reason": "LLM_RUNTIME_FAILURE"},
            )
            emit(
                "run.failed",
                node="orchestrator",
                message=error,
                    data={"error_type": error_type, "reason": "LLM_RUNTIME_FAILURE"},
            )
        elif (
            terminal_incomplete_reason is not None
            and not llm_activity["failed"]
            and payload_generation_failure is None
        ):
            # The graph completed normally, but its terminal state says the
            # requested engagement did not achieve a result.  Do not turn a
            # well-observed failed probe into a misleading successful run.
            final_state = dict(final_state)
            final_state["task_result"] = "INCOMPLETE"
            final_state["incomplete_reason"] = terminal_incomplete_reason
            error = f"Experiment incomplete: {terminal_incomplete_reason}"
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
            error = "LLM runtime failure: at least one provider call failed"
            status = "error"
            telemetry.emit(
                iteration=int(final_state.get("iteration_count", 0) or 0),
                node="runner",
                event_type="run.failed",
                status="error",
                payload={"error_type": "LLM_RUNTIME_FAILURE", "reason": "LLM_RUNTIME_FAILURE"},
            )
            emit(
                "run.failed",
                node="runner",
                message=error,
                data={"error_type": "LLM_RUNTIME_FAILURE", "reason": "LLM_RUNTIME_FAILURE"},
            )
        elif payload_generation_failure is not None:
            # Payload generation currently retains static seeds after a
            # provider exception.  That fallback is useful for auditability,
            # but it is not a successful hybrid experiment because the model
            # requested by the coordinate did not complete its call.
            final_state = dict(final_state)
            final_state["task_result"] = "INCOMPLETE"
            final_state["incomplete_reason"] = "LLM_RUNTIME_FAILURE"
            error = "LLM runtime failure: payload generation fell back to static seeds"
            status = "error"
            telemetry.emit(
                iteration=int(final_state.get("iteration_count", 0) or 0),
                node="payload_candidate_builder",
                event_type="run.failed",
                status="error",
                payload={"error_type": "LLM_RUNTIME_FAILURE", "reason": "LLM_RUNTIME_FAILURE"},
            )
            emit(
                "run.failed",
                node="payload_candidate_builder",
                message=error,
                data={"error_type": "LLM_RUNTIME_FAILURE", "reason": "LLM_RUNTIME_FAILURE"},
            )
        elif llm_required and llm_activity["started"] == 0:
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
        report = build_score_report(final_state).to_dict()
        if reporter:
            reporter.finalize(report)
    except CancellationRequested:
        final_state = final_state or init_state or new_default_state()
        report = build_score_report(final_state).to_dict()
        status = "cancelled"
        error = None
        emit("run.cancelled", message="Cancellation requested; latest safe state retained")
    except Exception as exc:
        final_state = new_default_state()
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
            "iteration_count": 0,
            "evasion_enabled": evasion_enabled,
            "evasion_mode": evasion_mode,
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
            "task_result": "INCOMPLETE",
            "incomplete_reason": "RUNNER_EXCEPTION",
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
    telemetry.emit(
        iteration=int(final_state.get("iteration_count", 0) or 0),
        node="runner",
        event_type="run.finished",
        status=status,
        payload={"duration_ms": duration_ms},
    )
    emit(
        "run.finished",
        message=f"Experiment {status}",
        data={"status": status, "duration_ms": duration_ms},
    )

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
            write_rich_report(base_dir / f"{execution_id}.rich.json", rich_payload)
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
                final_state={
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

    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    method_scores = dict(final_state.get("method_scores", {}))
    payload_scores = dict(final_state.get("payload_scores", {}))
    exploitation_scores = dict(final_state.get("exploitation_scores", {}))
    chain_scores = dict(final_state.get("chain_scores", {}))
    selected_method = final_state.get("selected_method")
    method_score = method_scores.get(selected_method, 0)
    exploitation_score = exploitation_scores.get(selected_method, 0)
    chain_score = chain_scores.get(selected_method, 0)
    llm_activity = _llm_activity(runtime_events)
    llm_performance = [dict(row) for row in call_context.records]
    llm_performance_summary = call_context.performance_summary()
    effective_llm_runtime_config = _effective_llm_runtime_config(
        call_context,
        candidate_budget=candidate_budget,
    )

    artifact = {
        "schema_version": "tui.v1",
        "execution_id": execution_id,
        "run_id": run_id,
        "status": status,
        "experiment_condition": experiment_condition,
        "target_method": target_method,
        "provider": llm_provider,
        "model": (model_config or {}).get("model_name"),
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
        "consistency_score": summary.get("consistency_score", 0.0),
        "guardrail_activations": list(final_state.get("guardrail_activations", [])),
        "guardrail_activation_count": len(final_state.get("guardrail_activations", [])),
        "payload_guardrail_activations": len(final_state.get("payload_guardrail_activations", [])),
        "attempts_to_success": int(round(summary.get("mean_attempts_to_success", 0.0) or 0.0)),
        "token_cost": summary.get("token_cost", 0.0),
        "config": {
            "target_url": target_url,
            "provider": llm_provider,
            "model": (model_config or {}).get("model_name"),
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
            "candidate_budget": candidate_budget,
            "repeat_index": repeat_index,
            "experiment_condition": experiment_condition,
            "target_method": target_method,
            "evasion_enabled": evasion_enabled,
            "evasion_mode": evasion_mode,
            "evasion_max_retries": evasion_max_retries,
            "evasion_cooldown_threshold": evasion_cooldown_threshold,
        },
        "timing": {
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_ms": duration_ms,
        },
        "final_state": {
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
            "payload_scores": payload_scores,
            "payload_provenance": dict(final_state.get("payload_provenance", {})),
            "method_scores": method_scores,
            "exploitation_scores": exploitation_scores,
            "chain_scores": chain_scores,
            "output_scores": dict(final_state.get("output_scores", {})),
            "composite_scores": dict(final_state.get("composite_scores", {})),
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
        "payload_provenance": dict(final_state.get("payload_provenance", {})),
        "confirmed_vulns": list(final_state.get("confirmed_vulns", [])),
        "achieved_outcomes": list(final_state.get("achieved_outcomes", [])),
        "invalid_json_events": list(final_state.get("invalid_json_events", [])),
        "fallback_events": list(final_state.get("fallback_events", [])),
        "containment_events": list(final_state.get("containment_events", [])),
        "execution_log": runtime_events,
        "response_evidence": list(final_state.get("response_evidence", [])),
        "timing_evidence": list(final_state.get("timing_evidence", [])),
        "verifier_decision": final_state.get("verifier_decision"),
        "output_score": dict(final_state.get("output_scores", {})).get(selected_method, 0),
        "composite_score": dict(final_state.get("composite_scores", {})).get(selected_method, 0),
        "error": error,
    }
    artifact["config_fingerprint"] = config_fingerprint(artifact["config"])
    artifact["manual_scoring_evidence"] = manual_scoring_rows(artifact)
    if output_dir:
        try:
            write_json_report(Path(output_dir) / f"{execution_id}.json", artifact)
        except Exception as exc:
            artifact["artifact_write_warning"] = f"{type(exc).__name__}: {exc}"
    if owns_runtime:
        runtime_service.close()
    return artifact
