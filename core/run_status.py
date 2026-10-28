"""Pure terminal-status mapping and conservative, rubric-backed evidence reads.

Legacy aliases describe findings, never execution reliability. Historical files
are read without mutation; an ambiguous old error remains unattributed.
"""
from collections.abc import Mapping

from core.state import ExecutionStatus, StatusReason, StatusReasonCode
from typing import cast


EXECUTION_STATUSES = ("completed", "failed", "interrupted")
SECURITY_OUTCOMES = ("confirmed", "no_finding", "unconfirmed", "fixture_limited")
STATUS_FIELDS = ("execution_status", "execution_reason", "security_outcome", "security_outcome_reason")
FAILURE_REASONS = frozenset({
    "LLM_RUNTIME_FAILURE", "LLM_NOT_CALLED", "LLM_ACTIVITY_INCOMPLETE",
    "RUNNER_EXCEPTION", "RESUME_REFUSED", "TARGET_TRANSPORT_FAILURE", "TARGET_REQUEST_FAILURE",
    "ARTIFACT_WRITE_FAILURE", "ARTIFACT_PROCESSING_FAILURE", "RUNTIME_FAILURE",
    "SESSION_LOGIN_FAILED", "METHOD_EXECUTION_FAILURE",
    "READINESS_FAILED", "READINESS_UNKNOWN", "CONTROL_CONTAMINATION",
    "TARGET_METHOD_INFEASIBLE",
})


def reason(code: str, detail: str = "", refs: list[str] | None = None) -> StatusReason:
    # Legacy failure codes remain readable; new producers use StatusReasonCode.
    return {"code": cast(StatusReasonCode, code), "detail": detail, "evidence_refs": list(refs or [])}


def lifecycle_alias(execution_status: str | None) -> str:
    return {"completed": "success", "failed": "error", "interrupted": "cancelled"}.get(execution_status, "unknown")


def _security_evidence(source: Mapping) -> tuple[str, StatusReason | None]:
    """Use existing scoring.v4 proof ceilings, without changing verifier rules."""
    from evaluation.scoring_evidence import candidate_base, oracle_negative_confirmed
    from evaluation.thesis_scoring import _resolve

    state = source.get("final_state", source)
    if not isinstance(state, Mapping):
        state = {}
    artifact = dict(source) if "final_state" in source else {
        "final_state": state, "response_evidence": state.get("response_evidence", []),
        "timing_evidence": state.get("timing_evidence", []), "config": {},
    }
    method = source.get("target_method") or state.get("target_method") or state.get("selected_method")
    methods = list(dict.fromkeys(([method] if method else []) + list(state.get("payload_candidates", {}))))
    assessed = []
    negative_refs = []
    partial = []
    missing_oracle = []
    for selected in methods:
        for candidate in state.get("payload_candidates", {}).get(selected, []):
            cid = candidate.get("candidate_id")
            if not cid or candidate.get("stage") not in {"exploit", "bypass"}:
                continue
            refs = [f"#/final_state/{field}/{i}" for field in ("response_evidence", "timing_evidence")
                for i, row in enumerate(state.get(field, []))
                if cid in {row.get("candidate_id"), row.get("source_candidate_id")} and row.get("agent_id") == selected
                and row.get("identity_kind") != "independent_control"]
            if not refs:
                if candidate.get("payload_or_logic") in state.get("tried_payloads", {}).get(selected, []):
                    assessed.append(None)
                continue
            try:
                base = candidate_base(artifact, cid, selected, refs)
            except (KeyError, TypeError, ValueError, IndexError):
                base = None  # Missing or invalid historical proof cannot establish a finding.
            decisions = [d for d in state.get("verifier_history", [])
                if d.get("agent_id") == selected and d.get("source") == "method_agent_evidence"
                and any(_resolve(artifact, ref).get("visit_id") == d.get("visit_id") for ref in refs)]
            if base == 3 and any(d.get("decision") == "confirmed" for d in decisions):
                return "confirmed", None
            controlled_negative = base == 0 and any(oracle_negative_confirmed(artifact, _resolve(artifact, ref))
                for ref in refs if isinstance(_resolve(artifact, ref), dict))
            if str(selected).startswith(("ac_", "bf_")) and not controlled_negative and (base is not None or any(
                    d.get("reason") == "missing_independent_authorization_control" for d in decisions)):
                # Session labels and absent attestations cannot prove a negative.
                missing_oracle.extend(refs)
                assessed.append(None)
            elif base == 0 and decisions and all(d.get("decision") == "not_confirmed" for d in decisions):
                usable = all((_resolve(artifact, ref).get("status_code") in (200, 404)
                    or oracle_negative_confirmed(artifact, _resolve(artifact, ref)))
                    and _resolve(artifact, ref).get("response_sha256") for ref in refs)
                assessed.append(0 if usable else None)
                if usable:
                    negative_refs.extend(refs)
            else:
                assessed.append(None)
                if base in (1, 2):
                    partial.extend(refs)
    if missing_oracle:
        code = "PERMISSION_ORACLE_UNAVAILABLE" if any(str(m).startswith("ac_") for m in methods) else "SESSION_ORACLE_UNAVAILABLE"
        return "fixture_limited", reason(code, "Required independent control does not establish the candidate outcome.", missing_oracle)
    if assessed and all(value == 0 for value in assessed):
        return "no_finding", reason("VERIFIED_NEGATIVE", "Assessed candidates have linked negative verifier evidence.", negative_refs)
    if partial:
        return "unconfirmed", reason("PARTIAL_SIGNAL", "Candidate evidence is below the confirmation threshold.", partial)
    return "unconfirmed", reason("NO_CANDIDATE_CONFIRMATION", "Missing or ambiguous candidate proof cannot establish presence or absence.")


def terminal_status(source: Mapping, *, execution_status: ExecutionStatus | None = None,
                    execution_reason: StatusReason | None = None, classify: bool = False) -> dict:
    """Validate canonical fields or map legacy evidence without rewriting it.

    Producers pass a known terminal lifecycle and classify=True. Readers retain
    None for unknown old lifecycle; skipped coordinates have no execution.
    """
    state = source.get("final_state", source)
    if not isinstance(state, Mapping):
        state = {}
    def value(key):
        return source.get(key) if source.get(key) is not None else state.get(key)

    legacy_reason = str(value("incomplete_reason") or "")
    lifecycle = execution_status or value("execution_status")
    if lifecycle is not None and lifecycle not in EXECUTION_STATUSES:
        raise ValueError(f"Invalid execution_status: {lifecycle}")
    failure = execution_reason or value("execution_reason")
    if lifecycle is None:
        raw = str(source.get("status") or "").lower()
        activity = source.get("llm_activity") or state.get("llm_activity") or {}
        if raw in {"cancelled", "interrupted"} or legacy_reason == "CANCELLED":
            lifecycle, failure = "interrupted", reason("CANCELLED")
        elif legacy_reason in FAILURE_REASONS or legacy_reason.startswith("INVALID_TASK_RESULT:") or source.get("failure") or activity.get("failed"):
            lifecycle, failure = "failed", reason(legacy_reason or "LLM_RUNTIME_FAILURE")
        elif raw in {"success", "completed", "finished"}:
            lifecycle = "completed"
        elif raw == "error" and legacy_reason in {"ALL_METHODS_FAILED", "ITERATION_LIMIT", "NO_VIABLE_METHODS", "MODEL_STOPPED_WITHOUT_FINDING", "UNSPECIFIED"}:
            responses = source.get("response_evidence", state.get("response_evidence", []))
            calls_complete = not source.get("llm_required") or (activity.get("started", 0) > 0
                and activity.get("started") == activity.get("completed"))
            if (any(e.get("event_type") == "run.finished" for e in source.get("execution_log", []))
                    and calls_complete and all(row.get("status_code") is not None for row in responses)):
                lifecycle = "completed"
        elif raw in {"error", "failed"} and not legacy_reason and source.get("error"):
            lifecycle, failure = "failed", reason("RUNNER_EXCEPTION", str(source["error"]))
    if lifecycle == "completed":
        failure = None
    elif lifecycle is not None and failure is None:
        failure = reason(legacy_reason or ("CANCELLED" if lifecycle == "interrupted" else "RUNTIME_FAILURE"))
    outcome = value("security_outcome")
    if outcome is not None and outcome not in SECURITY_OUTCOMES:
        raise ValueError(f"Invalid security_outcome: {outcome}")
    outcome_reason = value("security_outcome_reason")
    if classify or outcome is None:
        evidence_outcome, evidence_reason = _security_evidence(source)
        failure_code = str((failure or {}).get("code") or "")
        environment_failure = (
            lifecycle == "failed"
            and failure_code in {
                "READINESS_FAILED", "READINESS_UNKNOWN", "CONTROL_CONTAMINATION",
            }
        )
        if evidence_outcome == "confirmed":
            # Positive candidate proof always wins over a stale limitation label.
            outcome, outcome_reason = evidence_outcome, evidence_reason
        elif outcome == "fixture_limited" and environment_failure:
            # Readiness/quarantine blocks are fixture limitations, not absence of
            # a finding; preserve the specific recorded reason.
            outcome_reason = outcome_reason or reason(
                failure_code or "READINESS_FAILED",
                str((failure or {}).get("detail") or "Run limited by fixture state."),
                list((failure or {}).get("evidence_refs") or []),
            )
        else:
            outcome, outcome_reason = evidence_outcome, evidence_reason
    if outcome == "confirmed":
        outcome_reason = None
    elif outcome_reason is None:
        outcome_reason = reason("NO_CANDIDATE_CONFIRMATION")
    for item in (failure, outcome_reason):
        if item is not None and (not isinstance(item, dict) or not isinstance(item.get("code"), str)
                or not item["code"] or not isinstance(item.get("detail"), str)
                or not isinstance(item.get("evidence_refs"), list)
                or any(not isinstance(ref, str) for ref in item["evidence_refs"])):
            raise ValueError("Status reasons require code, detail, and evidence_refs")
    return dict(execution_status=lifecycle, execution_reason=failure,
                security_outcome=outcome, security_outcome_reason=outcome_reason)


def matrix_terminal_status(artifacts: list[dict], *, interrupted: bool = False, interruption_reason: str = "") -> dict:
    """Summarize child evidence independently of the matrix execution lifecycle."""
    fields = [terminal_status(artifact) for artifact in artifacts if artifact.get("status") != "skipped"]
    interrupted = interrupted or any(item["execution_status"] == "interrupted" for item in fields)
    failed = any(item["execution_status"] == "failed" for item in fields)
    unknown = any(item["execution_status"] is None for item in fields)
    lifecycle = "interrupted" if interrupted else "failed" if failed or unknown else "completed"
    outcome = ("confirmed" if any(item["security_outcome"] == "confirmed" for item in fields)
        else "no_finding" if fields and all(item["security_outcome"] == "no_finding" for item in fields)
        else "fixture_limited" if any(item["security_outcome"] == "fixture_limited" for item in fields)
        else "unconfirmed")
    return terminal_status({"security_outcome": outcome,
        "security_outcome_reason": None if outcome == "confirmed" else reason("CHILD_OUTCOMES", "See child reasons and separate outcome counts.")},
        execution_status=lifecycle, execution_reason=reason("CANCELLED", interruption_reason) if interrupted
        else reason("CHILD_EXECUTION_FAILED") if failed
        else reason("CHILD_EXECUTION_UNKNOWN", "Child lifecycle evidence is insufficient to establish matrix completion.") if unknown else None)
