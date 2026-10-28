"""Shared helpers for Stage 5 vulnerability and chain agents."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from core.payload_policy import (
    BUDGET_POLICY_VERSION,
    CONTROL_POLICY_VERSION,
    EXPERIMENT_POLICY_VERSION,
    PAYLOAD_POLICY_VERSION,
    STRICT_PAYLOAD_MODES,
    lifecycle_fact,
    origin_kind_permitted,
    require_payload_mode,
)
from foundation.http_client import RequestTimeoutError, TransportError
from foundation.payload_library import PayloadLibrary
from core.state import METHODS_BY_SURFACE, score_decision
from tesis.runtime_events import redact_secrets


class CandidatePayload(str):
    """String payload that retains its validated candidate identity in flight."""

    def __new__(cls, value: str, candidate_id: str):
        instance = super().__new__(cls, value)
        instance.candidate_id = candidate_id
        return instance

    def __getnewargs__(self) -> tuple[str, str]:
        """Keep identity when runtime state copies or pickles payload values."""
        return str(self), self.candidate_id


class ControlPayload(str):
    """Detection-control string that retains its frozen control identity."""

    def __new__(cls, value: str, control_id: str):
        instance = super().__new__(cls, value)
        instance.control_id = control_id
        return instance

    def __getnewargs__(self) -> tuple[str, str]:
        """Keep identity when runtime state copies or pickles control values."""
        return str(self), self.control_id


CONTROL_EVENT_POLICY_VERSION = "control-event.v1"
_NON_CANDIDATE_IDENTITY_KINDS = frozenset({
    "independent_control", "derived_control", "probe_candidate", "unresolved",
})


def state_payload_mode(state: Mapping[str, Any]) -> str:
    """Return the registered payload mode, failing closed on an invalid value."""
    return require_payload_mode(state.get("payload_mode", "static_only"))


def strict_payload_mode(state: Mapping[str, Any]) -> bool:
    """Return whether only current-visit model exploit candidates are allowed."""
    return state_payload_mode(state) in STRICT_PAYLOAD_MODES


def _is_graph_visit(state: Mapping[str, Any], module_name: str) -> bool:
    """A graph visit always carries a reserved visit or explicit queue/controls."""
    return bool(
        state.get("selected_visit_id")
        or isinstance(state.get("active_payload_candidates", {}).get(module_name), Mapping)
        or module_name in state.get("payload_validation_results", {})
        or module_name in state.get("probe_controls", {})
    )


def graph_visit(state: Mapping[str, Any], module_name: str) -> bool:
    """Return whether this invocation belongs to a reserved graph visit."""
    return _is_graph_visit(state, module_name)


def _visit_id(state: Mapping[str, Any], module_name: str) -> str:
    return str(state.get("selected_visit_id") or f"{module_name}:legacy:{state.get('iteration_count', 0)}")


def _scope_fields(state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "fixture_id": state.get("fixture_id"),
        "protocol_version": state.get("protocol_version"),
        "security_level": state.get("security_level"),
    }


def selection_opportunity(
    state: Mapping[str, Any],
    *,
    method: str | None,
    visit_id: str | None,
    required: bool,
    status: str,
    reason: str,
    call_id: str | None = None,
    decision_source: str | None = None,
    scope: str = "method",
) -> dict[str, Any]:
    """Build one append-only orchestrator selection opportunity receipt."""
    ordinal = 1 + sum(
        row.get("role") == "orchestrator"
        for row in state.get("model_call_requirements", [])
        if isinstance(row, Mapping)
    )
    return {
        "opportunity_id": f"orchestrator:{state.get('execution_id') or state.get('run_id') or 'run'}:{ordinal}",
        "role": "orchestrator",
        "method": method,
        "visit_id": visit_id,
        "required": bool(required),
        "status": str(status),
        "reason": str(reason),
        "call_id": call_id,
        "decision_source": decision_source,
        "scope": scope,
        "payload_mode": state.get("payload_mode"),
        "policy_version": EXPERIMENT_POLICY_VERSION,
    }


def rejected_selection_update(
    state: Mapping[str, Any],
    method: str,
    source: str,
    gate: Mapping[str, Any],
    *,
    decision_origin: str = "model",
    candidate_set_source: str | None = None,
    considered_methods: list[str] | None = None,
    history: list[dict] | None = None,
) -> dict[str, Any]:
    """Record a supported post-selection rejection without executing a visit."""
    surface = next((s for s, methods in METHODS_BY_SURFACE.items() if method in methods), "")
    ordinal = 1 + sum(d.get("dimension") == "Smethod" for d in state.get("scoring_decisions", []))
    visit_id = f"{method}:visit:{ordinal}"
    prior_model_decisions = [
        row for row in [*(state.get("selection_rejections", []) or []), *(history or [])]
        if isinstance(row, Mapping) and row.get("decision_origin") == "model"
    ]
    reason = str(gate.get("reason") or "precondition_false")
    from foundation.preconditions import derived_selector_observations
    row = {
        "decision_id": f"{visit_id}:selection:rejected",
        "method": method,
        "visit_id": visit_id,
        "source": source,
        "decision_origin": decision_origin,
        "candidate_set_source": candidate_set_source or ("canonical" if state.get("experiment_condition") != "akg_guided_hybrid" else "viable"),
        "surface": surface,
        "required_preconditions": list(gate.get("required") or []),
        "precondition_status": dict(gate.get("status") or {}),
        "observations": derived_selector_observations(state),
        "profile_sha256": (state.get('scoring_profile') or {}).get('sha256'),
        "profile_id": (state.get('scoring_profile') or {}).get('profile_id'),
        "reason_code": reason,
        "detail": str(gate.get("detail") or ""),
        "evidence_refs": list(gate.get("evidence_refs") or []),
        "considered_methods": list(considered_methods or []),
        "first_choice": decision_origin == "model" and not prior_model_decisions,
        "selected_at": datetime.now(timezone.utc).isoformat(),
        "rejected_at": datetime.now(timezone.utc).isoformat(),
        "policy_version": EXPERIMENT_POLICY_VERSION,
    }
    telemetry = [{
        "node": "orchestrator", "event": "orchestrator.selection.rejected",
        "status": "incomplete",
        "payload": {"method": method, "reason": reason, "visit_id": visit_id,
                    "preconditions": row["required_preconditions"],
                    "precondition_status": row["precondition_status"]},
    }]
    return {
        "selected_method": None,
        "selected_visit_id": visit_id,
        "next_agent": "scorer",
        "iteration_count": state.get("iteration_count", 0) + 1,
        "selection_rejections": [row],
        "telemetry_events": telemetry,
    }


def method_selection_update(state: dict, method: str, source: str, *, preconditions: list[str] | None = None,
                            viable_methods: list[str] | None = None, reason_refs=None, plan=None,
                            considered_methods: list[str] | None = None,
                            candidate_set_source: str | None = None,
                            decision_origin: str | None = None,
                            first_choice: bool | None = None) -> dict:
    """Grade every selection at its boundary, before execution changes viability."""
    from foundation.preconditions import (
        derived_selector_observations,
        precondition_keys_for_method,
        statuses_snapshot,
    )
    derived_observations = derived_selector_observations(state)
    surface = next(s for s, methods in METHODS_BY_SURFACE.items() if method in methods)
    status = statuses_snapshot(state, method)
    viable = ([candidate for candidate in METHODS_BY_SURFACE[surface]
               if all(value == "true" for value in statuses_snapshot(state, candidate).values())]
              if viable_methods is None else viable_methods)
    viable = [m for m in viable if m in METHODS_BY_SURFACE[surface]]
    known = set(state.get("confirmed_vulns", [])) | set(state.get("achieved_outcomes", []))
    # Surface aliases are used for prerequisites only, never vulnerability confirmations.
    for s, methods in METHODS_BY_SURFACE.items():
        if any(f"{m}_confirmed" in known for m in methods):
            known.add(f"{s}_confirmed")
    requirements = list(preconditions or precondition_keys_for_method(method))
    all_proved = all(status.get(key) == "true" for key in requirements) if requirements else True
    is_viable = method in viable and all_proved
    grade = 3 if is_viable else 1
    ordinal = 1 + sum(d.get("dimension") == "Smethod" for d in state.get("scoring_decisions", []))
    visit_id = f"{method}:visit:{ordinal}"
    origin = decision_origin or {
        "forced": "forced", "akg_route": "route", "route": "route",
        "deterministic_fallback": "deterministic_fallback", "model_orchestrator": "model",
    }.get(source, "model")
    set_source = candidate_set_source or (
        "forced" if origin == "forced"
        else "viable" if state.get("experiment_condition") == "akg_guided_hybrid"
        else "canonical"
    )
    if first_choice is None:
        first_choice = origin == "model" and not any(
            d.get("dimension") == "Smethod" and d.get("decision_origin") == "model"
            for d in state.get("scoring_decisions", []))
    return {"selected_method": method, "selected_visit_id": visit_id,
        "iteration_count": state.get("iteration_count", 0) + 1,
        "viable_methods": viable, "method_scores": {method: grade},
        "scoring_decisions": [score_decision(state, "Smethod", method, grade,
            "viable_at_selection" if is_viable else "prerequisites_not_proved_at_selection",
            visit_id=visit_id, selection_source=source, decision_origin=origin,
            candidate_set_source=set_source, first_choice=first_choice,
            considered_methods=list(considered_methods or METHODS_BY_SURFACE[surface]),
            surface=surface, viable=is_viable,
            preconditions=requirements, precondition_status=dict(status),
            observations=derived_observations,
            selected_at=datetime.now(timezone.utc).isoformat(),
            profile_sha256=(state.get('scoring_profile') or {}).get('sha256'),
            profile_id=(state.get('scoring_profile') or {}).get('profile_id'),
            comparison_methods=list(METHODS_BY_SURFACE[surface]),
            reason_refs=list(reason_refs or []), plan=deepcopy(plan or {}),
            known_nodes=sorted(known))]}

def agent_visit_gate(state: Mapping[str, Any], module_name: str) -> dict[str, Any]:
    """Return the fail-closed readiness/quarantine/prerequisite decision."""
    from foundation.control_catalog import precondition_gate, quarantine_gate
    from foundation.readiness import readiness_gate

    gate = readiness_gate(state)
    if gate.get("decision") == "block":
        return {"allow": False, "stop": "readiness", "gate": gate}
    quarantine = quarantine_gate(state)
    if quarantine.get("blocked"):
        return {"allow": False, "stop": "quarantine", "gate": quarantine}
    gate = precondition_gate(state, module_name)
    if gate.get("decision") == "reject":
        return {"allow": False, "stop": "precondition", "gate": gate}
    return {"allow": True, "stop": None, "gate": gate}


def visit_block_update(
    state: Mapping[str, Any],
    module_name: str,
    *,
    stop: str,
    gate: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the explicit terminal/no-request update for a blocked visit."""
    from core.run_status import reason
    from foundation.readiness import readiness_block_update

    telemetry = [{
        "node": module_name,
        "event": f"agent.visit.blocked.{stop}",
        "status": "incomplete",
        "payload": {"method": module_name, "visit_id": _visit_id(state, module_name),
                    "reason": gate.get("reason") or gate.get("code"),
                    "evidence_refs": list(gate.get("evidence_refs") or [])},
    }]
    if stop == "readiness":
        update = readiness_block_update(gate)
        update.update({"blocked_agents": [module_name], "telemetry_events": telemetry})
        return update
    if stop == "quarantine":
        code = "CONTROL_CONTAMINATION"
        detail = str(gate.get("reason") or "quarantined_visit")
        return {
            "next_agent": "scorer", "selected_method": None,
            "blocked_agents": [module_name],
            "task_result": "INCOMPLETE", "incomplete_reason": code,
            "workflow_stop_reason": "control_quarantine",
            "execution_status": "failed",
            "execution_reason": reason(code, detail, list(gate.get("evidence_refs") or [])),
            "security_outcome": "fixture_limited",
            "security_outcome_reason": reason(code, detail, list(gate.get("evidence_refs") or [])),
            "telemetry_events": telemetry,
            **_stopped_candidates_update(state, module_name, "control_quarantine"),
        }
    reason_code = str(gate.get("reason") or "precondition_false")
    update: dict[str, Any] = {
        "next_agent": "scorer" if state.get("target_method") == module_name else "orchestrator",
        "selected_method": None,
        "preparation_failures": [{
            "method": module_name, "visit_id": _visit_id(state, module_name),
            "reason": "PRECONDITION_UNMET", "detail": reason_code,
            "precondition_status": dict(gate.get("status") or {}),
            "evidence_refs": list(gate.get("evidence_refs") or []),
            "policy_version": CONTROL_POLICY_VERSION,
        }],
        "telemetry_events": telemetry,
        **_stopped_candidates_update(state, module_name, reason_code),
    }
    if state.get("target_method") == module_name:
        update.update({
            "task_result": "INCOMPLETE", "incomplete_reason": "PRECONDITION_UNMET",
            "workflow_stop_reason": reason_code,
            "execution_status": "completed",
            "execution_reason": reason("PRECONDITION_UNMET", reason_code,
                                       list(gate.get("evidence_refs") or [])),
        })
    return update


def _stopped_candidates_update(state: Mapping[str, Any], module_name: str,
                               reason_code: str) -> dict[str, Any]:
    """Mark every current-visit queue candidate as explicitly unexecuted."""
    rows: list[dict] = []
    visit_id = _visit_id(state, module_name)
    for candidate in validated_payload_candidates(dict(state), module_name):
        candidate_id = candidate.get("candidate_id")
        if candidate_id is None:
            continue
        rows.append(candidate_lifecycle_fact(
            method=module_name, visit_id=visit_id, candidate_id=str(candidate_id),
            origin_kind=str(candidate.get("origin_kind") or _candidate_origin_kind(state, candidate)),
            status="stopped_before_execution", reason=reason_code, evidence_refs=[]))
    return {"candidate_lifecycle": rows} if rows else {}


_LEGACY_ORIGIN_ALIASES = {
    "llm_generated": "seed_mutation",
    "llm_mutation": "seed_mutation",
    "model_generated": "seed_mutation",
    "template": "template_generation",
    "template_constructed": "template_generation",
    "static": "static_seed",
    "static_seed": "static_seed",
    "chain": "chain_derived",
    "chain_derived": "chain_derived",
}


def _candidate_origin_kind(state: Mapping[str, Any], candidate: Mapping[str, Any]) -> str:
    """Return a canonical origin kind, normalizing legacy reader labels only."""
    provenance = state.get("payload_provenance", {}).get(str(candidate.get("candidate_id")), {})
    recorded = str(candidate.get("origin_kind") or provenance.get("origin_kind")
                   or provenance.get("source") or candidate.get("source") or "static_seed")
    return _LEGACY_ORIGIN_ALIASES.get(recorded, recorded)


def candidate_lifecycle_fact(
    *,
    method: str,
    visit_id: str,
    candidate_id: str,
    origin_kind: str,
    status: str,
    reason: str | None,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    """Build one shared candidate-lifecycle row with the frozen identity."""
    row = lifecycle_fact(method=method, visit_id=visit_id, candidate_id=candidate_id,
                         origin_kind=origin_kind, status=status, reason=reason,
                         evidence_refs=list(evidence_refs or []))
    return {**row, "policy_version": BUDGET_POLICY_VERSION}


def probe_stage_blocked_update(
    state: Mapping[str, Any],
    module_name: str,
    *,
    reason: str = "no_safe_detection_control",
) -> dict[str, Any]:
    """Record an explicit zero-request stop when no safe detection control exists."""
    from core.run_status import reason as status_reason
    telemetry = [{
        "node": module_name, "event": "agent.probe.blocked", "status": "incomplete",
        "payload": {"method": module_name, "visit_id": _visit_id(state, module_name),
                    "reason": reason},
    }]
    update: dict[str, Any] = {
        "next_agent": "scorer" if state.get("target_method") == module_name else "orchestrator",
        "selected_method": None,
        "preparation_failures": [{
            "method": module_name, "visit_id": _visit_id(state, module_name),
            "reason": "NO_SAFE_DETECTION_CONTROL", "detail": reason,
            "policy_version": CONTROL_POLICY_VERSION,
        }],
        "telemetry_events": telemetry,
        **_stopped_candidates_update(state, module_name, reason),
    }
    if state.get("target_method") == module_name:
        update.update({
            "task_result": "INCOMPLETE", "incomplete_reason": "NO_SAFE_DETECTION_CONTROL",
            "workflow_stop_reason": reason,
            "execution_status": "completed",
            "execution_reason": status_reason("NO_SAFE_DETECTION_CONTROL", reason),
        })
    return update


def probe_outcome_update(
    state: Mapping[str, Any],
    module_name: str,
    observations: Mapping[str, Any],
    telemetry_events: list[dict],
    *,
    principal_id: str | None = None,
    session_fingerprint: str | None = None,
    snapshot: Mapping[str, Any] | None = None,
    snapshot_key: str | None = None,
) -> tuple[dict[str, Any], str | None]:
    """Record control events, scoped facts, and a quarantine decision.

    Probe requests are controls, never exploit candidates.  A control whose
    response unexpectedly authenticates, reads sensitive data, or proves the
    assessed exploit quarantines the visit instead of granting credit.
    """
    from foundation.control_catalog import (
        CONTROL_EVENT_POLICY_VERSION as EVENT_VERSION,
        control_event,
        resolve_catalog_controls,
    )
    from foundation.preconditions import (
        SESSION_FACT_KEYS,
        make_observation_fact,
        observation_update,
        precondition_keys_for_method,
    )

    if not isinstance(principal_id, str) or not principal_id:
        principal_id = None
    if not isinstance(session_fingerprint, str) or not session_fingerprint:
        session_fingerprint = None
    snapshot = snapshot if snapshot is not None else state.get("probe_controls", {}).get(module_name)
    visit_id = (str(snapshot.get("visit_id")) if isinstance(snapshot, Mapping) and snapshot.get("visit_id")
                else _visit_id(state, module_name))
    control_events: list[dict] = []
    facts: list[dict] = []
    quarantine: str | None = None
    if isinstance(snapshot, Mapping):
        resolved, skipped = resolve_catalog_controls(snapshot, principal_id)
        events_by_control: dict[str, list[dict]] = {}
        for event in telemetry_events:
            if not isinstance(event, dict) or event.get("event") != "agent.probe.sent":
                continue
            payload = event.get("payload") if isinstance(event.get("payload"), Mapping) else {}
            control_id = payload.get("control_id")
            if control_id:
                events_by_control.setdefault(str(control_id), []).append(dict(payload))
        for row in resolved:
            control_id = str(row.get("control_id"))
            events = events_by_control.get(control_id, [])
            if not events:
                resolved_payload = str(row.get("resolved_payload"))
                events = [dict(event.get("payload") or {}) for event in telemetry_events
                          if isinstance(event, dict) and event.get("event") == "agent.probe.sent"
                          and str((event.get("payload") or {}).get("payload")) == resolved_payload]
                for event in events:
                    event.setdefault("control_id", control_id)
            sent = [event for event in events if event.get("status_code") is not None]
            signal = any(event.get("signal_detected") is True for event in events)
            status = "sent" if sent else "failed" if events else "skipped"
            control_events.append(control_event(
                control_id=control_id, control_class="detection", method=module_name,
                visit_id=visit_id, phase=str(snapshot.get("phase") or "method_probe"),
                purpose=str(row.get("purpose") or "precondition_measurement"),
                status=status, reason="control_response_recorded" if sent else "control_request_failed" if events else "control_not_sent",
                request_id=sent[-1].get("request_id") if sent else None,
                evidence_id=None, http_status=sent[-1].get("status_code") if sent else None,
                signal_detected=signal if events else None,
                physical_requests=len(events)))
        for row in skipped:
            control_events.append(control_event(
                control_id=str(row.get("control_id")), control_class="detection",
                method=module_name, visit_id=visit_id,
                phase=str(snapshot.get("phase") or "method_probe"),
                purpose=str(row.get("purpose") or "precondition_measurement"),
                status="skipped", reason=str(row.get("reason") or "control_skipped")))
        sent_count = sum(1 for event in control_events if event.get("status") == "sent")
        physical_count = sum(int(event.get("physical_requests") or 0) for event in control_events)
        updated = {**dict(snapshot), "requests_used": sent_count,
                   "physical_requests_used": physical_count,
                   "control_events": [*list(snapshot.get("control_events", []) or []), *control_events]}
        declared_keys = set(precondition_keys_for_method(module_name)) | set(SESSION_FACT_KEYS)
        signal_rows = [row for row in resolved if any(
            event.get("signal_detected") is True for event in events_by_control.get(str(row.get("control_id")), []))]
        evidence_refs = [f"control:{row.get('control_id')}" for row in resolved]
        failed_control = any(event.get("status") == "failed" for event in control_events)
        for key, value in observations.items():
            if key not in declared_keys:
                continue
            method_scope = module_name
            fact_session_scope = "session"
            facts.append(make_observation_fact(
                key, (value if isinstance(value, bool) and sent_count
                      and (value is True or not failed_control) else None),
                source="detection_control", method=method_scope, visit_id=visit_id,
                control_id=str((signal_rows or resolved or [{}])[0].get("control_id") or "") or None,
                evidence_refs=evidence_refs, phase=str(snapshot.get("phase") or "method_probe"),
                fixture_id=state.get("fixture_id"),
                protocol_version=state.get("protocol_version"),
                security_level=state.get("security_level"),
                principal_id=principal_id,
                session_fingerprint=session_fingerprint,
                session_scope=fact_session_scope,
                detail=str(snapshot.get("catalog_sha256") or "")))
        scoped_state = {**dict(state)}
        if principal_id:
            scoped_state["method_principals"] = {
                **dict(state.get("method_principals", {}) or {}),
                module_name: str(principal_id),
            }
        if session_fingerprint:
            scoped_state["method_session_fingerprints"] = {
                **dict(state.get("method_session_fingerprints", {}) or {}),
                module_name: session_fingerprint,
            }
        update = observation_update(scoped_state, facts, method=module_name)
        if principal_id:
            update["method_principals"] = {module_name: str(principal_id)}
        if session_fingerprint:
            update["method_session_fingerprints"] = {module_name: session_fingerprint}
        update["probe_controls"] = {str(snapshot_key or module_name): updated}
        update["control_policy_version"] = CONTROL_POLICY_VERSION
        update["control_events"] = control_events
        if control_events:
            update["control_events"] = [{**event, "event_policy_version": EVENT_VERSION}
                                        for event in control_events]
        quarantine = probe_quarantine_reason(module_name, telemetry_events)
    else:
        # Legacy direct-agent callers have no frozen control snapshot, but the
        # measured booleans are still evidence. Record them as scoped facts so
        # the current tri-state view is derived rather than overwritten.
        from foundation.preconditions import (
            SESSION_FACT_KEYS as _SESSION_FACT_KEYS,
            make_observation_fact as _make_fact,
            observation_update as _observation_update,
        )
        for key, value in observations.items():
            if not isinstance(value, bool):
                continue
            facts.append(_make_fact(
                str(key), value, source="legacy_detection_control",
                method=module_name,
                visit_id=visit_id, phase="method_probe",
                fixture_id=state.get("fixture_id"),
                protocol_version=state.get("protocol_version"),
                security_level=state.get("security_level"),
                principal_id=principal_id,
                session_fingerprint=session_fingerprint,
                session_scope="session",
                detail="legacy direct-agent probe without frozen catalog"))
        legacy_state = {**dict(state)}
        if principal_id:
            legacy_state["method_principals"] = {
                **dict(state.get("method_principals", {}) or {}), module_name: principal_id}
        if session_fingerprint:
            legacy_state["method_session_fingerprints"] = {
                **dict(state.get("method_session_fingerprints", {}) or {}),
                module_name: session_fingerprint,
            }
        update = _observation_update(legacy_state, facts, method=module_name)
        if principal_id:
            update["method_principals"] = {module_name: principal_id}
        if session_fingerprint:
            update["method_session_fingerprints"] = {module_name: session_fingerprint}
        quarantine = probe_quarantine_reason(module_name, telemetry_events)
    return update, quarantine


def merge_probe_observations(
    update: dict[str, Any],
    probe_update: Mapping[str, Any] | None,
    state: Mapping[str, Any],
    observations: Mapping[str, Any],
) -> dict[str, Any]:
    """Merge successful probe evidence without overwriting the derived view.

    Frozen-control and legacy-fact paths return a full derived observation view;
    legacy callers without evidence fall back to a merged boolean view.
    """
    if isinstance(probe_update, Mapping) and probe_update:
        update.update(probe_update)
        derived = probe_update.get("observations")
        if isinstance(derived, Mapping):
            update["observations"] = dict(derived)
            return update
    merged = {key: value for key, value in (state.get("observations") or {}).items()
              if isinstance(value, bool)}
    merged.update({key: value for key, value in observations.items() if isinstance(value, bool)})
    update["observations"] = merged
    return update


def probe_quarantine_reason(module_name: str, telemetry_events: list[dict]) -> str | None:
    """Detect a detection control that exceeded its declared evidence role."""
    from foundation.control_catalog import structured_contamination_reason
    structured = structured_contamination_reason(module_name, telemetry_events)
    if structured is not None:
        return structured
    excerpts = [
        str((event.get("payload") or {}).get("response_excerpt") or "").lower()
        for event in telemetry_events
        if isinstance(event, dict) and event.get("event") == "agent.probe.sent"
    ]
    if module_name.startswith("bf_") and any(
        isinstance(event, dict) and event.get("event") == "agent.probe.sent"
        and (event.get("payload") or {}).get("signal_detected") is True
        and any(marker in str((event.get("payload") or {}).get("response_excerpt") or "").lower()
                for marker in ("password protected area", "welcome"))
        for event in telemetry_events
    ):
        return "unexpected_probe_authentication"
    if module_name in {"ac_idor", "ac_vertical_escalation", "ac_force_browse"}:
        for excerpt in excerpts:
            if ("database setup" in excerpt or "phpinfo()" in excerpt
                    or "view source" in excerpt or "source code" in excerpt):
                return "unexpected_sensitive_disclosure"
    for excerpt in excerpts:
        if __import__("re").search(r"\b(?:admin|gordonb|pablo|smithy)\b\s*:\s*[a-f0-9]{32}", excerpt):
            return "control_proved_assessed_exploit"
    return None


def previously_executed_exploit_payloads(state: Mapping[str, Any], module_name: str,
                                         visit_id: str | None = None) -> set[str]:
    """Return payloads executed by an own candidate exploit/bypass request."""
    payloads: set[str] = set()
    for row in state.get("response_evidence", []) or []:
        if not isinstance(row, Mapping):
            continue
        if row.get("agent_id") != module_name or row.get("stage") not in {"exploit", "bypass"}:
            continue
        if row.get("identity_kind") != "candidate" or not row.get("candidate_id"):
            continue
        if visit_id is not None and row.get("visit_id") != visit_id:
            continue
        payload = row.get("payload")
        if payload is not None:
            payloads.add(str(payload))
    return payloads


def candidate_execution_evidence(
    state: Mapping[str, Any],
    module_name: str,
    visit_id: str,
) -> list[dict]:
    """Return response rows that prove a candidate's own exploit/bypass request."""
    return [dict(row) for row in state.get("response_evidence", []) or []
            if isinstance(row, Mapping) and row.get("agent_id") == module_name
            and row.get("visit_id") == visit_id
            and row.get("stage") in {"exploit", "bypass"}
            and row.get("identity_kind") == "candidate"
            and row.get("candidate_id")
            and not row.get("control_id") and not row.get("source_candidate_id")]


def candidate_budget_receipt(
    state: Mapping[str, Any],
    method: str,
    visit_id: str,
) -> dict[str, Any]:
    """Derive the per-visit candidate/control budget receipt from shared facts."""
    rows = [row for row in state.get("candidate_lifecycle", []) or []
            if isinstance(row, Mapping) and row.get("method") == method
            and row.get("visit_id") == visit_id]

    def ids(*statuses: str) -> list[str]:
        seen: list[str] = []
        for row in rows:
            if str(row.get("status")) in statuses:
                candidate_id = str(row.get("candidate_id") or "")
                if candidate_id and candidate_id not in seen:
                    seen.append(candidate_id)
        return seen

    snapshot = state.get("probe_controls", {}).get(method) or {}
    control_events = [event for event in state.get("control_events", []) or []
                      if isinstance(event, Mapping) and event.get("method") == method
                      and event.get("visit_id") == visit_id]
    candidate_rows = candidate_execution_evidence(state, method, visit_id)
    from core.knowledge_graph import get_attack_knowledge_graph
    profile = get_attack_knowledge_graph().get_payload_profile(method) if method else {}
    from core.payload_policy import exploit_queue_limit
    configured_budget = int(state.get("candidate_budget", 0) or 0)
    effective_budget = exploit_queue_limit(configured_budget, profile)
    return {
        "policy_version": BUDGET_POLICY_VERSION,
        "method": method,
        "visit_id": visit_id,
        "candidate_budget": configured_budget,
        "configured_candidate_budget": configured_budget,
        "effective_candidate_budget": effective_budget,
        "profile_payload_budget": int(profile.get("payload_budget", 0) or 0),
        "generated": ids("generated"),
        "valid": ids("valid"),
        "queued": ids("queued"),
        "executed": ids("executed"),
        "stopped_before_execution": ids("stopped_before_execution"),
        "budget_excluded": ids("budget_excluded"),
        "rejected": ids("rejected"),
        "control_requests": int(snapshot.get("requests_used", 0) or 0),
        "physical_control_requests": int(snapshot.get("physical_requests_used", 0) or 0),
        "control_evidence_rows": len(control_events),
        "candidate_evidence_rows": len(candidate_rows),
        "evidence_row_count": len(candidate_rows) + len(control_events),
    }


# Single source of truth: agent_id → DVWA endpoint path fragment.
# Keep in sync with ALL_METHOD_AGENTS and foundation/payload_library endpoints.
_MODULE_ENDPOINT_FRAGMENTS: dict[str, str] = {
    "sqli_union": "/vulnerabilities/sqli/",
    "sqli_error": "/vulnerabilities/sqli/",
    "sqli_boolean_blind": "/vulnerabilities/sqli_blind/",
    "sqli_time_blind": "/vulnerabilities/sqli_blind/",
    "ac_idor": "/vulnerabilities/authbypass/get_user_data.php",
    "ac_vertical_escalation": "/vulnerabilities/authbypass/get_user_data.php",
    "ac_force_browse": "/vulnerabilities/authbypass/",
    "bf_dictionary": "/vulnerabilities/brute/",
    "bf_spray": "/vulnerabilities/brute/",
}


def normalize_security_level(level: str | None) -> str:
    """Handles normalize security level behavior for this module.

    Args:
        level: Value used by this function."""
    normalized = (level or "low").strip().lower()
    return normalized if normalized in {"low", "medium", "high"} else "low"


def already_tried_payloads(state: dict[str, Any], module_name: str) -> set[str]:
    """Return payloads already attempted for a module as a set."""
    module_payloads = state.get("tried_payloads", {}).get(module_name, [])
    return {str(payload) for payload in module_payloads}


def normalize_force_browse_path(path: str) -> str:
    """Match the literal dot-segment normalization already applied by HTTPX."""
    value = str(path or "").strip()
    if value.startswith("//") and "://" not in value:
        value = value.lstrip("/")
    if "://" not in value and ("/./" in value or value.endswith("/.")):
        from httpx import URL
        normalized = URL("http://dvwa.invalid/" + value.lstrip("/")).raw_path.decode("ascii")
        return normalized if value.startswith("/") else normalized.lstrip("/")
    return value


def candidate_evidence_payloads(module_name: str, payload: Any) -> tuple:
    """Match literal candidate text and only formats emitted by its method."""
    values = (payload,)
    if module_name == "ac_force_browse":
        values += (normalize_force_browse_path(payload),)
    elif module_name in {"ac_idor", "ac_vertical_escalation"}:
        values += (f"userId={payload}", f"userId={str(payload).strip()}")
    return values


def validated_candidate_ids(state: dict[str, Any], module_name: str) -> set[str] | None:
    """Return validated candidate IDs, or ``None`` before validation runs.

    The graph keeps candidate history for auditability. Once validation results
    exist, only candidates with an explicit ``valid`` result may enter an agent
    queue; an empty set is meaningful and blocks execution of rejected rows.
    """
    active = state.get("active_payload_candidates", {}).get(module_name)
    if active is not None:
        if active.get("status") != "validated" or active.get("visit_id") != state.get("selected_visit_id"):
            return set()
        return set(active.get("candidate_ids", []))
    results = state.get("payload_validation_results", {}).get(module_name)
    if not isinstance(results, list) or not results:
        return None
    return {
        str(result.get("candidate_id"))
        for result in results
        if isinstance(result, dict)
        and result.get("valid") is True
        and result.get("candidate_id") is not None
    }


def validated_payload_candidates(state: dict[str, Any], module_name: str) -> list[dict]:
    """Return the executable candidate queue after validation filtering."""
    candidates = state.get("payload_candidates", {}).get(module_name, [])
    valid_ids = validated_candidate_ids(state, module_name)
    if valid_ids is None:
        return [candidate for candidate in candidates if isinstance(candidate, dict)]
    by_id = {str(candidate.get("candidate_id")): candidate
             for candidate in candidates if isinstance(candidate, dict)}
    active = state.get("active_payload_candidates", {}).get(module_name)
    if active is not None:
        results = {str(row.get("candidate_id")): row
            for row in state.get("payload_validation_results", {}).get(module_name, [])
            if row.get("visit_id") == active.get("visit_id")}
        return [by_id[cid] for cid in active.get("candidate_ids", [])
            if cid in valid_ids and cid in by_id and results.get(cid, {}).get("valid") is True]
    # Candidate history is append-only; the validation rows carry the ranked
    # execution order. Do not revive the builder's older unranked ordering.
    return [by_id[candidate_id] for row in state["payload_validation_results"][module_name]
            if (candidate_id := str(row.get("candidate_id"))) in valid_ids and candidate_id in by_id]


def append_error_marker(target: list[str], context: str, exc: Exception) -> None:
    """Append a deterministic error marker for observability in state output."""
    target.append(f"{context}:{type(exc).__name__}")




def merge_scores(state: dict[str, Any], module_name: str, new_score: int) -> dict[str, int]:
    """Handles merge scores behavior for this module.

    Args:
        state: Value used by this function.
        module_name: Value used by this function.
        new_score: Value used by this function."""
    scores = dict(state.get("scores", {}))
    scores[module_name] = max(int(scores.get(module_name, 0)), int(new_score))
    return scores


def merge_score_map(
    state: dict[str, Any],
    map_name: str,
    module_name: str,
    new_score: int,
) -> dict[str, int]:
    """Handles merge score map behavior for this module.

    Args:
        state: Value used by this function.
        map_name: Value used by this function.
        module_name: Value used by this function.
        new_score: Value used by this function."""
    scores = dict(state.get(map_name, {}))
    scores[module_name] = max(int(scores.get(module_name, 0)), int(new_score))
    return scores


def merge_tried_payloads(
    state: dict[str, Any],
    module_name: str,
    payloads: list[str],
) -> dict[str, list[str]]:
    """Handles merge tried payloads behavior for this module.

    Args:
        state: Value used by this function.
        module_name: Value used by this function.
        payloads: Value used by this function."""
    tried_payloads = dict(state.get("tried_payloads", {}))
    module_payloads = list(tried_payloads.get(module_name, []))
    for payload in payloads:
        if payload not in module_payloads:
            module_payloads.append(payload)
    tried_payloads[module_name] = module_payloads
    return tried_payloads


def module_endpoint(state: dict[str, Any], module_name: str, fallback_path: str) -> str:
    """Handles module endpoint behavior for this module.

    Args:
        state: Value used by this function.
        module_name: Value used by this function.
        fallback_path: Value used by this function."""
    endpoints = state.get("endpoints", [])
    expected_fragment = _MODULE_ENDPOINT_FRAGMENTS.get(module_name, "")

    for endpoint in endpoints:
        if endpoint.get("module_name") != module_name:
            continue

        raw_url = str(endpoint.get("url", ""))
        parsed_path = urlparse(raw_url).path.lower()
        if expected_fragment and expected_fragment not in parsed_path:
            continue

        return str(endpoint.get("url") or fallback_path)

    for endpoint in endpoints:
        raw_url = str(endpoint.get("url", ""))
        parsed_path = urlparse(raw_url).path.lower()
        if expected_fragment and expected_fragment in parsed_path:
            return str(endpoint.get("url") or fallback_path)

    return fallback_path


def candidate_payloads_for_stage(
    state: dict[str, Any],
    module_name: str,
    security_level: str,
    stage: str,
) -> list[str]:
    """Return executable payloads for one stage under the active policy.

    Every live caller uses the validated exploit/bypass queue and a validated,
    frozen detection-control snapshot. Missing validation or controls means an
    empty stage; no direct-agent path may revive library payloads.
    """
    strict = strict_payload_mode(state)
    allowed_stages = {stage, "bypass"} if stage == "exploit" else {stage}
    if stage == "probe":
        controls = state.get("probe_controls", {}).get(module_name)
        if controls is not None:
            from foundation.payload_validator import validate_probe_controls
            results = validate_probe_controls(state, controls)
            if not results or any(row.get("valid") is not True for row in results):
                return []
            return [ControlPayload(str(row["payload_or_logic"]), str(row["control_id"]))
                    for row in controls.get("candidates", [])
                    if row.get("payload_or_logic") and row.get("control_id")]
        return []

    candidates = validated_payload_candidates(state, module_name)
    valid_ids = validated_candidate_ids(state, module_name)
    if valid_ids is None:
        return []
    model_only = strict and _payload_mode_requires_model(state)
    selected: list[str] = []
    for candidate in candidates:
        if (not isinstance(candidate, dict)
                or str(candidate.get("stage", stage)) not in allowed_stages
                or not candidate.get("payload_or_logic")):
            continue
        if model_only:
            origin = _candidate_origin_kind(state, candidate)
            if not origin_kind_permitted(state_payload_mode(state), origin):
                continue
            if (candidate.get("visit_id") != state.get("selected_visit_id")
                    or not candidate.get("model_call_id")):
                continue
        payload = str(candidate.get("payload_or_logic", ""))
        candidate_id = candidate.get("candidate_id")
        selected.append(CandidatePayload(payload, str(candidate_id))
                        if candidate_id is not None else payload)
    return selected


def _payload_mode_requires_model(state: Mapping[str, Any]) -> bool:
    return state_payload_mode(state) in STRICT_PAYLOAD_MODES


def resolve_stage_control_payloads(
    state: Mapping[str, Any],
    module_name: str,
    payloads: list[str],
    principal_id: str | None,
) -> list[str]:
    """Resolve catalog control tokens while retaining each control identity."""
    resolved: list[str] = []
    for payload in payloads:
        value = resolve_control_payload_for_stage(state, module_name, str(payload), principal_id)
        if value is None:
            continue
        control_id = getattr(payload, "control_id", None)
        resolved.append(ControlPayload(value, str(control_id)) if control_id else value)
    return resolved


def resolve_control_payload_for_stage(
    state: Mapping[str, Any],
    module_name: str,
    payload: str,
    principal_id: str | None,
) -> str | None:
    """Resolve a synthetic detection-control token for the visit principal."""
    from foundation.control_catalog import resolve_control_payload
    controls = state.get("probe_controls", {}).get(module_name)
    if isinstance(controls, Mapping):
        row = next((item for item in controls.get("candidates", [])
                    if isinstance(item, Mapping) and str(item.get("payload_or_logic")) == str(payload)), None)
        if row is not None:
            return resolve_control_payload(str(payload), principal_id)
    return str(payload)


def payload_score_updates(
    state: dict[str, Any],
    decisions: list[dict],
) -> dict[str, int]:
    """Retain candidate maxima only from that candidate's verifier receipts."""
    updates = dict(state.get("payload_scores", {}))
    for decision in decisions:
        candidate_id = decision["candidate_id"]
        updates[candidate_id] = max(updates.get(candidate_id, 0), decision["score"])
    return updates


def _materialize_request_evidence(
    state: dict[str, Any],
    module_name: str,
    telemetry_events: list[dict],
    tried_payloads: list[str],
) -> tuple[list[dict], list[dict], list[dict]]:
    """Normalize method telemetry into auditable response/timing evidence.

    Method agents emit compact request events rather than copying full response
    bodies into shared state. This helper fills the endpoint from recon when an
    event does not provide one and separates timing measurements for artifacts.
    """
    fallback_path = _MODULE_ENDPOINT_FRAGMENTS.get(module_name, "")
    endpoint = module_endpoint(state, module_name, fallback_path) if fallback_path else ""
    target_url = str(state.get("target_url") or "").rstrip("/")
    if endpoint.startswith("/") and target_url:
        endpoint = f"{target_url}{endpoint}"

    response_evidence: list[dict] = []
    timing_evidence: list[dict] = []
    normalized_events: list[dict] = []
    validation_rows = state.get("payload_validation_results", {}).get(module_name, [])
    validation_by_id = {
        str(row.get("candidate_id")): (index, row)
        for index, row in enumerate(validation_rows)
        if isinstance(row, dict) and row.get("candidate_id") is not None
    }
    candidates = []
    for candidate in validated_payload_candidates(state, module_name):
        candidate_id = candidate.get("candidate_id")
        indexed = validation_by_id.get(str(candidate_id)) if candidate_id is not None else None
        if indexed is None or indexed[1].get("valid") is not True:
            continue
        index, result = indexed
        candidates.append({
            "candidate": candidate,
            "candidate_id": str(candidate_id),
            "identity_kind": "candidate",
            "validation": result,
            "validation_ref": f"#/final_state/payload_validation_results/{module_name}/{index}",
        })
    controls = state.get("probe_controls", {}).get(module_name)
    if (isinstance(controls, dict) and controls.get("candidates")
            and controls.get("visit_id") == (state.get("selected_visit_id") or
                                               f"{module_name}:legacy:{state.get('iteration_count', 0)}")):
        from foundation.payload_validator import validate_probe_controls
        results = validate_probe_controls(state, controls)
        stored_results = controls.get("validation_results", [])
        if not isinstance(stored_results, list):
            stored_results = []
        if results and len(results) == len(controls["candidates"]):
            for index, (candidate, result) in enumerate(zip(controls["candidates"], results)):
                stored = stored_results[index] if index < len(stored_results) else None
                if (not isinstance(candidate, dict) or result.get("valid") is not True
                        or not isinstance(stored, dict) or stored.get("valid") is not True
                        or stored.get("candidate_id") != candidate.get("candidate_id")
                        or stored.get("reason") != result.get("reason")):
                    continue
                candidates.append({
                    "candidate": candidate,
                    "candidate_id": str(candidate.get("candidate_id")),
                    "identity_kind": "independent_control",
                    "validation": stored,
                    "validation_ref": f"#/final_state/probe_controls/{module_name}/validation_results/{index}",
                })
    attempted = set(tried_payloads)
    visit_id = state.get("selected_visit_id") or f"{module_name}:legacy:{state.get('iteration_count', 0)}"
    complementary_controls: dict[str, dict[str, Any]] = {}
    last_exploit_record: dict[str, Any] | None = None
    last_exploit_event_index: int | None = None
    evidence_offset = len(state.get("response_evidence", []))
    for event_index, event in enumerate(telemetry_events):
        if not isinstance(event, dict):
            normalized_events.append(event)
            continue
        event_copy = dict(event)
        payload = event_copy.get("payload")
        if (
            event_copy.get("event") not in {"agent.probe.sent", "agent.exploit.sent"}
            or not isinstance(payload, dict)
        ):
            normalized_events.append(event_copy)
            continue

        payload_copy = dict(payload)
        if payload_copy.get("credentials") and "response_excerpt" in payload_copy:
            payload_copy["response_excerpt"] = redact_secrets(payload_copy["response_excerpt"],
                [c.get("password") for c in payload_copy["credentials"]])
        payload_copy["visit_id"] = visit_id
        stage = "probe" if event_copy["event"] == "agent.probe.sent" else "exploit"
        payload_value = payload_copy.get("payload")
        allowed_stages = {"exploit", "bypass"} if stage == "exploit" else {"probe"}
        explicit_id = payload_copy.get("candidate_id")
        explicit_control = payload_copy.get("control_id")
        explicit_source = payload_copy.get("source_candidate_id")
        if explicit_control and not explicit_id:
            # Match controls only by their frozen identity. Resolved @self
            # values may differ from the catalog token; neither can borrow a
            # queued exploit's identity through an equal payload string.
            matches = [record for record in candidates
                       if record["identity_kind"] == "independent_control"
                       and record["candidate"].get("control_id") == explicit_control]
            selected = matches[0] if len(matches) == 1 else None
        else:
            matches = [
                record for record in candidates
                if record["candidate_id"]
                and record["candidate"].get("stage", stage) in allowed_stages
                and (explicit_id is not None
                     or record["candidate"].get("payload_or_logic") in attempted
                     or record["identity_kind"] == "independent_control")
                and payload_value in candidate_evidence_payloads(
                    module_name, record["candidate"].get("payload_or_logic"),
                )
            ]
            if explicit_id is not None:
                matches = [record for record in matches if record["candidate_id"] == str(explicit_id)]
            selected = matches[0] if len(matches) == 1 else None
        if selected is not None and explicit_source is not None:
            selected = None
        # Candidate-derived controls bind by their explicit source identity, not
        # by payload similarity or a nearby unrelated candidate request.
        derived_control = None
        if stage == "probe" and explicit_source:
            matches = [record for record in candidates
                       if record["identity_kind"] == "candidate"
                       and record["candidate_id"] == str(explicit_source)]
            derived_control = matches[0] if len(matches) == 1 else None
        elif stage == "probe" and not selected:
            derived_control = complementary_controls.get(str(payload_value))
        if (derived_control is None and not explicit_source and stage == "probe"
                and module_name == "sqli_boolean_blind"
                and last_exploit_record is not None and last_exploit_event_index == event_index - 1):
            # The agent records a control response even when the complementary
            # predicate is negative, before it annotates the source event.
            derived_control = last_exploit_record
        if derived_control is not None:
            selected = derived_control
            payload_copy.pop("candidate_id", None)
            payload_copy["source_candidate_id"] = selected["candidate_id"]
            payload_copy["control_id"] = f"control:{selected['candidate_id']}:complementary_boolean"
            payload_copy["identity_kind"] = "derived_control"
            payload_copy["validation_relation"] = "derived_from_candidate"
        elif selected is not None:
            payload_copy["candidate_id"] = selected["candidate_id"]
            if selected["identity_kind"] == "independent_control":
                payload_copy["control_id"] = selected["candidate_id"]
                payload_copy["identity_kind"] = "independent_control"
            else:
                payload_copy["identity_kind"] = "probe_candidate" if stage == "probe" else "candidate"
            if stage == "exploit" and payload_copy.get("control_payload") is not None:
                complementary_controls[str(payload_copy["control_payload"])] = selected
        else:
            payload_copy["identity_kind"] = "unresolved"
        if explicit_control and explicit_id is None:
            payload_copy.pop("candidate_id", None)
            payload_copy["control_id"] = str(explicit_control)
            payload_copy["identity_kind"] = ("derived_control" if explicit_source
                                             else "independent_control")
            if explicit_source:
                payload_copy["source_candidate_id"] = str(explicit_source)
                payload_copy.setdefault("validation_relation", "derived_from_candidate")
            else:
                payload_copy.setdefault("validation_relation", "independent_control")
        payload_copy["candidate_link_status"] = (
            "linked" if selected is not None else "ambiguous" if len(matches) > 1 else "unmatched"
        )
        if selected is not None:
            payload_copy["validation_ref"] = selected["validation_ref"]
            payload_copy["validation"] = {
                "method": module_name,
                "candidate_id": selected["candidate_id"],
                "visit_id": visit_id,
                "result": deepcopy(selected["validation"]),
            }
        else:
            payload_copy["validation_ref"] = None
            payload_copy["validation"] = None
        if selected is not None:
            provenance = deepcopy(state.get("payload_provenance", {}).get(selected["candidate_id"], {}))
            for key in ("method", "source", "source_seed_id", "mutation_type", "target_param", "expected_signal", "stage"):
                if key in selected["candidate"]:
                    provenance.setdefault(key, selected["candidate"][key])
            payload_copy["candidate_provenance"] = provenance
        payload_copy["method"] = module_name
        evidence_index = evidence_offset + len(response_evidence)
        request_id = f"request:{state.get('execution_id') or state.get('run_id') or 'unknown'}:{visit_id}:{evidence_index}"
        # The final JSON pointer is assigned by the artifact exporter after it
        # knows the stable execution-log position for this request.
        request_ref = None
        payload_copy.setdefault("request_structure", {
            "available": False,
            "reason": "prepared_request_unavailable",
            "redaction_applied": True,
            "raw_values_included": False,
        })
        payload_copy["request_id"] = request_id
        payload_copy["request_ref"] = request_ref
        payload_copy["request_link_status"] = "pending_export"
        session_fields = {
            "principal_id": payload_copy.get("principal_id"),
            "session_fingerprint": payload_copy.get("session_fingerprint"),
            "initial_session_fingerprint": payload_copy.get("initial_session_fingerprint"),
            "consumed_source_evidence_id": payload_copy.get("consumed_source_evidence_id"),
        }
        payload_copy["session_descriptor"] = {
            "available": any(value not in (None, "") for value in session_fields.values()),
            **{key: value for key, value in session_fields.items() if value not in (None, "")},
            "redaction_applied": True,
            "raw_values_included": False,
        }
        payload_copy["eligible_for_exploit_denominator"] = bool(
            selected is not None
            and payload_copy.get("identity_kind") == "candidate"
            and selected["identity_kind"] == "candidate"
            and stage == "exploit"
            and selected["candidate"].get("stage", stage) in {"exploit", "bypass"}
            and payload_copy.get("candidate_id")
            and not payload_copy.get("control_id")
            and not payload_copy.get("source_candidate_id")
            and payload_copy.get("response_sha256")
        )
        event_endpoint = str(payload_copy.get("endpoint") or endpoint or "")
        if event_endpoint and not urlparse(event_endpoint).scheme and target_url:
            event_endpoint = urljoin(f"{target_url}/", event_endpoint.lstrip("/"))
        payload_copy["endpoint"] = event_endpoint
        event_copy["payload"] = payload_copy
        normalized_events.append(event_copy)

        evidence = {
            "agent_id": str(payload_copy.get("agent_id") or module_name),
            "method": module_name,
            "stage": stage,
            "endpoint": payload_copy["endpoint"],
            "payload": payload_copy.get("payload"),
            "status_code": payload_copy.get("status_code"),
            "visit_id": visit_id,
            "evidence_id": f"response:{evidence_index}",
            "request_id": request_id,
            "request_ref": request_ref,
            "request_link_status": "pending_export",
            "request_structure": deepcopy(payload_copy["request_structure"]),
            "session_descriptor": deepcopy(payload_copy["session_descriptor"]),
            "identity_kind": payload_copy["identity_kind"],
            "candidate_link_status": payload_copy["candidate_link_status"],
            "eligible_for_exploit_denominator": payload_copy["eligible_for_exploit_denominator"],
            "validation_ref": payload_copy["validation_ref"],
            "validation": deepcopy(payload_copy["validation"]),
            "run_id": state.get('run_id'), "execution_id": state.get('execution_id'),
            "fixture_id": state.get('fixture_id'), "protocol_version": state.get('protocol_version'),
            "timestamp": datetime.now(timezone.utc).isoformat(), "origin": "method_agent_evidence",
        }
        for key in ("verified_grade", "verification_reason", "control_payload", "credentials", "consumed_source_evidence_id",
                    "response_sha256", "response_excerpt", "response_truncated", "oracle_ref",
                    "baseline_response_sha256", "baseline_control_id", "baseline_elapsed_ms", "delay_ms",
                    "principal_id", "object_id", "action", "session_fingerprint", "initial_session_fingerprint"):
            if key in payload_copy:
                evidence[key] = payload_copy[key]
        if payload_copy.get("candidate_id"):
            evidence["candidate_id"] = payload_copy["candidate_id"]
        if payload_copy.get("control_id"):
            evidence["control_id"] = payload_copy["control_id"]
        if payload_copy.get("source_candidate_id"):
            evidence["source_candidate_id"] = payload_copy["source_candidate_id"]
        if payload_copy.get("candidate_provenance") is not None:
            evidence["candidate_provenance"] = payload_copy["candidate_provenance"]
        if payload_copy.get("validation_relation"):
            evidence["validation_relation"] = payload_copy["validation_relation"]
        if "signal_detected" in payload_copy:
            evidence["signal_detected"] = payload_copy["signal_detected"]
        if "success" in payload_copy:
            evidence["success"] = payload_copy["success"]
        response_evidence.append(evidence)

        if stage == "exploit" and selected is not None and payload_copy.get("control_payload") is not None:
            complementary_controls[str(payload_copy["control_payload"])] = selected
        if stage == "exploit":
            last_exploit_record = selected
            last_exploit_event_index = event_index

        if "elapsed_ms" in payload_copy:
            timing_evidence.append({
                **evidence,
                "elapsed_ms": payload_copy.get("elapsed_ms"),
                "baseline_elapsed_ms": payload_copy.get("baseline_elapsed_ms"),
                "delay_ms": payload_copy.get("delay_ms"),
            })

    return normalized_events, response_evidence, timing_evidence


def make_update(
    *,
    state: dict[str, Any],
    module_name: str,
    score: int,
    tried_payloads: list[str],
    confirmed_vulns: list[str] | None = None,
    achieved_outcomes: list[str] | None = None,
    found_credentials: list[dict[str, str]] | None = None,
    next_agent: str = "orchestrator",
    telemetry_events: list[dict] | None = None,
    failure_agents: list[str] | None = None,
    blocked_agents: list[str] | None = None,
    task_result: str | None = None,
    incomplete_reason: str | None = None,
    execution_error: Exception | None = None,
    execution_failure_code: str | None = None,
    candidate_stop_reasons: dict[str, str] | None = None,
    default_candidate_stop_reason: str | None = None,
) -> dict[str, Any]:
    """Build a method-agent partial state update without mutating input state.

    The helper applies the 0-4 scoring rubric, deduplicates list-reducer fields,
    records tried payloads, updates payload scores for executed candidates, and
    emits routing/failure fields used by the chaining router.

    Args:
        state: Current shared LangGraph state.
        module_name: Static method agent identifier.
        score: Highest method score reached during this agent invocation.
        tried_payloads: Payload strings attempted by this invocation.
        confirmed_vulns: AKG node IDs confirmed by this invocation.
        achieved_outcomes: Outcome node IDs achieved by chain checks.
        found_credentials: Credentials recovered by brute-force agents.
        next_agent: Routing hint for the next graph stage.
        telemetry_events: Agent telemetry events to append.
        failure_agents: Method IDs to mark as failed.
        blocked_agents: Method IDs to mark as blocked.
        task_result: Optional terminal task status.
        incomplete_reason: Optional reason for incomplete execution.
        execution_error: Caught setup/execution exception retained as failure metadata.
        execution_failure_code: Explicit setup failure without a raised exception.

    Returns:
        Partial `ExploitationState` update suitable for LangGraph reducers.
    """
    # Access Control agents use the documented non-admin session. Their
    # candidate-bound observation can continue the graph, while the independent
    # operator oracle remains the gate for final v4 proof and scores.
    permission_candidate = any(
        isinstance(event, dict) and isinstance(event.get("payload"), dict)
        and event["payload"].get("agent_id") == module_name
        and event["payload"].get("status_code") == 200
        and event["payload"].get("signal_detected") is True
        and event["payload"].get("verified_grade") == 3
        and event["payload"].get("verification_reason") == "verified_permission_candidate"
        and event["payload"].get("principal_id") not in {None, "", "admin"}
        and event["payload"].get("session_fingerprint")
        and event["payload"].get("initial_session_fingerprint")
        and event["payload"].get("object_id") and event["payload"].get("action") == "read"
        for event in (telemetry_events or [])
    )
    authorization_unverified = module_name.startswith("ac_") and bool(confirmed_vulns) and not permission_candidate
    if authorization_unverified:
        score = min(score, 2)
        confirmed_vulns = None
        achieved_outcomes = None
        telemetry_events = [
            {**event, "payload": {**event["payload"], "score": score,
                                  "confirmed_vulns": [], "achieved_outcomes": []}}
            if event.get("event") == "agent.score.final" else event
            for event in (telemetry_events or [])
        ]
    update: dict[str, Any] = {
        "scores": merge_scores(state, module_name, score),
        "exploitation_scores": merge_score_map(state, "exploitation_scores", module_name, min(score, 3)),
        "chain_scores": {module_name: 0},
        "tried_payloads": merge_tried_payloads(state, module_name, tried_payloads),
        # Graph selections reserve a visit before preparation. Legacy direct
        # method callers have no reservation and account for their own visit.
        "iteration_count": state.get("iteration_count", 0) + (0 if state.get("selected_visit_id") else 1),
        "next_agent": next_agent,
    }

    # Validate score is within rubric bounds
    if not isinstance(score, int) or not (0 <= score <= 4):
        raise ValueError(f"score must be an int in range 0-4, got {score!r}")

    # confirmed_vulns, achieved_outcomes, and found_credentials all use
    # Annotated[list, add] reducers. We must filter out items already
    # present in state to avoid permanent duplication across agent runs.
    if confirmed_vulns:
        existing_confirmed = set(state.get("confirmed_vulns", []))
        new_confirmed = [c for c in confirmed_vulns if c not in existing_confirmed]
        if new_confirmed:
            update["confirmed_vulns"] = new_confirmed
    if achieved_outcomes:
        existing_outcomes = set(state.get("achieved_outcomes", []))
        new_outcomes = [o for o in achieved_outcomes if o not in existing_outcomes]
        if new_outcomes:
            update["achieved_outcomes"] = new_outcomes
    if found_credentials:
        existing_creds = state.get("found_credentials", [])
        existing_creds_set = {
            (c.get("username"), c.get("password"))
            for c in existing_creds
            if isinstance(c, dict)
        }
        new_creds = [
            c for c in found_credentials
            if isinstance(c, dict) and (c.get("username"), c.get("password")) not in existing_creds_set
        ]
        if new_creds:
            update["found_credentials"] = new_creds

    # Track attempted agents for fallback diversification.
    # attempted_agents uses Annotated[list[str], add] reducer in LangGraph,
    # so we must return ONLY the new item, not the full accumulated list.
    attempted = list(state.get("attempted_agents", []))
    if module_name not in attempted:
        update["attempted_agents"] = [module_name]

    # Merge telemetry events from agents and materialize auditable evidence.
    # telemetry_events uses Annotated[list[dict], add] reducer,
    # so we must return ONLY the new events, not existing + new.
    if telemetry_events:
        normalized_events, response_evidence, timing_evidence = _materialize_request_evidence(
            state, module_name, list(telemetry_events), tried_payloads
        )
        update["telemetry_events"] = normalized_events
        if response_evidence:
            update["response_evidence"] = response_evidence
        if timing_evidence:
            update["timing_evidence"] = timing_evidence

    # The runner records each graph snapshot, preserving prior confirmations
    # while recording this invocation's negative/failed decision as well.
    update["verifier_decision"] = {
        "agent_id": module_name,
        "decision": "unverified" if authorization_unverified else ("confirmed" if confirmed_vulns else "not_confirmed"),
        "confirmed_vulns": list(confirmed_vulns or []),
        "score": score,
        "evidence_count": len(update.get("response_evidence", [])),
        "source": "method_agent_evidence",
        "visit_id": state.get("selected_visit_id") or f"{module_name}:legacy:{state.get('iteration_count', 0)}",
        "evidence_refs": [f"#/final_state/response_evidence/{len(state.get('response_evidence', [])) + i}"
                          for i in range(len(update.get("response_evidence", [])))],
        "achieved_outcomes": list(achieved_outcomes or []),
    }
    if authorization_unverified:
        update["verifier_decision"]["reason"] = "missing_independent_authorization_control"

    decision = update["verifier_decision"]
    decision["verifier_id"] = f"verifier:{decision['visit_id']}:{len(state.get('verifier_history', []))}"
    update["verifier_history"] = [decision]
    payload_decisions = []
    evidence = update.get("response_evidence", [])
    # Score validated queue candidates only. Independent controls are stored in
    # probe_controls and deliberately never enter this candidate denominator;
    # queue probe candidates may still retain their measured payload grade.
    for candidate in validated_payload_candidates(state, module_name):
        candidate_id = candidate.get("candidate_id")
        linked = [(i, row) for i, row in enumerate(evidence) if row.get("candidate_id") == candidate_id]
        if not linked:
            continue
        grade = max((row.get("verified_grade", 0) for _, row in linked), default=0)
        # Old/direct telemetry without a verifier grade proves execution only.
        grade = min(int(grade), 2 if module_name.startswith("ac_") else 3)
        best = next((row for _, row in linked if row.get("verified_grade", 0) == grade), linked[-1][1])
        refs = [f"#/final_state/response_evidence/{len(state.get('response_evidence', [])) + i}" for i, _ in linked]
        # Complementary Boolean controls are evidence of this expression, not extra candidates.
        refs.extend(f"#/final_state/response_evidence/{len(state.get('response_evidence', [])) + i}"
            for i, row in enumerate(evidence) if row.get("payload") in {r.get("control_payload") for _, r in linked} - {None})
        payload_decisions.append(score_decision(state, "Spayload", module_name, grade,
            best.get("verification_reason") or "no_verified_candidate_signal", candidate_id=candidate_id,
            stage=candidate.get("stage"), provenance=state.get("payload_provenance", {}).get(candidate_id, {}),
            evidence_refs=refs, verifier_id=decision["verifier_id"]))
    update["payload_scores"] = payload_score_updates(state, payload_decisions)
    update["scoring_decisions"] = [*payload_decisions,
        score_decision(state, "Sexploit", module_name, min(score, 3), decision["decision"],
            evidence_refs=decision["evidence_refs"], verifier_id=decision["verifier_id"]),
        score_decision(state, "Schain", module_name, 0, "awaiting_post_method_dependency_check",
            aggregation="destination_visit", verifier_id=decision["verifier_id"])]
    extracted = []
    for row in evidence:
        for credential in row.get("credentials", []):
            extracted.append({**credential, "source_visit_id": decision["visit_id"],
                "source_candidate_id": row.get("candidate_id"), "source_evidence_id": row["evidence_id"]})
    if extracted:
        update["found_credentials"] = extracted
    route = state.get("active_chain_route") or {}
    if route.get("target_agent") == module_name:
        source_rows = {item.get("evidence_id"): item for item in state.get("response_evidence", [])
            if isinstance(item, dict)}
        update["chain_consumption"] = [{
            "route_id": route["route_id"], "visit_id": decision["visit_id"],
            "source_candidate_id": source_rows.get(row.get("consumed_source_evidence_id"), {}).get("candidate_id"),
            "source_visit_id": source_rows.get(row.get("consumed_source_evidence_id"), {}).get("visit_id"),
            "candidate_id": row.get("candidate_id"), "source_evidence_id": row["consumed_source_evidence_id"],
            "destination_evidence_id": row["evidence_id"], "representation": "plaintext"}
            for row in evidence if row.get("consumed_source_evidence_id")]

    # Track failure agents for fallback loop and adaptation metrics.
    # failure_agents uses Annotated[list[str], add] reducer.
    if failure_agents:
        existing_failures = set(state.get("failure_agents", []))
        new_failures = [a for a in failure_agents if a not in existing_failures]
        if new_failures:
            update["failure_agents"] = new_failures

    if blocked_agents:
        existing_blocked = set(state.get("blocked_agents", []))
        new_blocked = [a for a in blocked_agents if a not in existing_blocked]
        if new_blocked:
            update["blocked_agents"] = new_blocked

    lifecycle: list[dict] = []
    visit_id = state.get("selected_visit_id") or f"{module_name}:legacy:{state.get('iteration_count', 0)}"
    evidence_rows = list(update.get("response_evidence", []))
    attempted_rows: dict[str, list[dict]] = {}
    for row in evidence_rows:
        if (row.get("identity_kind") != "candidate" or row.get("stage") not in {"exploit", "bypass"}
                or not row.get("candidate_id") or row.get("control_id")
                or row.get("source_candidate_id")):
            continue
        attempted_rows.setdefault(str(row["candidate_id"]), []).append(row)
    executed_rows = {
        candidate_id: [row for row in rows if row.get("response_sha256")]
        for candidate_id, rows in attempted_rows.items()
    }
    executed_rows = {cid: rows for cid, rows in executed_rows.items() if rows}
    queue_by_id = {str(candidate.get("candidate_id")): candidate
                   for candidate in validated_payload_candidates(state, module_name)
                   if candidate.get("candidate_id") is not None}
    for candidate_id, rows in executed_rows.items():
        origin_kind = _candidate_origin_kind(state, queue_by_id.get(candidate_id, {}))
        lifecycle.append(candidate_lifecycle_fact(
            method=module_name, visit_id=visit_id, candidate_id=candidate_id,
            origin_kind=origin_kind, status="executed", reason="own_request_recorded",
            evidence_refs=[str(row.get("evidence_id")) for row in rows if row.get("evidence_id")]))
    for candidate_id, rows in attempted_rows.items():
        if candidate_id in executed_rows:
            continue
        origin_kind = _candidate_origin_kind(state, queue_by_id.get(candidate_id, {}))
        failed_fact = candidate_lifecycle_fact(
            method=module_name, visit_id=visit_id, candidate_id=candidate_id,
            origin_kind=origin_kind, status="stopped_before_execution",
            reason="request_failed",
            evidence_refs=[str(row.get("evidence_id")) for row in rows if row.get("evidence_id")])
        failed_fact["http_attempted"] = True
        lifecycle.append(failed_fact)
    prior_executed = previously_executed_exploit_payloads(state, module_name, visit_id)
    probe_payloads = {
        str(row.get("payload")) for row in [*state.get("response_evidence", []), *evidence_rows]
        if isinstance(row, Mapping) and row.get("agent_id") == module_name
        and row.get("stage") == "probe" and row.get("visit_id") == visit_id
    }
    method_status = {
        key: str(value)
        for key, value in (state.get("precondition_status") or {}).items()
    }
    for candidate in validated_payload_candidates(state, module_name):
        candidate_id = candidate.get("candidate_id")
        if candidate_id is None or str(candidate_id) in executed_rows:
            continue
        if str(candidate_id) in attempted_rows:
            continue
        payload = str(candidate.get("payload_or_logic", ""))
        reason = (candidate_stop_reasons or {}).get(str(candidate_id))
        if not reason:
            reason = default_candidate_stop_reason
        if not reason:
            if payload in probe_payloads:
                reason = "skipped_already_probed"
            elif payload in prior_executed:
                reason = "already_executed_in_prior_visit"
            elif confirmed_vulns:
                reason = "earlier_candidate_confirmed"
            else:
                from foundation.preconditions import precondition_keys_for_method
                keys = precondition_keys_for_method(module_name)
                if any(method_status.get(key) == "false" for key in keys):
                    reason = "precondition_false"
                elif any(method_status.get(key) != "true" for key in keys):
                    reason = "precondition_unknown"
                else:
                    reason = "not_attempted"
        lifecycle.append(candidate_lifecycle_fact(
            method=module_name, visit_id=visit_id, candidate_id=str(candidate_id),
            origin_kind=_candidate_origin_kind(state, candidate),
            status="stopped_before_execution", reason=reason, evidence_refs=[]))
    if lifecycle:
        update["candidate_lifecycle"] = lifecycle

    if task_result is not None:
        update["task_result"] = task_result
    if incomplete_reason is not None:
        update["incomplete_reason"] = incomplete_reason
    if execution_error is not None or execution_failure_code is not None:
        from core.run_status import reason
        code = execution_failure_code or ("TARGET_TRANSPORT_FAILURE"
            if isinstance(execution_error, (TransportError, RequestTimeoutError)) else "METHOD_EXECUTION_FAILURE")
        detail = f"{module_name}: {type(execution_error).__name__}" if execution_error is not None else f"{module_name}: session login failed"
        update.update(execution_status="failed", execution_reason=reason(code, detail))

    return update


def chain_check(confirmed_node: str, state: dict[str, Any]) -> tuple[int, list[str]]:
    """Compatibility seam; the merged post-method coordinator awards chain credit."""
    return 0, []
