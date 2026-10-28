"""Explicit runtime readiness receipt for direct node tests."""

READY_RECEIPT = {
    "policy_version": "readiness.v1",
    "status": "ready",
    "requested_level": "low",
    "observed_level": "low",
    "authentication": {
        "requested_principal": "admin", "observed_principal": "admin",
        "login_ok": True, "identity_verified": True,
        "evidence_refs": ["session:login"],
    },
    "endpoints": {"required": [], "observed": [], "missing": [], "evidence_refs": []},
    "token": {"required": False, "present": None, "evidence_refs": []},
    "fixture": {"fixture_id": None, "protocol_version": None,
                "configured": False, "equivalence": "unavailable"},
    "fixture_restoration": {"equivalence": "unknown", "evidence_refs": [],
                            "reason": "fixture_restoration_unverified"},
    "session": {"principal": None, "fingerprint": None},
    "setup_state": "authenticated_crawl",
    "reasons": [],
    "assessed_at": "2026-10-28T00:00:00+00:00",
}

def ready_state(method: str | None = None, *, level: str = "low") -> dict:
    """Build explicit upstream evidence for a direct-node unit test."""
    from copy import deepcopy

    from core.state import new_default_state
    from foundation.preconditions import (
        make_observation_fact,
        observation_update,
        precondition_keys_for_method,
    )

    state = new_default_state()
    state["security_level"] = level
    state["readiness"] = deepcopy(READY_RECEIPT)
    state["readiness"]["requested_level"] = level
    state["readiness"]["observed_level"] = level
    if method is not None:
        facts = [
            make_observation_fact(
                key, True, source="unit_test_upstream_control",
                method=method, security_level=level,
                evidence_refs=[f"fixture:upstream:{method}:{key}"],
            )
            for key in precondition_keys_for_method(method)
        ]
        state.update(observation_update(state, facts, method=method))
        from core.state import METHODS_BY_SURFACE
        from evaluation.payload_replay import _apply_state_update
        from foundation.payload_generator import build_payload_candidates
        from foundation.payload_validator import payload_validator_node

        state.update({
            "selected_method": method,
            "selected_visit_id": f"{method}:visit:1",
            "current_surface": next(surface for surface, methods in METHODS_BY_SURFACE.items()
                                    if method in methods),
            "payload_mode": "static_only",
        })
        state = _apply_state_update(state, build_payload_candidates(state))
        state = _apply_state_update(state, payload_validator_node(state))
    return state



def install_fixture_runtime(monkeypatch, fixture):
    """Route LLMRuntime calls to an offline fixture without provider dispatch.

    The runtime's provider pool still receives no secret, and call receipts are
    recorded in the coordinate context so frozen inputs keep the current
    role/method/visit binding contract.
    """
    import json
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from evaluation.scoring_evidence import evidence_hash
    from llm.runtime import LLMCallResult, LLMOutputError, LLMRuntime

    def invoke(self, *, context, role, system_message, user_message, schema,
               schema_version, validator, max_tokens, evidence_context=None):
        response = fixture.invoke([
            SimpleNamespace(content=system_message),
            SimpleNamespace(content=user_message),
        ])
        text = str(getattr(response, "content", response))
        parsed = None
        try:
            candidate = json.loads(text)
            if isinstance(candidate, dict):
                parsed = validator(candidate)
        except Exception:  # noqa: BLE001 - fixture output must obey the runtime schema
            parsed = None
        call_id = context.next_call_id(role)
        method = (evidence_context or {}).get("method")
        visit_id = (evidence_context or {}).get("visit_id")
        performance = {
            "call_id": call_id, "role": role, "method": method,
            "visit_id": visit_id, "provider": "openai_compatible",
            "model": "fixture-model", "schema_version": schema_version,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "parse_status": "ok" if parsed is not None else "invalid",
            "validation_status": "valid" if parsed is not None else "invalid",
            "attempt": 1, "structured_output_fallback": None,
        }
        context.emit_activity("llm.started", call_id=call_id, record=performance)
        if parsed is None:
            context.emit_activity("llm.failed", call_id=call_id, record=performance)
            raise LLMOutputError(
                "fixture returned non-JSON or schema-invalid output",
                text=text, performance=performance)
        safe_input = (evidence_context or {}).get("input", {})
        record = {
            **performance,
            "input": safe_input, "output": parsed,
            "input_sha256": evidence_hash(safe_input),
            "output_sha256": evidence_hash(parsed),
        }
        context.append_record(record)
        context.emit_activity("llm.completed", call_id=call_id, record=record)
        return LLMCallResult(text=text, parsed=parsed, performance=record)

    monkeypatch.setattr(LLMRuntime, "invoke", invoke)
    return fixture

