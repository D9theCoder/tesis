"""Behavior tests for strict mutation, Template, provenance, and budget policy.

These tests exercise only local code paths: no provider call and no HTTP request
is made.  The payload-generation model call is replaced with a deterministic
fake, and the detection-control catalog is replaced with an in-memory stub.
"""
from typing import Any


import foundation.payload_generator as payload_generator
from core.payload_policy import (
    BUDGET_EXCLUSION_REASON,
    PAYLOAD_POLICY_VERSION,
)
from core.state import new_default_state
from foundation.payload_generator import build_payload_candidates
from foundation.payload_templates import (
    template_confidentiality_findings,
)
from foundation.payload_validator import (
    validate_payload_candidates,
)
from llm.prompts.payload_generation_prompt import (
    sanitized_template_observations,
)



def _state(method: str, mode: str, **overrides: Any) -> dict[str, Any]:
    return {
        **new_default_state(),
        "selected_method": method,
        "payload_mode": mode,
        "security_level": "low",
        "selected_visit_id": f"{method}:visit:1",
        "active_payload_candidates": {},
        "payload_candidates": {},
        **overrides,
    }


def _fake_mutation_generator(payload: str, mutation_type: str = "encoding"):
    def fake(*, state: dict[str, Any], method: str, seeds: list[dict], profile: dict, budget: int):
        seed = next(
            candidate for candidate in seeds
            if candidate["stage"] in {"exploit", "bypass"}
        )
        return (
            [{
                "candidate_id": "model-supplied-id",
                "source": "static_seed",
                "source_seed_id": seed["candidate_id"],
                "mutation_type": mutation_type,
                "payload_or_logic": payload,
                "target_param": seed["target_param"],
                "expected_signal": seed["expected_signal"],
            }],
            {
                "method": method,
                "visit_id": state["selected_visit_id"],
                "call_id": "call-mutation",
                "prompt_id": "payload_generation.constrained_variant",
                "schema_version": "payload-variants.v3",
                "origin_kind": "seed_mutation",
                "policy_version": PAYLOAD_POLICY_VERSION,
                "parsed_candidate_ids": [],
                "prompt_visible_seed_ids": [seed["candidate_id"]],
            },
            [],
        )

    return fake


def test_template_registry_has_no_payload_or_credential_leak():
    assert template_confidentiality_findings() == []


def test_sanitized_template_observations_are_boolean_and_allowlisted():
    sanitized = sanitized_template_observations({
        "authenticated_crawl": True,
        "low_priv_session_available": "yes",
        "union_select_possible": True,
    })
    assert sanitized == {"authenticated_crawl": True}


def test_template_mode_never_uses_static_or_chain_candidates(monkeypatch):
    monkeypatch.setattr(
        payload_generator,
        "generate_llm_variants",
        lambda **_kwargs: ([], {"failure_reason": "guardrail_refusal"}, []),
    )
    state = _state(
        "bf_dictionary",
        "llm_template",
        active_chain_route={
            "source": "credentials_extracted",
            "target_agent": "bf_dictionary",
            "source_evidence_ids": ["ev-1"],
        },
        found_credentials=[{
            "username": "fixture",
            "password": "fixture",
            "representation": "plaintext",
            "source_evidence_id": "ev-1",
            "source_visit_id": "bf_dictionary:visit:0",
            "source_candidate_id": "c0",
        }],
    )
    built = build_payload_candidates(state)
    validated = validate_payload_candidates({**state, **built})

    assert built["payload_candidates"]["bf_dictionary"] == []
    assert validated["payload_candidates"]["bf_dictionary"] == []
    reasons = {row["event"] for row in validated["fallback_events"]}
    assert "payload_validation.strict_no_candidate" in reasons
    assert "payload_generation.static_seed_fallback" not in reasons


def test_one_per_visit_budget_applies_across_static_model_and_chain_origins(monkeypatch):
    monkeypatch.setattr(
        payload_generator,
        "generate_llm_variants",
        _fake_mutation_generator("candidate:secretpair", "credential_ordering"),
    )
    route = {
        "source": "credentials_extracted",
        "target_agent": "bf_dictionary",
        "source_evidence_ids": ["ev-1"],
    }
    state = _state(
        "bf_dictionary",
        "hybrid",
        candidate_budget=1,
        active_chain_route=route,
        found_credentials=[{
            "username": "route-user",
            "password": "route-pass",
            "representation": "plaintext",
            "source_evidence_id": "ev-1",
            "source_visit_id": "bf_dictionary:visit:0",
            "source_candidate_id": "c0",
        }],
    )
    built = build_payload_candidates(state)
    validated = validate_payload_candidates({**state, **built})

    queue = validated["payload_candidates"]["bf_dictionary"]
    assert len(queue) == 1
    assert queue[0]["origin_kind"] == "chain_derived"
    excluded = [
        row for row in validated["payload_validation_results"]["bf_dictionary"]
        if row.get("reason") == BUDGET_EXCLUSION_REASON
    ]
    assert excluded
    assert {row["origin_kind"] for row in excluded} >= {"static_seed", "seed_mutation"}
    lifecycle = [
        row for row in validated["candidate_lifecycle"]
        if row["status"] == "budget_excluded"
    ]
    assert lifecycle and all(row["reason"] == BUDGET_EXCLUSION_REASON for row in lifecycle)


def test_zero_budget_makes_no_call_and_queues_nothing(monkeypatch):
    calls: list[dict[str, Any]] = []

    def fake(**kwargs: Any):
        calls.append(kwargs)
        return [], {"failure_reason": "should_not_run"}, []

    monkeypatch.setattr(payload_generator, "generate_llm_variants", fake)
    state = _state("sqli_union", "llm_mutation_only", candidate_budget=0)
    built = build_payload_candidates(state)

    assert calls == []
    assert built["payload_candidates"]["sqli_union"] == []
    opportunity = built["model_call_requirements"][0]
    assert opportunity["status"] == "not_run"
    assert opportunity["reason"] == "candidate_budget_zero"
    assert opportunity["required"] is True
