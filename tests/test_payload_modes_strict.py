"""Behavior tests for strict mutation, Template, provenance, and budget policy.

These tests exercise only local code paths: no provider call and no HTTP request
is made.  The payload-generation model call is replaced with a deterministic
fake, and the detection-control catalog is replaced with an in-memory stub.
"""
from typing import Any


import foundation.payload_generator as payload_generator

from agents.state_utils import validated_payload_candidates
from core.payload_policy import (
    BUDGET_EXCLUSION_REASON,
    CANDIDATE_ORDER_POLICY,
    CANDIDATE_ORDER_POLICY_VERSION,
    CANDIDATE_ORDER_TRIGGER,
    PAYLOAD_POLICY_VERSION,
)
from core.state import new_default_state
from foundation.payload_generator import (
    _stamp_static_candidates,
    build_payload_candidates,
)
from foundation.payload_library import PayloadLibrary
from foundation.payload_templates import (
    template_confidentiality_findings,
)
from foundation.payload_validator import (
    payload_validator_node,
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
    # The frozen hybrid order ranks the valid generated candidate first; the
    # static and chain-derived origins are budget-excluded, not dropped.
    assert queue[0]["origin_kind"] == "seed_mutation"
    excluded = [
        row for row in validated["payload_validation_results"]["bf_dictionary"]
        if row.get("reason") == BUDGET_EXCLUSION_REASON
    ]
    assert excluded
    assert {row["origin_kind"] for row in excluded} >= {"static_seed", "chain_derived"}
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


def _static_ids(method: str = "sqli_union", level: str = "low") -> list[str]:
    visit_id = f"{method}:visit:1"
    seeds = [
        candidate for candidate in PayloadLibrary().load_seed_candidates(method, level)
        if candidate["stage"] in {"exploit", "bypass"}
    ]
    return [
        row["candidate_id"]
        for row in _stamp_static_candidates(method, level, visit_id, seeds)
    ]


def test_hybrid_queues_valid_generated_candidate_before_static_fallback(monkeypatch):
    """A valid model candidate precedes the static seeds it falls back to."""
    monkeypatch.setattr(
        payload_generator,
        "generate_llm_variants",
        _fake_mutation_generator("1' UNION SELECT user,password FROM users-- -"),
    )
    built = build_payload_candidates(_state("sqli_union", "hybrid"))
    queue = built["payload_candidates"]["sqli_union"]

    assert queue
    generated = [row for row in queue if row["origin_kind"] == "seed_mutation"]
    static = [row for row in queue if row["origin_kind"] == "static_seed"]
    assert len(generated) == 1
    assert queue[0]["candidate_id"] == generated[0]["candidate_id"]
    assert generated[0]["source"] == "llm_generated"
    # Static seeds stay queued, in canonical order, after every generated row.
    assert static
    assert [row["candidate_id"] for row in static] == _static_ids()
    assert queue.index(generated[0]) < queue.index(static[0])

    order = built["active_payload_candidates"]["sqli_union"]["candidate_order"]
    assert order["triggered"] is True
    assert order["trigger"] == CANDIDATE_ORDER_TRIGGER
    assert order["policy_version"] == CANDIDATE_ORDER_POLICY_VERSION
    for row in queue:
        provenance = built["payload_provenance"][row["candidate_id"]]
        assert provenance["candidate_order_policy_version"] == CANDIDATE_ORDER_POLICY_VERSION


def test_hybrid_validated_queue_ranks_generated_before_static_fallback(monkeypatch):
    """The final validated/executed queue is generated-first, static second."""
    monkeypatch.setattr(
        payload_generator,
        "generate_llm_variants",
        _fake_mutation_generator("1' UNION SELECT user,password FROM users LIMIT 1-- -"),
    )
    state = _state("sqli_union", "hybrid")
    built = build_payload_candidates(state)
    validated = payload_validator_node({**state, **built})
    final_state = {**state, **built, **validated}
    queue = validated["payload_candidates"]["sqli_union"]

    assert queue
    assert queue[0]["origin_kind"] == "seed_mutation"
    assert queue[0]["source"] == "llm_generated"
    static = [row for row in queue if row["origin_kind"] == "static_seed"]
    assert [row["candidate_id"] for row in static] == _static_ids()
    assert queue.index(queue[0]) < queue.index(static[0])
    # This is the exact order agents consume for execution.
    executed = validated_payload_candidates(final_state, "sqli_union")
    assert [row["candidate_id"] for row in executed] == [
        row["candidate_id"] for row in queue
    ]
    assert [row["origin_kind"] for row in executed] == (
        ["seed_mutation"] + ["static_seed"] * len(static)
    )
    # The builder's frozen order identity survives revalidation provenance.
    generated_provenance = validated["payload_provenance"][queue[0]["candidate_id"]]
    assert generated_provenance["candidate_order_policy"] == CANDIDATE_ORDER_POLICY
    assert (
        generated_provenance["candidate_order_policy_version"]
        == CANDIDATE_ORDER_POLICY_VERSION
    )
    for row in static:
        provenance = validated["payload_provenance"][row["candidate_id"]]
        assert provenance["candidate_order_policy"] == CANDIDATE_ORDER_POLICY
        assert provenance["candidate_order_policy_version"] == CANDIDATE_ORDER_POLICY_VERSION


def test_static_only_validated_queue_keeps_chain_before_static(monkeypatch):
    """Static-only ranking keeps its historical route-derived-first order."""
    monkeypatch.setattr(
        payload_generator,
        "generate_llm_variants",
        lambda **_kwargs: ([], {"failure_reason": "should_not_run"}, []),
    )
    route = {
        "source": "credentials_extracted",
        "target_agent": "bf_dictionary",
        "source_evidence_ids": ["ev-1"],
    }
    state = _state(
        "bf_dictionary",
        "static_only",
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

    assert queue
    assert queue[0]["origin_kind"] == "chain_derived"
    assert {row["origin_kind"] for row in queue} == {"chain_derived", "static_seed"}


def test_hybrid_keeps_static_seeds_as_fallback_without_generated_candidate(monkeypatch):
    """No valid generated candidate leaves the static queue order untouched."""
    monkeypatch.setattr(
        payload_generator,
        "generate_llm_variants",
        lambda **_kwargs: ([], {"failure_reason": "invalid_json"}, []),
    )
    state = _state("sqli_union", "hybrid")
    built = build_payload_candidates(state)
    queue = built["payload_candidates"]["sqli_union"]

    assert [row["candidate_id"] for row in queue] == _static_ids()
    assert all(row["origin_kind"] == "static_seed" for row in queue)
    order = built["active_payload_candidates"]["sqli_union"]["candidate_order"]
    assert order["triggered"] is False
    assert order["generated_count"] == 0
    assert order["static_count"] == len(queue)
    validated = validate_payload_candidates({**state, **built})
    validated_queue = validated["payload_candidates"]["sqli_union"]
    assert [row["candidate_id"] for row in validated_queue] == _static_ids()


def test_static_only_queue_order_is_unchanged_and_makes_no_generation_call(monkeypatch):
    calls: list[dict[str, Any]] = []

    def fake(**kwargs: Any):
        calls.append(kwargs)
        return [], {"failure_reason": "should_not_run"}, []

    monkeypatch.setattr(payload_generator, "generate_llm_variants", fake)
    built = build_payload_candidates(_state("sqli_union", "static_only"))
    queue = built["payload_candidates"]["sqli_union"]

    assert calls == []
    assert built["generation_prompts"] == []
    assert [row["candidate_id"] for row in queue] == _static_ids()
    assert all(row["origin_kind"] == "static_seed" for row in queue)
    order = built["active_payload_candidates"]["sqli_union"]["candidate_order"]
    assert order["triggered"] is False
    assert order["generated_count"] == 0


def test_strict_mode_generated_candidate_never_gains_static_fallback(monkeypatch):
    """Mutation-only queues the generated candidate alone in generated-first order."""
    monkeypatch.setattr(
        payload_generator,
        "generate_llm_variants",
        _fake_mutation_generator("1' UNION SELECT user,password FROM users-- -"),
    )
    state = _state("sqli_union", "llm_mutation_only")
    built = build_payload_candidates(state)
    queue = built["payload_candidates"]["sqli_union"]

    assert len(queue) == 1
    assert queue[0]["origin_kind"] == "seed_mutation"
    assert queue[0]["source"] == "llm_generated"
    static_ids = set(_static_ids())
    assert not static_ids & {row["candidate_id"] for row in queue}
    order = built["active_payload_candidates"]["sqli_union"]["candidate_order"]
    assert order["triggered"] is False
    assert order["static_count"] == 0
    validated = validate_payload_candidates({**state, **built})
    validated_queue = validated["payload_candidates"]["sqli_union"]
    assert [row["candidate_id"] for row in validated_queue] == [queue[0]["candidate_id"]]
    assert all(row["origin_kind"] == "seed_mutation" for row in validated_queue)
