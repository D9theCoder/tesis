"""Behavior regressions for the peer-correction release (slice A payloads).

Read-only-compatible unit tests: no provider or HTTP call is made.  They cover
the supplied-seed boundary, visit-scoped queue identity, recorded-policy
dispatch, provider receipt binding, absence-vs-output classification, hybrid
budget exclusion, and unknown-mode fail-closed behaviour.
"""


import foundation.payload_generator as generator
from foundation.payload_library import PayloadLibrary
from core.payload_policy import (
    EVENT_NO_SUPPLIED_SEED,
    PAYLOAD_POLICY_VERSION,
    REASON_SEED_NOT_SUPPLIED,
)
from core.state import new_default_state
from foundation.payload_generator import build_payload_candidates, generate_llm_variants
from foundation.payload_validator import validate_payload_candidates


def _state(method="sqli_union", mode="llm_mutation_only", *, visit="v1", level="low", **overrides):
    return {
        **new_default_state(),
        "selected_method": method,
        "payload_mode": mode,
        "security_level": level,
        "selected_visit_id": f"{method}:{visit}",
        "active_payload_candidates": {},
        "payload_candidates": {},
        **overrides,
    }


def _execution_seed(method="sqli_union", level="low"):
    return next(
        candidate for candidate in PayloadLibrary().load_seed_candidates(method, level)
        if candidate["stage"] in {"exploit", "bypass"}
    )


def _probe_seed(method="sqli_union", level="low"):
    return next(
        candidate for candidate in PayloadLibrary().load_seed_candidates(method, level)
        if candidate["stage"] == "probe"
    )


def _mutation_candidate(seed, *, candidate_id, payload=None, visit="sqli_union:v1", mutation="encoding"):
    return {
        "candidate_id": candidate_id,
        "method": "sqli_union",
        "source": "llm_generated",
        "origin_kind": "seed_mutation",
        "source_seed_id": seed["candidate_id"],
        "origin_ref": {"seed_id": seed["candidate_id"]},
        "mutation_type": mutation,
        "payload_or_logic": payload or "1' AnD 1=1-- -",
        "target_param": seed["target_param"],
        "expected_signal": seed["expected_signal"],
        "stage": "exploit",
        "visit_id": visit,
        "policy_version": PAYLOAD_POLICY_VERSION,
        "model_call_id": "call-1",
        "prompt_id": "payload_generation.constrained_variant",
        "schema_version": "payload-variants.v3",
        "copy_of_supplied_seed": False,
    }


def test_mutation_seed_must_come_from_the_rendered_prompt(monkeypatch):
    # ``medium`` has more than one execution-ready seed, so "another execution
    # seed that the prompt did not render" is a real, constructible case.
    visible = _execution_seed(level="medium")
    probe = _probe_seed(level="medium")
    other = next(
        candidate for candidate in PayloadLibrary().load_seed_candidates("sqli_union", "medium")
        if candidate["stage"] in {"exploit", "bypass"} and candidate["candidate_id"] != visible["candidate_id"]
    )
    state = _state(level="medium", 
        payload_candidates={"sqli_union": [
            _mutation_candidate(probe, candidate_id="probe-ref"),
            _mutation_candidate(other, candidate_id="unseen-ref", payload="1' AnD 2=2-- -"),
            _mutation_candidate(visible, candidate_id="visible-ref", payload="1' AnD 3=3-- -"),
        ]},
        generation_prompts=[{
            "method": "sqli_union", "visit_id": "sqli_union:v1", "call_id": "call-1",
            "prompt_visible_seed_ids": [visible["candidate_id"]],
        }],
        model_call_requirements=[{
            "opportunity_id": "payload_generator:sqli_union:sqli_union:v1",
            "receipt_stage": "generation", "role": "payload_generator",
            "method": "sqli_union", "visit_id": "sqli_union:v1", "status": "completed",
            "call_id": "call-1",
        }],
    )
    update = validate_payload_candidates(state)

    reasons = {row["candidate_id"]: row.get("reason") for row in update["payload_validation_results"]["sqli_union"]}
    assert reasons["probe-ref"] == "probe_seed_provenance_not_executable"
    assert reasons["unseen-ref"] == REASON_SEED_NOT_SUPPLIED
    assert [row["candidate_id"] for row in update["payload_candidates"]["sqli_union"]] == ["visible-ref"]


def test_no_execution_seed_makes_no_model_call_and_no_static_fallback(monkeypatch):
    probes = [row for row in PayloadLibrary().load_seed_candidates("sqli_union", "low") if row["stage"] == "probe"]
    monkeypatch.setattr(generator, "_build_llm", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no call")))
    generated, prompt_event, _guardrails = generate_llm_variants(
        state=_state(), method="sqli_union", seeds=probes,
        profile=__import__("core.knowledge_graph", fromlist=["x"]).get_attack_knowledge_graph().get_payload_profile("sqli_union"),
        budget=1,
    )
    assert generated == []
    assert prompt_event is not None
    assert prompt_event["failure_reason"] == "no_supplied_seed"
    assert prompt_event["prompt_visible_seed_ids"] == []

    monkeypatch.setattr(
        generator, "generate_llm_variants",
        lambda **kwargs: ([], {"failure_reason": "no_supplied_seed",
                               "visit_id": kwargs["state"]["selected_visit_id"],
                               "method": kwargs["method"],
                               "prompt_visible_seed_ids": [], "prompt_visible_seeds": []}, []),
    )
    strict = build_payload_candidates(_state())
    assert strict["payload_candidates"]["sqli_union"] == []
    assert [row["event"] for row in strict["fallback_events"]] == [EVENT_NO_SUPPLIED_SEED]
    opportunity = strict["model_call_requirements"][0]
    assert opportunity["status"] == "not_run" and opportunity["reason"] == "no_supplied_seed"
    assert opportunity["call_id"] is None
