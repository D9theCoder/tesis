"""Behavior regressions for the peer-correction release (slice A payloads).

Read-only-compatible unit tests: no provider or HTTP call is made.  They cover
the supplied-seed boundary, visit-scoped queue identity, recorded-policy
dispatch, provider receipt binding, absence-vs-output classification, hybrid
budget exclusion, and unknown-mode fail-closed behaviour.
"""
import json
from types import SimpleNamespace

import pytest

import foundation.payload_generator as generator
from foundation.payload_library import PayloadLibrary
from core.payload_policy import (
    EVENT_NO_SUPPLIED_SEED,
    PAYLOAD_POLICY_BASIS_HISTORICAL,
    PAYLOAD_POLICY_VERSION,
    REASON_SEED_NOT_SUPPLIED,
    RECORDED_POLICY_STATE_KEY,
)
from core.state import new_default_state
from evaluation.scoring_evidence import evidence_hash
from foundation.payload_generator import build_payload_candidates, generate_llm_variants
from foundation.payload_templates import load_template, template_reference
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


class _FakeLLM:
    def __init__(self, content):
        self.content = content

    def invoke(self, _messages):
        return SimpleNamespace(content=self.content)


class _RaisingRuntime:
    def __init__(self, exc):
        self.exc = exc

    def invoke(self, **_kwargs):
        raise self.exc


def _provider_exception(message: str, **attributes):
    error = RuntimeError(message)
    for key, value in attributes.items():
        setattr(error, key, value)
    return error


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


def test_copy_evidence_only_counts_rendered_seeds(monkeypatch):
    visible = _execution_seed()
    probe = _probe_seed()
    response = json.dumps({"variants": [{
        "source_seed_id": visible["candidate_id"],
        "mutation_type": "encoding",
        "payload_or_logic": probe["payload_or_logic"],
    }]})
    monkeypatch.setattr(generator, "_build_llm", lambda *args, **kwargs: _FakeLLM(response))
    state = _state()
    generated, prompt_event, _guardrails = generate_llm_variants(
        state=state, method="sqli_union",
        seeds=PayloadLibrary().load_seed_candidates("sqli_union", "low"),
        profile=__import__("core.knowledge_graph", fromlist=["x"]).get_attack_knowledge_graph().get_payload_profile("sqli_union"),
        budget=1,
    )
    assert generated
    assert prompt_event is not None
    assert generated[0]["copy_of_supplied_seed"] is False
    assert generated[0]["equals_canonical_seed_id"] == probe["candidate_id"]
    assert prompt_event["prompt_visible_seed_ids"] == [visible["candidate_id"]]
    assert prompt_event["prompt_visible_seeds_sha256"] == evidence_hash(prompt_event["prompt_visible_seeds"])


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


def test_provider_exception_keeps_the_runtime_receipt_when_retained(monkeypatch):
    failure = _provider_exception(
        "socket closed", performance={"call_id": "call-9", "parse_status": "provider_error"}
    )
    monkeypatch.setattr(
        generator, "current_call_context",
        lambda: SimpleNamespace(runtime=_RaisingRuntime(failure)),
    )
    state = _state()
    generated, prompt_event, _guardrails = generate_llm_variants(
        state=state, method="sqli_union",
        seeds=PayloadLibrary().load_seed_candidates("sqli_union", "low"),
        profile=__import__("core.knowledge_graph", fromlist=["x"]).get_attack_knowledge_graph().get_payload_profile("sqli_union"),
        budget=1,
    )
    assert generated == []
    assert prompt_event is not None
    assert prompt_event["call_id"] == "call-9"
    assert prompt_event["receipt_binding"] == "runtime_receipt"

    monkeypatch.setattr(
        generator, "current_call_context",
        lambda: SimpleNamespace(runtime=_RaisingRuntime(_provider_exception("no dispatch"))),
    )
    _generated, prompt_event, _guardrails = generate_llm_variants(
        state=state, method="sqli_union",
        seeds=PayloadLibrary().load_seed_candidates("sqli_union", "low"),
        profile=__import__("core.knowledge_graph", fromlist=["x"]).get_attack_knowledge_graph().get_payload_profile("sqli_union"),
        budget=1,
    )
    assert prompt_event is not None
    assert prompt_event["call_id"] is None
    assert prompt_event["receipt_binding"] == "unavailable_no_dispatch"


def test_static_queue_ids_are_visit_scoped(monkeypatch):
    seed = _execution_seed()
    monkeypatch.setattr(
        generator, "generate_llm_variants",
        lambda **kwargs: ([], {"failure_reason": "guardrail_refusal",
                               "visit_id": kwargs["state"]["selected_visit_id"],
                               "method": kwargs["method"], "prompt_visible_seed_ids": []}, []),
    )
    first = build_payload_candidates(_state(mode="hybrid", visit="v1"))
    second = build_payload_candidates(_state(mode="hybrid", visit="v2"))
    first_rows = first["payload_candidates"]["sqli_union"]
    second_rows = second["payload_candidates"]["sqli_union"]

    assert first_rows and second_rows
    assert {row["candidate_id"] for row in first_rows}.isdisjoint({row["candidate_id"] for row in second_rows})
    assert [row["source_seed_id"] for row in first_rows] == [row["source_seed_id"] for row in second_rows]
    assert all(row["candidate_id"] != row["source_seed_id"] for row in first_rows + second_rows)
    assert all(row["visit_id"] == "sqli_union:v1" for row in first_rows)


def test_stale_visit_candidate_is_rejected_in_non_strict_mode():
    seed = _execution_seed()
    stale = _mutation_candidate(seed, candidate_id="stale", visit="sqli_union:v0")
    state = _state(
        mode="hybrid", visit="v1",
        payload_candidates={"sqli_union": [stale]},
        generation_prompts=[{
            "method": "sqli_union", "visit_id": "sqli_union:v1",
            "prompt_visible_seed_ids": [seed["candidate_id"]],
        }],
    )
    update = validate_payload_candidates(state)
    assert update["payload_candidates"]["sqli_union"] == []
    assert any(
        row.get("reason") == "stale_visit_candidate"
        for row in update["payload_validation_results"]["sqli_union"]
    )


def test_unknown_live_payload_mode_fails_closed():
    with pytest.raises(ValueError, match="unknown payload mode"):
        build_payload_candidates({**_state(), "payload_mode": "mutatation_only"})
    with pytest.raises(ValueError, match="unknown payload mode"):
        validate_payload_candidates({**_state(), "payload_mode": "mutatation_only"})


def test_historical_basis_uses_recorded_policy_and_registry():
    template = load_template("sqli_union", "low")
    legacy_rows = [
        candidate for candidate in PayloadLibrary().load_seed_candidates("sqli_union", "low")
        if candidate["stage"] in {"exploit", "bypass"}
    ]
    state = _state(
        mode="hybrid",
        payload_candidates={"sqli_union": legacy_rows},
        **{"payload_policy_basis": PAYLOAD_POLICY_BASIS_HISTORICAL},
    )
    update = validate_payload_candidates(state)
    assert update["payload_candidates"]["sqli_union"]

    template_candidate = {
        "candidate_id": "hist-template",
        "method": "sqli_union",
        "source": "llm_generated",
        "origin_kind": "template_generation",
        "origin_ref": template_reference(template),
        "mutation_type": "template_construction",
        "payload_or_logic": "1' AND 1=2-- -",
        "target_param": "id",
        "expected_signal": "data_extraction_evidence",
        "stage": "exploit",
        "copy_of_supplied_seed": False,
    }
    recorded = {
        "policy_version": "payload-policy.v1",
        "template_registry": {("sqli_union", "low"): template},
    }
    historical_state = _state(
        mode="llm_template",
        payload_candidates={"sqli_union": [template_candidate]},
        policy_basis=PAYLOAD_POLICY_BASIS_HISTORICAL,
        **{RECORDED_POLICY_STATE_KEY: recorded},
    )
    accepted = validate_payload_candidates(historical_state, policy_basis="historical")
    assert [row["candidate_id"] for row in accepted["payload_candidates"]["sqli_union"]] == ["hist-template"]

    del historical_state[RECORDED_POLICY_STATE_KEY]
    refused = validate_payload_candidates(historical_state, policy_basis="historical")
    assert refused["payload_candidates"]["sqli_union"] == []
    assert any(
        row.get("reason") == "historical_template_registry_unavailable"
        for row in refused["payload_validation_results"]["sqli_union"]
    )


def test_hybrid_budget_exclusion_is_not_a_generation_failure(monkeypatch):
    seed = _execution_seed()
    monkeypatch.setattr(
        generator, "generate_llm_variants",
        lambda **kwargs: ([_mutation_candidate(seed, candidate_id="model-1", payload="1' AnD 4=4-- -")],
                          {"visit_id": kwargs["state"]["selected_visit_id"], "call_id": "call-1",
                           "method": kwargs["method"], "prompt_visible_seed_ids": [seed["candidate_id"]]}, []),
    )
    state = _state(mode="hybrid", candidate_budget=1)
    built = build_payload_candidates(state)
    validated = validate_payload_candidates({**state, **built})

    queue = validated["payload_candidates"]["sqli_union"]
    assert len(queue) == 1 and queue[0]["origin_kind"] == "static_seed"
    events = {row["event"]: row for row in validated["fallback_events"]}
    assert "payload_generation.static_seed_fallback" not in events
    assert events["payload_validation.model_candidate_budget_excluded"]["candidate_ids"]
    lifecycle = validated["candidate_lifecycle"]
    assert any(row["status"] == "budget_excluded" for row in lifecycle)


def test_target_no_payload_event_is_role_and_origin_bound():
    state = _state(
        mode="llm_mutation_only",
        target_method="sqli_union",
        payload_candidates={"sqli_union": []},
        selection_rejections=[],
    )
    update = validate_payload_candidates(state)
    events = {row["event"]: row for row in update["fallback_events"]}
    terminal = events["target_method.no_valid_payloads"]
    assert terminal["role"] == "payload_generator"
    assert terminal["origin"] == "payload_validator"
    assert terminal["scope"] == "method"
    assert terminal["origin_kind"] == "seed_mutation"
    assert terminal["strict_no_candidate"] is True


@pytest.mark.parametrize("call_id,has_receipt,accepted", [
    (None, True, False),
    ("wrong-call", True, False),
    ("call-1", False, False),
    ("call-1", True, True),
])
def test_model_queue_requires_current_generation_call_binding(call_id, has_receipt, accepted):
    from agents.state_utils import candidate_payloads_for_stage

    seed = _execution_seed()
    candidate = _mutation_candidate(seed, candidate_id="bound-candidate")
    candidate["model_call_id"] = call_id
    state = _state(
        payload_candidates={"sqli_union": [candidate]},
        generation_prompts=[{
            "method": "sqli_union", "visit_id": "sqli_union:v1",
            "prompt_visible_seed_ids": [seed["candidate_id"]],
        }],
        model_call_requirements=[{
            "role": "payload_generator", "receipt_stage": "generation",
            "method": "sqli_union", "visit_id": "sqli_union:v1",
            "status": "completed", "call_id": "call-1",
        }] if has_receipt else [],
    )
    assert candidate_payloads_for_stage(state, "sqli_union", "low", "exploit") == []
    update = validate_payload_candidates(state)
    assert bool(update["payload_candidates"]["sqli_union"]) is accepted
    queue = candidate_payloads_for_stage({**state, **update}, "sqli_union", "low", "exploit")
    assert queue == [candidate["payload_or_logic"]] if accepted else queue == []


@pytest.mark.parametrize("mode", ["llm_mutation_only", "llm_template"])
@pytest.mark.parametrize("violation", ["extra_field", "wrong_root", "multiple_candidates"])
def test_current_model_schema_rejects_covert_fields_and_excess_candidates(monkeypatch, mode, violation):
    seed = _execution_seed()
    if mode == "llm_template":
        template = load_template("sqli_union", "low")
        key = "candidates"
        row = {
            "payload_or_logic": "1' UNION SELECT 1,2-- -",
            "target_param": template["target_param"],
            "expected_signal": template["expected_signal"],
        }
    else:
        key = "variants"
        row = {
            "source_seed_id": seed["candidate_id"], "mutation_type": "encoding",
            "payload_or_logic": "1' AnD 7=7-- -",
        }
    if violation == "extra_field":
        row["source"] = "static_seed"
    response = {key: [row, dict(row)] if violation == "multiple_candidates" else [row]}
    if violation == "wrong_root":
        response = {"variants" if key == "candidates" else "candidates": response[key]}
    monkeypatch.setattr(generator, "_build_llm", lambda *args, **kwargs: _FakeLLM(json.dumps(response)))
    from core.knowledge_graph import get_attack_knowledge_graph
    generated, event, _ = generate_llm_variants(
        state=_state(mode=mode), method="sqli_union", seeds=[seed],
        profile=get_attack_knowledge_graph().get_payload_profile("sqli_union"), budget=1,
    )
    assert generated == []
    assert event["failure_reason"] == "invalid_schema"
