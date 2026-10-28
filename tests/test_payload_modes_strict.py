"""Behavior tests for strict mutation, Template, provenance, and budget policy.

These tests exercise only local code paths: no provider call and no HTTP request
is made.  The payload-generation model call is replaced with a deterministic
fake, and the detection-control catalog is replaced with an in-memory stub.
"""
import sys
import types
from typing import Any

import pytest

import foundation.payload_generator as payload_generator
from core.knowledge_graph import AttackKnowledgeGraph
from core.payload_policy import (
    BUDGET_EXCLUSION_REASON,
    CONTROL_POLICY_VERSION,
    PAYLOAD_MODES,
    PAYLOAD_POLICY_VERSION,
    STRICT_PAYLOAD_MODES,
    TEMPLATE_MUTATION_TYPE,
    allows_chain_derived,
    allows_static_candidates,
    coerce_payload_mode,
    exploit_queue_limit,
    generation_budget,
    is_strict_mode,
    mode_display_label,
    origin_kind_permitted,
    requires_model_candidate,
)
from core.state import new_default_state
from foundation.payload_generator import build_payload_candidates
from foundation.payload_library import PayloadLibrary
from foundation.payload_templates import (
    SECURITY_LEVELS,
    TEMPLATE_REGISTRY,
    TemplateUnavailableError,
    load_template,
    template_confidentiality_findings,
    template_coverage,
    template_reference,
    validate_template_reference,
)
from foundation.payload_validator import (
    freeze_probe_controls,
    validate_payload_candidates,
    validate_probe_controls,
)
from llm.prompts import manifests
from llm.prompts.payload_generation_prompt import (
    build_template_generation_prompt,
    sanitized_template_observations,
)

METHODS = tuple(sorted(AttackKnowledgeGraph.TARGET_PARAMS))


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


def _exploit_seed(method: str, level: str = "low") -> dict[str, Any]:
    return next(
        candidate
        for candidate in PayloadLibrary().load_seed_candidates(method, level)
        if candidate["stage"] in {"exploit", "bypass"}
    )


def _template_event(template: dict[str, Any], call_id: str = "call-template") -> dict[str, Any]:
    return {
        "method": template["method"],
        "visit_id": f"{template['method']}:visit:1",
        "call_id": call_id,
        "prompt_id": "payload_generation.template_construction",
        "schema_version": "payload-template.v1",
        "origin_kind": "template_generation",
        "policy_version": PAYLOAD_POLICY_VERSION,
        "template_reference": template_reference(template),
        "template_id": template["template_id"],
        "template_version": template["template_version"],
        "template_sha256": template["template_sha256"],
        "template_feasibility": template["feasibility"],
        "parsed_candidate_ids": [],
    }


def _fake_template_generator(value: str = "1' UNION SELECT 1,2-- -"):
    def fake(*, state: dict[str, Any], method: str, seeds: list[dict], profile: dict, budget: int):
        return (
            [{
                "candidate_id": "model-supplied-id",
                "source": "static_seed",
                "source_seed_id": "fabricated-seed",
                "stage": "probe",
                "method": method,
                "mutation_type": "case_variant",
                "payload_or_logic": value,
                "target_param": "id",
                "expected_signal": "data_extraction_evidence",
            }],
            _template_event(load_template(method, state["security_level"])),
            [],
        )

    return fake


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


def test_payload_mode_registry_and_origin_matrix():
    assert PAYLOAD_MODES == (
        "static_only",
        "hybrid",
        "llm_mutation_only",
        "llm_template",
    )
    assert STRICT_PAYLOAD_MODES == {"llm_mutation_only", "llm_template"}
    assert mode_display_label("llm_template") == "Template"
    assert coerce_payload_mode(" LLM_TEMPLATE ") == "llm_template"
    assert coerce_payload_mode("unknown") == "static_only"

    assert is_strict_mode("llm_template") is True
    assert is_strict_mode("hybrid") is False
    assert requires_model_candidate("llm_template") is True
    assert requires_model_candidate("static_only") is False
    assert allows_static_candidates("hybrid") is True
    assert allows_static_candidates("llm_template") is False
    assert allows_chain_derived("hybrid") is True
    assert allows_chain_derived("llm_mutation_only") is False

    assert origin_kind_permitted("llm_template", "template_generation") is True
    assert origin_kind_permitted("llm_template", "static_seed") is False
    assert origin_kind_permitted("llm_mutation_only", "seed_mutation") is True
    assert origin_kind_permitted("llm_mutation_only", "chain_derived") is False
    assert origin_kind_permitted("hybrid", "seed_mutation") is True
    assert origin_kind_permitted("static_only", "seed_mutation") is False
    # A verification control is never a queue candidate in any mode.
    for mode in PAYLOAD_MODES:
        assert origin_kind_permitted(mode, "derived_control") is False


def test_budget_policy_is_one_rule_across_origins():
    profile = {"payload_budget": 5, "max_generated_candidates": 5}
    assert exploit_queue_limit(1, profile) == 1
    assert exploit_queue_limit(3, profile) == 3
    assert exploit_queue_limit(9, profile) == 5
    assert exploit_queue_limit(0, profile) == 0
    assert exploit_queue_limit(None, profile) == 5
    assert generation_budget(1, profile) == 1
    assert generation_budget(9, {**profile, "max_generated_candidates": 2}) == 2


def test_template_registry_covers_every_method_and_level():
    rows = template_coverage()
    assert len(rows) == len(METHODS) * len(SECURITY_LEVELS)
    assert {(row["method"], row["security_level"]) for row in rows} == {
        (method, level) for method in METHODS for level in SECURITY_LEVELS
    }
    for row in rows:
        assert row["template_id"].startswith("template.")
        assert row["template_version"]
        assert len(row["template_sha256"]) == 64
        assert row["feasibility"] in {"supported", "limited", "unsupported"}
        assert row["supported"] is (row["feasibility"] != "unsupported")
        if row["feasibility"] != "supported":
            assert row["reason"], "a limited/unsupported template needs a reason"


def test_template_registry_has_no_payload_or_credential_leak():
    assert template_confidentiality_findings() == []


def test_template_is_inert_and_hash_is_stable():
    template = load_template("sqli_union", "low")
    assert template["template_sha256"] == TEMPLATE_REGISTRY[("sqli_union", "low")]["template_sha256"]
    assert "payload_or_logic" not in template
    assert template["template_sha256"] != load_template("sqli_union", "medium")["template_sha256"]
    assert validate_template_reference(
        template_reference(template), "sqli_union", "low"
    ) == []
    copy = load_template("sqli_union", "low")
    copy["objective"] = "tampered"
    assert load_template("sqli_union", "low")["objective"] != "tampered"


def test_template_lookup_rejects_unknown_coordinates():
    with pytest.raises(TemplateUnavailableError):
        load_template("not_a_method", "low")


def test_template_reference_validation_rejects_wrong_identity():
    template = load_template("ac_idor", "low")
    reference = template_reference(template)
    assert validate_template_reference(reference, "ac_idor", "medium")
    assert validate_template_reference({**reference, "template_sha256": "0" * 64}, "ac_idor", "low")
    assert validate_template_reference(None, "ac_idor", "low")


def test_template_prompt_closed_allowlist_excludes_seeds_and_credentials():
    template = load_template("sqli_union", "low")
    prompt = build_template_generation_prompt(
        template=template,
        observations={
            "union_select_possible": True,
            "authenticated_crawl": True,
            "no_rate_limit": True,
            "found_credentials": [{"username": "admin", "password": "password"}],
        },
        candidate_budget=1,
    )
    context = prompt.split("Context: ", 1)[1]
    assert "authenticated_crawl" in context
    # Non-allowlisted observation names and values never reach the prompt.
    for excluded in ("union_select_possible", "no_rate_limit", "admin", "password"):
        assert excluded not in context

    # No static seed payload of the registry may appear in the prompt.
    for method in METHODS:
        for level in SECURITY_LEVELS:
            for candidate in PayloadLibrary().load_seed_candidates(method, level):
                payload = str(candidate.get("payload_or_logic", ""))
                if len(payload) >= 6:
                    assert payload.lower() not in prompt.lower()
    assert "source_seed_id" not in prompt


def test_template_prompt_builder_has_no_seed_or_history_parameter():
    import inspect

    parameters = set(
        inspect.signature(build_template_generation_prompt).parameters
    )
    assert parameters == {"template", "observations", "candidate_budget"}


def test_sanitized_template_observations_are_boolean_and_allowlisted():
    sanitized = sanitized_template_observations({
        "authenticated_crawl": True,
        "low_priv_session_available": "yes",
        "union_select_possible": True,
    })
    assert sanitized == {"authenticated_crawl": True}


def test_template_prompt_manifest_is_registered():
    assert manifests.TEMPLATE_PROMPT_ID == "payload_generation.template_construction"
    manifest = manifests.PROMPT_MANIFESTS[manifests.TEMPLATE_PROMPT_ID]
    assert manifest["output_schema_version"] == "payload-template.v1"
    assert manifest["template_hash"].startswith("sha256:")
    assert "template" in manifest["input_schema"]["parameters"]
    assert "static_seeds" not in manifest["input_schema"]["parameters"]


def test_template_mode_queues_model_candidate_with_template_provenance(monkeypatch):
    template = load_template("sqli_union", "low")
    monkeypatch.setattr(
        payload_generator,
        "generate_llm_variants",
        _fake_template_generator("1' UNION SELECT null,null-- -"),
    )
    state = _state("sqli_union", "llm_template")
    built = build_payload_candidates(state)
    validated = validate_payload_candidates({**state, **built})

    queue = validated["payload_candidates"]["sqli_union"]
    assert len(queue) == 1
    candidate = queue[0]
    assert candidate["origin_kind"] == "template_generation"
    assert candidate["source"] == "llm_generated"
    assert candidate["mutation_type"] == TEMPLATE_MUTATION_TYPE
    assert "source_seed_id" not in candidate
    assert candidate["visit_id"] == "sqli_union:visit:1"
    assert candidate["model_call_id"] == "call-template"
    assert candidate["origin_ref"] == template_reference(template)
    assert candidate["copy_of_supplied_seed"] is False
    # A template output that equals a local canonical seed is recorded, not hidden.
    assert candidate["equals_canonical_seed_id"] is not None
    provenance = validated["payload_provenance"][candidate["candidate_id"]]
    assert provenance["origin_kind"] == "template_generation"
    assert "source_seed_id" not in provenance
    assert provenance["policy_version"] == PAYLOAD_POLICY_VERSION
    assert provenance["feasibility"]["status"] == template["feasibility"]["status"]


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


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda row: row.update(source_seed_id="not-a-real-seed"), "fabricated_source_seed_id"),
        (lambda row: row.update(visit_id="sqli_union:visit:0"), "stale_visit_candidate"),
        (lambda row: row.update(policy_version="payload-policy.v1"), "stale_payload_policy_version"),
        (lambda row: row.update(model_call_id="other-call"), "model_call_mismatch"),
        (lambda row: row.update(origin_ref={"template_id": "x"}), "incomplete_template_provenance"),
    ],
)
def test_template_provenance_gates_reject_invalid_candidates(mutate, reason):
    template = load_template("sqli_union", "low")
    row = {
        "candidate_id": "t1",
        "method": "sqli_union",
        "source": "llm_generated",
        "origin_kind": "template_generation",
        "origin_ref": template_reference(template),
        "mutation_type": TEMPLATE_MUTATION_TYPE,
        "payload_or_logic": "1' AND 1=2-- -",
        "target_param": "id",
        "expected_signal": "data_extraction_evidence",
        "stage": "exploit",
        "visit_id": "sqli_union:visit:1",
        "policy_version": PAYLOAD_POLICY_VERSION,
        "model_call_id": "call-template",
        "copy_of_supplied_seed": False,
    }
    mutate(row)
    state = _state(
        "sqli_union",
        "llm_template",
        payload_candidates={"sqli_union": [row]},
        generation_prompts=[_template_event(template)],
        model_call_requirements=[{
            "opportunity_id": "payload_generator:sqli_union:sqli_union:visit:1",
            "receipt_stage": "generation",
            "role": "payload_generator",
            "method": "sqli_union",
            "visit_id": "sqli_union:visit:1",
            "status": "completed",
            "call_id": "call-template",
        }],
    )
    update = validate_payload_candidates(state)

    assert update["payload_candidates"]["sqli_union"] == []
    assert any(
        row["reason"] == reason
        for row in update["payload_validation_results"]["sqli_union"]
    )


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


def test_static_probe_rows_never_consume_the_exploit_budget():
    seeds = PayloadLibrary().load_seed_candidates("sqli_union", "low")
    probe = next(row for row in seeds if row["stage"] == "probe")
    exploit = next(row for row in seeds if row["stage"] == "exploit")
    # A live queue row carries the visit/policy identity the builder stamps;
    # the probe row is injected raw to prove it is rejected as a control.
    live_exploit = payload_generator._stamp_static_candidates(
        "sqli_union", "low", "sqli_union:visit:1", [exploit],
    )[0]
    state = _state(
        "sqli_union",
        "static_only",
        candidate_budget=1,
        payload_candidates={"sqli_union": [probe, live_exploit]},
    )
    update = validate_payload_candidates(state)

    queue = update["payload_candidates"]["sqli_union"]
    assert [row["source_seed_id"] for row in queue] == [exploit["candidate_id"]]
    assert not any(
        row["candidate_id"] == probe["candidate_id"]
        for row in update["payload_validation_results"]["sqli_union"]
    )
    probe_lifecycle = [
        row for row in update["candidate_lifecycle"]
        if row["candidate_id"] == probe["candidate_id"]
    ]
    assert probe_lifecycle[0]["status"] == "rejected"
    assert probe_lifecycle[0]["reason"] == "probe_is_detection_control"


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


def test_static_only_records_a_not_required_generation_opportunity():
    built = build_payload_candidates(_state("sqli_union", "static_only"))
    opportunity = built["model_call_requirements"][0]
    assert opportunity["required"] is False
    assert opportunity["status"] == "not_required"
    assert opportunity["reason"] == "static_payload_mode"
    assert opportunity["call_id"] is None


def test_lifecycle_and_validation_receipt_cover_the_visit(monkeypatch):
    monkeypatch.setattr(
        payload_generator,
        "generate_llm_variants",
        _fake_mutation_generator("1' AnD 1=1-- -", "encoding"),
    )
    state = _state("sqli_union", "hybrid", candidate_budget=2)
    built = build_payload_candidates(state)
    validated = validate_payload_candidates({**state, **built})

    # The graph merges both append-only batches; the builder records generation,
    # the validator records validation, queueing, and budget decisions.
    generated_statuses = {row["status"] for row in built["candidate_lifecycle"]}
    validated_statuses = {row["status"] for row in validated["candidate_lifecycle"]}
    assert "generated" in generated_statuses
    assert {"valid", "queued"} <= validated_statuses
    receipts = validated["model_call_requirements"]
    assert [row["receipt_stage"] for row in receipts] == ["validation"]
    assert receipts[0]["opportunity_id"] == (
        "payload_generator:sqli_union:sqli_union:visit:1"
    )
    assert receipts[0]["parsed_candidate_ids"]
    assert receipts[0]["valid_candidate_ids"]


def test_legacy_probe_control_snapshot_still_validates(monkeypatch):
    canonical = [
        row for row in PayloadLibrary().load_seed_candidates("sqli_union", "low")
        if row["stage"] == "probe"
    ]
    from evaluation.scoring_evidence import evidence_hash

    snapshot = {
        "visit_id": "sqli_union:visit:1",
        "candidates": canonical,
        "sha256": evidence_hash(canonical),
    }
    state = _state("sqli_union", "hybrid")
    results = validate_probe_controls(state, snapshot)
    assert results and all(row["valid"] is True for row in results)

    tampered = {**snapshot, "candidates": canonical[:1], "sha256": evidence_hash(canonical[:1])}
    assert any(
        row["reason"] == "probe_control_catalog_mismatch"
        for row in validate_probe_controls(state, tampered)
    )


def test_versioned_probe_control_snapshot_delegates_to_catalog(monkeypatch):
    captured: dict[str, Any] = {}

    def validate_detection_controls(state, method, snapshot):
        captured.update({"method": method, "visit_id": snapshot.get("visit_id")})
        return [{"valid": True, "reason": "ok", "control_id": "c1"}]

    module = types.ModuleType("foundation.control_catalog")
    module.validate_detection_controls = validate_detection_controls
    module.freeze_detection_controls = lambda *args, **kwargs: {}
    monkeypatch.setitem(sys.modules, "foundation.control_catalog", module)

    snapshot = {
        "visit_id": "sqli_union:visit:1",
        "policy_version": CONTROL_POLICY_VERSION,
        "candidates": [],
    }
    results = validate_probe_controls(_state("sqli_union", "hybrid"), snapshot)
    assert results == [{"valid": True, "reason": "ok", "control_id": "c1"}]
    assert captured == {"method": "sqli_union", "visit_id": "sqli_union:visit:1"}


def test_control_catalog_failure_fails_closed(monkeypatch):
    def boom(*args: Any, **kwargs: Any):
        raise RuntimeError("catalog offline")

    module = types.ModuleType("foundation.control_catalog")
    module.freeze_detection_controls = boom
    module.validate_detection_controls = boom
    monkeypatch.setitem(sys.modules, "foundation.control_catalog", module)

    snapshot = freeze_probe_controls(_state("sqli_union", "hybrid"), "sqli_union", "sqli_union:visit:1")
    assert snapshot["candidates"] == []
    assert snapshot["policy_version"] == CONTROL_POLICY_VERSION
    assert snapshot["quarantined"] is False
    assert snapshot["validation_results"][0]["reason"] == "detection_control_freeze_failed"

    results = validate_probe_controls(
        _state("sqli_union", "hybrid"),
        {
            "visit_id": "sqli_union:visit:1",
            "policy_version": CONTROL_POLICY_VERSION,
            "candidates": [],
        },
    )
    assert results[0]["valid"] is False
    assert results[0]["reason"] == "detection_control_validation_failed"


def test_revisit_does_not_reuse_the_previous_visit_candidate(monkeypatch):
    monkeypatch.setattr(
        payload_generator,
        "generate_llm_variants",
        _fake_template_generator("1' UNION SELECT 1,2-- -"),
    )
    first_state = _state("sqli_union", "llm_template")
    first = validate_payload_candidates(
        {**first_state, **build_payload_candidates(first_state)}
    )
    first_id = first["payload_candidates"]["sqli_union"][0]["candidate_id"]

    second_state = _state(
        "sqli_union",
        "llm_template",
        selected_visit_id="sqli_union:visit:2",
        active_payload_candidates={
            "sqli_union": {
                "visit_id": "sqli_union:visit:2",
                "candidate_ids": [first_id],
                "status": "pending",
            }
        },
        payload_candidates={"sqli_union": first["payload_candidates"]["sqli_union"]},
    )
    second = validate_payload_candidates(second_state)

    assert second["payload_candidates"]["sqli_union"] == []
    events = {row["event"] for row in second.get("fallback_events", [])}
    assert "payload_validation.strict_no_candidate" in events or "payload_validation.no_usable_candidate" in events


def test_template_generation_prompt_is_deterministic():
    template = load_template("sqli_time_blind", "high")
    first = build_template_generation_prompt(template=template, observations=None, candidate_budget=1)
    second = build_template_generation_prompt(template=load_template("sqli_time_blind", "high"), observations=None, candidate_budget=1)
    assert first == second
    assert first.split("\nContext: ")[0].startswith("Construct exactly one")


def test_payload_schema_versions_come_from_policy():
    from llm import runtime

    assert runtime.PAYLOAD_SCHEMA_VERSION == "payload-variants.v3"
    assert runtime.PAYLOAD_TEMPLATE_SCHEMA_VERSION == "payload-template.v1"
