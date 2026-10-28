"""Regression tests for the DVWA payload pipeline.

This module verifies current behavior for state handling, payload generation,
validation, and mode-aware fallback semantics without running providers or HTTP.
"""
import json
from typing import Any

import pytest

from agents.state_utils import candidate_payloads_for_stage
from core.knowledge_graph import AttackKnowledgeGraph
from core.payload_policy import PAYLOAD_POLICY_VERSION
from core.state import new_default_state
from foundation.payload_generator import (
    _filter_execution_ready_variants,
    _parse_candidates,
    _stamp_static_candidates,
    build_payload_candidates,
)
from foundation.payload_library import PayloadLibrary
from foundation.payload_ranker import rank_candidates
from foundation.payload_validator import validate_candidate, validate_payload_candidates
from llm.prompts.payload_generation_prompt import build_payload_generation_prompt


def _exploit_seed(method: str, security_level: str = "low") -> dict[str, Any]:
    return next(
        candidate
        for candidate in PayloadLibrary().load_seed_candidates(method, security_level)
        if candidate["stage"] in {"exploit", "bypass"}
    )


def _live_static(method: str, level: str = "low", visit: str | None = None) -> list[dict[str, Any]]:
    visit = visit or f"{method}:visit:1"
    seeds = [
        candidate for candidate in PayloadLibrary().load_seed_candidates(method, level)
        if candidate["stage"] in {"exploit", "bypass"}
    ]
    return _stamp_static_candidates(method, level, visit, seeds)


def _strict_state(
    method: str, mode: str = "llm_mutation_only", **overrides: Any
) -> dict[str, Any]:
    return {
        **new_default_state(),
        "selected_method": method,
        "payload_mode": mode,
        "security_level": "low",
        "selected_visit_id": f"{method}:visit:1",
        **overrides,
    }


def test_compact_variant_is_enriched_with_deterministic_provenance():
    seeds = PayloadLibrary().load_seed_candidates("sqli_union", "low")
    source = seeds[0]
    raw = {
        "variants": [{
            "source_seed_id": source["candidate_id"],
            "mutation_type": "case_variant",
            "payload_or_logic": "1' UnIoN SeLeCt null,null-- -",
        }]
    }
    candidates, status = _parse_candidates(
        json.dumps(raw),
        "sqli_union",
        seeds=seeds,
        profile=AttackKnowledgeGraph().get_payload_profile("sqli_union"),
    )

    assert status == "ok"
    assert candidates[0]["candidate_id"].startswith("sqli_union_llm_0_")
    assert candidates[0]["source"] == "llm_generated"
    assert candidates[0]["method"] == "sqli_union"
    assert candidates[0]["stage"] == "exploit"
    assert candidates[0]["target_param"] == source["target_param"]
    assert candidates[0]["expected_signal"] == source["expected_signal"]


def test_payload_generation_prompt_exposes_execution_ready_seeds():
    """Mutation prompts must not present a detection probe as the exploit seed."""
    seeds = PayloadLibrary().load_seed_candidates("sqli_union", "medium")
    prompt = build_payload_generation_prompt(
        method="sqli_union",
        security_level="medium",
        observations={},
        static_seeds=seeds,
        payload_profile=AttackKnowledgeGraph().get_payload_profile("sqli_union"),
        candidate_budget=1,
    )
    capsule = json.loads(prompt.split("Context: ", 1)[1].split("\n", 1)[0])
    compact_seeds = capsule["static_seeds"]

    assert compact_seeds
    assert all(seed["stage"] in {"exploit", "bypass"} for seed in compact_seeds)
    assert "sqli_union_medium_probe_0" not in {
        seed["source_seed_id"] for seed in compact_seeds
    }


def test_generated_probe_seed_is_rejected_from_exploit_execution():
    """Probe provenance cannot silently become an executable exploit variant."""
    seeds = PayloadLibrary().load_seed_candidates("sqli_union", "medium")
    probe_seed = next(seed for seed in seeds if seed["stage"] == "probe")
    exploit_seed = next(seed for seed in seeds if seed["stage"] in {"exploit", "bypass"})
    candidates = [
        {"source_seed_id": probe_seed["candidate_id"]},
        {"source_seed_id": exploit_seed["candidate_id"]},
    ]

    accepted, rejected_count = _filter_execution_ready_variants(candidates, seeds)

    assert accepted == [candidates[1]]
    assert rejected_count == 1


def test_strict_mode_rejected_generated_candidate_queues_nothing():
    """An out-of-scope model candidate never revives a static seed."""
    seed = _exploit_seed("ac_force_browse")
    generated = {
        **seed,
        "candidate_id": "generated-out-of-scope",
        "source": "llm_generated",
        "origin_kind": "seed_mutation",
        "visit_id": "ac_force_browse:visit:1",
        "policy_version": PAYLOAD_POLICY_VERSION,
        "mutation_type": "path_normalization",
        "payload_or_logic": "vulnerabilities/../security.php",
    }
    update = validate_payload_candidates(
        _strict_state(
            "ac_force_browse",
            payload_candidates={"ac_force_browse": [generated]},
        )
    )

    assert any(
        row["reason"] == "out_of_scope_target"
        for row in update["payload_validation_results"]["ac_force_browse"]
    )
    assert update["payload_candidates"]["ac_force_browse"] == []
    events = [row["event"] for row in update["fallback_events"]]
    assert "payload_validation.strict_no_candidate" in events
    assert "payload_generation.static_seed_fallback" not in events


def test_hybrid_rejected_generated_candidate_keeps_validated_static_seed():
    """Hybrid keeps its documented static coverage and records the reason."""
    seed = _exploit_seed("ac_force_browse")
    static_rows = _live_static("ac_force_browse")
    generated = {
        **seed,
        "candidate_id": "generated-out-of-scope",
        "source": "llm_generated",
        "origin_kind": "seed_mutation",
        "visit_id": "ac_force_browse:visit:1",
        "policy_version": PAYLOAD_POLICY_VERSION,
        "mutation_type": "path_normalization",
        "payload_or_logic": "vulnerabilities/../security.php",
    }
    update = validate_payload_candidates({
        **new_default_state(),
        "selected_method": "ac_force_browse",
        "payload_mode": "hybrid",
        "security_level": "low",
        "selected_visit_id": "ac_force_browse:visit:1",
        "payload_candidates": {"ac_force_browse": [generated, *static_rows]},
    })

    queue = update["payload_candidates"]["ac_force_browse"]
    # Hybrid keeps its validated static coverage: the rejected model candidate
    # cannot remove any valid static seed from the queue.
    assert queue
    assert seed["candidate_id"] in {candidate["source_seed_id"] for candidate in queue}
    assert all(candidate["origin_kind"] == "static_seed" for candidate in queue)
    fallback = [
        row for row in update["fallback_events"]
        if row["event"] == "payload_generation.static_seed_fallback"
    ]
    assert fallback
    assert fallback[0]["candidate_ids"] == [candidate["candidate_id"] for candidate in queue]
    assert fallback[0]["origin_kind"] == "static_seed"
    assert fallback[0]["visit_id"] is None or isinstance(fallback[0]["visit_id"], str)


def test_unbounded_time_mutation_is_rejected_without_static_fallback():
    """CPU-heavy BENCHMARK variants must not reach the DVWA HTTP client."""
    seed = _exploit_seed("sqli_time_blind")
    generated = {
        **seed,
        "candidate_id": "generated-benchmark",
        "source": "llm_generated",
        "origin_kind": "seed_mutation",
        "visit_id": "sqli_time_blind:visit:1",
        "policy_version": PAYLOAD_POLICY_VERSION,
        "mutation_type": "delay_function_variant",
        "payload_or_logic": "1' AND BENCHMARK(5000000,SHA1('test'))-- -",
    }
    update = validate_payload_candidates(
        _strict_state(
            "sqli_time_blind",
            payload_candidates={"sqli_time_blind": [generated]},
        )
    )

    assert any(
        row["reason"] == "unsafe_resource_cost"
        for row in update["payload_validation_results"]["sqli_time_blind"]
    )
    assert update["payload_candidates"]["sqli_time_blind"] == []
    assert all(
        row["event"] != "payload_generation.static_seed_fallback"
        for row in update["fallback_events"]
    )


@pytest.mark.parametrize("payload", [
    "1 AND BENCHMARK/**/(5000000,SHA1('test'))",
    "1 AND SLEEP/**/(100)#",
    "1 AND SLEEP(0x100)#",
    "1 AND SLEEP(1e3)#",
    "1 AND %2553LEEP(100)#",
])
def test_obfuscated_or_opaque_delay_mutations_never_enter_http_queue(payload):
    """Delay-function obfuscation cannot bypass pre-HTTP validation."""
    seed = _exploit_seed("sqli_time_blind")
    generated = {
        **seed,
        "candidate_id": "generated-unsafe-delay",
        "source": "llm_generated",
        "origin_kind": "seed_mutation",
        "mutation_type": "delay_function_variant",
        "payload_or_logic": payload,
    }
    update = validate_payload_candidates(
        _strict_state(
            "sqli_time_blind",
            payload_candidates={"sqli_time_blind": [generated]},
        )
    )

    assert any(
        row["candidate_id"] == generated["candidate_id"]
        and row["reason"] == "unsafe_resource_cost"
        for row in update["payload_validation_results"]["sqli_time_blind"]
    )
    assert payload not in candidate_payloads_for_stage(
        {**update, "active_payload_candidates": {}}, "sqli_time_blind", "low", "exploit"
    )


@pytest.mark.parametrize("security_level", ["low", "medium", "high"])
def test_bounded_time_blind_static_seeds_remain_executable(security_level):
    """The bounded handwritten SLEEP(3) seeds remain valid at every level."""
    visit = "sqli_time_blind:visit:1"
    seeds = _live_static("sqli_time_blind", security_level, visit)
    state = {
        **new_default_state(),
        "selected_method": "sqli_time_blind",
        "payload_mode": "hybrid",
        "security_level": security_level,
        "selected_visit_id": visit,
        "payload_candidates": {"sqli_time_blind": seeds},
    }

    update = validate_payload_candidates(state)
    exploit_queue = candidate_payloads_for_stage(
        update, "sqli_time_blind", security_level, "exploit"
    )

    assert update["payload_candidates"]["sqli_time_blind"]
    assert any("SLEEP(3)" in payload for payload in exploit_queue)
    assert not any(
        row.get("reason") == "unsafe_resource_cost"
        for row in update["payload_validation_results"]["sqli_time_blind"]
        if row.get("valid") is not True
    )


def test_method_queue_uses_only_validated_candidate_ids():
    """Accumulated rejected candidates remain audit data, never execution data."""
    seed = PayloadLibrary().load_seed_candidates("sqli_union", "low")[0]
    safe = {
        **seed,
        "candidate_id": "safe-candidate",
        "stage": "exploit",
        "payload_or_logic": "1 UNION SELECT user,password FROM users-- -",
    }
    blocked = {**safe, "candidate_id": "blocked-candidate", "payload_or_logic": "//external.invalid"}
    state = {
        **new_default_state(),
        "payload_candidates": {"sqli_union": [blocked, safe]},
        "payload_validation_results": {
            "sqli_union": [
                {"candidate_id": "blocked-candidate", "valid": False, "reason": "out_of_scope_target"},
                {"candidate_id": "safe-candidate", "valid": True, "reason": "ok"},
            ],
        },
    }

    assert candidate_payloads_for_stage(state, "sqli_union", "low", "exploit") == [
        safe["payload_or_logic"]
    ]


def test_method_queue_stays_empty_after_all_candidates_are_rejected():
    """A completed validation pass cannot revive rejected history via static fallback."""
    seed = PayloadLibrary().load_seed_candidates("sqli_union", "low")[0]
    blocked = {**seed, "candidate_id": "blocked-candidate", "payload_or_logic": "//external.invalid"}
    state = {
        **new_default_state(),
        "payload_candidates": {"sqli_union": [blocked]},
        "payload_validation_results": {
            "sqli_union": [{
                "candidate_id": "blocked-candidate",
                "valid": False,
                "reason": "out_of_scope_target",
            }],
        },
    }

    assert candidate_payloads_for_stage(state, "sqli_union", "low", "probe") == []
    assert candidate_payloads_for_stage(state, "sqli_union", "low", "exploit") == []


def test_strict_invalid_json_never_queues_static_seeds(monkeypatch):
    """Malformed model output in a strict mode is an explicit no-candidate stop."""
    monkeypatch.setattr(
        "foundation.payload_generator.generate_llm_variants",
        lambda **_kwargs: ([], {"failure_reason": "invalid_json", "provider": "offline"}, []),
    )
    update = build_payload_candidates(_strict_state("sqli_union"))

    assert update["payload_candidates"]["sqli_union"] == []
    events = update["fallback_events"]
    assert any(row["event"] == "payload_generation.strict_no_candidate" for row in events)
    assert any(row["reason"] == "invalid_json" for row in events)
    assert all(row["event"] != "payload_generation.static_seed_fallback" for row in events)
    opportunity = update["model_call_requirements"][0]
    assert opportunity["role"] == "payload_generator"
    assert opportunity["required"] is True
    assert opportunity["status"] == "failed"
    assert opportunity["reason"] == "invalid_json"
    assert opportunity["receipt_stage"] == "generation"


def test_hybrid_generation_failure_keeps_static_coverage(monkeypatch):
    """Hybrid still supplies validated static seeds when generation fails."""
    monkeypatch.setattr(
        "foundation.payload_generator.generate_llm_variants",
        lambda **kwargs: ([], {
            "failure_reason": "invalid_json",
            "provider": "offline",
            "method": "sqli_union",
            "visit_id": kwargs["state"]["selected_visit_id"],
        }, []),
    )
    state = _strict_state("sqli_union", mode="hybrid")
    built = build_payload_candidates(state)
    validated = validate_payload_candidates({**state, **built})

    assert validated["payload_candidates"]["sqli_union"]
    assert all(
        candidate["origin_kind"] == "static_seed"
        for candidate in validated["payload_candidates"]["sqli_union"]
    )
    fallback = [
        row for row in validated["fallback_events"]
        if row["event"] == "payload_generation.static_seed_fallback"
    ]
    assert fallback
    assert fallback[0]["reason"] == "invalid_json"
    assert fallback[0]["candidate_ids"]


def test_payload_generation_guardrail_is_preserved_in_run_guardrail_events(monkeypatch):
    """Payload-level refusals are visible in the canonical artifact telemetry."""
    guardrail = {"event": "guardrail.activation", "context": "payload_generation"}
    monkeypatch.setattr(
        "foundation.payload_generator.generate_llm_variants",
        lambda **kwargs: ([], {
            "failure_reason": "guardrail_refusal",
            "method": "sqli_union",
            "visit_id": kwargs["state"]["selected_visit_id"],
        }, [guardrail]),
    )
    state = _strict_state("sqli_union", mode="hybrid")
    built = build_payload_candidates(state)

    assert built["payload_guardrail_activations"] == [guardrail]
    assert built["guardrail_activations"] == [guardrail]
    validated = validate_payload_candidates({**state, **built})
    fallback = [
        row for row in validated["fallback_events"]
        if row["event"] == "payload_generation.static_seed_fallback"
    ]
    assert fallback[0]["reason"] == "guardrail_refusal"


def test_validator_rejects_wrong_target_param_and_keeps_valid_seed():
    """A wrong parameter is rejected while a valid static seed stays queued."""
    seed = _exploit_seed("sqli_union")
    live_seed = _live_static("sqli_union")[0]
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_mode": "hybrid",
        "selected_visit_id": "sqli_union:visit:1",
        "payload_candidates": {
            "sqli_union": [
                {
                    "candidate_id": "bad",
                    "source_seed_id": seed["candidate_id"],
                    "source": "llm_generated",
                    "origin_kind": "seed_mutation",
                    "visit_id": "sqli_union:visit:1",
                    "policy_version": PAYLOAD_POLICY_VERSION,
                    "method": "sqli_union",
                    "mutation_type": "encoding",
                    "payload_or_logic": "1' UNION SELECT user,password FROM users-- -",
                    "target_param": "username",
                    "expected_signal": "data_extraction_evidence",
                },
                live_seed,
            ]
        },
    }
    update = validate_payload_candidates(state)
    results = update["payload_validation_results"]["sqli_union"]
    assert any(row["reason"] == "wrong_target_param" for row in results)
    assert update["payload_candidates"]["sqli_union"][0]["source"] == "static_seed"


def test_validator_rejects_brute_payload_without_credential_pair():
    """Brute-force candidates must contain an executable credential prefix."""
    seed = _exploit_seed("bf_spray", "high")
    candidate = {
        **seed,
        "candidate_id": "invalid-credential-logic",
        "source": "llm_generated",
        "origin_kind": "seed_mutation",
        "source_seed_id": seed["candidate_id"],
        "mutation_type": AttackKnowledgeGraph().get_payload_profile("bf_spray")["allowed_mutation_types"][0],
        "payload_or_logic": "wait 8-12s between attempts",
    }
    update = validate_payload_candidates({
        **new_default_state(),
        "selected_method": "bf_spray",
        "payload_mode": "llm_mutation_only",
        "security_level": "high",
        "payload_candidates": {"bf_spray": [candidate]},
    })
    assert update["payload_candidates"]["bf_spray"] == []
    assert update["payload_validation_results"]["bf_spray"][0]["reason"] == "invalid_credential_pair"


def test_validator_rejects_generated_candidates_without_seed_provenance():
    """Seed-origin candidates must bind a real canonical seed id."""
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_mode": "llm_mutation_only",
        "selected_visit_id": "sqli_union:visit:1",
        "payload_candidates": {
            "sqli_union": [
                {
                    "candidate_id": "gen-1",
                    "source": "llm_generated",
                    "origin_kind": "seed_mutation",
                    "visit_id": "sqli_union:visit:1",
                    "policy_version": PAYLOAD_POLICY_VERSION,
                    "source_seed_id": "",
                    "method": "sqli_union",
                    "mutation_type": "encoding",
                    "payload_or_logic": "1' UNION SELECT user,password FROM users-- -",
                    "target_param": "id",
                    "expected_signal": "data_extraction_evidence",
                },
            ]
        },
    }
    update = validate_payload_candidates(state)
    results = update["payload_validation_results"]["sqli_union"]
    assert any(row["reason"] == "missing_source_seed_id" for row in results)


def test_validator_accepts_canonical_generated_candidate_in_llm_mutation_only():
    """A model variant bound to a supplied exploit seed is queueable."""
    seed = _exploit_seed("sqli_union")
    profile = AttackKnowledgeGraph().get_payload_profile("sqli_union")
    generated = {
        **seed,
        "candidate_id": "generated-1",
        "source": "llm_generated",
        "origin_kind": "seed_mutation",
        "visit_id": "sqli_union:visit:1",
        "policy_version": PAYLOAD_POLICY_VERSION,
        "source_seed_id": seed["candidate_id"],
        "model_call_id": "call-generated",
        "mutation_type": profile["allowed_mutation_types"][0],
    }
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_mode": "llm_mutation_only",
        "security_level": "low",
        "selected_visit_id": "sqli_union:visit:1",
        "generation_prompts": [{
            "method": "sqli_union", "visit_id": "sqli_union:visit:1", "call_id": "call-generated",
            "prompt_visible_seed_ids": [seed["candidate_id"]],
        }],
        "model_call_requirements": [{
            "role": "payload_generator", "method": "sqli_union",
            "visit_id": "sqli_union:visit:1", "status": "completed",
            "call_id": "call-generated",
        }],
        "payload_candidates": {"sqli_union": [generated]},
    }

    update = validate_payload_candidates(state)

    assert [candidate["candidate_id"] for candidate in update["payload_candidates"]["sqli_union"]] == ["generated-1"]
    assert update["payload_validation_results"]["sqli_union"][-1]["reason"] == "ok"
    assert update["payload_provenance"]["generated-1"]["origin_kind"] == "seed_mutation"


def test_validator_rejects_unlisted_generated_mutation_type():
    """Generated candidates must use an AKG-allowed mutation type."""
    seed = _exploit_seed("sqli_union")
    generated = {
        **seed,
        "candidate_id": "generated-unsupported-mutation",
        "source": "llm_generated",
        "origin_kind": "seed_mutation",
        "visit_id": "sqli_union:visit:1",
        "policy_version": PAYLOAD_POLICY_VERSION,
        "mutation_type": "unlisted_mutation",
    }
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_mode": "llm_mutation_only",
        "security_level": "low",
        "selected_visit_id": "sqli_union:visit:1",
        "generation_prompts": [{
            "method": "sqli_union", "visit_id": "sqli_union:visit:1",
            "prompt_visible_seed_ids": [seed["candidate_id"]],
        }],
        "payload_candidates": {"sqli_union": [generated]},
    }

    update = validate_payload_candidates(state)

    assert any(
        row["reason"] == "mutation_type_not_allowed"
        for row in update["payload_validation_results"]["sqli_union"]
    )
    assert update["payload_candidates"]["sqli_union"] == []
    assert all(
        row["event"] != "payload_generation.static_seed_fallback"
        for row in update["fallback_events"]
    )


@pytest.mark.parametrize("external_value", ["//example.invalid/escape", "../../setup.php", "..\\\\setup.php"])
def test_validator_rejects_external_or_traversal_payloads(external_value):
    """Payload validation blocks external targets and base-path escapes."""
    seed = _exploit_seed("ac_force_browse", "low")
    candidate = {**seed, "candidate_id": f"blocked-{external_value}", "payload_or_logic": external_value}
    state = {
        **new_default_state(),
        "selected_method": "ac_force_browse",
        "security_level": "low",
        "payload_candidates": {"ac_force_browse": [candidate]},
    }
    update = validate_payload_candidates(state)
    assert update["payload_candidates"]["ac_force_browse"] == []
    assert update["payload_validation_results"]["ac_force_browse"][0]["reason"] == "out_of_scope_target"


def test_containment_allows_escaped_sql_quote_syntax():
    """SQL escape syntax is not an external target or path traversal."""
    from foundation.payload_validator import _is_out_of_scope

    assert _is_out_of_scope("1\\'") is False
    assert _is_out_of_scope("//external.invalid/escape") is True
    assert _is_out_of_scope("../../setup.php") is True


def test_validator_rejects_duplicate_payload_strings():
    """A duplicate of an already-validated payload is rejected, not executed twice."""
    seed = _exploit_seed("sqli_union")
    live_seed = _live_static("sqli_union")[0]
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_mode": "hybrid",
        "selected_visit_id": "sqli_union:visit:1",
        "generation_prompts": [{
            "method": "sqli_union", "visit_id": "sqli_union:visit:1",
            "call_id": "call-dup",
            "prompt_visible_seed_ids": [seed["candidate_id"]],
        }],
        "model_call_requirements": [{
            "opportunity_id": "payload_generator:sqli_union:sqli_union:visit:1",
            "receipt_stage": "generation", "role": "payload_generator",
            "method": "sqli_union", "visit_id": "sqli_union:visit:1",
            "status": "completed", "call_id": "call-dup",
        }],
        "payload_candidates": {
            "sqli_union": [
                live_seed,
                {
                    **live_seed,
                    "candidate_id": "dup-1",
                    "source": "llm_generated",
                    "origin_kind": "seed_mutation",
                    "source_seed_id": seed["candidate_id"],
                    "model_call_id": "call-dup",
                    "prompt_id": "payload_generation.constrained_variant",
                    "schema_version": "payload-variants.v3",
                    "mutation_type": "encoding",
                    "visit_id": "sqli_union:visit:1",
                    "policy_version": PAYLOAD_POLICY_VERSION,
                },
            ]
        },
    }
    update = validate_payload_candidates(state)
    results = update["payload_validation_results"]["sqli_union"]
    assert any(row["reason"] == "duplicate_payload_or_logic" for row in results)
    assert len(update["payload_candidates"]["sqli_union"]) == 1


def test_rank_candidates_seed_first_and_budgeted():
    """Static and chain-derived origins rank ahead of model candidates."""
    ranked = rank_candidates(
        [
            {"candidate_id": "z", "origin_kind": "seed_mutation"},
            {"candidate_id": "a", "origin_kind": "static_seed"},
            {"candidate_id": "b", "origin_kind": "chain_derived"},
        ],
        max_total=2,
    )
    assert [item["candidate_id"] for item in ranked] == ["b", "a"]
