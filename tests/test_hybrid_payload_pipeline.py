"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
import json

import pytest

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import ALL_METHOD_AGENTS, new_default_state
from foundation.payload_generator import build_payload_candidates
from foundation.payload_generator import _filter_execution_ready_variants, _parse_candidates
from foundation.payload_library import PayloadLibrary
from foundation.payload_ranker import rank_candidates
from foundation.payload_validator import validate_payload_candidates
from agents.state_utils import candidate_payloads_for_stage, make_update, payload_score_updates
from llm.prompts.payload_generation_prompt import build_payload_generation_prompt


def test_all_methods_have_payload_profiles():
    """Verifies all methods have payload profiles behavior."""
    kg = AttackKnowledgeGraph()
    for method in ALL_METHOD_AGENTS:
        profile = kg.get_payload_profile(method)
        assert profile["seed_payload_refs"]
        assert profile["allowed_mutation_types"]
        assert profile["validation_rules"]
        assert profile["expected_success_signals"]
        assert profile["target_params"]
        assert profile["max_total_candidates"] >= len(profile["seed_payload_refs"])


def test_payload_library_loads_seed_candidates():
    """Verifies payload library loads seed candidates behavior."""
    seeds = PayloadLibrary().load_seed_candidates("sqli_union", "low")
    assert seeds
    assert seeds[0]["source"] == "static_seed"
    assert seeds[0]["method"] == "sqli_union"
    assert seeds[0]["target_param"] == "id"
    assert seeds[0]["candidate_id"]


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


@pytest.mark.parametrize("method,level", [
    ("ac_vertical_escalation", "medium"),
    ("ac_force_browse", "high"),
    ("bf_dictionary", "medium"),
])
def test_payload_library_deduplicates_reused_level_seeds(method, level):
    """Repeated bypass seeds are removed before validation."""
    seeds = PayloadLibrary().load_seed_candidates(method, level)
    payloads = [candidate["payload_or_logic"] for candidate in seeds]
    assert len(payloads) == len(set(payloads))


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


def test_rejected_generated_candidate_falls_back_to_static_seeds():
    """An invalid generated candidate must not leave the method without a safe queue."""
    seed = next(
        candidate
        for candidate in PayloadLibrary().load_seed_candidates("ac_force_browse", "low")
        if candidate["stage"] == "exploit"
    )
    generated = {
        **seed,
        "candidate_id": "generated-out-of-scope",
        "source": "llm_generated",
        "mutation_type": "path_normalization",
        "payload_or_logic": "vulnerabilities/../security.php",
    }
    update = validate_payload_candidates({
        **new_default_state(),
        "selected_method": "ac_force_browse",
        "payload_mode": "llm_mutation_only",
        "security_level": "low",
        "payload_candidates": {"ac_force_browse": [generated]},
    })

    assert any(
        row["reason"] == "out_of_scope_target"
        for row in update["payload_validation_results"]["ac_force_browse"]
    )
    assert update["payload_candidates"]["ac_force_browse"]
    assert all(
        candidate["source"] == "static_seed"
        for candidate in update["payload_candidates"]["ac_force_browse"]
    )
    assert update["fallback_events"][0]["event"] == "payload_validation.static_seed_fallback"


def test_unbounded_time_mutation_is_rejected_and_falls_back_to_static():
    """CPU-heavy BENCHMARK variants must not reach the DVWA HTTP client."""
    seed = next(
        candidate
        for candidate in PayloadLibrary().load_seed_candidates("sqli_time_blind", "low")
        if candidate["stage"] == "exploit"
    )
    generated = {
        **seed,
        "candidate_id": "generated-benchmark",
        "source": "llm_generated",
        "mutation_type": "delay_function_variant",
        "payload_or_logic": "1' AND BENCHMARK(5000000,SHA1('test'))-- -",
    }
    update = validate_payload_candidates({
        **new_default_state(),
        "selected_method": "sqli_time_blind",
        "payload_mode": "llm_mutation_only",
        "security_level": "low",
        "payload_candidates": {"sqli_time_blind": [generated]},
    })

    assert any(
        row["reason"] == "unsafe_resource_cost"
        for row in update["payload_validation_results"]["sqli_time_blind"]
    )
    assert update["fallback_events"][0]["reason"] == "no_valid_generated_candidates"
    assert all(
        candidate["source"] == "static_seed"
        for candidate in update["payload_candidates"]["sqli_time_blind"]
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
    seed = next(
        candidate
        for candidate in PayloadLibrary().load_seed_candidates("sqli_time_blind", "low")
        if candidate["stage"] == "exploit"
    )
    generated = {
        **seed,
        "candidate_id": "generated-unsafe-delay",
        "source": "llm_generated",
        "mutation_type": "delay_function_variant",
        "payload_or_logic": payload,
    }
    state = {
        **new_default_state(),
        "selected_method": "sqli_time_blind",
        "payload_mode": "llm_mutation_only",
        "security_level": "low",
        "payload_candidates": {"sqli_time_blind": [generated]},
    }

    update = validate_payload_candidates(state)

    assert any(
        row["candidate_id"] == generated["candidate_id"]
        and row["reason"] == "unsafe_resource_cost"
        for row in update["payload_validation_results"]["sqli_time_blind"]
    )
    assert payload not in candidate_payloads_for_stage(
        update, "sqli_time_blind", "low", "exploit"
    )


@pytest.mark.parametrize("security_level", ["low", "medium", "high"])
def test_bounded_time_blind_static_seeds_remain_executable(security_level):
    """The bounded handwritten SLEEP(3) seeds remain valid at every level."""
    seeds = PayloadLibrary().load_seed_candidates("sqli_time_blind", security_level)
    state = {
        **new_default_state(),
        "selected_method": "sqli_time_blind",
        "payload_mode": "llm_mutation_only",
        "security_level": security_level,
        "payload_candidates": {"sqli_time_blind": seeds},
    }

    update = validate_payload_candidates(state)
    valid_payloads = {
        candidate["payload_or_logic"]
        for candidate in update["payload_candidates"]["sqli_time_blind"]
    }
    probe_queue = candidate_payloads_for_stage(
        update, "sqli_time_blind", security_level, "probe"
    )
    exploit_queue = candidate_payloads_for_stage(
        update, "sqli_time_blind", security_level, "exploit"
    )

    assert valid_payloads
    assert "1' AND SLEEP(3)-- -" in probe_queue
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


def test_static_only_candidate_builder_does_not_generate_llm_candidates():
    """Verifies static only candidate builder does not generate llm candidates behavior."""
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "next_agent": "payload_candidate_builder",
        "payload_mode": "static_only",
        "security_level": "low",
    }
    update = build_payload_candidates(state)
    assert update["payload_candidates"]["sqli_union"]
    assert update["generated_payloads"]["sqli_union"] == []
    assert update["generation_prompts"] == []


def test_hybrid_candidate_builder_marks_generated_candidates_as_exploit_stage():
    """Verifies hybrid candidate builder marks generated candidates as exploit stage behavior."""
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "next_agent": "payload_candidate_builder",
        "payload_mode": "hybrid",
        "security_level": "low",
    }
    update = build_payload_candidates(state)
    generated = update["generated_payloads"]["sqli_union"]
    assert all(candidate["stage"] == "exploit" for candidate in generated)


def test_llm_mutation_only_uses_logged_static_fallback_for_invalid_json(monkeypatch):
    """Malformed model output never produces an empty, unaccounted execution path."""
    monkeypatch.setattr(
        "foundation.payload_generator.generate_llm_variants",
        lambda **_kwargs: ([], {"fallback_reason": "invalid_json", "provider": "offline"}, []),
    )
    update = build_payload_candidates({
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_mode": "llm_mutation_only",
        "security_level": "low",
    })

    assert update["payload_candidates"]["sqli_union"]
    assert all(item["source"] == "static_seed" for item in update["payload_candidates"]["sqli_union"])
    assert update["fallback_events"] == [{
        "event": "payload_generation.static_seed_fallback",
        "method": "sqli_union",
        "payload_mode": "llm_mutation_only",
        "reason": "invalid_json",
    }]
    assert update["invalid_json_events"] == [{
        "event": "payload_generation.invalid_json",
        "method": "sqli_union",
        "provider": "gemini",
    }]


def test_payload_generation_guardrail_is_preserved_in_run_guardrail_events(monkeypatch):
    """Payload-level refusals are visible in the canonical artifact telemetry."""
    guardrail = {"event": "guardrail.activation", "context": "payload_generation"}
    monkeypatch.setattr(
        "foundation.payload_generator.generate_llm_variants",
        lambda **_kwargs: ([], {"fallback_reason": "guardrail_refusal"}, [guardrail]),
    )
    update = build_payload_candidates({
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_mode": "hybrid",
        "security_level": "low",
    })

    assert update["payload_guardrail_activations"] == [guardrail]
    assert update["guardrail_activations"] == [guardrail]
    assert update["fallback_events"][0]["reason"] == "guardrail_refusal"


def test_validator_rejects_wrong_target_param_and_keeps_valid_seed():
    """Verifies validator rejects wrong target param and keeps valid seed behavior."""
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_candidates": {
            "sqli_union": [
                {
                    "candidate_id": "bad",
                    "source_seed_id": "seed",
                    "source": "llm_generated",
                    "method": "sqli_union",
                    "mutation_type": "encoding",
                    "payload_or_logic": "1' UNION SELECT user,password FROM users-- -",
                    "target_param": "username",
                    "expected_signal": "data_extraction_evidence",
                },
                PayloadLibrary().load_seed_candidates("sqli_union", "low")[0],
            ]
        },
    }
    update = validate_payload_candidates(state)
    results = update["payload_validation_results"]["sqli_union"]
    assert any(row["reason"] == "wrong_target_param" for row in results)
    assert update["payload_candidates"]["sqli_union"][0]["source"] == "static_seed"


def test_validator_rejects_brute_payload_without_credential_pair():
    """Brute-force candidates must contain an executable credential prefix."""
    seed = PayloadLibrary().load_seed_candidates("bf_spray", "high")[0]
    candidate = {
        **seed,
        "candidate_id": "invalid-credential-logic",
        "source": "llm_generated",
        "source_seed_id": seed["candidate_id"],
        "mutation_type": AttackKnowledgeGraph().get_payload_profile("bf_spray")["allowed_mutation_types"][0],
        "payload_or_logic": "wait 8-12s between attempts",
    }
    update = validate_payload_candidates({
        **new_default_state(),
        "selected_method": "bf_spray",
        "security_level": "high",
        "payload_candidates": {"bf_spray": [candidate]},
    })
    assert update["payload_candidates"]["bf_spray"] == []
    assert update["payload_validation_results"]["bf_spray"][0]["reason"] == "invalid_credential_pair"


def test_validator_rejects_generated_candidates_without_seed_provenance():
    """Verifies validator rejects generated candidates without seed provenance behavior."""
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_candidates": {
            "sqli_union": [
                {
                    "candidate_id": "gen-1",
                    "source": "llm_generated",
                    "source_seed_id": "",
                    "method": "sqli_union",
                    "mutation_type": "encoding",
                    "payload_or_logic": "1' UNION SELECT user,password FROM users-- -",
                    "target_param": "id",
                    "expected_signal": "data_extraction_evidence",
                },
                PayloadLibrary().load_seed_candidates("sqli_union", "low")[0],
            ]
        },
    }
    update = validate_payload_candidates(state)
    results = update["payload_validation_results"]["sqli_union"]
    assert any(row["reason"] == "missing_source_seed_id" for row in results)


def test_validator_accepts_canonical_generated_candidate_in_llm_mutation_only():
    """Canonical static seed provenance remains valid when seeds are omitted from execution candidates."""
    seed = PayloadLibrary().load_seed_candidates("sqli_union", "low")[0]
    profile = AttackKnowledgeGraph().get_payload_profile("sqli_union")
    generated = {
        **seed,
        "candidate_id": "generated-1",
        "source": "llm_generated",
        "mutation_type": profile["allowed_mutation_types"][0],
    }
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_mode": "llm_mutation_only",
        "security_level": "low",
        "payload_candidates": {"sqli_union": [generated]},
    }

    update = validate_payload_candidates(state)

    assert [candidate["candidate_id"] for candidate in update["payload_candidates"]["sqli_union"]] == ["generated-1"]
    assert update["payload_validation_results"]["sqli_union"][-1]["reason"] == "ok"


def test_validator_rejects_unlisted_generated_mutation_type():
    """Generated candidates must use an AKG-allowed mutation type."""
    seed = PayloadLibrary().load_seed_candidates("sqli_union", "low")[0]
    generated = {
        **seed,
        "candidate_id": "generated-unsupported-mutation",
        "source": "llm_generated",
        "mutation_type": "unlisted_mutation",
    }
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_mode": "llm_mutation_only",
        "security_level": "low",
        "payload_candidates": {"sqli_union": [generated]},
    }

    update = validate_payload_candidates(state)

    assert any(
        row["reason"] == "mutation_type_not_allowed"
        for row in update["payload_validation_results"]["sqli_union"]
    )
    assert update["payload_candidates"]["sqli_union"]
    assert all(
        candidate["source"] == "static_seed"
        for candidate in update["payload_candidates"]["sqli_union"]
    )
    assert update["fallback_events"][0]["event"] == "payload_validation.static_seed_fallback"


@pytest.mark.parametrize("external_value", ["//example.invalid/escape", "../../setup.php", "..\\\\setup.php"])
def test_validator_rejects_external_or_traversal_payloads(external_value):
    """Payload validation blocks external targets and base-path escapes."""
    seed = PayloadLibrary().load_seed_candidates("ac_force_browse", "low")[0]
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


def test_validator_allows_escaped_sql_quote_seed():
    """SQL escape syntax is not an external target or path traversal."""
    seed = next(
        candidate
        for candidate in PayloadLibrary().load_seed_candidates("sqli_error", "low")
        if candidate["payload_or_logic"] == "1\\'"
    )
    update = validate_payload_candidates({
        **new_default_state(),
        "selected_method": "sqli_error",
        "security_level": "low",
        "payload_candidates": {"sqli_error": [seed]},
    })
    assert update["payload_validation_results"]["sqli_error"] == [
        {"valid": True, "reason": "ok", "candidate_id": seed["candidate_id"]}
    ]


def test_validator_rejects_duplicate_payload_strings():
    """Verifies validator rejects duplicate payload strings behavior."""
    seed = PayloadLibrary().load_seed_candidates("sqli_union", "low")[0]
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_candidates": {
            "sqli_union": [
                seed,
                {
                    **seed,
                    "candidate_id": "dup-1",
                    "source": "llm_generated",
                    "source_seed_id": seed["candidate_id"],
                    "mutation_type": "encoding",
                },
            ]
        },
    }
    update = validate_payload_candidates(state)
    results = update["payload_validation_results"]["sqli_union"]
    assert any(row["reason"] == "duplicate_payload_or_logic" for row in results)
    assert len(update["payload_candidates"]["sqli_union"]) == 1


def test_payload_score_updates_only_attempted_candidates():
    """Verifies payload score updates only attempted candidates behavior."""
    state = {
        **new_default_state(),
        "tried_payloads": {"sqli_union": ["1' UNION SELECT user,password FROM users-- -"]},
        "payload_candidates": {
            "sqli_union": [
                {
                    "candidate_id": "seed-1",
                    "payload_or_logic": "1' UNION SELECT user,password FROM users-- -",
                },
                {
                    "candidate_id": "seed-2",
                    "payload_or_logic": "1' AND 1=1-- -",
                },
            ]
        },
    }
    updates = payload_score_updates(state, "sqli_union", 3)
    assert updates["seed-1"] == 3
    assert "seed-2" not in updates


def test_make_update_scores_current_invocation_candidates():
    """The first method invocation must score payloads in the returned update."""
    state = {
        **new_default_state(),
        "payload_candidates": {
            "sqli_union": [
                {
                    "candidate_id": "current-1",
                    "payload_or_logic": "1' UNION SELECT user,password FROM users-- -",
                }
            ]
        },
    }

    update = make_update(
        state=state,
        module_name="sqli_union",
        score=3,
        tried_payloads=["1' UNION SELECT user,password FROM users-- -"],
    )

    assert update["payload_scores"] == {"current-1": 3}


def test_rank_candidates_seed_first_and_budgeted():
    """Verifies rank candidates seed first and budgeted behavior."""
    ranked = rank_candidates(
        [
            {"candidate_id": "z", "source": "llm_generated"},
            {"candidate_id": "a", "source": "static_seed"},
            {"candidate_id": "b", "source": "static_seed"},
        ],
        max_total=2,
    )
    assert [item["candidate_id"] for item in ranked] == ["a", "b"]
