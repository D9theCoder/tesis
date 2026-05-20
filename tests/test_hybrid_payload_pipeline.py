"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from core.knowledge_graph import AttackKnowledgeGraph
from core.state import ALL_METHOD_AGENTS, new_default_state
from foundation.payload_generator import build_payload_candidates
from foundation.payload_library import PayloadLibrary
from foundation.payload_ranker import rank_candidates
from foundation.payload_validator import validate_payload_candidates
from agents.state_utils import payload_score_updates


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
