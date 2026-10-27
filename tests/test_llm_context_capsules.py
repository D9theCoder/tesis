"""Regression coverage for the compact, coordinate-local model inputs."""

from agents.orchestrator import _ORCHESTRATOR_SCHEMA, _decision_schema
from llm.prompts.payload_generation_prompt import build_payload_generation_prompt
from llm.prompts.orchestrator_prompt import build_orchestrator_prompt


def test_payload_capsule_drops_credential_observations_and_seed_rationale():
    prompt = build_payload_generation_prompt(
        method="sqli_union",
        security_level="low",
        observations={"sqli_endpoint_present": True, "credential_dump": "secret"},
        static_seeds=[{
            "candidate_id": "seed-1",
            "source_seed_id": "seed-1",
            "payload_or_logic": "seed",
            "target_param": "id",
            "expected_signal": "rows",
            "rationale": "long internal history",
            "raw_response": "never replay this",
        }],
        payload_profile={
            "allowed_mutation_types": ["case_variant"],
            "forbidden_mutation_types": ["external_target"],
            "expected_success_signals": ["rows"],
        },
        candidate_budget=1,
    )

    assert "credential_dump" not in prompt
    assert "secret" not in prompt
    assert "raw_response" not in prompt
    assert "long internal history" not in prompt
    assert '"variants"' in prompt
    assert '"source_seed_id":"seed-1"' in prompt


def test_orchestrator_native_schema_is_bound_to_current_allowed_methods():
    schema = _decision_schema({"sqli_union", "scorer"})
    assert schema["properties"]["next_agent"]["enum"] == ["scorer", "sqli_union"]
    assert "enum" not in _ORCHESTRATOR_SCHEMA["properties"]["next_agent"]


def test_payload_observations_change_only_after_shared_rules_and_seeds():
    kwargs = dict(method="sqli_union", security_level="low", candidate_budget=1,
        static_seeds=[{"source_seed_id": "seed", "stage": "exploit", "payload_or_logic": "seed"}],
        payload_profile={"allowed_mutation_types": ["case_variant"]})
    first = build_payload_generation_prompt(**kwargs, observations={"endpoint": True})
    second = build_payload_generation_prompt(**kwargs, observations={"endpoint": False})
    assert first.startswith("Choose an exploit or bypass seed")
    assert first.split('"observations":', 1)[0] == second.split('"observations":', 1)[0]
    assert first != second


def test_orchestrator_prompt_stays_deterministic_and_keeps_progress_at_end():
    kwargs = dict(current_surface="sqli", viable_methods=["sqli_union"], security_level="low",
        attempted_agents=[], blocked_agents=[], failure_agents=[], scores={},
        confirmed_vulns=[], achieved_outcomes=[], iteration_count=0, max_iterations=5)
    first = build_orchestrator_prompt(**kwargs, observations={"a": True, "b": False})
    reordered = build_orchestrator_prompt(**kwargs, observations={"b": False, "a": True})
    progressed = build_orchestrator_prompt(**{**kwargs, "iteration_count": 1},
        observations={"a": False})
    assert first == reordered
    assert first.startswith("Select one next_agent")
    assert first.split('"attempted_methods":', 1)[0] == progressed.split('"attempted_methods":', 1)[0]
    assert '"remaining_iterations":5' in first
    assert '"remaining_iterations":4' in progressed
