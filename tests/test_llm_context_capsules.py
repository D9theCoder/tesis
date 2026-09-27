"""Regression coverage for the compact, coordinate-local model inputs."""

from agents.orchestrator import _ORCHESTRATOR_SCHEMA, _decision_schema
from llm.prompts.payload_generation_prompt import build_payload_generation_prompt


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
