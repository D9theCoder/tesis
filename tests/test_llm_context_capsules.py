"""Regression coverage for the compact, coordinate-local model inputs."""

from agents.orchestrator import _ORCHESTRATOR_SCHEMA, _decision_schema


def test_orchestrator_native_schema_is_bound_to_current_allowed_methods():
    schema = _decision_schema({"sqli_union", "scorer"})
    assert schema["properties"]["next_agent"]["enum"] == ["scorer", "sqli_union"]
    assert "enum" not in _ORCHESTRATOR_SCHEMA["properties"]["next_agent"]
