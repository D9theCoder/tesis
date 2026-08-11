"""Tests for the shared declarative configuration-field schema."""

from __future__ import annotations

import pytest

from core.state import ALL_METHOD_AGENTS, SECURITY_LEVELS, SURFACES
from llm.provider import SUPPORTED_PROVIDERS
from tesis.config_fields import (
    FORM_MATRIX,
    FORM_SINGLE,
    FieldValidationError,
    coerce_field_value,
    fields_for_form,
    get_config_value,
    is_secret_field,
    method_choices,
    provider_choices,
    security_level_choices,
    set_config_value,
    surface_choices,
    validate_field_value,
)


def test_form_schemas_share_canonical_registries_and_required_controls():
    assert provider_choices() == tuple(SUPPORTED_PROVIDERS)
    assert surface_choices() == tuple(SURFACES)
    assert security_level_choices() == tuple(SECURITY_LEVELS)
    assert set(method_choices()) == set(ALL_METHOD_AGENTS)

    single_paths = {field.path for field in fields_for_form(FORM_SINGLE)}
    matrix_paths = {field.path for field in fields_for_form(FORM_MATRIX)}
    assert {"target_url", "provider", "surface", "payload_mode", "target_method"} <= single_paths
    assert {"providers", "surfaces", "payload_modes", "repeats"} <= matrix_paths


def test_field_coercion_constraints_and_secret_metadata():
    assert coerce_field_value("candidate_budget", "7") == 7
    assert coerce_field_value("enriched_reporting", "true") is True
    assert validate_field_value("coverage_target", "0.75") == 0.75
    with pytest.raises(FieldValidationError):
        validate_field_value("coverage_target", "1.5")
    assert is_secret_field("models.{provider}.api_key")


def test_nested_model_path_helpers_preserve_existing_shape():
    config = {"models": {"gemini": {"model_name": "old", "future": "kept"}}}
    set_config_value(config, "models.{provider}.model_name", "new", context={"provider": "gemini"})

    assert get_config_value(
        config,
        "models.{provider}.model_name",
        context={"provider": "gemini"},
    ) == "new"
    assert config["models"]["gemini"]["future"] == "kept"
