"""Tests for the shared declarative configuration-field schema."""

from __future__ import annotations

import pytest

from tesis.config_fields import (
    configured_provider_choices,
    FieldValidationError,
    validate_field_value,
)


def test_unconfigured_providers_cannot_be_selected():
    config = {"models": {"primary": {"provider": "openai_compatible", "model_name": "test"}}}
    assert configured_provider_choices(config) == ("openai_compatible", "primary")
    with pytest.raises(FieldValidationError):
        validate_field_value("provider", "gemini", config=config)
