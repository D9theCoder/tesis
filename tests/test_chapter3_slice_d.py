"""Slice D behavior controls: modes, blocks, epoch metadata, telemetry.

Offline only: no HTTP, provider, graph-node, or experiment execution.
"""

from __future__ import annotations


import pytest

from evaluation.runner import _payload_generation_failure
from llm.cache_metrics import cache_performance_summary


def test_payload_failure_dispatch_separates_provider_from_strict() -> None:
    provider = _payload_generation_failure({"fallback_events": [{
        "event": "payload_generation.provider_failure", "reason": "llm_error",
        "method": "sqli_error", "visit_id": "v1", "payload_mode": "hybrid",
    }]})
    assert provider is not None and provider["reason"] == "llm_error"
    strict = _payload_generation_failure({"fallback_events": [{
        "event": "payload_generation.strict_no_candidate", "reason": "guardrail_refusal",
        "method": "sqli_error", "visit_id": "v1", "payload_mode": "llm_mutation_only",
    }]})
    assert strict is None
    template = _payload_generation_failure({"fallback_events": [{
        "event": "payload_generation.template_unavailable", "reason": "template_unavailable",
        "method": "bf_dictionary", "visit_id": "v1", "payload_mode": "llm_template",
    }]})
    assert template is None


def test_fixture_restoration_evidence_is_validated_and_kept() -> None:
    from tesis.config_loader import ConfigError, _validate_engagement_config
    from tesis.model_config import EngagementConfig

    valid = {
        "policy_version": "fixture-restoration.v1",
        "evidence_id": "fixture-reset-1",
        "kind": "operator_attestation",
        "fixture_id": "fixture-1",
        "protocol_version": "protocol-1",
        "security_level": "low",
        "epoch_id": "epoch-1",
        "source_hashes_sha256": "a" * 64,
        "restoration": "reset",
        "authorized_protocol": "operator-reset.v1",
        "evidence_refs": ["evidence:fixture-reset-1"],
        "evidence_sha256": "b" * 64,
        "observed_at": "2026-10-28T00:00:00+00:00",
        "operator": "operator-1",
    }
    config = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai", level="low",
        fixture_id="fixture-1", protocol_version="protocol-1",
        fixture_restoration_evidence=valid,
    )
    _validate_engagement_config(config)
    assert config.fixture_restoration_evidence["by_level"] == {"low": valid}
    assert config.fixture_restoration_evidence["missing_levels"] == []
    envelope_config = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai", level="low",
        fixture_id="fixture-1", protocol_version="protocol-1",
        fixture_restoration_evidence={"by_level": {"low": valid}},
    )
    _validate_engagement_config(envelope_config)
    assert envelope_config.fixture_restoration_evidence["by_level"] == {"low": valid}
    list_config = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai", level="low",
        fixture_id="fixture-1", protocol_version="protocol-1",
        fixture_restoration_evidence=[valid],
    )
    _validate_engagement_config(list_config)
    assert list_config.fixture_restoration_evidence["levels"] == ["low"]
    with pytest.raises(ConfigError, match="outside the attestation document"):
        _validate_engagement_config(EngagementConfig(
            target_url="http://localhost/dvwa", provider="openai", level="low",
            fixture_id="fixture-1", protocol_version="protocol-1",
            fixture_restoration_evidence={**valid, "identity_sha256": "c" * 64},
        ))
    # A document for a level this invocation does not run is filtered out of the
    # canonical envelope rather than rejected (D8: a fixture-wide attestation must
    # stay usable by a single-level run), so the only remaining refusal is the
    # level the run actually needs being unattested.
    with pytest.raises(ConfigError, match="no attestation for level 'low'"):
        _validate_engagement_config(EngagementConfig(
            target_url="http://localhost/dvwa", provider="openai", level="low",
            fixture_id="fixture-1", protocol_version="protocol-1",
            fixture_restoration_evidence=[dict(valid, security_level="high")],
        ))
    wide = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai", level="low",
        fixture_id="fixture-1", protocol_version="protocol-1",
        fixture_restoration_evidence=[
            valid,
            dict(valid, security_level="medium", evidence_id="fixture-reset-2"),
            dict(valid, security_level="high", evidence_id="fixture-reset-3"),
        ],
    )
    _validate_engagement_config(wide)
    assert list(wide.fixture_restoration_evidence["by_level"]) == ["low"]
    assert wide.fixture_restoration_evidence["missing_levels"] == []
    invalid = dict(valid, evidence_refs=[])
    with pytest.raises(ConfigError):
        _validate_engagement_config(EngagementConfig(
            target_url="http://localhost/dvwa", provider="openai", level="low",
            fixture_id="fixture-1", protocol_version="protocol-1",
            fixture_restoration_evidence=invalid,
        ))


def test_no_call_cache_rate_is_null_not_zero() -> None:
    summary = cache_performance_summary([])
    assert summary["response_cache_hit_rate"] is None
    assert summary["response_cache_hit_rate_status"] == "no_calls"
    assert summary["response_cache_hit_rate_denominator"] == 0
