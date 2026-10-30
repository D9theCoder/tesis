"""Deterministic coverage for the offline and explicit-live TESIS Doctor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import tesis.doctor as doctor
from core.knowledge_graph import AKGValidationError
from tesis.model_config import EngagementConfig, LLMRuntimeConfig, ModelConfig, RoleConfig


@pytest.fixture
def valid_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EngagementConfig:
    # Keep offline/fault tests independent of credentials loaded from the real .env.
    for name in ("OPENAI_API_KEY", "OPENAI_COMPATIBLE_API_KEY", "GOOGLE_API_KEY",
                 "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    profile = ModelConfig(
        provider="openai",
        api_key="unit-test-provider-secret",
        model_name="doctor-test-model",
        base_url="https://provider.example/v1",
    )
    runtime = LLMRuntimeConfig(
        roles={
            "orchestrator": RoleConfig(model_profile="openai"),
            "payload_generator": RoleConfig(model_profile="openai"),
        }
    )
    return EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="openai",
        level="low",
        surface="sqli",
        output_dir=str(tmp_path / "results"),
        models={"openai": profile},
        llm_runtime=runtime,
    )


def check_by_id(report: dict, check_id: str) -> dict:
    return next(check for check in report["checks"] if check["id"] == check_id)


def test_akg_validation_failure_is_reported_and_does_not_abort(
    valid_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenAKG:
        def __init__(self) -> None:
            raise AKGValidationError(
                "missing node",
                invariant="payload_profiles",
                repair="restore the static node",
            )

    monkeypatch.setattr(doctor, "AttackKnowledgeGraph", BrokenAKG)
    report = doctor.run_doctor(valid_config)
    check = check_by_id(report, "akg.integrity")

    assert check["status"] == "failed"
    assert "AKG validation failed [payload_profiles]" in check["summary"]
    assert "Repair: restore the static node" in check["summary"]
    assert len(report["checks"]) > 1


def test_containment_violation_is_reported(
    valid_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PermissiveClient:
        def __init__(self, _base_url: str) -> None:
            pass

        def _assert_in_scope(self, _url: str, *, kind: str) -> None:
            pass

        def close(self) -> None:
            pass

    monkeypatch.setattr(doctor, "HTTPClient", PermissiveClient)
    check = check_by_id(doctor.run_doctor(valid_config), "containment.http")

    assert check["status"] == "failed"
    assert "external request was not blocked" in check["details"]
    assert "external redirect was not blocked" in check["details"]


def test_missing_credential_is_actionable(valid_config: EngagementConfig) -> None:
    valid_config.models["openai"].api_key = ""

    check = check_by_id(doctor.run_doctor(valid_config), "config.credentials")

    assert check["status"] == "failed"
    assert "openai" in check["details"]
    assert "environment variable" in check["remediation"]


def test_report_redacts_configured_secret_from_failures(
    valid_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = valid_config.models["openai"].api_key

    def expose_secret(_config: EngagementConfig) -> doctor.DoctorCheck:
        raise RuntimeError(
            f"provider rejected api_key={secret} at "
            "https://provider.example/v1?session=url-query-secret#token-fragment"
        )

    monkeypatch.setattr(doctor, "_check_graph", expose_secret)
    report = doctor.run_doctor(valid_config)
    text = json.dumps(report, sort_keys=True)

    assert secret not in text
    assert "<redacted>" in text
    assert "url-query-secret" not in text
    assert "token-fragment" not in text


# Regression failure modes: offline success mistaken for reachability; connection
# refusal; unrelated/error pages accepted as login; local cookies accepted as
# server evidence; login redirects/navigation accepted as surfaces; containment.
# Exercise the real Doctor/session/HTTP stack with only HTTP responses simulated.


def test_doctor_rejects_missing_method_preconditions(valid_config, monkeypatch):
    preconditions = dict(doctor.AttackKnowledgeGraph.METHOD_PRECONDITIONS)
    preconditions.pop('sqli_union')
    monkeypatch.setattr(doctor.AttackKnowledgeGraph, 'METHOD_PRECONDITIONS', preconditions)
    report = doctor.run_doctor(valid_config)
    assert check_by_id(report, 'akg.integrity')['status'] == 'failed'
