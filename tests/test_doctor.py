"""Deterministic coverage for the offline and explicit-live TESIS Doctor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import tesis.config_loader as config_loader
import tesis.doctor as doctor
from core.knowledge_graph import AKGValidationError
from tesis.model_config import EngagementConfig, LLMRuntimeConfig, ModelConfig, RoleConfig


@pytest.fixture
def valid_config(tmp_path: Path) -> EngagementConfig:
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


def test_offline_report_shape_and_status_aggregation(valid_config: EngagementConfig) -> None:
    report = doctor.run_doctor(valid_config)

    assert set(report) == {"status", "summary", "checks"}
    assert report["status"] == "passed"
    assert report["summary"] == {
        "passed": len(report["checks"]),
        "failed": 0,
        "skipped": 0,
        "total": len(report["checks"]),
    }
    assert report["checks"]
    for check in report["checks"]:
        assert set(check) == {"id", "category", "status", "summary", "details", "remediation"}
        assert check["status"] in {"passed", "failed", "skipped"}
        assert all(isinstance(check[key], str) for key in check)


def test_accumulates_multiple_independent_failures(
    valid_config: EngagementConfig,
) -> None:
    valid_config.models["openai"].api_key = ""
    valid_config.models["openai"].provider = "gemini"
    valid_config.models["openai"].reasoning_effort = "high"

    report = doctor.run_doctor(valid_config)

    assert report["status"] == "failed"
    failed_ids = {check["id"] for check in report["checks"] if check["status"] == "failed"}
    assert "config.credentials" in failed_ids
    assert "reasoning.controls" in failed_ids
    assert report["summary"]["failed"] >= 2
    assert report["summary"]["total"] == len(report["checks"])


def test_coverage_reports_all_fixed_axis_counts(valid_config: EngagementConfig) -> None:
    check = check_by_id(doctor.run_doctor(valid_config), "coverage.scope")

    assert check["status"] == "passed"
    assert "surfaces=3" in check["details"]
    assert "methods=9" in check["details"]
    assert "security_levels=3" in check["details"]
    assert "payload_modes=3" in check["details"]
    assert "experiment_conditions=2" in check["details"]


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


def test_static_seed_rejection_is_reported(
    valid_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(state: dict) -> dict:
        method = state["selected_method"]
        return {
            "payload_candidates": {method: []},
            "payload_validation_results": {
                method: [{"valid": False, "reason": "unit-test rejection"}]
            },
        }

    monkeypatch.setattr(doctor, "validate_payload_candidates", reject)
    check = check_by_id(doctor.run_doctor(valid_config), "payload.static_seeds")

    assert check["status"] == "failed"
    assert "81 coordinate" in check["summary"]
    assert "validated_coordinates=81" in check["details"]
    assert "unit-test rejection" in check["details"]


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


def test_unwritable_output_directory_is_reported(
    valid_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor,
        "_path_is_writable",
        lambda path: (False, path.parent),
    )

    check = check_by_id(doctor.run_doctor(valid_config), "output.writability")

    assert check["status"] == "failed"
    assert "not writable or creatable" in check["summary"]


def test_missing_dependency_is_reported(
    valid_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = doctor.importlib.import_module

    def selective_import(name: str):
        if name == "textual":
            raise ModuleNotFoundError("No module named 'textual'")
        return real_import(name)

    monkeypatch.setattr(doctor.importlib, "import_module", selective_import)
    check = check_by_id(doctor.run_doctor(valid_config), "environment.dependencies")

    assert check["status"] == "failed"
    assert "textual" in check["details"]
    assert "pyproject.toml" in check["remediation"]


def test_invalid_reasoning_effort_is_reported(valid_config: EngagementConfig) -> None:
    valid_config.llm_runtime.roles["orchestrator"].reasoning_effort = "impossible"

    check = check_by_id(doctor.run_doctor(valid_config), "reasoning.controls")

    assert check["status"] == "failed"
    assert "requests invalid effort 'impossible'" in check["details"]
    assert "orchestrator=impossible" in check["details"]


def test_explicit_reasoning_on_unsupported_provider_is_reported(
    valid_config: EngagementConfig,
) -> None:
    valid_config.models["openai"].provider = "claude"
    valid_config.models["openai"].reasoning_effort = "medium"

    check = check_by_id(doctor.run_doctor(valid_config), "reasoning.controls")

    assert check["status"] == "failed"
    assert "cannot be forwarded" in check["summary"]
    assert "native thinking parameters" in check["remediation"]


@pytest.mark.parametrize(
    ("report_status", "expected_exit"),
    [("passed", doctor.EXIT_OK), ("failed", doctor.EXIT_RUNTIME_ERROR)],
)
def test_cli_main_returns_report_exit_code(
    valid_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    report_status: str,
    expected_exit: int,
) -> None:
    monkeypatch.setattr(config_loader, "load_and_resolve_config", lambda **_kwargs: valid_config)
    monkeypatch.setattr(
        doctor,
        "run_doctor",
        lambda _config, *, live=False: {
            "status": report_status,
            "summary": {
                "passed": int(report_status == "passed"),
                "failed": int(report_status == "failed"),
                "skipped": 0,
                "total": 1,
            },
            "checks": [{
                "id": "test",
                "category": "test",
                "status": report_status,
                "summary": "test result",
                "details": "",
                "remediation": "",
            }],
        },
    )

    assert doctor.main([]) == expected_exit
    assert "Doctor summary:" in capsys.readouterr().out


def test_cli_json_is_one_object_and_forwards_config_and_live(
    valid_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls: dict[str, object] = {}
    config_path = tmp_path / "custom.yaml"

    def load(*, config_path: str, cli_args: dict) -> EngagementConfig:
        calls["path"] = config_path
        calls["cli"] = cli_args
        return valid_config

    def run(_config: EngagementConfig, *, live: bool = False) -> dict:
        calls["live"] = live
        return {
            "status": "passed",
            "summary": {"passed": 0, "failed": 0, "skipped": 0, "total": 0},
            "checks": [],
        }

    monkeypatch.setattr(config_loader, "load_and_resolve_config", load)
    monkeypatch.setattr(doctor, "run_doctor", run)

    assert doctor.main(["--config", str(config_path), "--live", "--json"]) == 0
    output = capsys.readouterr().out
    assert output.count("\n") == 1
    assert json.loads(output)["status"] == "passed"
    assert calls == {"path": str(config_path), "cli": {}, "live": True}


def test_cli_config_error_is_clean_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    def fail(**_kwargs):
        raise config_loader.ConfigError("broken test config. Repair: fix YAML")

    monkeypatch.setattr(config_loader, "load_and_resolve_config", fail)
    # An existing path keeps this a content-error case; path problems have
    # their own message (see the missing/directory path tests below).
    config_path = tmp_path / "broken.yaml"
    config_path.write_text("provider: openai\n", encoding="utf-8")

    assert doctor.main(["--config", str(config_path), "--json"]) == 1
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["status"] == "failed"
    assert report["checks"][0]["id"] == "config.load"
    assert "broken test config" in report["checks"][0]["summary"]
    assert "Traceback" not in captured.out + captured.err


def test_cli_usage_error_returns_two(capsys: pytest.CaptureFixture[str]) -> None:
    assert doctor.main(["--not-a-doctor-option"]) == doctor.EXIT_USAGE_ERROR
    assert "unrecognized arguments" in capsys.readouterr().err


def test_live_checks_skip_when_credentials_and_url_are_unavailable(
    valid_config: EngagementConfig,
) -> None:
    valid_config.models["openai"].api_key = ""
    valid_config.target_url = ""

    report = doctor.run_doctor(valid_config, live=True)
    live_checks = [check for check in report["checks"] if check["id"].startswith("live.")]

    assert len(live_checks) == 5
    assert all(check["status"] == "skipped" for check in live_checks)
    assert all("unavailable" in (check["summary"] + check["details"]) for check in live_checks)


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


def test_report_redacts_target_url_userinfo_and_keeps_the_host(tmp_path: Path) -> None:
    userinfo_secret = "unit-test-userinfo-secret"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://admin:{secret}@127.0.0.1/dvwa\n"
        "provider: openai\n"
        "level: low\n"
        "models:\n"
        "  openai:\n"
        "    model_name: doctor-test-model\n"
        "    api_key: unit-test-api-key\n".format(secret=userinfo_secret),
        encoding="utf-8",
    )
    config = config_loader.load_and_resolve_config(
        config_path=str(config_path), cli_args={}
    )

    report = doctor.run_doctor(config, live=False)
    text = json.dumps(report, sort_keys=True)

    assert userinfo_secret not in text
    assert f"admin:{userinfo_secret}" not in text
    assert "127.0.0.1" in check_by_id(report, "containment.http")["details"]
    assert "127.0.0.1" in check_by_id(report, "config.endpoints")["details"]


def test_redact_text_strips_url_userinfo_from_failure_messages(
    valid_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def expose_userinfo(_config: EngagementConfig) -> doctor.DoctorCheck:
        raise RuntimeError(
            "provider rejected https://svc-user:unit-test-userinfo-secret@provider.example/v1/models"
        )

    monkeypatch.setattr(doctor, "_check_graph", expose_userinfo)
    report = doctor.run_doctor(valid_config)
    text = json.dumps(report, sort_keys=True)

    assert "unit-test-userinfo-secret" not in text
    assert "svc-user" not in text
    assert "provider.example" in text
    assert "<redacted>" in text


@pytest.mark.parametrize(
    "body",
    [
        "target_url: http://127.0.0.1/dvwa\nprovider: openai\nlevel: low\ncoverage_target: abc\n",
        "target_url: http://127.0.0.1/dvwa\nprovider: openai\nlevel: low\niterations: many\n",
        "target_url: http://127.0.0.1/dvwa\nprovider: openai\nlevel: low\nmodels:\n  - oops\n",
    ],
    ids=["float-scalar", "int-scalar", "mapping-shape"],
)
def test_cli_malformed_config_is_one_json_object(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    body: str,
) -> None:
    config_path = tmp_path / "malformed.yaml"
    config_path.write_text(body, encoding="utf-8")

    exit_code = doctor.main(["--config", str(config_path), "--json"])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == doctor.EXIT_RUNTIME_ERROR
    assert captured.out.count("\n") == 1
    assert report["status"] == "failed"
    assert report["checks"][0]["id"] == "config.load"
    assert "YAML" in report["checks"][0]["remediation"]
    assert "Traceback" not in captured.out + captured.err


def test_cli_missing_config_path_names_the_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "absent.yaml"

    exit_code = doctor.main(["--config", str(missing), "--json"])
    captured = capsys.readouterr()
    summary = json.loads(captured.out)["checks"][0]["summary"]

    assert exit_code == doctor.EXIT_RUNTIME_ERROR
    assert str(missing) in summary
    assert "not found" in summary
    assert "Invalid target URL" not in summary
    assert "Traceback" not in captured.out + captured.err


def test_cli_directory_config_path_names_the_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = doctor.main(["--config", str(tmp_path), "--json"])
    captured = capsys.readouterr()
    summary = json.loads(captured.out)["checks"][0]["summary"]

    assert exit_code == doctor.EXIT_RUNTIME_ERROR
    assert str(tmp_path) in summary
    assert "not a regular file" in summary
    assert "Traceback" not in captured.out + captured.err


def test_coverage_axis_follows_the_loader_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert doctor._check_coverage().status == "passed"

    monkeypatch.setattr(
        config_loader,
        "_VALID_EXPERIMENT_CONDITIONS",
        frozenset({"regressed_condition"}),
    )
    check = doctor._check_coverage()

    assert check.status == "failed"
    assert "conditions:" in check.details
    assert "regressed_condition" in check.details


def test_endpoints_accept_environment_provided_base_url(
    valid_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid_config.models["openai"].provider = "openai_compatible"
    valid_config.models["openai"].base_url = None
    monkeypatch.delenv("OPENAI_COMPATIBLE_BASE_URL", raising=False)

    without_environment = doctor._check_endpoints(valid_config)

    assert without_environment.status == "failed"
    assert "OPENAI_COMPATIBLE_BASE_URL" in without_environment.details

    monkeypatch.setenv("OPENAI_COMPATIBLE_BASE_URL", "http://127.0.0.1:1/v1")
    with_environment = doctor._check_endpoints(valid_config)

    assert with_environment.status == "passed"
    assert "configured_model_endpoints=1" in with_environment.details
    assert "openai=environment" in with_environment.details
