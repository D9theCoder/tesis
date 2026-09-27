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


def test_offline_report_shape_and_status_aggregation(valid_config: EngagementConfig) -> None:
    report = doctor.run_doctor(valid_config)

    assert set(report) == {"status", "summary", "checks"}
    assert report["status"] == "passed"
    assert report["summary"] == {
        "passed": len(report["checks"]) - 5,
        "failed": 0,
        "skipped": 5,
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


def test_reasoning_check_uses_runtime_rule_for_custom_provider(
    valid_config: EngagementConfig,
) -> None:
    valid_config.models["openai"].provider = "deepseek"
    valid_config.models["openai"].reasoning_effort = "medium"

    check = check_by_id(doctor.run_doctor(valid_config), "reasoning.controls")

    assert check["status"] == "failed"
    assert "deepseek" in check["details"]
    assert "cannot be forwarded" in check["summary"]


def test_secret_discovery_failure_is_reported_without_aborting_doctor(
    valid_config: EngagementConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor,
        "_known_secrets",
        lambda _config: (_ for _ in ()).throw(RuntimeError("secret discovery failed")),
    )

    report = doctor.run_doctor(valid_config)

    check = check_by_id(report, "config.redaction")
    assert report["status"] == "failed"
    assert check["status"] == "failed"
    assert "RuntimeError" in check["details"]
    assert report["summary"]["total"] == len(report["checks"])


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


def test_config_load_report_redacts_both_duplicate_secret_scalars(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = "thk_live_first_duplicate_secret"
    second = "thk_live_second_duplicate_secret"
    config_path = tmp_path / "duplicate.yaml"
    config_path.write_text(
        "provider: openai\n"
        "models:\n"
        "  openai:\n"
        f"    api_key: {first}\n"
        f"    api_key: {second}\n",
        encoding="utf-8",
    )

    assert doctor.main(
        ["--config", str(config_path), "--json"]
    ) == doctor.EXIT_RUNTIME_ERROR
    captured = capsys.readouterr()

    assert first not in captured.out + captured.err
    assert second not in captured.out + captured.err
    report = json.loads(captured.out)
    assert "duplicate key 'api_key'" in report["checks"][0]["summary"]


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


# Regression failure modes: offline success mistaken for reachability; connection
# refusal; unrelated/error pages accepted as login; local cookies accepted as
# server evidence; login redirects/navigation accepted as surfaces; containment.
# Exercise the real Doctor/session/HTTP stack with only HTTP responses simulated.
@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("healthy", ("passed", "passed", "passed")),
        ("down", ("failed", "skipped", "skipped")),
        ("wrong_service", ("failed", "skipped", "skipped")),
        ("error_page", ("failed", "skipped", "skipped")),
        ("levels_down", ("passed", "failed", "passed")),
        ("levels_missing", ("passed", "failed", "passed")),
        ("surface_login", ("passed", "passed", "failed")),
        ("surface_navigation", ("passed", "passed", "failed")),
        ("surface_index", ("passed", "passed", "passed")),
        ("external_redirect", ("failed", "skipped", "skipped")),
    ],
)
def test_doctor_dvwa_http_evidence(valid_config, monkeypatch, scenario, expected):
    import httpx
    from urllib.parse import parse_qs

    level = "low"
    requests = []
    home = '<title>DVWA</title><a href="logout.php">Logout</a>'

    def respond(request):
        nonlocal level
        requests.append(str(request.url))
        assert request.url.host == "localhost", "redirect escaped containment"
        path = request.url.path
        if scenario == "down":
            raise httpx.ConnectError("simulated connection refused", request=request)
        if scenario == "external_redirect":
            return httpx.Response(302, headers={"location": "https://example.invalid/login.php"})
        if scenario == "wrong_service":
            return httpx.Response(200, text='<title>Other app</title><a href="logout.php">Logout</a>')
        if scenario == "error_page":
            return httpx.Response(503, text=home)
        if path.endswith("login.php"):
            if request.method == "POST":
                return httpx.Response(302, headers={"location": "/dvwa/index.php"})
            return httpx.Response(200, text='<title>DVWA Login</title><input name="password">')
        if path.endswith("security.php"):
            if scenario == "levels_down":
                raise httpx.ConnectError("security service unavailable", request=request)
            if scenario == "levels_missing":
                return httpx.Response(200, text=home)
            if request.method == "POST":
                level = parse_qs(request.content.decode())["security"][0]
            return httpx.Response(200, text=home +
                f'<select name="security"><option selected value="{level}">{level}</option></select>')
        if "/vulnerabilities/" in path:
            if scenario == "surface_index" and not path.endswith("index.php"):
                return httpx.Response(302, headers={"location": path + "index.php"})
            path = path.removesuffix("index.php")
            if scenario == "surface_login":
                return httpx.Response(302, headers={"location": "/dvwa/login.php"})
            if scenario == "surface_navigation":
                return httpx.Response(200, text=home + '<nav>SQL Injection | Access Control | Brute Force</nav>')
            heading = {"sqli": "SQL Injection", "authbypass": "Authorisation Bypass", "brute": "Brute Force"}[path.strip("/").split("/")[-1]]
            return httpx.Response(200, text=home + f'<h1>Vulnerability: {heading}</h1>')
        return httpx.Response(200, text=home)

    def timed_response(request):
        from datetime import timedelta

        response = respond(request)
        response.elapsed = timedelta(milliseconds=1)
        return response

    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**kw, transport=httpx.MockTransport(timed_response)))
    monkeypatch.setattr(doctor, "_model_probe_checks", lambda _config: [])
    report = doctor.run_doctor(valid_config, live=True)
    checks = [check_by_id(report, f"live.dvwa.{name}") for name in ("authentication", "levels", "surfaces")]
    evidence = Path("results/validation/doctor")
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / f"{scenario}.json").write_text(json.dumps({"report": report, "requests": requests}, indent=2))
    assert tuple(check["status"] for check in checks) == expected


def test_offline_explicitly_skips_service_verification(valid_config, monkeypatch):
    import httpx

    def unexpected_request(*_args, **_kwargs):
        pytest.fail("offline Doctor attempted network access")

    monkeypatch.setattr(httpx.Client, "request", unexpected_request)
    report = doctor.run_doctor(valid_config)
    for check_id in ("live.dvwa.authentication", "live.dvwa.levels", "live.dvwa.surfaces",
                     "live.model.orchestrator", "live.model.payload_generator"):
        check = check_by_id(report, check_id)
        assert check["status"] == "skipped"
        assert "not checked" in check["summary"].lower()


@pytest.mark.parametrize('fault,check_id', [
    ('swapped_methods', 'coverage.scope'),
    ('missing_seed_evidence', 'payload.static_seeds'),
    ('blocks_target', 'containment.http'),
    ('invalid_port', 'config.endpoints'),
    ('whitespace_host', 'config.endpoints'),
    ('missing_sqlite', 'environment.dependencies'),
    ('runs_is_file', 'output.writability'),
    ('dangling_output', 'output.writability'),
    ('disk_full', 'output.writability'),
])
def test_doctor_audit_local_faults(valid_config, monkeypatch, tmp_path, fault, check_id):
    # Each fault breaks a real prerequisite that existing baseline checks missed.
    if fault == 'swapped_methods':
        methods = {k: list(v) for k, v in doctor.METHODS_BY_SURFACE.items()}
        methods['sqli'][0], methods['brute_force'][0] = methods['brute_force'][0], methods['sqli'][0]
        monkeypatch.setattr(doctor, 'METHODS_BY_SURFACE', methods)
    elif fault == 'missing_seed_evidence':
        monkeypatch.setattr(doctor, 'validate_payload_candidates', lambda state: {
            'payload_candidates': state['payload_candidates'], 'payload_validation_results': {}})
    elif fault == 'blocks_target':
        def reject_all(self, url, *, kind='request'):
            raise doctor.ContainmentError('all blocked', kind=kind)
        monkeypatch.setattr(doctor.HTTPClient, '_assert_in_scope', reject_all)
    elif fault == 'invalid_port':
        valid_config.models['openai'].base_url = 'http://localhost:70000/v1'
    elif fault == 'whitespace_host':
        valid_config.models['openai'].base_url = 'https://bad host/v1'
    elif fault == 'missing_sqlite':
        original = doctor.importlib.import_module
        def missing(name):
            if name == 'langgraph.checkpoint.sqlite':
                raise ModuleNotFoundError('missing sqlite checkpointer')
            return original(name)
        monkeypatch.setattr(doctor.importlib, 'import_module', missing)
    elif fault == 'runs_is_file':
        root = Path(valid_config.output_dir)
        root.mkdir()
        (root / 'runs').write_text('blocking file')
    elif fault == 'dangling_output':
        Path(valid_config.output_dir).symlink_to(tmp_path / 'nonexistent')
    elif fault == 'disk_full':
        import tempfile
        def full(*args, **kwargs):
            raise OSError(28, 'No space left on device')
        monkeypatch.setattr(tempfile, 'TemporaryFile', full)
    report = doctor.run_doctor(valid_config)
    root = Path('results/validation/doctor-audit')
    root.mkdir(parents=True, exist_ok=True)
    (root / f'{fault}.json').write_text(json.dumps(report, indent=2))
    assert check_by_id(report, check_id)['status'] == 'failed'


@pytest.mark.parametrize('scenario,expected', [
    ('no_usage', 'passed'), ('extra_schema_key', 'failed'),
    ('profile_budget', 'passed'), ('selected_profile', 'passed'),
    ('provider_rejected', 'failed'),
])
def test_doctor_audit_provider_flow(valid_config, monkeypatch, scenario, expected):
    # Exercise Doctor -> real LLMRuntime -> simulated SDK client; no paid calls.
    from types import SimpleNamespace

    profile = valid_config.models['openai']
    profile.max_tokens = 1024
    if scenario == 'selected_profile':
        from dataclasses import replace
        valid_config.models['chosen'] = replace(profile, model_name='chosen-model')
        valid_config.model_profile = 'chosen'
        for role in valid_config.llm_runtime.roles.values():
            role.model_profile = None

    def client_factory(provider, **kwargs):
        class Client:
            def invoke(self, messages):
                if scenario == 'provider_rejected':
                    raise RuntimeError('simulated unauthorized')
                if scenario == 'selected_profile' and kwargs['model_name'] != 'chosen-model':
                    raise RuntimeError('Doctor probed the wrong model')
                truncated = scenario == 'profile_budget' and kwargs['max_tokens'] < 1024
                return SimpleNamespace(
                    content='{"status":"ok","extra":true}' if scenario == 'extra_schema_key' else '{"status":"ok"}',
                    usage_metadata=None if scenario == 'no_usage' else {'input_tokens': 5, 'output_tokens': 5},
                    response_metadata={'finish_reason': 'length' if truncated else 'stop'},
                )
        return Client()

    monkeypatch.setattr('llm.runtime.get_llm', client_factory)
    monkeypatch.setattr(doctor, '_dvwa_live_checks', lambda _config: [])
    report = doctor.run_doctor(valid_config, live=True)
    root = Path('results/validation/doctor-audit')
    root.mkdir(parents=True, exist_ok=True)
    (root / f'{scenario}.json').write_text(json.dumps(report, indent=2))
    for role in valid_config.llm_runtime.roles:
        assert check_by_id(report, f'live.model.{role}')['status'] == expected


@pytest.mark.parametrize('source', ['environment', 'extra'])
def test_doctor_uses_and_redacts_effective_credentials(valid_config, monkeypatch, source):
    secret = 'effective-doctor-private-key'
    valid_config.models['openai'].api_key = ''
    if source == 'environment':
        monkeypatch.setenv('OPENAI_API_KEY', secret)
    else:
        monkeypatch.delenv('OPENAI_API_KEY', raising=False)
        valid_config.models['openai'].extra['api_key'] = secret
    monkeypatch.setattr(doctor, '_check_graph', lambda _config: (_ for _ in ()).throw(RuntimeError(secret)))
    report = doctor.run_doctor(valid_config)
    assert check_by_id(report, 'config.credentials')['status'] == 'passed'
    assert secret not in json.dumps(report)


def test_doctor_checks_effective_endpoint_override(valid_config):
    valid_config.models['openai'].extra['base_url'] = 'http://localhost:invalid/v1'
    report = doctor.run_doctor(valid_config)
    assert check_by_id(report, 'config.endpoints')['status'] == 'failed'


def test_doctor_rejects_missing_method_preconditions(valid_config, monkeypatch):
    preconditions = dict(doctor.AttackKnowledgeGraph.METHOD_PRECONDITIONS)
    preconditions.pop('sqli_union')
    monkeypatch.setattr(doctor.AttackKnowledgeGraph, 'METHOD_PRECONDITIONS', preconditions)
    report = doctor.run_doctor(valid_config)
    assert check_by_id(report, 'akg.integrity')['status'] == 'failed'
