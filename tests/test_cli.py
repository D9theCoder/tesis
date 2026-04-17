import json
from pathlib import Path

import tesis.cli as cli
from tesis.config_loader import ConfigError
from tesis.model_config import EngagementConfig


def _config(*, matrix: bool = False) -> EngagementConfig:
    return EngagementConfig(
        target_url="http://localhost/dvwa",
        provider="gemini",
        level="low",
        iterations=30,
        repeats=1,
        output_dir="results",
        matrix=matrix,
        providers=["gemini"],
        levels=["low", "medium", "high"] if matrix else ["low"],
        report_format="both",
        models={},
    )


def test_run_single_invokes_runner_with_expected_args(monkeypatch):
    called = {}

    monkeypatch.setattr(cli, "load_and_resolve_config", lambda **kwargs: _config(matrix=False))
    monkeypatch.setattr(cli, "_preflight_target_reachable", lambda *_args, **_kwargs: True)

    def fake_single(**kwargs):
        called.update(kwargs)
        return {
            "run_id": "gemini-low-0",
            "status": "success",
            "config": {"provider": "gemini", "security_level": "low"},
            "final_state": {"guardrail_activations": [], "iteration_count": 1},
            "report": {"module_scores": {}, "summary": {}},
        }

    monkeypatch.setattr(cli, "run_single_engagement", fake_single)
    monkeypatch.setattr(cli, "write_json_report", lambda path, payload: Path(path))
    monkeypatch.setattr(cli, "write_markdown_report", lambda path, payload: Path(path))
    monkeypatch.setattr(cli, "format_module_scores_table", lambda *_args, **_kwargs: "ok")

    exit_code = cli.main(["run"])

    assert exit_code == 0
    assert called["target_url"] == "http://localhost/dvwa"
    assert called["security_level"] == "low"
    assert called["llm_provider"] == "gemini"


def test_run_matrix_invokes_matrix_runner_with_expected_args(monkeypatch):
    called = {}

    monkeypatch.setattr(cli, "load_and_resolve_config", lambda **kwargs: _config(matrix=True))
    monkeypatch.setattr(cli, "_preflight_target_reachable", lambda *_args, **_kwargs: True)

    def fake_matrix(**kwargs):
        called.update(kwargs)
        return ([{
            "run_id": "gemini-low-0",
            "status": "success",
            "config": {"provider": "gemini", "security_level": "low"},
            "final_state": {"guardrail_activations": [], "iteration_count": 1},
            "report": {"module_scores": {}, "summary": {}},
        }], {"schema_version": "stage6.v1", "totals": {"successful_runs": 1}})

    monkeypatch.setattr(cli, "run_provider_matrix", fake_matrix)
    monkeypatch.setattr(cli, "write_json_report", lambda path, payload: Path(path))
    monkeypatch.setattr(cli, "write_markdown_report", lambda path, payload: Path(path))
    monkeypatch.setattr(cli, "format_provider_comparison_table", lambda *_args, **_kwargs: "matrix")

    exit_code = cli.main(["run", "--matrix"])

    assert exit_code == 0
    assert called["target_url"] == "http://localhost/dvwa"
    assert called["include_aggregate"] is True


def test_dry_run_skips_runtime_invocation(monkeypatch):
    monkeypatch.setattr(cli, "load_and_resolve_config", lambda **kwargs: _config(matrix=False))
    monkeypatch.setattr(cli, "run_single_engagement", lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("should not run")))

    exit_code = cli.main(["run", "--dry-run"])

    assert exit_code == 0


def test_info_subcommand_outputs_schema_modules_providers(capsys):
    exit_code = cli.main(["info"])

    captured = capsys.readouterr().out
    payload = json.loads(captured)
    assert exit_code == 0
    assert "schema_version" in payload
    assert "providers" in payload
    assert "modules" in payload


def test_exit_code_2_for_config_error(monkeypatch):
    def raise_config_error(**_kwargs):
        raise ConfigError("bad config")

    monkeypatch.setattr(cli, "load_and_resolve_config", raise_config_error)

    exit_code = cli.main(["run"])
    assert exit_code == 2


def test_exit_code_1_for_runtime_error(monkeypatch):
    monkeypatch.setattr(cli, "load_and_resolve_config", lambda **kwargs: _config(matrix=False))
    monkeypatch.setattr(cli, "_preflight_target_reachable", lambda *_args, **_kwargs: True)

    def raise_runtime_error(**_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "run_single_engagement", raise_runtime_error)

    exit_code = cli.main(["run"])
    assert exit_code == 1


def test_exit_code_0_for_success(monkeypatch):
    monkeypatch.setattr(cli, "load_and_resolve_config", lambda **kwargs: _config(matrix=False))
    monkeypatch.setattr(cli, "_preflight_target_reachable", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        cli,
        "run_single_engagement",
        lambda **_kwargs: {
            "run_id": "gemini-low-0",
            "status": "success",
            "config": {"provider": "gemini", "security_level": "low"},
            "final_state": {"guardrail_activations": [], "iteration_count": 1},
            "report": {"module_scores": {}, "summary": {}},
        },
    )
    monkeypatch.setattr(cli, "write_json_report", lambda path, payload: Path(path))
    monkeypatch.setattr(cli, "write_markdown_report", lambda path, payload: Path(path))
    monkeypatch.setattr(cli, "format_module_scores_table", lambda *_args, **_kwargs: "ok")

    exit_code = cli.main(["run"])
    assert exit_code == 0


def test_exit_code_3_for_target_unreachable(monkeypatch):
    monkeypatch.setattr(cli, "load_and_resolve_config", lambda **kwargs: _config(matrix=False))
    monkeypatch.setattr(cli, "_preflight_target_reachable", lambda *_args, **_kwargs: False)

    exit_code = cli.main(["run"])
    assert exit_code == 3


def test_config_default_output_masks_api_keys(tmp_path, capsys):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
models:
  gemini:
    model_name: gemini-3-flash-preview
    api_key: super-secret-key-1234
""",
        encoding="utf-8",
    )

    exit_code = cli.main(["config", "--config", str(config_file)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "super-secret-key-1234" not in output
    assert "****1234" in output


def test_report_invalid_json_returns_config_error(tmp_path):
    artifact = tmp_path / "bad.json"
    artifact.write_text("not-json", encoding="utf-8")

    exit_code = cli.main(["report", str(artifact), "--show-scores"])
    assert exit_code == 2
