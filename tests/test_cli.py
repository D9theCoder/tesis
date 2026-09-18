"""Tests for the interactive launcher and deterministic dry-run contract."""

from __future__ import annotations

from pathlib import Path

import tesis.cli as cli
import tesis.tui as tui


def test_run_launches_tui_in_interactive_terminal(monkeypatch):
    called: list[bool] = []
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(tui, "run_tui", lambda: called.append(True))

    assert cli.main(["run"]) == cli.EXIT_OK
    assert called == [True]


def test_non_interactive_run_fails_clearly(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: False)

    assert cli.main(["run"]) == cli.EXIT_USAGE_ERROR
    assert "interactive terminal" in capsys.readouterr().err


def test_dry_run_validates_default_configuration_without_terminal(monkeypatch, capsys):
    """The documented preflight command is deliberately safe in CI/headless use."""
    called: list[str] = []

    monkeypatch.setattr(cli, "_dry_run", lambda path: called.append(path) or cli.EXIT_OK)

    assert cli.main(["run", "--dry-run", "--config", "config.yaml"]) == cli.EXIT_OK
    assert cli.main(["run", "--config", "config.yaml", "--dry-run"]) == cli.EXIT_OK
    assert cli.main(["run", "--dry-run"]) == cli.EXIT_OK
    assert called == ["config.yaml", "config.yaml", "config.yaml"]
    assert not capsys.readouterr().err


def test_unsupported_subcommands_and_flags_are_rejected(capsys):
    for arguments in (
        [],
        ["info"],
        ["config"],
        ["validate", "--all-agents"],
        ["run", "--config", "elsewhere.yaml"],
        ["run", "--dry-run", "--unexpected"],
    ):
        assert cli.main(arguments) == cli.EXIT_USAGE_ERROR

    error = capsys.readouterr().err
    assert "python -m tesis run" in error
    assert "--dry-run" in error


def test_headless_flags_are_forwarded_without_opening_tui(monkeypatch):
    captured: list[list[str]] = []

    monkeypatch.setattr(
        cli,
        "_headless_run",
        lambda arguments: captured.append(arguments) or cli.EXIT_OK,
    )

    assert cli.main(["run", "--headless", "--mode", "matrix"]) == cli.EXIT_OK
    assert captured == [["--headless", "--mode", "matrix"]]


def test_headless_keyboard_interrupt_is_reported_as_cancelled(monkeypatch, capsys):
    def interrupting_run(**_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("tesis.headless.run_headless", interrupting_run)

    assert cli.main(["run", "--headless", "--mode", "single"]) == cli.EXIT_OK
    assert "cancelled" in capsys.readouterr().err.lower()


def test_headless_override_parser_maps_csv_coordinates():
    namespace = cli._headless_parser().parse_args([
        "--headless",
        "--mode",
        "matrix",
        "--providers",
        "openai_compatible",
        "--levels",
        "low,high",
        "--payload-modes",
        "hybrid,llm_mutation_only",
        "--condition",
        "akg_guided_hybrid",
    ])

    assert cli._headless_overrides(namespace) == {
        "providers": ["openai_compatible"],
        "levels": ["low", "high"],
        "payload_modes": ["hybrid", "llm_mutation_only"],
        "experiment_condition": "akg_guided_hybrid",
        "matrix": True,
    }


def test_cli_config_load_errors_redact_duplicate_scalars_across_modes(
    tmp_path: Path,
    capsys,
):
    first = "thk_live_cli_first_duplicate_secret"
    second = "thk_live_cli_second_duplicate_secret"
    config_path = tmp_path / "duplicate.yaml"
    config_path.write_text(
        "provider: openai\n"
        "models:\n"
        "  openai:\n"
        f"    api_key: {first}\n"
        f"    api_key: {second}\n",
        encoding="utf-8",
    )

    commands = (
        ["run", "--dry-run", "--config", str(config_path)],
        [
            "run", "--headless", "--mode", "single", "--config", str(config_path), "--json",
        ],
        [
            "run", "--headless", "--mode", "matrix", "--config", str(config_path), "--json",
        ],
    )
    for command in commands:
        assert cli.main(command) == cli.EXIT_RUNTIME_ERROR
        captured = capsys.readouterr()
        assert first not in captured.out + captured.err
        assert second not in captured.out + captured.err
