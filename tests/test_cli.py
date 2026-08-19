"""Tests for the interactive launcher and deterministic dry-run contract."""

from __future__ import annotations

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
