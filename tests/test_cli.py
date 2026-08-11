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
