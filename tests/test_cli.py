"""Tests for the intentionally narrow interactive launcher contract."""

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


def test_legacy_subcommands_and_flags_are_rejected(capsys):
    for arguments in (
        [],
        ["info"],
        ["config"],
        ["validate", "--all-agents"],
        ["run", "--dry-run"],
        ["run", "--config", "elsewhere.yaml"],
    ):
        assert cli.main(arguments) == cli.EXIT_USAGE_ERROR

    error = capsys.readouterr().err
    assert "Legacy subcommands and run flags were removed" in error
    assert "python -m tesis run" in error
