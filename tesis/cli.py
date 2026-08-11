"""Strict launcher for the interactive TESIS terminal application."""

from __future__ import annotations

import sys
from collections.abc import Sequence


EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_USAGE_ERROR = 2


def _interactive_terminal() -> bool:
    return bool(sys.stdin.isatty() and sys.stdout.isatty())


def main(argv: Sequence[str] | None = None) -> int:
    """Launch the sole supported interface: ``python -m tesis run``."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments != ["run"]:
        print(
            "Usage: python -m tesis run\n"
            "Legacy subcommands and run flags were removed; configure and operate the framework inside the TUI.",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR
    if not _interactive_terminal():
        print(
            "TESIS requires an interactive terminal; piped and headless execution are not supported.",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR
    try:
        from tesis.tui import run_tui

        run_tui()
        return EXIT_OK
    except KeyboardInterrupt:
        return EXIT_OK
    except Exception as exc:  # pragma: no cover - protects terminal startup
        print(f"Unable to start TESIS TUI: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR


__all__ = ["main"]
