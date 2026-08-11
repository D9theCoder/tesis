"""Launcher for the interactive TESIS application and offline validation."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path


EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_USAGE_ERROR = 2


def _interactive_terminal() -> bool:
    return bool(sys.stdin.isatty() and sys.stdout.isatty())


def _dry_run(config_path: str) -> int:
    """Validate one resolved configuration without contacting DVWA or an LLM.

    The dry run deliberately exercises only deterministic local components:
    configuration parsing, AKG construction, graph compilation, and static seed
    validation for every method reachable from the configured surface(s).  It
    is therefore safe to use before an authorized live DVWA experiment.
    """
    from core.graph_builder import build_framework
    from core.knowledge_graph import AttackKnowledgeGraph
    from core.state import METHODS_BY_SURFACE, new_default_state
    from foundation.payload_library import PayloadLibrary
    from foundation.payload_validator import validate_payload_candidates
    from tesis.config_loader import ConfigError, load_and_resolve_config

    try:
        config = load_and_resolve_config(config_path=config_path, cli_args={})
        graph = AttackKnowledgeGraph()
        # Compilation validates the canonical runtime topology without invoking
        # a node, so neither the HTTP client nor a model provider is touched.
        build_framework(llm_provider=config.provider, surface=config.surface)

        surfaces = config.surfaces if config.matrix else [config.surface]
        levels = config.levels if config.matrix else [config.level]
        payload_modes = config.payload_modes if config.matrix else [config.payload_mode]
        methods = [
            config.target_method
        ] if config.target_method else [
            method
            for surface in surfaces
            for method in METHODS_BY_SURFACE[surface]
        ]
        checked = 0
        payload_library = PayloadLibrary()
        for method in methods:
            for level in levels:
                for payload_mode in payload_modes:
                    seeds = payload_library.load_seed_candidates(method, level)
                    result = validate_payload_candidates({
                        **new_default_state(),
                        "selected_method": method,
                        "security_level": level,
                        "payload_mode": payload_mode,
                        "payload_candidates": {method: seeds},
                    })
                    rejected = [
                        item for item in result["payload_validation_results"][method]
                        if not item.get("valid", False)
                    ]
                    if not result["payload_candidates"][method] or rejected:
                        raise ConfigError(
                            f"Static payload validation failed for {method}/{level}/{payload_mode}: "
                            f"{rejected or 'no accepted candidates'}"
                        )
                    checked += 1
    except (ConfigError, ValueError, KeyError) as exc:
        print(f"TESIS dry-run failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    print(
        f"TESIS dry-run passed: {checked} payload coordinate(s) validated; "
        f"AKG and runtime graph compiled from {Path(config_path)}."
    )
    return EXIT_OK


def _parse_dry_run(arguments: list[str]) -> str | None:
    """Return a config path for the one supported non-interactive command."""
    if not arguments or arguments[0] != "run" or "--dry-run" not in arguments:
        return None
    remaining = arguments[1:]
    if remaining == ["--dry-run"]:
        return "config.yaml"
    if len(remaining) == 3 and remaining[0] == "--dry-run" and remaining[1] == "--config":
        return remaining[2]
    if len(remaining) == 3 and remaining[0] == "--config" and remaining[2] == "--dry-run":
        return remaining[1]
    return None


def main(argv: Sequence[str] | None = None) -> int:
    """Launch the TUI or run deterministic preflight validation.

    ``python -m tesis run`` remains the interactive interface.  The documented
    ``python -m tesis run --dry-run --config config.yaml`` form is intentionally
    headless and performs no HTTP or model-provider calls.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    dry_run_config = _parse_dry_run(arguments)
    if dry_run_config is not None:
        return _dry_run(dry_run_config)
    if arguments != ["run"]:
        print(
            "Usage: python -m tesis run\n"
            "       python -m tesis run --dry-run [--config config.yaml]",
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
