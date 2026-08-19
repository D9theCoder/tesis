"""Launcher for the interactive TESIS application and offline validation."""

from __future__ import annotations

import argparse
import json
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


def _csv_values(raw: str) -> list[str]:
    return [part.strip() for part in str(raw).split(",") if part.strip()]


def _llm_concurrency(raw: str) -> int:
    """Parse the bounded LLM-only concurrency CLI value."""

    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("LLM concurrency must be an integer from 1 to 4") from exc
    if not 1 <= value <= 4:
        raise argparse.ArgumentTypeError("LLM concurrency must be from 1 to 4")
    return value


def _headless_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tesis run --headless",
        description="Run a single DVWA experiment or matrix without opening the TUI.",
    )
    parser.add_argument("--headless", "--non-interactive", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--mode", choices=("single", "matrix"))
    parser.add_argument("--target")
    parser.add_argument("--provider")
    parser.add_argument("--providers", type=_csv_values)
    parser.add_argument("--level")
    parser.add_argument("--levels", type=_csv_values)
    parser.add_argument("--surface")
    parser.add_argument("--surfaces", type=_csv_values)
    parser.add_argument("--payload-mode")
    parser.add_argument("--payload-modes", type=_csv_values)
    parser.add_argument("--condition", "--experiment-condition", dest="experiment_condition")
    parser.add_argument("--target-method")
    parser.add_argument("--model")
    parser.add_argument("--llm-max-concurrency", type=_llm_concurrency)
    parser.add_argument(
        "--llm-cache",
        dest="llm_cache",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Reuse successful validated LLM responses within this run.",
    )
    parser.add_argument("--orchestrator-model-profile")
    parser.add_argument("--orchestrator-model")
    parser.add_argument("--payload-model-profile")
    parser.add_argument("--payload-model")
    parser.add_argument("--repeats", type=int)
    parser.add_argument("--candidate-budget", type=int)
    parser.add_argument("--iterations", type=int)
    parser.add_argument("--stop-policy", choices=("impact", "coverage"))
    parser.add_argument("--coverage-target", type=float)
    parser.add_argument("--output-dir")
    parser.add_argument("--format", choices=("json", "markdown", "both"))
    parser.add_argument("--verbosity", dest="log_verbosity", choices=("debug", "info", "warning", "error"))
    parser.add_argument("--enriched-reporting", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--diagnose", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument(
        "--guardrail-enabled",
        dest="guardrail_retry_enabled",
        action=argparse.BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--guardrail-mode",
        dest="guardrail_handling",
        choices=("reactive", "proactive", "disabled"),
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Print a compact machine-readable result summary.",
    )
    return parser


def _headless_overrides(namespace: argparse.Namespace) -> dict[str, object]:
    values = vars(namespace)
    overrides: dict[str, object] = {}
    for key in (
        "target", "provider", "level", "surface", "payload_mode", "experiment_condition",
        "target_method", "repeats", "candidate_budget", "iterations", "stop_policy",
        "coverage_target", "output_dir", "format", "log_verbosity", "providers", "levels",
        "surfaces", "payload_modes", "enriched_reporting", "diagnose",
        "guardrail_retry_enabled", "guardrail_handling", "llm_max_concurrency", "llm_cache",
        "orchestrator_model_profile", "orchestrator_model", "payload_model_profile", "payload_model",
    ):
        value = values.get(key)
        if value is not None:
            overrides[key] = value
    if values.get("mode") is not None:
        overrides["matrix"] = values["mode"] == "matrix"
    if values.get("payload_mode") is not None and values.get("mode") == "matrix":
        overrides["payload_modes"] = [values["payload_mode"]]
    return overrides


def _headless_summary(result: dict[str, object], artifact_root: Path) -> dict[str, object]:
    summary: dict[str, object] = {
        "status": result.get("status", "unknown"),
        "artifact_dir": str(artifact_root),
        "manifest": str(artifact_root / "experiment.manifest.json"),
    }
    for key in ("execution_id", "run_id", "error", "matrix", "totals"):
        if key in result:
            summary[key] = result[key]
    return summary


def _headless_run(arguments: list[str]) -> int:
    parser = _headless_parser()
    try:
        namespace = parser.parse_args(arguments)
    except SystemExit as exc:
        return int(exc.code)

    from tesis.config_loader import ConfigError
    from tesis.headless import run_headless

    try:
        exit_code, result, artifact_root = run_headless(
            config_path=namespace.config,
            cli_args=_headless_overrides(namespace),
            model_name=namespace.model,
        )
    except KeyboardInterrupt:
        print("TESIS headless run cancelled", file=sys.stderr)
        return EXIT_OK
    except (ConfigError, ValueError, OSError) as exc:
        print(f"TESIS headless run failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    summary = _headless_summary(result, artifact_root)
    if namespace.json_output:
        print(json.dumps(summary, sort_keys=True))
    else:
        mode = "matrix" if namespace.mode == "matrix" or "totals" in result else "single run"
        print(f"TESIS {mode} {summary['status']}; artifacts: {summary['artifact_dir']}")
        if result.get("totals"):
            print(json.dumps(result["totals"], sort_keys=True))
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """Launch the TUI, deterministic preflight, or headless experiment runner.

    ``python -m tesis run`` remains the interactive interface.  The documented
    ``python -m tesis run --dry-run --config config.yaml`` form is intentionally
    safe and performs no HTTP or model-provider calls.  Add ``--headless`` plus
    explicit coordinate flags for automation or LLM-driven terminal execution.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    dry_run_config = _parse_dry_run(arguments)
    if dry_run_config is not None:
        return _dry_run(dry_run_config)
    if arguments and arguments[0] == "run" and (
        "--headless" in arguments or "--non-interactive" in arguments
    ):
        return _headless_run(arguments[1:])
    if arguments != ["run"]:
        print(
            "Usage: python -m tesis run\n"
            "       python -m tesis run --dry-run [--config config.yaml]\n"
            "       python -m tesis run --headless --mode single|matrix [options]",
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
