"""Stage 7 CLI interface for config-driven execution and reporting."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from core.state import MODULE_NAMES, SECURITY_LEVELS
from evaluation.multi_llm_runner import run_provider_matrix
from evaluation.reporter import write_json_report, write_markdown_report
from evaluation.runner import run_single_engagement
from llm.provider import SUPPORTED_PROVIDERS
from tesis.config_loader import (
    ConfigError,
    load_and_resolve_config,
    load_yaml_config,
    mask_secret,
    save_yaml_config,
)
from tesis.report_formatters import (
    format_module_scores_table,
    format_provider_comparison_table,
    format_rejection_table,
    format_rich_report_sections,
    parse_artifact_or_matrix,
)


LOGGER = logging.getLogger("tesis.cli")
SCHEMA_VERSION = "stage6.v1"

EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_TARGET_UNREACHABLE = 3


def setup_logging(*, verbose: bool = False, quiet: bool = False) -> None:
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def _preflight_target_reachable(url: str, timeout: float = 5.0) -> bool:
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        return response.status_code < 500
    except httpx.RequestError:
        return False


def _iso_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _summarize_totals(artifacts: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total_runs": len(artifacts),
        "successful_runs": sum(1 for item in artifacts if item.get("status") == "success"),
        "error_runs": sum(1 for item in artifacts if item.get("status") == "error"),
        "skipped_runs": sum(1 for item in artifacts if item.get("status") == "skipped"),
    }


def _write_run_artifacts(output_dir: Path, artifacts: list[dict[str, Any]]) -> list[Path]:
    paths: list[Path] = []
    runs_dir = output_dir / "runs"
    for artifact in artifacts:
        run_id = str(artifact.get("run_id", "unknown-run"))
        path = write_json_report(runs_dir / f"{run_id}.json", artifact)
        paths.append(path)
    return paths


def _print_resolved_config(config: Any) -> None:
    masked_models = {
        provider: {
            "model_name": model.model_name,
            "temperature": model.temperature,
            "timeout": model.timeout,
            "api_key": mask_secret(model.api_key),
        }
        for provider, model in config.models.items()
    }
    payload = {
        "target_url": config.target_url,
        "provider": config.provider,
        "level": config.level,
        "iterations": config.iterations,
        "repeats": config.repeats,
        "output_dir": config.output_dir,
        "matrix": config.matrix,
        "providers": config.providers,
        "levels": config.levels,
        "format": config.report_format,
        "enriched_reporting": config.enriched_reporting,
        "stop_policy": config.stop_policy,
        "coverage_target": config.coverage_target,
        "diagnose": config.diagnose,
        "models": masked_models,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


def _masked_config_payload(config: dict[str, Any]) -> dict[str, Any]:
    masked = json.loads(json.dumps(config))
    models = masked.get("models", {})
    if isinstance(models, dict):
        for provider in models:
            entry = models.get(provider)
            if isinstance(entry, dict) and "api_key" in entry:
                entry["api_key"] = mask_secret(str(entry.get("api_key", "")))
    return masked


def handle_run(args: argparse.Namespace) -> int:
    try:
        config = load_and_resolve_config(config_path=args.config, cli_args=vars(args))
    except ConfigError as exc:
        print(f"Config error: {exc}")
        return EXIT_CONFIG_ERROR

    if args.dry_run:
        print("Dry-run successful. Resolved configuration:")
        _print_resolved_config(config)
        return EXIT_OK

    if not _preflight_target_reachable(config.target_url):
        print(f"Target unreachable: {config.target_url}")
        return EXIT_TARGET_UNREACHABLE

    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        if config.matrix:
            result = run_provider_matrix(
                target_url=config.target_url,
                providers=config.providers,
                security_levels=config.levels,
                repeats=config.repeats,
                max_iterations=config.iterations,
                stop_policy=config.stop_policy,
                coverage_target=config.coverage_target,
                enriched_reporting=config.enriched_reporting,
                diagnose=config.diagnose,
                output_dir=str(output_dir / "runs"),
                include_aggregate=True,
            )
            if isinstance(result, tuple):
                artifacts, aggregate = result
            else:
                artifacts = result
                aggregate = {
                    "schema_version": SCHEMA_VERSION,
                    "totals": _summarize_totals(artifacts),
                    "runs": artifacts,
                    "by_provider_level": {},
                    "by_provider": {},
                }

            _write_run_artifacts(output_dir, artifacts)

            run_id = _iso_timestamp()
            reports_dir = output_dir / "reports"
            write_json_report(reports_dir / f"matrix_{run_id}.json", aggregate)
            if config.report_format in {"markdown", "both"}:
                write_markdown_report(reports_dir / f"matrix_{run_id}.md", aggregate)

            if not args.no_summary:
                print(format_provider_comparison_table({"runs": artifacts}))

            if aggregate.get("totals", {}).get("successful_runs", 0) == 0:
                return EXIT_RUNTIME_ERROR
            return EXIT_OK

        artifact = run_single_engagement(
            target_url=config.target_url,
            security_level=config.level,
            llm_provider=config.provider,
            max_iterations=config.iterations,
            repeat_index=0,
            stop_policy=config.stop_policy,
            coverage_target=config.coverage_target,
            enriched_reporting=config.enriched_reporting,
            diagnose=config.diagnose,
            output_dir=str(output_dir / "runs"),
        )
        _write_run_artifacts(output_dir, [artifact])

        if config.enriched_reporting:
            sidecar_base = output_dir / "runs" / f"{artifact['run_id']}"
            print(f"Rich sidecar: {sidecar_base}.rich.json")
            print(f"Events sidecar: {sidecar_base}.events.jsonl")
            if artifact.get("status") == "error":
                print(f"Failure artifact: {sidecar_base}.failure.json")

        if config.report_format in {"markdown", "both"}:
            summary_payload = {
                "schema_version": SCHEMA_VERSION,
                "totals": _summarize_totals([artifact]),
            }
            write_markdown_report(output_dir / "reports" / f"{artifact['run_id']}_summary.md", summary_payload)

        print(format_module_scores_table(artifact, show_chains=True))
        if artifact.get("status") == "error":
            return EXIT_RUNTIME_ERROR
        return EXIT_OK
    except ConfigError as exc:
        print(f"Config error: {exc}")
        return EXIT_CONFIG_ERROR
    except Exception as exc:  # pragma: no cover - guarded by tests via monkeypatch
        LOGGER.exception("Runtime failure")
        print(f"Runtime error: {exc}")
        return EXIT_RUNTIME_ERROR


def handle_info(args: argparse.Namespace) -> int:
    info = {
        "schema_version": SCHEMA_VERSION,
        "providers": list(SUPPORTED_PROVIDERS),
        "modules": list(MODULE_NAMES),
        "security_levels": list(SECURITY_LEVELS),
    }
    print(json.dumps(info, indent=2, sort_keys=True))
    return EXIT_OK


def handle_config(args: argparse.Namespace) -> int:
    try:
        config_path = Path(args.config)
        config = load_yaml_config(config_path)
        models = config.setdefault("models", {})
        changed = False

        if args.interactive:
            provider = (input("Provider name [gemini]: ").strip() or "gemini").lower()
            model = input("Model name [gemini-3-flash-preview]: ").strip() or "gemini-3-flash-preview"
            api_key = getpass.getpass("API key (input hidden): ")
            entry = models.setdefault(provider, {})
            entry["model_name"] = model
            if api_key:
                entry["api_key"] = api_key
            changed = True

        if args.set_provider:
            provider = args.set_provider.strip().lower()
            entry = models.setdefault(provider, {})
            if args.model:
                entry["model_name"] = args.model
            if args.api_key:
                entry["api_key"] = args.api_key
            changed = True

        if args.set_temperature:
            provider, raw_temp = args.set_temperature
            try:
                temperature = float(raw_temp)
            except ValueError as exc:
                raise ConfigError(f"Invalid temperature value: {raw_temp}") from exc
            entry = models.setdefault(provider.strip().lower(), {})
            entry["temperature"] = temperature
            changed = True

        if changed:
            save_yaml_config(config_path, config)
            print(f"Saved config changes to {config_path}")

        if args.list:
            for provider in sorted(models.keys()):
                model_name = models.get(provider, {}).get("model_name", "(unset)")
                print(f"{provider}: {model_name}")

        if args.show_keys:
            for provider in sorted(models.keys()):
                raw_key = str(models.get(provider, {}).get("api_key", ""))
                print(f"{provider}: {mask_secret(raw_key)}")

        if not any([args.list, args.show_keys, args.set_provider, args.set_temperature, args.interactive]):
            print(json.dumps(_masked_config_payload(config), indent=2, sort_keys=True))

        return EXIT_OK
    except ConfigError as exc:
        print(f"Config error: {exc}")
        return EXIT_CONFIG_ERROR
    except Exception as exc:  # pragma: no cover
        print(f"Runtime error: {exc}")
        return EXIT_RUNTIME_ERROR


def handle_report(args: argparse.Namespace) -> int:
    try:
        data = parse_artifact_or_matrix(args.artifact)
        show_rejections = bool(args.show_rejections)
        show_scores = bool(args.show_scores)
        if not show_rejections and not show_scores:
            show_scores = True

        sections: list[str] = []
        if show_rejections:
            sections.append(format_rejection_table(data, verbose=bool(args.verbose)))

        if show_scores:
            sections.append(
                format_module_scores_table(
                    data,
                    show_chains=bool(args.show_chains),
                    module_filter=args.module,
                    level_filter=args.level,
                )
            )
            runs = data.get("runs") if isinstance(data.get("runs"), list) else []
            if len(runs) > 1:
                sections.append(format_provider_comparison_table(data))

        rich_section = format_rich_report_sections(data)
        if rich_section and "No rich sidecar data available" not in rich_section:
            sections.append(rich_section)

        rendered = "\n\n".join(section for section in sections if section)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
            print(f"Wrote report output to {output_path}")
        else:
            print(rendered)
        return EXIT_OK
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Config error: {exc}")
        return EXIT_CONFIG_ERROR
    except Exception as exc:  # pragma: no cover
        print(f"Runtime error: {exc}")
        return EXIT_RUNTIME_ERROR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tesis", description="Stage 7 CLI for tesis framework")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a single or matrix engagement")
    run_parser.add_argument("--config", default="config.yaml", help="Path to YAML config file")
    run_parser.add_argument("--target", dest="target", help="Target URL")
    run_parser.add_argument("--level", choices=SECURITY_LEVELS, help="Security level")
    run_parser.add_argument("--provider", help="LLM provider")
    run_parser.add_argument("--iterations", type=int, help="Max iterations")
    run_parser.add_argument("--matrix", action="store_true", help="Run provider/level matrix")
    run_parser.add_argument("--providers", nargs="+", help="Providers for matrix mode")
    run_parser.add_argument("--levels", nargs="+", help="Security levels for matrix mode")
    run_parser.add_argument("--repeats", type=int, help="Repeats per provider/level")
    run_parser.add_argument("--output-dir", dest="output_dir", help="Output directory")
    run_parser.add_argument("--format", choices=["json", "markdown", "both"], help="Output format")
    run_parser.add_argument("--enriched-reporting", action="store_true", help="Write Stage 7.1 rich sidecar artifacts")
    run_parser.add_argument(
        "--stop-policy",
        choices=["impact", "coverage"],
        help="Orchestration stop policy",
    )
    run_parser.add_argument(
        "--coverage-target",
        type=float,
        help="Coverage target in [0.0, 1.0] when using coverage stop policy",
    )
    run_parser.add_argument("--diagnose", action="store_true", help="Attach quality diagnostics in report summary")
    run_parser.add_argument("--dry-run", action="store_true", help="Validate config and exit")
    run_parser.add_argument("--no-summary", action="store_true", help="Suppress stdout run summary")
    run_parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    run_parser.add_argument("--quiet", action="store_true", help="Reduce logging noise")
    run_parser.set_defaults(handler=handle_run)

    info_parser = subparsers.add_parser("info", help="Print framework metadata")
    info_parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    info_parser.add_argument("--quiet", action="store_true", help="Reduce logging noise")
    info_parser.set_defaults(handler=handle_info)

    config_parser = subparsers.add_parser("config", help="Inspect or update model configuration")
    config_parser.add_argument("--config", default="config.yaml", help="Path to YAML config file")
    config_parser.add_argument("--list", action="store_true", help="List configured providers")
    config_parser.add_argument("--set-provider", help="Provider key to set/update")
    config_parser.add_argument("--api-key", help="API key for --set-provider")
    config_parser.add_argument("--model", help="Model name for --set-provider")
    config_parser.add_argument(
        "--set-temperature",
        nargs=2,
        metavar=("PROVIDER", "TEMPERATURE"),
        help="Update model temperature for provider",
    )
    config_parser.add_argument("--interactive", action="store_true", help="Interactive provider setup")
    config_parser.add_argument("--show-keys", action="store_true", help="Show masked configured API keys")
    config_parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    config_parser.add_argument("--quiet", action="store_true", help="Reduce logging noise")
    config_parser.set_defaults(handler=handle_config)

    report_parser = subparsers.add_parser("report", help="Render artifact reports to stdout or file")
    report_parser.add_argument("artifact", help="Path to run artifact or matrix aggregate JSON")
    report_parser.add_argument("--show-rejections", action="store_true", help="Render rejection-rate table")
    report_parser.add_argument("--show-scores", action="store_true", help="Render module score table")
    report_parser.add_argument("--show-chains", action="store_true", help="Include chain column in score table")
    report_parser.add_argument("--module", help="Filter module names by substring")
    report_parser.add_argument("--level", help="Filter by security level")
    report_parser.add_argument("--output", help="Optional output file path")
    report_parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    report_parser.add_argument("--quiet", action="store_true", help="Reduce logging noise")
    report_parser.set_defaults(handler=handle_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=bool(getattr(args, "verbose", False)), quiet=bool(getattr(args, "quiet", False)))
    return int(args.handler(args))
