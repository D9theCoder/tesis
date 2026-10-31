"""Record live target/provider readiness evidence for one frozen epoch.

The readiness report cannot prove DVWA authentication, security-level control,
endpoint availability, containment behavior or provider reachability from
source alone.  This module performs one explicitly authorized benign probe per
required check and writes a timestamped, source-bound artifact.  It is never
imported by the readiness reporter; that reporter only validates recorded
evidence.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evaluation.research_plan import source_identity
from tesis.config_loader import load_and_resolve_config

ARTIFACT_TYPE = "autoresearch_live_readiness"
ARTIFACT_VERSION = "autoresearch-live-readiness.v1"


def _probe_profile(config: Any, profile_id: str) -> dict[str, Any]:
    """Make one benign structured request through the named model profile."""
    from tesis.doctor import _failed, _passed

    from llm.runtime import LLMRuntime

    profiles = {name: dataclasses.asdict(profile) for name, profile in config.models.items()}
    profile = profiles.get(profile_id)
    if profile is None:
        return _failed(
            f"live.model.{profile_id}", "live-model",
            "Model probe skipped because the profile is not configured",
            f"profile={profile_id}",
            "Configure the profile before readiness.",
        ).as_dict()
    role_settings = {
        name: dataclasses.asdict(settings)
        for name, settings in config.llm_runtime.roles.items()
    }
    role_settings["orchestrator"] = {
        **role_settings.get("orchestrator", {}),
        "model_profile": profile_id,
    }
    schema = {
        "title": "TesisLiveReadinessProbe",
        "type": "object",
        "properties": {"status": {"type": "string", "enum": ["ok"]}},
        "required": ["status"],
        "additionalProperties": False,
    }

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        if payload != {"status": "ok"}:
            raise ValueError("provider probe did not return exactly the requested status schema")
        return {"status": "ok"}

    runtime = LLMRuntime(
        max_concurrency=1,
        rate_limit_config=dataclasses.asdict(config.llm_runtime),
    )
    try:
        with runtime.coordinate(
            coordinate_id=f"live-readiness-{profile_id}",
            default_provider=config.provider,
            default_model_config=profile,
            model_profiles=profiles,
            role_settings=role_settings,
            cache_enabled=False,
        ) as context:
            _, options, _ = context.role_config("orchestrator", max_tokens=256)
            budget = int(options["max_tokens"])
            result = runtime.invoke(
                context=context,
                role="orchestrator",
                system_message="Return the requested health-check JSON only.",
                user_message='Return exactly {"status":"ok"}.',
                schema=schema,
                schema_version="live-readiness-probe.v1",
                validator=validate,
                max_tokens=budget,
            )
        performance = result.performance if isinstance(result.performance, dict) else {}
        effort = performance.get("reasoning_effort_requested") or "provider-default"
        usage = performance.get("provider_usage") or {}
        return _passed(
            f"live.model.{profile_id}", "live-model",
            "Provider returned valid structured output",
            f"profile={profile_id}; provider={profile.get('provider')}; "
            f"model={profile.get('model_name')}; requested_effort={effort}; "
            f"usage_fields={','.join(sorted(map(str, usage)))}",
        ).as_dict()
    except Exception as exc:  # noqa: BLE001 - a failed probe is retained evidence
        return _failed(
            f"live.model.{profile_id}", "live-model",
            f"Provider probe failed for profile {profile_id}",
            f"profile={profile_id}; provider={profile.get('provider')}; "
            f"error={type(exc).__name__}: {exc}",
            "Verify credential, endpoint, model name and reasoning settings.",
        ).as_dict()
    finally:
        runtime.close()


def collect_live_readiness(
    *,
    config_path: str,
    epoch_id: str,
    output_path: str | Path,
    repo_root: str | Path = ".",
) -> dict[str, Any]:
    """Run the authorized live checks and write one source-bound artifact."""
    from tesis.doctor import _check_containment, _dvwa_live_checks

    config = load_and_resolve_config(config_path=config_path, cli_args={})
    checks = [_check_containment(config).as_dict()]
    checks.extend(check.as_dict() for check in _dvwa_live_checks(config))
    for profile_id in sorted(config.providers or config.models):
        checks.append(_probe_profile(config, str(profile_id)))
    identity = source_identity(
        repository_root=Path(repo_root).resolve(),
        config_path=config_path,
    )
    document = {
        "artifact_type": ARTIFACT_TYPE,
        "artifact_version": ARTIFACT_VERSION,
        "epoch_id": epoch_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_url": config.target_url,
        "config_path": str(Path(config_path).resolve()),
        "config_sha256": identity.get("config_sha256"),
        "source_hashes_sha256": identity["source_hashes_sha256"],
        "checks": checks,
        "provider_profiles": sorted(config.providers or []),
        "note": (
            "One benign probe per check under the owner-approved study. This artifact "
            "records readiness only; it is not an experiment result."
        ),
    }
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(target)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--epoch-id", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repo-root", default=".")
    args = parser.parse_args(argv)
    document = collect_live_readiness(
        config_path=args.config,
        epoch_id=args.epoch_id,
        output_path=args.output,
        repo_root=args.repo_root,
    )
    failed = [check["id"] for check in document["checks"] if check.get("status") != "passed"]
    print(json.dumps({
        "output": str(Path(args.output).resolve()),
        "checks": len(document["checks"]),
        "failed": failed,
    }, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
