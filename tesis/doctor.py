"""Deterministic diagnostics for the TESIS runtime and its optional live services."""

from __future__ import annotations

import argparse
import dataclasses
import importlib
import json
import logging
import os
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit

from core.graph_builder import RUNTIME_AGENT_NODE_NAMES, build_framework
from core.knowledge_graph import AKGValidationError, AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE, SECURITY_LEVELS, SURFACES, new_default_state
from foundation.http_client import ContainmentError, HTTPClient
from foundation.payload_library import PayloadLibrary
from foundation.payload_validator import validate_payload_candidates
from llm.provider import SUPPORTED_PROVIDERS
from tesis.model_config import (
    EngagementConfig,
    LLM_RUNTIME_ROLES,
    PAYLOAD_MODES,
    REASONING_EFFORTS,
)

EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_USAGE_ERROR = 2

# Mirrors the fallback in llm.provider.get_llm for the OpenAI-compatible adapter.
_OPENAI_COMPATIBLE_BASE_URL_ENV = "OPENAI_COMPATIBLE_BASE_URL"

_EXPERIMENT_CONDITIONS = ("linear_hybrid", "akg_guided_hybrid")
_REQUIRED_IMPORTS: tuple[tuple[str, str], ...] = (
    ("langchain", "langchain"),
    ("langgraph", "langgraph"),
    ("langchain-google-genai", "langchain_google_genai"),
    ("langchain-openai", "langchain_openai"),
    ("langchain-anthropic", "langchain_anthropic"),
    ("python-dotenv", "dotenv"),
    ("pydantic", "pydantic"),
    ("httpx", "httpx"),
    ("beautifulsoup4", "bs4"),
    ("networkx", "networkx"),
    ("pyyaml", "yaml"),
    ("rich", "rich"),
    ("textual", "textual"),
    ("ruamel-yaml", "ruamel.yaml"),
    ("scipy", "scipy"),
)


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One stable, JSON-safe Doctor result."""

    id: str
    category: str
    status: str
    summary: str
    details: str = ""
    remediation: str = ""

    def as_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)


def _passed(check_id: str, category: str, summary: str, details: str = "") -> DoctorCheck:
    return DoctorCheck(check_id, category, "passed", summary, details)


def _failed(
    check_id: str,
    category: str,
    summary: str,
    details: str = "",
    remediation: str = "",
) -> DoctorCheck:
    return DoctorCheck(check_id, category, "failed", summary, details, remediation)


def _skipped(check_id: str, category: str, summary: str, details: str = "") -> DoctorCheck:
    return DoctorCheck(check_id, category, "skipped", summary, details)


def _safe_check(
    check_id: str,
    category: str,
    remediation: str,
    operation: Callable[[], DoctorCheck],
) -> DoctorCheck:
    """Turn an unexpected check-local exception into an accumulated failure."""

    try:
        return operation()
    except Exception as exc:
        return _failed(
            check_id,
            category,
            f"{type(exc).__name__}: {exc}",
            remediation=remediation,
        )


def _registered_experiment_conditions() -> frozenset[str]:
    """Return the conditions the config loader validates ``experiment_condition`` against.

    Imported inside the check so the Doctor compares the fixed contract with the
    registry that is actually on disk instead of a second copy of the literal.
    """

    from tesis.config_loader import _VALID_EXPERIMENT_CONDITIONS

    return frozenset(_VALID_EXPERIMENT_CONDITIONS)


def _check_coverage() -> DoctorCheck:
    expected_surfaces = {"sqli", "access_control", "brute_force"}
    expected_methods = {
        "sqli_union",
        "sqli_error",
        "sqli_boolean_blind",
        "sqli_time_blind",
        "ac_idor",
        "ac_vertical_escalation",
        "ac_force_browse",
        "bf_dictionary",
        "bf_spray",
    }
    expected_levels = {"low", "medium", "high"}
    expected_modes = {"static_only", "hybrid", "llm_mutation_only"}
    expected_conditions = set(_EXPERIMENT_CONDITIONS)
    methods = {method for values in METHODS_BY_SURFACE.values() for method in values}
    actual = {
        "surfaces": set(SURFACES),
        "methods": methods,
        "levels": set(SECURITY_LEVELS),
        "payload_modes": set(PAYLOAD_MODES),
        "conditions": set(_registered_experiment_conditions()),
    }
    expected = {
        "surfaces": expected_surfaces,
        "methods": expected_methods,
        "levels": expected_levels,
        "payload_modes": expected_modes,
        "conditions": expected_conditions,
    }
    details = (
        f"surfaces={len(actual['surfaces'])}; methods={len(actual['methods'])}; "
        f"security_levels={len(actual['levels'])}; payload_modes={len(actual['payload_modes'])}; "
        f"experiment_conditions={len(actual['conditions'])}"
    )
    mismatches = [
        f"{name}: expected={sorted(expected[name])}, actual={sorted(actual[name])}"
        for name in expected
        if actual[name] != expected[name]
    ]
    if mismatches or set(RUNTIME_AGENT_NODE_NAMES) != expected_methods:
        if set(RUNTIME_AGENT_NODE_NAMES) != expected_methods:
            mismatches.append(
                "runtime agents: expected="
                f"{sorted(expected_methods)}, actual={sorted(RUNTIME_AGENT_NODE_NAMES)}"
            )
        return _failed(
            "coverage.scope",
            "coverage",
            "In-scope experiment coverage is incomplete",
            f"{details}. {'; '.join(mismatches)}",
            "Restore the fixed TESIS scope in core.state, core.graph_builder, and tesis.model_config.",
        )
    return _passed(
        "coverage.scope",
        "coverage",
        "All fixed experiment axes are represented",
        details,
    )


def _check_akg() -> DoctorCheck:
    graph = AttackKnowledgeGraph()
    method_profiles = sum(
        isinstance(graph.graph.nodes[method].get("payload_profile"), dict)
        for method in RUNTIME_AGENT_NODE_NAMES
    )
    preconditions = sum(
        len(metadata.get("preconditions", ()))
        for _source, _target, metadata in graph.graph.edges(data=True)
    )
    details = (
        f"nodes={graph.graph.number_of_nodes()}; edges={graph.graph.number_of_edges()}; "
        f"method_preconditions={sum(len(value) for value in graph.METHOD_PRECONDITIONS.values())}; "
        f"edge_preconditions={preconditions}; payload_profiles={method_profiles}"
    )
    return _passed("akg.integrity", "akg", "Static AKG invariants are valid", details)


def _check_graph(config: EngagementConfig) -> DoctorCheck:
    compiled = build_framework(llm_provider=config.provider, surface=config.surface)
    if compiled is None:
        raise RuntimeError("build_framework returned no compiled graph")
    return _passed(
        "graph.compilation",
        "runtime",
        "Canonical LangGraph compiled without invoking a node",
        f"provider={config.provider}; surface={config.surface}; method_nodes={len(RUNTIME_AGENT_NODE_NAMES)}",
    )


def _check_static_seeds() -> DoctorCheck:
    library = PayloadLibrary()
    checked = 0
    candidates_checked = 0
    failures: list[str] = []
    methods = [method for surface in SURFACES for method in METHODS_BY_SURFACE[surface]]
    for method in methods:
        for level in SECURITY_LEVELS:
            for payload_mode in sorted(PAYLOAD_MODES):
                seeds = library.load_seed_candidates(method, level)
                result = validate_payload_candidates({
                    **new_default_state(),
                    "selected_method": method,
                    "security_level": level,
                    "payload_mode": payload_mode,
                    "payload_candidates": {method: seeds},
                })
                validation_rows = result.get("payload_validation_results", {}).get(method, [])
                accepted = result.get("payload_candidates", {}).get(method, [])
                rejected = [row for row in validation_rows if not row.get("valid", False)]
                checked += 1
                candidates_checked += len(validation_rows)
                if not accepted or rejected:
                    reason = rejected or "no accepted candidates"
                    failures.append(f"{method}/{level}/{payload_mode}: {reason}")
    details = f"validated_coordinates={checked}; validation_rows={candidates_checked}"
    if failures:
        return _failed(
            "payload.static_seeds",
            "payloads",
            f"Static seed validation failed in {len(failures)} coordinate(s)",
            f"{details}; failures={' | '.join(failures)}",
            "Repair the handwritten seed metadata or its AKG payload profile; do not bypass validation.",
        )
    return _passed(
        "payload.static_seeds",
        "payloads",
        "Static seeds were accepted at every method/level/mode coordinate",
        details,
    )


def _host_display(value: str) -> str:
    """Return the host and port of *value*, never its userinfo credentials."""

    parsed = urlparse(str(value))
    if not parsed.hostname:
        return "missing"
    try:
        port = parsed.port
    except ValueError:
        port = None
    return parsed.hostname if port is None else f"{parsed.hostname}:{port}"


def _check_containment(config: EngagementConfig) -> DoctorCheck:
    client = HTTPClient(config.target_url)
    blocked: list[str] = []
    failures: list[str] = []
    containment_logger = logging.getLogger("foundation.http_client")
    was_disabled = containment_logger.disabled
    containment_logger.disabled = True
    try:
        for kind in ("request", "redirect"):
            try:
                client._assert_in_scope("https://example.invalid/doctor-containment", kind=kind)
            except ContainmentError as exc:
                if exc.kind == kind:
                    blocked.append(kind)
                else:
                    failures.append(f"{kind} classified as {exc.kind}")
            else:
                failures.append(f"external {kind} was not blocked")
    finally:
        containment_logger.disabled = was_disabled
        client.close()
    if failures:
        return _failed(
            "containment.http",
            "safety",
            "HTTP target containment did not enforce every boundary",
            "; ".join(failures),
            "Restore same-host request and redirect enforcement in foundation.http_client.HTTPClient.",
        )
    return _passed(
        "containment.http",
        "safety",
        "External requests and redirects are blocked",
        f"configured_host={_host_display(config.target_url)}; blocked={','.join(blocked)}",
    )


def _profile_for_role(config: EngagementConfig, role_name: str) -> tuple[str, Any | None]:
    role = config.llm_runtime.roles[role_name]
    profile_name = role.model_profile or config.model_profile or config.provider
    return str(profile_name), config.models.get(str(profile_name))


def _check_profiles_and_roles(config: EngagementConfig) -> DoctorCheck:
    problems: list[str] = []
    if not config.models:
        problems.append("no model profiles are configured")
    for profile_name, profile in config.models.items():
        provider = str(profile.provider).strip().lower()
        if provider not in SUPPORTED_PROVIDERS:
            problems.append(f"profile {profile_name!r} uses unsupported provider {provider!r}")
        if not str(profile.model_name).strip():
            problems.append(f"profile {profile_name!r} has no model_name")
    missing_roles = sorted(set(LLM_RUNTIME_ROLES) - set(config.llm_runtime.roles))
    if missing_roles:
        problems.append(f"required runtime roles are missing: {','.join(missing_roles)}")
    resolved_roles: list[str] = []
    for role_name in sorted(config.llm_runtime.roles):
        profile_name, profile = _profile_for_role(config, role_name)
        if profile is None:
            problems.append(f"role {role_name!r} references missing profile {profile_name!r}")
        else:
            resolved_roles.append(f"{role_name}->{profile_name}")
    details = f"profiles={len(config.models)}; roles={len(config.llm_runtime.roles)}; resolved={','.join(resolved_roles) or 'none'}"
    if problems:
        return _failed(
            "config.profiles_roles",
            "configuration",
            "Configured model profiles or role mappings are invalid",
            f"{details}; problems={' | '.join(problems)}",
            "Define every referenced models.<profile> with a supported provider and non-empty model_name.",
        )
    return _passed(
        "config.profiles_roles",
        "configuration",
        "Configured model profiles and role mappings resolve",
        details,
    )


def _check_credentials(config: EngagementConfig) -> DoctorCheck:
    missing = [name for name, profile in config.models.items() if not str(profile.api_key).strip()]
    if not config.models:
        missing.append("<no model profiles>")
    if missing:
        return _failed(
            "config.credentials",
            "configuration",
            "One or more model credentials did not resolve",
            f"profiles_missing_credentials={','.join(sorted(missing))}; configured_profiles={len(config.models)}",
            "Set the documented provider API-key environment variable, a ${VAR} config reference, or the profile api_key secret.",
        )
    return _passed(
        "config.credentials",
        "configuration",
        "Credentials resolved for every configured model profile",
        f"credential_profiles={len(config.models)}; secret_values=redacted",
    )


def _valid_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname)


def _effective_base_url(profile: Any) -> tuple[str, str]:
    """Return ``(base_url, source)`` for one profile, mirroring llm.provider.

    ``ChatOpenAI`` for the OpenAI-compatible adapter falls back to
    ``OPENAI_COMPATIBLE_BASE_URL`` when the profile has no endpoint, so the
    Doctor must accept the same environment-provided endpoint.
    """

    configured = str(profile.base_url or "").strip()
    if configured:
        return configured, "config"
    if str(profile.provider).strip().lower() == "openai_compatible":
        from_environment = os.getenv(_OPENAI_COMPATIBLE_BASE_URL_ENV, "").strip()
        if from_environment:
            return from_environment, "environment"
    return "", "missing"


def _check_endpoints(config: EngagementConfig) -> DoctorCheck:
    problems: list[str] = []
    if not _valid_http_url(config.target_url):
        problems.append("target_url is not a well-formed HTTP(S) URL")
    configured_endpoints = 0
    sources: list[str] = []
    for profile_name, profile in config.models.items():
        base_url, source = _effective_base_url(profile)
        if base_url:
            configured_endpoints += 1
            sources.append(f"{profile_name}={source}")
            if not _valid_http_url(base_url):
                problems.append(
                    f"profile {profile_name!r} base_url ({source}) is not a well-formed HTTP(S) URL"
                )
        elif str(profile.provider).strip().lower() == "openai_compatible":
            problems.append(
                f"OpenAI-compatible profile {profile_name!r} requires base_url "
                f"(models.{profile_name}.base_url or {_OPENAI_COMPATIBLE_BASE_URL_ENV})"
            )
    details = (
        f"target_host={_host_display(config.target_url)}; "
        f"configured_model_endpoints={configured_endpoints}; "
        f"endpoint_sources={','.join(sources) or 'none'}"
    )
    if problems:
        return _failed(
            "config.endpoints",
            "configuration",
            "Configured target or model endpoints are invalid",
            f"{details}; problems={' | '.join(problems)}",
            "Use absolute http:// or https:// URLs and configure base_url for OpenAI-compatible profiles.",
        )
    return _passed(
        "config.endpoints",
        "configuration",
        "Target and model endpoints are well formed",
        details,
    )


def _check_dependencies() -> DoctorCheck:
    missing: list[str] = []
    for distribution, module_name in _REQUIRED_IMPORTS:
        try:
            importlib.import_module(module_name)
        except (ImportError, ModuleNotFoundError) as exc:
            missing.append(f"{distribution} ({type(exc).__name__})")
    if missing:
        return _failed(
            "environment.dependencies",
            "environment",
            "Required Python dependencies are unavailable",
            f"missing={', '.join(missing)}; checked={len(_REQUIRED_IMPORTS)}",
            "Synchronize the Python 3.12 environment from pyproject.toml (for example, uv sync).",
        )
    return _passed(
        "environment.dependencies",
        "environment",
        "Required third-party modules import successfully",
        f"imports_checked={len(_REQUIRED_IMPORTS)}",
    )


def _path_is_writable(path: Path) -> tuple[bool, Path]:
    """Check an output path without creating or rewriting user files."""

    candidate = path.expanduser()
    if candidate.exists():
        return candidate.is_dir() and os.access(candidate, os.W_OK | os.X_OK), candidate
    ancestor = candidate
    while not ancestor.exists() and ancestor != ancestor.parent:
        ancestor = ancestor.parent
    return ancestor.is_dir() and os.access(ancestor, os.W_OK | os.X_OK), ancestor


def _check_output(config: EngagementConfig) -> DoctorCheck:
    output = Path(config.output_dir)
    writable, checked_path = _path_is_writable(output)
    if not writable:
        return _failed(
            "output.writability",
            "artifacts",
            "Configured artifact directory is not writable or creatable",
            f"output_dir={output}; nearest_existing_path={checked_path}",
            "Create the output directory or grant write and traversal permission to its nearest existing parent.",
        )
    state = "exists" if output.expanduser().exists() else "creatable"
    return _passed(
        "output.writability",
        "artifacts",
        "Configured artifact directory is writable",
        f"output_dir={output}; state={state}; layout_root={output / 'runs'}",
    )


def _effective_reasoning(config: EngagementConfig, role_name: str) -> tuple[str, str, str]:
    role = config.llm_runtime.roles[role_name]
    profile_name, profile = _profile_for_role(config, role_name)
    effort = role.reasoning_effort
    if effort is None and profile is not None:
        effort = profile.reasoning_effort
    provider = str(profile.provider if profile is not None else profile_name).strip().lower()
    return str(effort or "provider-default"), profile_name, provider


def _check_reasoning(config: EngagementConfig) -> DoctorCheck:
    problems: list[str] = []
    requested: list[str] = []
    for role_name in sorted(config.llm_runtime.roles):
        effort, profile_name, provider = _effective_reasoning(config, role_name)
        requested.append(f"{role_name}={effort} ({profile_name}/{provider})")
        if effort != "provider-default" and effort not in REASONING_EFFORTS:
            problems.append(f"role {role_name!r} requests invalid effort {effort!r}")
        if effort != "provider-default" and provider in {"gemini", "claude"}:
            problems.append(
                f"role {role_name!r} requests {effort!r} for {provider}, whose adapter cannot forward portable reasoning_effort"
            )
    details = f"roles={len(requested)}; requested_effort={'; '.join(requested)}"
    if problems:
        return _failed(
            "reasoning.controls",
            "models",
            "Reasoning controls cannot be forwarded as configured",
            f"{details}; problems={' | '.join(problems)}",
            "Use null/provider-default plus native thinking parameters for Gemini/Claude, or select an OpenAI-compatible reasoning profile.",
        )
    return _passed(
        "reasoning.controls",
        "models",
        "Reasoning effort settings are valid for their providers",
        details,
    )


def _model_probe_checks(config: EngagementConfig) -> list[DoctorCheck]:
    """Make one benign structured request for each configured runtime role."""

    from llm.runtime import LLMRuntime

    profiles = {name: dataclasses.asdict(profile) for name, profile in config.models.items()}
    role_settings = {
        name: dataclasses.asdict(settings) for name, settings in config.llm_runtime.roles.items()
    }
    default_model = profiles.get(config.provider, {})
    runtime = LLMRuntime(max_concurrency=1)
    checks: list[DoctorCheck] = []
    schema = {
        "title": "TesisDoctorProbe",
        "type": "object",
        "properties": {"status": {"type": "string", "enum": ["ok"]}},
        "required": ["status"],
        "additionalProperties": False,
    }

    def validate(payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("status") != "ok":
            raise ValueError("provider probe did not return status=ok")
        return {"status": "ok"}

    try:
        for role_name in sorted(config.llm_runtime.roles):
            check_id = f"live.model.{role_name}"
            profile_name, profile = _profile_for_role(config, role_name)
            if profile is None:
                checks.append(_skipped(
                    check_id,
                    "live-model",
                    "Model probe skipped because the role profile is unresolved",
                    f"role={role_name}; profile={profile_name}",
                ))
                continue
            if not str(profile.api_key).strip():
                checks.append(_skipped(
                    check_id,
                    "live-model",
                    "Model probe skipped because credentials are unavailable",
                    f"role={role_name}; profile={profile_name}; provider={profile.provider}",
                ))
                continue
            try:
                with runtime.coordinate(
                    coordinate_id=f"doctor-{role_name}",
                    default_provider=config.provider,
                    default_model_config=default_model,
                    model_profiles=profiles,
                    role_settings=role_settings,
                    cache_enabled=False,
                ) as context:
                    result = runtime.invoke(
                        context=context,
                        role=role_name,
                        system_message="Return the requested health-check JSON only.",
                        user_message='Return exactly {"status":"ok"}.',
                        schema=schema,
                        schema_version="doctor-probe.v1",
                        validator=validate,
                        max_tokens=32,
                    )
                usage = result.performance.get("provider_usage") or {}
                evidence = result.performance.get("reasoning_token_evidence")
                effort = result.performance.get("reasoning_effort_requested") or "provider-default"
                common = (
                    f"role={role_name}; profile={profile_name}; provider={profile.provider}; "
                    f"requested_effort={effort}; provider_responded=true"
                )
                if not usage:
                    checks.append(_skipped(
                        check_id,
                        "live-model",
                        "Provider responded, but usage telemetry is unavailable",
                        f"{common}; reasoning_tokens=unknown (provider usage missing)",
                    ))
                elif not evidence:
                    checks.append(_passed(
                        check_id,
                        "live-model",
                        "Provider returned valid structured output and usage telemetry",
                        f"{common}; reasoning_tokens=not_reported; provider_side_reasoning=unverified; "
                        f"usage_fields={','.join(sorted(map(str, usage)))}",
                    ))
                else:
                    checks.append(_passed(
                        check_id,
                        "live-model",
                        "Provider returned valid structured output and reasoning-token usage",
                        f"{common}; reasoning_tokens={evidence.get('tokens')}; evidence={evidence.get('source')}",
                    ))
            except Exception as exc:
                checks.append(_failed(
                    check_id,
                    "live-model",
                    f"Provider probe failed for role {role_name}",
                    f"role={role_name}; profile={profile_name}; provider={profile.provider}; error={type(exc).__name__}: {exc}",
                    "Verify the profile credential, endpoint, model name, structured-output support, and reasoning settings.",
                ))
    finally:
        runtime.close()
    return checks


def _dvwa_live_checks(config: EngagementConfig) -> list[DoctorCheck]:
    from foundation.session_manager import DVWASession

    ids = ("live.dvwa.authentication", "live.dvwa.levels", "live.dvwa.surfaces")
    if not str(config.target_url).strip():
        reason = "target_url is unavailable"
        return [_skipped(check_id, "live-dvwa", "DVWA check skipped", reason) for check_id in ids]

    username = str(getattr(config, "dvwa_username", "admin") or "").strip()
    password = str(getattr(config, "dvwa_password", "password") or "")
    if not username or not password:
        reason = "DVWA credentials are unavailable"
        return [_skipped(check_id, "live-dvwa", "DVWA check skipped", reason) for check_id in ids]

    try:
        session = DVWASession(config.target_url)
    except Exception as exc:
        return [
            _failed(
                ids[0],
                "live-dvwa",
                "Could not initialize the contained DVWA session",
                f"error={type(exc).__name__}: {exc}",
                "Verify target_url and local DVWA reachability.",
            ),
            _skipped(ids[1], "live-dvwa", "Security-level check skipped", "authentication session unavailable"),
            _skipped(ids[2], "live-dvwa", "Surface check skipped", "authentication session unavailable"),
        ]

    checks: list[DoctorCheck] = []
    try:
        try:
            authenticated = bool(session.login(username, password))
        except Exception as exc:
            checks.append(_failed(
                ids[0],
                "live-dvwa",
                "DVWA authentication request failed",
                f"target_host={_host_display(config.target_url)}; error={type(exc).__name__}: {exc}",
                "Verify the contained DVWA URL, service state, and configured credentials.",
            ))
            authenticated = False
        else:
            if authenticated:
                checks.append(_passed(
                    ids[0],
                    "live-dvwa",
                    "DVWA authentication succeeded",
                    f"target_host={_host_display(config.target_url)}; username_configured=true; password=redacted",
                ))
            else:
                checks.append(_failed(
                    ids[0],
                    "live-dvwa",
                    "DVWA authentication was rejected",
                    f"target_host={_host_display(config.target_url)}; username_configured=true; password=redacted",
                    "Verify the configured DVWA username/password and reset the local lab if necessary.",
                ))
        if not authenticated:
            checks.append(_skipped(ids[1], "live-dvwa", "Security-level check skipped", "DVWA authentication did not succeed"))
            checks.append(_skipped(ids[2], "live-dvwa", "Surface check skipped", "DVWA authentication did not succeed"))
            return checks

        level_failures: list[str] = []
        available_levels: list[str] = []
        for level in SECURITY_LEVELS:
            try:
                session.set_security_level(level)
                detected = session.detect_security_level()
                if detected == level:
                    available_levels.append(level)
                else:
                    level_failures.append(f"{level}: detected={detected}")
            except Exception as exc:
                level_failures.append(f"{level}: {type(exc).__name__}: {exc}")
        if level_failures:
            checks.append(_failed(
                ids[1],
                "live-dvwa",
                "One or more DVWA security levels are unavailable",
                f"available={','.join(available_levels) or 'none'}; failures={' | '.join(level_failures)}",
                "Enable low, medium, and high in the contained DVWA instance and verify security.php.",
            ))
        else:
            checks.append(_passed(
                ids[1],
                "live-dvwa",
                "All configured DVWA security levels are available",
                f"levels={','.join(available_levels)}; count={len(available_levels)}",
            ))

        surface_specs = {
            "sqli": ("vulnerabilities/sqli/", ("sql injection", "user id")),
            "access_control": ("vulnerabilities/authbypass/", ("auth", "user id", "access control")),
            "brute_force": ("vulnerabilities/brute/", ("brute force", "username")),
        }
        available_surfaces: list[str] = []
        surface_failures: list[str] = []
        for surface, (path, markers) in surface_specs.items():
            try:
                response = session.http.get(path)
                body = str(response.text).lower()
                if response.status_code == 200 and any(marker in body for marker in markers):
                    available_surfaces.append(surface)
                else:
                    surface_failures.append(
                        f"{surface}: status={response.status_code}, expected_marker=false"
                    )
            except Exception as exc:
                surface_failures.append(f"{surface}: {type(exc).__name__}: {exc}")
        if surface_failures:
            checks.append(_failed(
                ids[2],
                "live-dvwa",
                "One or more in-scope DVWA surfaces are unavailable",
                f"available={','.join(available_surfaces) or 'none'}; failures={' | '.join(surface_failures)}",
                "Install/enable the expected DVWA SQLi, auth-bypass, and brute-force pages at the configured base URL.",
            ))
        else:
            checks.append(_passed(
                ids[2],
                "live-dvwa",
                "All in-scope DVWA surfaces returned expected markers",
                f"surfaces={','.join(available_surfaces)}; count={len(available_surfaces)}",
            ))
    finally:
        session.close()
    return checks


def _known_secrets(config: EngagementConfig) -> tuple[str, ...]:
    values = [str(profile.api_key) for profile in config.models.values() if profile.api_key]
    password = getattr(config, "dvwa_password", None)
    if password:
        values.append(str(password))
    return tuple(sorted(set(values), key=len, reverse=True))


def _redact_text(value: str, secrets: Sequence[str]) -> str:
    redacted = str(value)
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "<redacted>")
    # Credentials embedded in URL userinfo (scheme://user:pass@host) are not
    # query values, so they need their own pass before the key/value scrub.
    redacted = re.sub(r"(?i)(https?://)[^/@\s]+@", r"\1<redacted>@", redacted)
    redacted = re.sub(
        r"(?i)((?:authorization|api[_-]?key|password|passwd|secret|token|session|cookie)"
        r"\s*[:=]\s*(?:bearer\s+)?)[^\s,;]+",
        r"\1<redacted>",
        redacted,
    )

    def scrub_url(match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            parsed = urlsplit(raw)
        except ValueError:
            return raw
        if not parsed.query and not parsed.fragment:
            return raw
        return urlunsplit((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "<redacted>" if parsed.query else "",
            "<redacted>" if parsed.fragment else "",
        ))

    return re.sub(r"https?://[^\s,;]+", scrub_url, redacted)


def _redact_report(report: dict[str, Any], secrets: Sequence[str]) -> dict[str, Any]:
    def scrub(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): scrub(item) for key, item in value.items()}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, str):
            return _redact_text(value, secrets)
        return value

    return scrub(report)


def _build_report(checks: Sequence[DoctorCheck], *, secrets: Sequence[str] = ()) -> dict[str, Any]:
    rows = [check.as_dict() for check in checks]
    passed = sum(row["status"] == "passed" for row in rows)
    failed = sum(row["status"] == "failed" for row in rows)
    skipped = sum(row["status"] == "skipped" for row in rows)
    report = {
        "status": "failed" if failed else "passed",
        "summary": {
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "total": len(rows),
        },
        "checks": rows,
    }
    return _redact_report(report, secrets)


def run_doctor(config: EngagementConfig, *, live: bool = False) -> dict[str, Any]:
    """Run independent offline checks and optional explicit live probes."""

    checks = [
        _safe_check(
            "coverage.scope",
            "coverage",
            "Restore the fixed scope constants and registered method nodes.",
            _check_coverage,
        ),
        _safe_check(
            "akg.integrity",
            "akg",
            "Repair the invariant identified by AKGValidationError in core.knowledge_graph.",
            _check_akg,
        ),
        _safe_check(
            "graph.compilation",
            "runtime",
            "Repair the canonical topology in core.graph_builder without invoking runtime nodes.",
            lambda: _check_graph(config),
        ),
        _safe_check(
            "payload.static_seeds",
            "payloads",
            "Repair static seed metadata or AKG payload profiles.",
            _check_static_seeds,
        ),
        _safe_check(
            "containment.http",
            "safety",
            "Restore request and redirect same-host checks in foundation.http_client.",
            lambda: _check_containment(config),
        ),
        _safe_check(
            "config.profiles_roles",
            "configuration",
            "Define every role's model profile under models.",
            lambda: _check_profiles_and_roles(config),
        ),
        _safe_check(
            "config.credentials",
            "configuration",
            "Resolve provider API keys through documented environment variables or secret references.",
            lambda: _check_credentials(config),
        ),
        _safe_check(
            "config.endpoints",
            "configuration",
            "Use valid absolute HTTP(S) target and provider endpoint URLs.",
            lambda: _check_endpoints(config),
        ),
        _safe_check(
            "environment.dependencies",
            "environment",
            "Synchronize the Python 3.12 environment from pyproject.toml.",
            _check_dependencies,
        ),
        _safe_check(
            "output.writability",
            "artifacts",
            "Create the output path or repair parent-directory permissions.",
            lambda: _check_output(config),
        ),
        _safe_check(
            "reasoning.controls",
            "models",
            "Use a supported effort or provider-native thinking configuration.",
            lambda: _check_reasoning(config),
        ),
    ]
    if live:
        try:
            checks.extend(_model_probe_checks(config))
        except Exception as exc:
            checks.append(_failed(
                "live.model.setup",
                "live-model",
                "Model probes could not be initialized",
                f"error={type(exc).__name__}: {exc}",
                "Verify the local provider dependencies and resolved role/profile configuration.",
            ))
        try:
            checks.extend(_dvwa_live_checks(config))
        except Exception as exc:
            checks.append(_failed(
                "live.dvwa.setup",
                "live-dvwa",
                "DVWA probes could not be completed",
                f"error={type(exc).__name__}: {exc}",
                "Verify the contained target URL, DVWA service, and local session configuration.",
            ))
    return _build_report(checks, secrets=_known_secrets(config))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tesis doctor",
        description="Validate TESIS locally, with optional explicit provider and DVWA probes.",
    )
    parser.add_argument("--config", default="config.yaml", help="Configuration YAML path")
    parser.add_argument("--live", action="store_true", help="Run benign provider and contained DVWA probes")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Print one JSON report")
    return parser


def _config_path_problem(config_path: str) -> str | None:
    """Return a path-specific load problem, or ``None`` when the path is usable."""

    candidate = Path(config_path).expanduser()
    if candidate.exists() and not candidate.is_file():
        return f"config path is not a regular file: {candidate}"
    if not candidate.exists():
        return f"config file not found: {candidate}"
    if not os.access(candidate, os.R_OK):
        return f"config file is not readable: {candidate}"
    return None


def _config_error_report(config_path: str, exc: BaseException) -> dict[str, Any]:
    """Build the single-check report for a configuration that could not load."""

    path_problem = _config_path_problem(config_path)
    if path_problem:
        summary = f"Configuration could not be loaded: {path_problem}"
        details = f"config_path={config_path}; loader_error={type(exc).__name__}: {exc}"
    else:
        summary = f"Configuration could not be loaded: {type(exc).__name__}: {exc}"
        details = f"config_path={config_path}"
    check = _failed(
        "config.load",
        "configuration",
        summary,
        details,
        "Repair the YAML/path and required environment references, then rerun Doctor.",
    )
    return _build_report([check])


def _print_human(report: Mapping[str, Any]) -> None:
    marks = {"passed": "PASS", "failed": "FAIL", "skipped": "SKIP"}
    for check in report.get("checks", []):
        status = str(check.get("status", "failed"))
        print(
            f"[{marks.get(status, 'FAIL'):<4}] "
            f"{check.get('category', 'general')}/{check.get('id', 'unknown')}: "
            f"{check.get('summary', '')}"
        )
        details = str(check.get("details") or "").strip()
        remediation = str(check.get("remediation") or "").strip()
        if details:
            print(f"       {details}")
        if remediation:
            print(f"       Repair: {remediation}")
    summary = report.get("summary", {})
    print(
        "Doctor summary: "
        f"{summary.get('passed', 0)} passed, "
        f"{summary.get('failed', 0)} failed, "
        f"{summary.get('skipped', 0)} skipped, "
        f"{summary.get('total', 0)} total"
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning TESIS's standard process exit codes."""

    parser = _parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return int(exc.code)

    from tesis.config_loader import load_and_resolve_config

    try:
        config = load_and_resolve_config(config_path=args.config, cli_args={})
    except Exception as exc:
        # The documented contract is one report (JSON or human) plus exit code
        # 1; a malformed scalar in the YAML must not surface as a traceback.
        report = _config_error_report(args.config, exc)
    else:
        report = run_doctor(config, live=bool(args.live))

    if args.json_output:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        _print_human(report)
    return EXIT_OK if report.get("status") == "passed" else EXIT_RUNTIME_ERROR


__all__ = ["DoctorCheck", "main", "run_doctor"]
