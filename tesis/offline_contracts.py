"""Offline payload-contract preflight shared by ``--dry-run`` and Doctor.

No HTTP, provider, graph-node, or filesystem-write work happens here. A
preflight validates the *contract* each payload mode will enforce at runtime:

* ``static_only``/``hybrid`` need structurally valid canonical exploit seeds and
  a valid frozen detection-control snapshot; probes never enter the exploit
  queue.
* ``llm_mutation_only`` needs valid seed *inputs* and the registered mutation
  prompt/schema; static seeds are never treated as generated output.
* ``llm_template`` needs a real neutral template for the coordinate (or an
  explicit, recorded limitation) and the registered template prompt/schema.

Issue rows are returned instead of raising so callers can aggregate every
coordinate before deciding whether a configuration may run.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from core.knowledge_graph import get_attack_knowledge_graph
from core.payload_policy import (
    PAYLOAD_SCHEMA_VERSION,
    PAYLOAD_TEMPLATE_SCHEMA_VERSION,
    TEMPLATE_REGISTRY_VERSION,
    is_template_mode,
    mode_display_label,
    normalize_payload_mode,
)
from core.state import new_default_state
from foundation.payload_library import PayloadLibrary
from foundation.payload_templates import template_coverage
from foundation.payload_validator import validate_candidate, validate_probe_controls
from foundation.payload_validator import freeze_probe_controls


def _issue(method: str, level: str, mode: str, code: str, detail: str) -> dict[str, Any]:
    return {
        "method": method,
        "security_level": level,
        "payload_mode": mode,
        "mode_label": mode_display_label(mode),
        "code": code,
        "detail": detail,
    }


def _manifest_problems(modes: Iterable[str]) -> list[str]:
    """Check only prompt contracts required by the requested payload modes."""
    modes = set(modes)
    needs_mutation = bool(modes & {"hybrid", "llm_mutation_only"})
    needs_template = "llm_template" in modes
    if not needs_mutation and not needs_template:
        return []

    from llm.prompts.manifests import (
        PAYLOAD_PROMPT_ID,
        TEMPLATE_PROMPT_ID,
        PROMPT_MANIFESTS,
    )

    problems: list[str] = []
    expectations = {}
    if needs_mutation:
        expectations[PAYLOAD_PROMPT_ID] = PAYLOAD_SCHEMA_VERSION
    if needs_template:
        expectations[TEMPLATE_PROMPT_ID] = PAYLOAD_TEMPLATE_SCHEMA_VERSION
    for prompt_id, schema_version in expectations.items():
        manifest = PROMPT_MANIFESTS.get(prompt_id)
        if not isinstance(manifest, Mapping):
            problems.append(f"prompt manifest {prompt_id!r} is not registered")
            continue
        if manifest.get("prompt_id") != prompt_id:
            problems.append(f"prompt manifest {prompt_id!r} has a mismatched prompt_id")
        for key in ("template_hash", "output_schema_hash", "validator_hash"):
            value = manifest.get(key)
            if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                problems.append(f"prompt manifest {prompt_id!r} has an invalid {key}")
        if manifest.get("output_schema_version") != schema_version:
            problems.append(
                f"prompt manifest {prompt_id!r} schema is "
                f"{manifest.get('output_schema_version')!r}, expected {schema_version!r}"
            )
    return problems


def check_coordinate(
    method: str,
    security_level: str,
    payload_mode: str,
    *,
    candidate_budget: int = 5,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Check one method/level/mode coordinate.

    Returns ``(issues, limitations)``. Limitations are explicit, recorded
    template infeasibilities that must remain visible but are not preflight
    failures.
    """
    mode = normalize_payload_mode(payload_mode)
    issues: list[dict[str, Any]] = []
    limitations: list[dict[str, Any]] = []
    try:
        profile = get_attack_knowledge_graph().get_payload_profile(method)
    except Exception as exc:  # noqa: BLE001 - preflight reports, never crashes
        return (
            [_issue(method, security_level, mode, "payload_profile_unavailable", f"{type(exc).__name__}: {exc}")],
            limitations,
        )
    canonical = [
        dict(row)
        for row in PayloadLibrary().load_seed_candidates(method, security_level)
        if isinstance(row, dict)
    ]
    canonical_payloads = {
        str(row.get("candidate_id")): str(row.get("payload_or_logic", ""))
        for row in canonical if row.get("candidate_id")
    }
    canonical_stages = {
        str(row.get("candidate_id")): str(row.get("stage") or "")
        for row in canonical if row.get("candidate_id")
    }
    exploit_inputs = [row for row in canonical if str(row.get("stage", "exploit")) in {"exploit", "bypass"}]

    if is_template_mode(mode):
        rows = [row for row in template_coverage() if row["method"] == method and row["security_level"] == security_level]
        if not rows:
            issues.append(_issue(method, security_level, mode, "template_missing", "no neutral template registered"))
            return issues, limitations
        row = rows[0]
        if row.get("registry_version") != TEMPLATE_REGISTRY_VERSION:
            issues.append(_issue(
                method, security_level, mode, "template_registry_mismatch",
                f"registry {row.get('registry_version')!r} != {TEMPLATE_REGISTRY_VERSION!r}",
            ))
        if not row.get("supported"):
            limitations.append({
                "method": method,
                "security_level": security_level,
                "payload_mode": mode,
                "code": "template_infeasible",
                "detail": row.get("reason") or "no usable neutral template",
            })
            return issues, limitations
        try:
            from foundation.payload_templates import load_template

            template = load_template(method, security_level)
        except Exception as exc:  # noqa: BLE001
            issues.append(_issue(method, security_level, mode, "template_unavailable", f"{type(exc).__name__}: {exc}"))
            return issues, limitations
        if not template.get("template_id") or not template.get("template_sha256"):
            issues.append(_issue(method, security_level, mode, "template_identity_missing", "template id/hash absent"))
        if template.get("method") != method or template.get("security_level") != security_level:
            issues.append(_issue(method, security_level, mode, "template_scope_mismatch", "template scope differs"))
        if row.get("feasibility") == "limited":
            limitations.append({
                "method": method,
                "security_level": security_level,
                "payload_mode": mode,
                "code": "template_limited",
                "detail": row.get("reason") or "recorded feasibility limitation",
            })
    elif mode == "llm_mutation_only":
        if not exploit_inputs:
            issues.append(_issue(method, security_level, mode, "seed_inputs_missing", "no exploit/ bypass seed inputs"))
        for row in exploit_inputs:
            # Strict mutation treats these canonical rows purely as seed inputs;
            # they are never presented as generated model output.
            result = validate_candidate(
                row, method, profile, security_level=security_level,
                canonical_seed_payloads=canonical_payloads,
                canonical_stage_by_id=canonical_stages,
            )
            if result.get("valid") is not True:
                issues.append(_issue(
                    method, security_level, mode, "seed_input_invalid",
                    f"{row.get('candidate_id')}: {result.get('reason')}",
                ))
    else:
        if not exploit_inputs:
            issues.append(_issue(method, security_level, mode, "exploit_seed_missing", "no canonical exploit/bypass seed"))
        for row in exploit_inputs:
            result = validate_candidate(
                row, method, profile, mode=mode,
                security_level=security_level,
                canonical_seed_payloads=canonical_payloads,
                canonical_stage_by_id=canonical_stages,
            )
            if result.get("valid") is not True:
                issues.append(_issue(
                    method, security_level, mode, "exploit_seed_invalid",
                    f"{row.get('candidate_id')}: {result.get('reason')}",
                ))
        state = {
            **new_default_state(),
            "selected_method": method,
            "selected_visit_id": f"{method}:preflight:1",
            "security_level": security_level,
            "payload_mode": mode,
            "candidate_budget": max(1, int(candidate_budget)),
        }
        visit_id = str(state["selected_visit_id"])
        try:
            controls = freeze_probe_controls(state, method, visit_id)
            control_rows = controls.get("validation_results") or []
            if controls.get("candidates") and not control_rows:
                control_rows = validate_probe_controls(state, controls)
            invalid = [row for row in control_rows if row.get("valid") is not True]
            if invalid:
                issues.append(_issue(
                    method, security_level, mode, "detection_control_invalid",
                    "; ".join(str(row.get("reason")) for row in invalid[:3]),
                ))
        except Exception as exc:  # noqa: BLE001
            issues.append(_issue(method, security_level, mode, "detection_control_unavailable", f"{type(exc).__name__}: {exc}"))

    return issues, limitations


def check_payload_contracts(
    methods: Iterable[str],
    levels: Iterable[str],
    modes: Iterable[str],
    *,
    candidate_budget: int = 5,
) -> dict[str, Any]:
    """Check every requested coordinate and the shared prompt manifests."""
    methods = tuple(methods)
    levels = tuple(levels)
    modes = tuple(normalize_payload_mode(str(mode)) for mode in modes)
    issues: list[dict[str, Any]] = []
    limitations: list[dict[str, Any]] = []
    checked = 0
    for method in methods:
        for level in levels:
            for mode in modes:
                coordinate_issues, coordinate_limitations = check_coordinate(
                    str(method), str(level), str(mode), candidate_budget=candidate_budget,
                )
                issues.extend(coordinate_issues)
                limitations.extend(coordinate_limitations)
                checked += 1
    manifest_problems = _manifest_problems(modes)
    issues.extend({
        "method": None,
        "security_level": None,
        "payload_mode": None,
        "mode_label": None,
        "code": "prompt_manifest_invalid",
        "detail": problem,
    } for problem in manifest_problems)
    return {
        "checked_coordinates": checked,
        "issues": issues,
        "limitations": limitations,
        "manifest_problems": manifest_problems,
    }


__all__ = ["check_coordinate", "check_payload_contracts"]
