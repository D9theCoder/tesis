"""Offline owner-review ranking draft. Never a scoring profile or selector input.

The draft is deliberately *not* shaped as a frozen ``scoring_profile``.  It has
no ``frozen_at``/``profile_id``/profile hash, declares itself unapproved and
unfrozen, and is never imported by the method selector.  Its only job is to let
the owner review the nine scenario / twenty-seven entry ranking material and to
separate two questions that are easy to conflate:

* **coverage** — are all registered methods present for every surface/level?
* **freeze readiness** — is every confirmed number backed by a resolvable
  evidence pin, is the file identity intact, and has the owner approved it?

No network, target, provider, runner, graph, or selector code is called here.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable, Mapping
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE, SECURITY_LEVELS, SURFACES
from evaluation.scoring_evidence import evidence_hash, validate_profile

DRAFT_ARTIFACT_TYPE = "autoresearch_ranking_draft"
DRAFT_VERSION = "ranking-draft.v1"
DRAFT_STATUS = "draft_unapproved_unfrozen"
APPROVED_DRAFT_STATUS = "draft_approved_unfrozen"
DRAFT_STATUSES = frozenset({DRAFT_STATUS, APPROVED_DRAFT_STATUS})
DEFAULT_DRAFT_PATH = "config/research/autoresearch-ranking-draft-2026-10-31.json"

EXPECTED_SCENARIOS = tuple(
    f"{surface}:{level}" for surface in SURFACES for level in SECURITY_LEVELS
)
EXPECTED_ENTRY_COUNT = sum(
    len(METHODS_BY_SURFACE[surface]) * len(SECURITY_LEVELS) for surface in SURFACES
)

ALLOWED_PLAN_KINDS = frozenset({
    "stop_after_target", "stop_at_budget", "continue_same_surface", "chain",
})
ALLOWED_SOURCE_ORIGINS = frozenset({"operator_fixture", "offline_control"})
CONFIRMED_SOURCE_ORIGINS = frozenset({"operator_fixture"})
ALLOWED_REFERENCE_ROLES = frozenset({
    "fit", "count", "status", "protocol", "observations", "controls", "review",
})
BASELINE_SOURCE_MARKERS = (
    "results/runs/",
    "remediation-2026-10-30",
    "full-2026-10-30",
)
REQUIRED_ENTRY_KEYS = frozenset({
    "preconditions", "fit_predicates", "allowed_plans", "protocol_refs",
    "reference_status", "reference_fit", "planned_request_count",
    "reference_reason", "evidence_refs",
})
ORACLE_PREREGISTRATION_REQUIRED = (
    "source_id",
    "protocol_version",
    "fixture_id",
    "identity",
    "object",
    "action",
    "allowed_control",
    "denied_control",
    "collected_at",
    "collector_sha256",
    "response_sha256",
)


class DraftValidationError(ValueError):
    """Structural or evidence-integrity failure; not the same as freeze-blocked."""

    def __init__(self, errors: Iterable[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def draft_hash(document: Mapping[str, Any]) -> str:
    """Hash the draft exactly like an evidence source, excluding its own hash."""
    return evidence_hash({key: value for key, value in document.items() if key != "draft_sha256"})


def load_draft(path: str | Path) -> dict[str, Any]:
    document = json.loads(Path(path).read_bytes())
    if not isinstance(document, dict):
        raise DraftValidationError(["ranking draft must be a JSON object"])
    return document


def resolve_pointer(document: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 JSON pointer; an empty pointer means the document."""
    if pointer == "":
        return document
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("evidence pointer must be empty or start with '/'")
    current = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not token.isdigit():
                raise ValueError(f"non-numeric list token in evidence pointer: {token!r}")
            current = current[int(token)]
        elif isinstance(current, dict):
            if token not in current:
                raise ValueError(f"evidence pointer does not resolve: {pointer}")
            current = current[token]
        else:
            raise ValueError(f"evidence pointer crosses a scalar: {pointer}")
    return current


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")
    return datetime.fromisoformat(value)


def _file_pin(root: Path, path: Any, expected: Any) -> tuple[bool, str]:
    if not isinstance(path, str) or not path.strip():
        return False, "missing_path"
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    if not candidate.is_file():
        return False, "missing"
    actual = sha256(candidate.read_bytes()).hexdigest()
    if not isinstance(expected, str) or actual != expected:
        return False, "mismatch"
    return True, "verified"


def _source_map(draft: Mapping[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    sources = draft.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append("ranking draft requires a non-empty sources list")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for source in sources:
        if not isinstance(source, dict):
            errors.append("ranking source must be an object")
            continue
        source_id = source.get("source_id")
        if not isinstance(source_id, str) or not source_id.strip():
            errors.append("ranking source requires a non-empty source_id")
            continue
        if source_id in result:
            errors.append(f"duplicate ranking source_id: {source_id}")
            continue
        origin = source.get("origin")
        if origin not in ALLOWED_SOURCE_ORIGINS:
            errors.append(f"ranking source {source_id} has unsupported origin {origin!r}")
        document = source.get("document")
        if not isinstance(document, (dict, list)):
            errors.append(f"ranking source {source_id} requires an object/list document")
            continue
        try:
            document_hash = evidence_hash(document)
        except (TypeError, ValueError) as exc:
            errors.append(f"ranking source {source_id} is not hashable: {exc}")
            continue
        if source.get("sha256") != document_hash:
            errors.append(f"ranking source {source_id} document hash mismatch")
        result[source_id] = source
    return result


def _check_entry(
    coordinate: str,
    method: str,
    entry: Any,
    sources: Mapping[str, Mapping[str, Any]],
    errors: list[str],
) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        errors.append(f"{coordinate}/{method}: entry must be an object")
        return None
    absent = REQUIRED_ENTRY_KEYS - set(entry)
    if absent:
        errors.append(f"{coordinate}/{method}: missing keys {sorted(absent)}")
        return None
    if entry.get("preconditions") != AttackKnowledgeGraph.METHOD_PRECONDITIONS[method]:
        errors.append(f"{coordinate}/{method}: preconditions differ from the static AKG")
    predicates = {
        predicate
        for required in AttackKnowledgeGraph.METHOD_PRECONDITIONS.values()
        for predicate in required
    }
    tests = entry.get("fit_predicates")
    if not isinstance(tests, list) or not tests or any(
        not isinstance(test, dict)
        or test.get("key") not in predicates
        or type(test.get("equals")) is not bool
        for test in tests
    ):
        errors.append(f"{coordinate}/{method}: invalid fit_predicates")
    plans = entry.get("allowed_plans")
    if (
        not isinstance(plans, list)
        or not plans
        or any(not isinstance(plan, str) for plan in plans)
        or not set(plans) <= ALLOWED_PLAN_KINDS
    ):
        errors.append(f"{coordinate}/{method}: invalid allowed_plans")
    protocol_refs = entry.get("protocol_refs")
    if (
        not isinstance(protocol_refs, list)
        or not protocol_refs
        or any(not isinstance(ref, str) for ref in protocol_refs)
        or not set(protocol_refs) <= set(sources)
    ):
        errors.append(f"{coordinate}/{method}: protocol_refs do not resolve")
    status = entry.get("reference_status")
    reason = entry.get("reference_reason")
    if status not in {"confirmed", "pending"}:
        errors.append(f"{coordinate}/{method}: reference_status must be confirmed or pending")
    if not isinstance(reason, str) or not reason.strip():
        errors.append(f"{coordinate}/{method}: reference_reason must be non-empty")

    refs = entry.get("evidence_refs")
    if not isinstance(refs, list) or not refs:
        errors.append(f"{coordinate}/{method}: requires at least one evidence pin")
        refs = []
    roles: set[str] = set()
    claims: dict[str, list[Any]] = {"fit": [], "count": []}
    for ref in refs:
        if not isinstance(ref, dict):
            errors.append(f"{coordinate}/{method}: evidence pin must be an object")
            continue
        source_id = ref.get("source_id")
        if not isinstance(source_id, str) or not source_id:
            errors.append(f"{coordinate}/{method}: evidence pin requires a source_id")
            continue
        source = sources.get(source_id)
        if source is None:
            errors.append(f"{coordinate}/{method}: unresolved evidence source {source_id!r}")
            continue
        pointer = ref.get("pointer", "")
        try:
            resolved = resolve_pointer(source["document"], pointer)
        except (TypeError, ValueError) as exc:
            errors.append(f"{coordinate}/{method}: {exc}")
            continue
        expect = ref.get("expect")
        if not isinstance(expect, dict) or not expect:
            errors.append(f"{coordinate}/{method}: evidence pin requires explicit expected values")
        elif not isinstance(resolved, dict):
            errors.append(f"{coordinate}/{method}: evidence pointer does not resolve to a record")
        else:
            for key, expected in expect.items():
                if key not in resolved:
                    errors.append(f"{coordinate}/{method}: evidence record lacks {key!r}")
                elif resolved[key] != expected:
                    errors.append(
                        f"{coordinate}/{method}: evidence mismatch for {key!r}: "
                        f"draft expects {expected!r}, source has {resolved[key]!r}"
                    )
        claim = ref.get("claim")
        if claim is not None:
            if not isinstance(claim, dict):
                errors.append(f"{coordinate}/{method}: evidence claim must be an object")
            else:
                for claim_key in ("fit", "count"):
                    if claim_key not in claim:
                        continue
                    claim_value = claim[claim_key]
                    claims[claim_key].append(claim_value)
                    if claim_key == "fit" and (
                        type(claim_value) is not int or not 1 <= claim_value <= 3
                    ):
                        errors.append(f"{coordinate}/{method}: fit claim must be 1..3")
                    if claim_key == "count" and (
                        type(claim_value) is not int or claim_value <= 0
                    ):
                        errors.append(f"{coordinate}/{method}: count claim must be positive")
                    if isinstance(resolved, dict):
                        if claim_key == "count":
                            available = [
                                resolved[name] for name in (
                                    "comparison_request_count", "reference_requests",
                                    "planned_request_count", "request_count",
                                ) if name in resolved
                            ]
                            if claim_value not in available:
                                errors.append(
                                    f"{coordinate}/{method}: count claim {claim_value!r} "
                                    "is not supported by the evidence record"
                                )
                        elif "reference_fit" in resolved and resolved["reference_fit"] != claim_value:
                            errors.append(
                                f"{coordinate}/{method}: fit claim {claim_value!r} "
                                "contradicts the evidence record"
                            )
        pin_roles = ref.get("roles")
        if (
            not isinstance(pin_roles, list)
            or not pin_roles
            or any(not isinstance(role, str) for role in pin_roles)
            or not set(pin_roles) <= ALLOWED_REFERENCE_ROLES
        ):
            errors.append(f"{coordinate}/{method}: invalid evidence pin roles")
        else:
            roles.update(pin_roles)
        if status == "confirmed" and source.get("origin") not in CONFIRMED_SOURCE_ORIGINS:
            errors.append(
                f"{coordinate}/{method}: synthetic/offline source {source_id!r} cannot "
                "confirm a ranking reference"
            )
        if status == "confirmed" and any(
            marker in str(source.get("path") or "") for marker in BASELINE_SOURCE_MARKERS
        ):
            errors.append(
                f"{coordinate}/{method}: baseline-outcome source {source_id!r} cannot "
                "confirm a ranking reference"
            )

    fit = entry.get("reference_fit")
    count = entry.get("planned_request_count")
    if status == "confirmed":
        if type(fit) is not int or not 1 <= fit <= 3:
            errors.append(f"{coordinate}/{method}: confirmed fit must be an integer 1..3")
        if type(count) is not int or count <= 0:
            errors.append(f"{coordinate}/{method}: confirmed count must be a positive integer")
        if "fit" not in roles:
            errors.append(f"{coordinate}/{method}: confirmed fit requires a 'fit' evidence pin")
        if "count" not in roles:
            errors.append(f"{coordinate}/{method}: confirmed count requires a 'count' evidence pin")
        if not claims["fit"]:
            errors.append(f"{coordinate}/{method}: confirmed fit requires a fit claim")
        elif any(value != fit for value in claims["fit"]):
            errors.append(f"{coordinate}/{method}: fit claim does not match the entry fit")
        if not claims["count"]:
            errors.append(f"{coordinate}/{method}: confirmed count requires a count claim")
        elif any(value != count for value in claims["count"]):
            errors.append(f"{coordinate}/{method}: count claim does not match the entry count")
    elif status == "pending":
        if fit is not None:
            errors.append(f"{coordinate}/{method}: pending fit must be null, not hand-graded")
        if count is not None and (type(count) is not int or count <= 0):
            errors.append(f"{coordinate}/{method}: pending count must be null or a positive integer")
        if count is not None and "count" not in roles:
            errors.append(f"{coordinate}/{method}: pending count requires a 'count' evidence pin")
        if count is not None and claims["count"] and any(value != count for value in claims["count"]):
            errors.append(f"{coordinate}/{method}: pending count contradicts its count claim")
        proposed = entry.get("proposed_reference_fit")
        if proposed is not None:
            if type(proposed) is not int or not 1 <= proposed <= 3:
                errors.append(f"{coordinate}/{method}: proposed_reference_fit must be 1..3")
            elif claims["fit"] and any(value != proposed for value in claims["fit"]):
                errors.append(
                    f"{coordinate}/{method}: proposed fit contradicts its fit claim"
                )
        if isinstance(reason, str) and not reason.strip():
            errors.append(f"{coordinate}/{method}: pending requires an explicit reason")
    return {
        "status": status,
        "fit": fit,
        "count": count,
        "reason": reason,
        "evidence_refs": len(refs),
    }


def assess_draft(
    draft: Mapping[str, Any],
    *,
    root: str | Path = ".",
) -> dict[str, Any]:
    """Validate draft structure/evidence and report coverage vs freeze readiness.

    Structural/evidence failures raise :class:`DraftValidationError`.  A valid
    draft may still be freeze-blocked; that is reported, not raised, because the
    draft is intentionally unapproved and may legitimately contain pending
    entries.
    """
    errors: list[str] = []
    blockers: list[str] = []
    root_path = Path(root)

    if not isinstance(draft, dict):
        raise DraftValidationError(["ranking draft must be a JSON object"])
    if draft.get("artifact_type") != DRAFT_ARTIFACT_TYPE:
        errors.append(f"artifact_type must be {DRAFT_ARTIFACT_TYPE!r}")
    if draft.get("draft_version") != DRAFT_VERSION:
        errors.append(f"draft_version must be {DRAFT_VERSION!r}")
    if draft.get("status") not in DRAFT_STATUSES:
        errors.append(f"draft status must be one of {sorted(DRAFT_STATUSES)}")
    if draft.get("not_a_scoring_profile") is not True:
        errors.append("draft must declare not_a_scoring_profile: true")
    if draft.get("runtime_selector_eligible") is not False:
        errors.append("draft must declare runtime_selector_eligible: false")
    for forbidden in ("frozen_at", "profile_id", "version", "sha256"):
        if forbidden in draft:
            errors.append(
                f"draft must not carry runtime-profile field {forbidden!r}; "
                "freeze is a separate owner-approved step"
            )
    try:
        expected_draft_hash = draft_hash(draft)
    except (TypeError, ValueError) as exc:
        errors.append(f"ranking draft is not hashable: {exc}")
    else:
        if draft.get("draft_sha256") != expected_draft_hash:
            errors.append("ranking draft hash mismatch")
    try:
        _timestamp(draft.get("evidence_cutoff"))
    except ValueError as exc:
        errors.append(f"evidence_cutoff invalid: {exc}")
    if not isinstance(draft.get("fixture_id"), str) or not draft["fixture_id"].strip():
        errors.append("fixture_id must be a non-empty string")
    if not isinstance(draft.get("protocol_version"), str) or not draft["protocol_version"].strip():
        errors.append("protocol_version must be a non-empty string")
    if type(draft.get("candidate_budget")) is not int or draft["candidate_budget"] <= 0:
        errors.append("candidate_budget must be a positive integer")

    sources = _source_map(draft, errors)

    static_akg = draft.get("static_akg")
    if not isinstance(static_akg, dict):
        errors.append("draft requires static_akg metadata")
    else:
        if static_akg.get("method_preconditions") != dict(AttackKnowledgeGraph.METHOD_PRECONDITIONS):
            errors.append("static_akg method_preconditions differ from the runtime AKG")
        ok, state = _file_pin(root_path, static_akg.get("path"), static_akg.get("sha256"))
        if not ok:
            blockers.append(f"static_akg_pin_{state}")
    registry = draft.get("method_registry")
    if not isinstance(registry, dict):
        errors.append("draft requires method_registry metadata")
    else:
        if registry.get("methods_by_surface") != {surface: list(methods) for surface, methods in METHODS_BY_SURFACE.items()}:
            errors.append("method_registry methods_by_surface differ from the runtime registry")
        ok, state = _file_pin(root_path, registry.get("path"), registry.get("sha256"))
        if not ok:
            blockers.append(f"method_registry_pin_{state}")
    rubric = draft.get("rubric_source")
    if isinstance(rubric, dict):
        ok, state = _file_pin(root_path, rubric.get("path"), rubric.get("sha256"))
        if not ok:
            blockers.append(f"rubric_source_pin_{state}")
    else:
        blockers.append("rubric_source_pin_missing")

    owner = draft.get("owner_approval")
    deferred_entries: set[str] = set()
    if not isinstance(owner, dict) or owner.get("approved") is not True:
        blockers.append("owner_approval_missing")
    else:
        try:
            _timestamp(owner.get("approved_at"))
        except ValueError as exc:
            errors.append(f"owner_approval.approved_at invalid: {exc}")
        for field in ("approved_by", "approval_reference", "signature"):
            if not isinstance(owner.get(field), str) or not owner[field].strip():
                errors.append(f"owner_approval requires {field}")
        deferred: Any = owner.get("deferred_entries")
        if deferred is not None:
            if not isinstance(deferred, list):
                errors.append("owner_approval.deferred_entries must be a list")
            else:
                for index, item in enumerate(deferred):
                    if (
                        not isinstance(item, dict)
                        or not isinstance(item.get("scenario"), str)
                        or not isinstance(item.get("method"), str)
                        or not isinstance(item.get("reason"), str)
                        or not item["reason"].strip()
                    ):
                        errors.append(
                            f"owner_approval.deferred_entries[{index}] requires "
                            "scenario, method and an explicit reason"
                        )
                        continue
                    deferred_entries.add(f"{item['scenario']}/{item['method']}")

    oracle = draft.get("oracle_preregistration")
    if not isinstance(oracle, dict):
        blockers.append("oracle_preregistration_schema_missing")
    else:
        oracle_status = oracle.get("status")
        if oracle_status not in {"not_collected", "preregistered"}:
            errors.append("oracle_preregistration status must be not_collected or preregistered")
        if oracle.get("attestations") not in (None, []):
            errors.append("draft must not contain fabricated oracle attestations")
        required = oracle.get("required_fields")
        if (
            not isinstance(required, list)
            or any(not isinstance(field, str) for field in required)
            or not set(ORACLE_PREREGISTRATION_REQUIRED) <= set(required)
        ):
            errors.append("oracle_preregistration schema is incomplete")
        if not isinstance(oracle.get("reason"), str) or not oracle["reason"].strip():
            errors.append("oracle_preregistration requires an explicit reason")
        if oracle_status == "not_collected":
            blockers.append("oracle_preregistration_not_collected")
        else:
            # A preregistered protocol is a commitment recorded before the
            # epoch; collected per-run attestations remain separate proof.
            ok, state = _file_pin(
                root_path, oracle.get("document_path"), oracle.get("document_sha256")
            )
            if not ok:
                blockers.append(f"oracle_preregistration_document_{state}")
            else:
                from evaluation.oracle_preregistration import (
                    assess_draft as assess_oracle,
                    load_draft as load_oracle_draft,
                )

                try:
                    oracle_report = assess_oracle(load_oracle_draft(root_path / oracle["document_path"]),
                                                  root=root_path)
                except (OSError, ValueError) as exc:
                    blockers.append(f"oracle_preregistration_invalid:{exc}")
                else:
                    if not oracle_report["readiness"]["commitment"]["preregistered"]:
                        blockers.append("oracle_preregistration_commitment_missing")

    scenarios = draft.get("scenarios")
    if not isinstance(scenarios, dict):
        errors.append("ranking draft scenarios must be an object")
        scenarios = {}
    expected_scenarios = set(EXPECTED_SCENARIOS)
    actual_scenarios = set(scenarios)
    missing_scenarios = sorted(expected_scenarios - actual_scenarios)
    extra_scenarios = sorted(actual_scenarios - expected_scenarios)
    if missing_scenarios:
        errors.append(f"missing scenarios: {missing_scenarios}")
    if extra_scenarios:
        errors.append(f"scenarios outside the registry: {extra_scenarios}")

    entries: dict[str, dict[str, Any]] = {}
    pending: list[dict[str, str]] = []
    deferred: list[dict[str, str]] = []
    confirmed = 0
    for coordinate in EXPECTED_SCENARIOS:
        surface = coordinate.split(":", 1)[0]
        scenario = scenarios.get(coordinate)
        if not isinstance(scenario, dict):
            errors.append(f"{coordinate}: scenario must be an object")
            continue
        expected_methods = set(METHODS_BY_SURFACE[surface])
        if set(scenario) != expected_methods:
            errors.append(
                f"{coordinate}: methods differ from the registry; "
                f"missing={sorted(expected_methods - set(scenario))}, "
                f"extra={sorted(set(scenario) - expected_methods)}"
            )
        for method in METHODS_BY_SURFACE[surface]:
            result = _check_entry(coordinate, method, scenario.get(method), sources, errors)
            if result is None:
                continue
            entries[f"{coordinate}/{method}"] = result
            if result["status"] == "pending":
                row = {
                    "scenario": coordinate,
                    "method": method,
                    "reason": str(result["reason"]),
                }
                if f"{coordinate}/{method}" in deferred_entries:
                    deferred.append(row)
                else:
                    pending.append(row)
            elif result["status"] == "confirmed":
                confirmed += 1

    unknown_deferred = sorted(
        deferred_entries - {f"{item['scenario']}/{item['method']}" for item in deferred}
    )
    if unknown_deferred:
        errors.append(
            f"owner_approval.deferred_entries does not match pending entries: {unknown_deferred}"
        )

    for source_id, source in sources.items():
        path_text = str(source.get("path") or "")
        if any(marker in path_text for marker in BASELINE_SOURCE_MARKERS):
            blockers.append(f"baseline_source_not_ranking_evidence:{source_id}")
        if source.get("file_sha256") is not None:
            ok, state = _file_pin(root_path, source.get("path"), source.get("file_sha256"))
            if not ok:
                blockers.append(f"source_file_pin_{state}:{source_id}")
        elif source.get("path") is not None:
            blockers.append(f"source_file_pin_missing_sha256:{source_id}")

    open_review = draft.get("open_review_items")
    if not isinstance(open_review, list):
        errors.append("open_review_items must be a list")
        open_review = []
    for index, item in enumerate(open_review):
        if not isinstance(item, dict) or not isinstance(item.get("reason"), str) or not item["reason"].strip():
            errors.append(f"open_review_items[{index}] requires an explicit reason")
        elif item.get("resolution") not in {"resolved", "deferred"}:
            blockers.append(f"owner_review_required:{item.get('id') or index}")
        elif item.get("resolution") == "resolved" and not (
            isinstance(item.get("decision_reference"), str) and item["decision_reference"].strip()
        ):
            errors.append(
                f"open_review_items[{index}] resolved requires a decision_reference"
            )

    if errors:
        raise DraftValidationError(errors)

    coverage_complete = (
        not missing_scenarios
        and not extra_scenarios
        and len(entries) == EXPECTED_ENTRY_COUNT
        and all(
            set(scenarios[coordinate]) == set(METHODS_BY_SURFACE[coordinate.split(":", 1)[0]])
            for coordinate in EXPECTED_SCENARIOS
        )
    )
    if pending:
        blockers.append(f"pending_evidence:{len(pending)}")
    freeze_ready = coverage_complete and not pending and not blockers
    if freeze_ready:
        try:
            projection = project_profile(draft)
            validate_profile(projection)
        except (DraftValidationError, ValueError) as exc:
            freeze_ready = False
            blockers.append(f"runtime_profile_validation_failed:{exc}")
    runtime_validation = "passed" if freeze_ready else "blocked"

    return {
        "draft_id": draft.get("draft_id"),
        "status": draft.get("status"),
        "not_a_scoring_profile": True,
        "runtime_selector_eligible": False,
        "coverage": {
            "complete": coverage_complete,
            "scenario_count": len(actual_scenarios & expected_scenarios),
            "expected_scenario_count": len(EXPECTED_SCENARIOS),
            "entry_count": len(entries),
            "expected_entry_count": EXPECTED_ENTRY_COUNT,
            "confirmed_entries": confirmed,
            "pending_entries": len(pending),
            "deferred_entries": len(deferred),
            "missing_scenarios": missing_scenarios,
            "extra_scenarios": extra_scenarios,
            "pending": pending,
            "deferred": deferred,
        },
        "freeze_readiness": {
            "ready": bool(freeze_ready),
            "blockers": sorted(set(blockers)),
            "runtime_profile_validation": runtime_validation,
        },
        "evidence_sources": sorted(sources),
    }


def project_profile(draft: Mapping[str, Any]) -> dict[str, Any]:
    """Project an approved, evidence-pinned draft into candidate profile shape.

    The projection is a *candidate* for ``research_plan.freeze_ranking_profile``:
    it carries the approved evidence entries (including explicitly deferred nulls)
    but is not itself frozen.  Freeze adds the epoch identity and timestamp.
    """
    owner = draft["owner_approval"]
    profile: dict[str, Any] = {
        "profile_id": f"{draft['draft_id']}-frozen",
        "version": "ranking-draft-freeze.v1",
        "fixture_id": draft["fixture_id"],
        "protocol_version": draft["protocol_version"],
        "candidate_budget": draft["candidate_budget"],
        "frozen_at": owner["approved_at"],
        "sources": [
            {
                "source_id": source["source_id"],
                "origin": source["origin"],
                "document": source["document"],
                "sha256": source["sha256"],
            }
            for source in draft["sources"]
        ],
        "scenarios": {
            coordinate: {
                method: {
                    key: entry[key]
                    for key in (
                        "preconditions", "fit_predicates", "allowed_plans",
                        "protocol_refs", "reference_status", "reference_fit",
                        "planned_request_count", "reference_reason",
                    )
                }
                for method, entry in entries.items()
            }
            for coordinate, entries in draft["scenarios"].items()
        },
    }
    profile["sha256"] = evidence_hash(profile)
    return profile


def render_report(report: Mapping[str, Any]) -> str:
    coverage = report["coverage"]
    readiness = report["freeze_readiness"]
    lines = [
        f"Draft: {report.get('draft_id')} ({report.get('status')})",
        f"Not a scoring profile: {report.get('not_a_scoring_profile')}; "
        f"selector eligible: {report.get('runtime_selector_eligible')}",
        f"Coverage: {'complete' if coverage['complete'] else 'incomplete'} — "
        f"{coverage['scenario_count']}/{coverage['expected_scenario_count']} scenarios, "
        f"{coverage['entry_count']}/{coverage['expected_entry_count']} entries "
        f"({coverage['confirmed_entries']} confirmed, {coverage['pending_entries']} pending)",
        f"Freeze readiness: {'READY' if readiness['ready'] else 'BLOCKED'} "
        f"(runtime profile validation: {readiness['runtime_profile_validation']})",
    ]
    if coverage["missing_scenarios"]:
        lines.append(f"Missing scenarios: {', '.join(coverage['missing_scenarios'])}")
    if coverage["pending"]:
        lines.append("Pending evidence:")
        for item in coverage["pending"]:
            lines.append(f"  - {item['scenario']}/{item['method']}: {item['reason']}")
    if readiness["blockers"]:
        lines.append("Freeze blockers:")
        for blocker in readiness["blockers"]:
            lines.append(f"  - {blocker}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draft", default=DEFAULT_DRAFT_PATH)
    parser.add_argument("--root", default=".")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--require-freeze-ready", action="store_true",
        help="exit 2 unless the draft is owner-approved and every evidence pin verifies",
    )
    parser.add_argument(
        "--project", default=None,
        help="write the validated candidate profile JSON to this path (freeze is separate)",
    )
    args = parser.parse_args(argv)
    try:
        report = assess_draft(load_draft(args.draft), root=args.root)
    except (OSError, json.JSONDecodeError, DraftValidationError) as exc:
        if args.as_json:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
        else:
            print(f"Invalid ranking draft: {exc}")
        return 1
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_report(report))
    if not report["coverage"]["complete"]:
        return 1
    if args.require_freeze_ready and not report["freeze_readiness"]["ready"]:
        return 2
    if args.project:
        if not report["freeze_readiness"]["ready"]:
            print("Refusing to project a draft that is not freeze-ready")
            return 2
        candidate = project_profile(load_draft(args.draft))
        destination = Path(args.project)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(destination)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
