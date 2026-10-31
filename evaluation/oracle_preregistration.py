"""Offline independent-oracle preregistration draft. Never an attestation.

Three layers are deliberately kept apart:

* **protocol commitments** — for a future epoch, which already-frozen operator
  protocols (by ``source_id`` and content SHA-256) will be used, and which
  controls each one requires.  ``status`` is always ``planned``.
* **collected attestations** — per-run records produced by the operator.  This
  draft contains none: ``collection.status`` is ``not_collected`` and the list
  is empty.  Nothing here fabricates, infers, or backdates one.
* **missing controls** — derived offline as ``required - covered``; for the
  current draft every required control is missing.

A schema, a frozen protocol source, or a matching hash is not a
preregistration.  Preregistration additionally needs recorded approval metadata
with a timestamp before collection.  The validator reports that requirement as
a blocker; it never creates the approval and never promotes ``offline_control``
fixtures to operator evidence.

Validation establishes structural integrity, hash/source identity, and
timestamp order only.  It cannot verify a cryptographic signature, prove that
the approver is the owner, validate an approval reference, or confirm that an
attestation is true; those require independent owner/operator verification.

No target, provider, runner, planner, collector, or graph code is imported or
called.  Everything here is filesystem reads and hashing.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from evaluation.scoring_evidence import evidence_hash, timestamp, validate_sources

DRAFT_ARTIFACT_TYPE = "autoresearch_oracle_preregistration_draft"
DRAFT_VERSION = "oracle-preregistration-draft.v1"
DRAFT_STATUS = "draft_not_preregistered"
PREREGISTERED_STATUS = "preregistered"
DRAFT_STATUSES = frozenset({DRAFT_STATUS, PREREGISTERED_STATUS})
DEFAULT_DRAFT_PATH = "config/research/autoresearch-oracle-preregistration-draft-2026-10-31.json"

OPERATOR_ORIGIN = "operator_fixture"
SYNTHETIC_ORIGIN = "offline_control"
ORIGINS = frozenset({OPERATOR_ORIGIN, SYNTHETIC_ORIGIN})
OPERATOR_SCOPE = "operator_fixture"
SYNTHETIC_SCOPE = "offline_synthetic_fixture"
VALIDATION_SCOPES = frozenset({OPERATOR_SCOPE, SYNTHETIC_SCOPE})

COMMITMENT_STATUSES = frozenset({"planned"})
COLLECTION_STATUSES = frozenset({"not_collected", "collected"})
APPROVAL_STATUSES = frozenset({"not_approved", "approved"})
EPOCH_STATUSES = frozenset({"not_started", "started"})
FALSE_CLAIM_KEYS = ("approved", "frozen", "preregistered", "historical_preregistered")

REQUIRED_COMMITMENT_FIELDS = (
    "commitment_id", "status", "source_id", "origin", "protocol_kind",
    "fixture_id", "protocol_version", "document_sha256", "scope",
    "required_controls", "rubric_use",
)
REQUIRED_ATTESTATION_FIELDS = (
    "attestation_id", "source_id", "protocol_version", "fixture_id", "epoch_id",
    "identity", "object", "action", "allowed_control", "denied_control",
    "collected_at", "collector_sha256", "response_sha256", "origin",
    "validation_scope",
)
REQUIRED_APPROVAL_FIELDS = (
    "status", "approved_at", "approved_by", "approval_reference", "signature", "reason",
)


class PreregistrationValidationError(ValueError):
    """Structural or evidence-integrity failure of the draft artifact."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def draft_hash(document: Mapping[str, Any]) -> str:
    """Hash the draft exactly like an evidence source, excluding its own hash."""
    return evidence_hash({key: value for key, value in document.items() if key != "draft_sha256"})


def load_draft(path: str | Path) -> dict[str, Any]:
    document = json.loads(Path(path).read_bytes())
    if not isinstance(document, dict):
        raise PreregistrationValidationError(["oracle preregistration draft must be a JSON object"])
    return document


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _hex64(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _parsed_time(value: Any, label: str, errors: list[str]) -> datetime | None:
    try:
        return timestamp(value)
    except (TypeError, ValueError) as exc:
        errors.append(f"{label} invalid: {exc}")
        return None


def _check_epoch(epoch: Any, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(epoch, Mapping):
        errors.append("intended_epoch must be an object")
        return None
    epoch_id = epoch.get("epoch_id")
    if not _nonempty(epoch_id):
        errors.append("intended_epoch.epoch_id must be a non-empty string")
    output_root = epoch.get("output_root")
    if _nonempty(epoch_id) and output_root != f"results/runs/{epoch_id}":
        errors.append("intended_epoch.output_root must be results/runs/<epoch_id>")
    status = epoch.get("status")
    if status not in EPOCH_STATUSES:
        errors.append(f"intended_epoch.status must be one of {sorted(EPOCH_STATUSES)}")
    started_at = epoch.get("started_at")
    if status == "not_started" and started_at is not None:
        errors.append("intended_epoch.started_at must be null while the epoch is not_started")
    if status == "started" and started_at is None:
        errors.append("intended_epoch.started_at is required once the epoch has started")
    return {
        "epoch_id": epoch_id,
        "output_root": output_root,
        "status": status,
        "started_at": started_at,
    }


def _check_fixture(fixture: Any, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(fixture, Mapping):
        errors.append("fixture must be an object")
        return None
    for key in ("fixture_id", "protocol_version"):
        if not _nonempty(fixture.get(key)):
            errors.append(f"fixture.{key} must be a non-empty string")
    return {"fixture_id": fixture.get("fixture_id"),
            "protocol_version": fixture.get("protocol_version")}


def _load_source_record(
    record: Any, root: Path, errors: list[str],
) -> tuple[dict[str, dict[str, Any]], Path | None]:
    """Load the pinned operator source record and re-validate its hashes."""
    if not isinstance(record, Mapping):
        errors.append("source_record must be an object")
        return {}, None
    path_text = record.get("path")
    if not _nonempty(path_text):
        errors.append("source_record.path must be a non-empty string")
        return {}, None
    path = Path(path_text)
    if not path.is_absolute():
        path = root / path
    if not path.is_file():
        errors.append(f"source_record.path does not resolve: {path_text}")
        return {}, None
    raw = path.read_bytes()
    actual_file_hash = sha256(raw).hexdigest()
    if record.get("file_sha256") != actual_file_hash:
        errors.append("source_record.file_sha256 does not match the pinned source file")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        errors.append(f"source record is not valid JSON: {exc}")
        return {}, path
    if not isinstance(parsed, list) or not parsed:
        errors.append("source record must be a non-empty list of operator protocol sources")
        return {}, path
    try:
        validate_sources(parsed)
    except ValueError as exc:
        errors.append(f"pinned source record is invalid: {exc}")
    try:
        content_hash = evidence_hash(parsed)
    except (TypeError, ValueError) as exc:
        errors.append(f"pinned source record is not hashable: {exc}")
        return {}, path
    if record.get("content_sha256") != content_hash:
        errors.append("source_record.content_sha256 does not match the pinned source content")
    if record.get("source_count") != len(parsed):
        errors.append("source_record.source_count does not match the pinned source content")
    sources = {
        source["source_id"]: source
        for source in parsed
        if isinstance(source, Mapping) and _nonempty(source.get("source_id"))
    }
    return sources, path


def _check_commitments(
    commitments: Any,
    *,
    sources: Mapping[str, Mapping[str, Any]],
    fixture: Mapping[str, Any] | None,
    errors: list[str],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(commitments, list) or not commitments:
        errors.append("protocol_commitments must be a non-empty list")
        return {}, []
    fixture_id = (fixture or {}).get("fixture_id")
    protocol_version = (fixture or {}).get("protocol_version")
    result: dict[str, dict[str, Any]] = {}
    report: list[dict[str, Any]] = []
    commitment_ids: set[str] = set()
    source_ids: set[str] = set()
    for index, entry in enumerate(commitments):
        label = f"protocol_commitments[{index}]"
        if not isinstance(entry, Mapping):
            errors.append(f"{label} must be an object")
            continue
        absent = [field for field in REQUIRED_COMMITMENT_FIELDS if field not in entry]
        if absent:
            errors.append(f"{label} missing fields: {absent}")
        commitment_id = entry.get("commitment_id")
        if not _nonempty(commitment_id):
            errors.append(f"{label}.commitment_id must be a non-empty string")
        elif commitment_id in commitment_ids:
            errors.append(f"duplicate commitment_id: {commitment_id}")
        else:
            commitment_ids.add(commitment_id)
        source_id = entry.get("source_id")
        if not _nonempty(source_id):
            errors.append(f"{label}.source_id must be a non-empty string")
            continue
        if source_id in source_ids:
            errors.append(f"duplicate commitment source_id: {source_id}")
            continue
        source_ids.add(source_id)
        source = sources.get(source_id)
        if source is None:
            errors.append(f"{label}.source_id does not resolve in the pinned source record: {source_id}")
            continue
        document = source.get("document")
        if not isinstance(document, Mapping):
            errors.append(f"{label}: pinned source {source_id} has no document object")
            continue
        protocol = document.get("oracle_protocol")
        if not isinstance(protocol, Mapping):
            errors.append(f"{label}: pinned source {source_id} has no oracle_protocol")
            continue
        if entry.get("status") not in COMMITMENT_STATUSES:
            errors.append(f"{label}.status must be 'planned'; a commitment is never collected evidence")
        if entry.get("origin") != OPERATOR_ORIGIN or source.get("origin") != OPERATOR_ORIGIN:
            errors.append(f"{label}: offline_control_not_operator_evidence ({source_id})")
        if entry.get("document_sha256") != source.get("sha256"):
            errors.append(f"{label}: content SHA-256 does not match the pinned protocol {source_id}")
        if entry.get("document_sha256") != evidence_hash(document):
            errors.append(f"{label}: pinned protocol content SHA-256 is not reproducible")
        if entry.get("protocol_kind") != protocol.get("kind"):
            errors.append(f"{label}.protocol_kind differs from the pinned protocol")
        if entry.get("scope") != protocol.get("scope"):
            errors.append(f"{label}.scope differs from the pinned protocol")
        if document.get("fixture_id") != entry.get("fixture_id"):
            errors.append(f"{label}.fixture_id differs from the pinned protocol fixture")
        if document.get("protocol_version") != entry.get("protocol_version"):
            errors.append(f"{label}.protocol_version differs from the pinned protocol version")
        if entry.get("fixture_id") != fixture_id:
            errors.append(f"{label}.fixture_id differs from the draft fixture")
        if entry.get("protocol_version") != protocol_version:
            errors.append(f"{label}.protocol_version differs from the draft protocol")
        if not _nonempty(entry.get("rubric_use")):
            errors.append(f"{label}.rubric_use must be a non-empty string")
        controls = entry.get("required_controls")
        if (not isinstance(controls, list) or not controls
                or any(not _nonempty(control) for control in controls)):
            errors.append(f"{label}.required_controls must be a non-empty list of names")
        elif len(set(controls)) != len(controls):
            errors.append(f"{label}.required_controls contains duplicates")
        elif not isinstance(protocol.get("controls"), list) or set(controls) != set(protocol["controls"]):
            errors.append(f"{label}.required_controls differ from the frozen protocol controls")
        result[str(source_id)] = {**entry, "_source": source}
        report.append({
            "commitment_id": commitment_id,
            "source_id": source_id,
            "status": entry.get("status"),
            "origin": entry.get("origin"),
            "protocol_kind": entry.get("protocol_kind"),
            "rubric_use": entry.get("rubric_use"),
            "fixture_id": entry.get("fixture_id"),
            "protocol_version": entry.get("protocol_version"),
            "document_sha256": entry.get("document_sha256"),
            "required_controls": list(controls) if isinstance(controls, list) else [],
            "matches_fixture": document.get("fixture_id") == fixture_id,
            "matches_protocol": document.get("protocol_version") == protocol_version,
        })
    uncommitted = sorted(set(sources) - source_ids)
    if uncommitted:
        errors.append(f"pinned protocols without a commitment: {uncommitted}")
    return result, report


def _check_attestations(
    attestations: Any,
    *,
    commitments: Mapping[str, Mapping[str, Any]],
    epoch: Mapping[str, Any] | None,
    fixture: Mapping[str, Any] | None,
    errors: list[str],
) -> list[dict[str, Any]]:
    if not isinstance(attestations, list):
        errors.append("collected_attestations must be a list")
        return []
    fixture_id = (fixture or {}).get("fixture_id")
    protocol_version = (fixture or {}).get("protocol_version")
    epoch_id = (epoch or {}).get("epoch_id")
    checked: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(attestations):
        label = f"collected_attestations[{index}]"
        if not isinstance(entry, Mapping):
            errors.append(f"{label} must be an object")
            continue
        absent = [field for field in REQUIRED_ATTESTATION_FIELDS if field not in entry]
        if absent:
            errors.append(f"{label} missing fields: {absent}")
        attestation_id = entry.get("attestation_id")
        if not _nonempty(attestation_id):
            errors.append(f"{label}.attestation_id must be a non-empty string")
        elif attestation_id in seen_ids:
            errors.append(f"duplicate attestation_id: {attestation_id}")
        else:
            seen_ids.add(attestation_id)
        source_id = entry.get("source_id")
        commitment = commitments.get(str(source_id)) if _nonempty(source_id) else None
        if commitment is None:
            errors.append(f"{label}.source_id does not resolve to a protocol commitment")
        if not _nonempty(entry.get("identity")):
            errors.append(f"{label}.identity must be a non-empty string")
        if not _nonempty(entry.get("object")):
            errors.append(f"{label}.object must be a non-empty string")
        if not _nonempty(entry.get("action")):
            errors.append(f"{label}.action must be a non-empty string")
        allowed = entry.get("allowed_control")
        denied = entry.get("denied_control")
        if not _nonempty(allowed) or not _nonempty(denied):
            errors.append(f"{label} requires named allowed_control and denied_control")
        elif allowed == denied:
            errors.append(f"{label} allowed_control and denied_control must differ")
        elif commitment is not None:
            required = set(commitment.get("required_controls") or [])
            for field, control in (("allowed_control", allowed), ("denied_control", denied)):
                if control not in required:
                    errors.append(f"{label}.{field} is not a committed protocol control: {control}")
        if entry.get("fixture_id") != fixture_id:
            errors.append(f"{label}.fixture_id differs from the draft fixture")
        if entry.get("protocol_version") != protocol_version:
            errors.append(f"{label}.protocol_version differs from the draft protocol")
        if entry.get("epoch_id") != epoch_id:
            errors.append(f"{label}.epoch_id differs from the intended epoch")
        if not _hex64(entry.get("collector_sha256")):
            errors.append(f"{label}.collector_sha256 must be a lowercase SHA-256 hex digest")
        if not _hex64(entry.get("response_sha256")):
            errors.append(f"{label}.response_sha256 must be a lowercase SHA-256 hex digest")
        origin = entry.get("origin")
        scope = entry.get("validation_scope")
        if origin not in ORIGINS:
            errors.append(f"{label}.origin must be one of {sorted(ORIGINS)}")
        if scope not in VALIDATION_SCOPES:
            errors.append(f"{label}.validation_scope must be one of {sorted(VALIDATION_SCOPES)}")
        elif origin in ORIGINS and (origin == OPERATOR_ORIGIN) != (scope == OPERATOR_SCOPE):
            errors.append(f"{label}: origin and validation_scope disagree; synthetic fixtures "
                          "cannot be labelled as operator evidence")
        collected_at = _parsed_time(entry.get("collected_at"), f"{label}.collected_at", errors)
        recorded_at = None
        if entry.get("recorded_at") is not None:
            recorded_at = _parsed_time(entry.get("recorded_at"), f"{label}.recorded_at", errors)
        if collected_at is not None and recorded_at is not None and recorded_at < collected_at:
            errors.append(f"{label}.recorded_at precedes collected_at")
        checked.append({
            "attestation_id": attestation_id,
            "source_id": source_id,
            "origin": origin,
            "validation_scope": scope,
            "allowed_control": allowed,
            "denied_control": denied,
            "collected_at": collected_at,
            "recorded_at": recorded_at,
        })
    return checked


def _check_collection(
    collection: Any,
    *,
    attestations: list[dict[str, Any]],
    created_at: datetime | None,
    errors: list[str],
) -> None:
    """Validate collection metadata against the recorded attestations."""
    if not isinstance(collection, Mapping):
        errors.append("collection must be an object")
        return
    status = collection.get("status")
    if status not in COLLECTION_STATUSES:
        errors.append(f"collection.status must be one of {sorted(COLLECTION_STATUSES)}")
    if not _nonempty(collection.get("reason")):
        errors.append("collection.reason must state why attestations are or are not collected")
    for key in ("target_access_performed", "provider_access_performed"):
        if not isinstance(collection.get(key), bool):
            errors.append(f"collection.{key} must be a boolean")
    started_at = None
    completed_at = None
    if status == "not_collected":
        if attestations:
            errors.append("collection.status is not_collected but attestations are present")
        if collection.get("target_access_performed") or collection.get("provider_access_performed"):
            errors.append("collection.status is not_collected but the artifact claims access")
        for key in ("collector", "collector_sha256", "collection_started_at", "collection_completed_at"):
            if collection.get(key) is not None:
                errors.append(f"collection.{key} must be null while not_collected")
    elif status == "collected":
        if not _nonempty(collection.get("collector")):
            errors.append("collection.collector is required once collection is marked collected")
        if not _hex64(collection.get("collector_sha256")):
            errors.append("collection.collector_sha256 must be a lowercase SHA-256 hex digest")
        started_at = _parsed_time(collection.get("collection_started_at"),
                                  "collection.collection_started_at", errors)
        completed_at = _parsed_time(collection.get("collection_completed_at"),
                                    "collection.collection_completed_at", errors)
        if started_at is not None and completed_at is not None and completed_at < started_at:
            errors.append("collection.collection_completed_at precedes collection_started_at")
        if started_at is not None and created_at is not None and started_at < created_at:
            errors.append("collection.collection_started_at predates the recorded commitment")
        if not attestations:
            errors.append("collection.status is collected but no attestation is recorded")
        for attestation in attestations:
            collected_at = attestation["collected_at"]
            if collected_at is None:
                continue
            if started_at is not None and collected_at < started_at:
                errors.append(f"attestation {attestation['attestation_id']}.collected_at "
                              "predates collection_started_at")
            if completed_at is not None and collected_at > completed_at:
                errors.append(f"attestation {attestation['attestation_id']}.collected_at "
                              "postdates collection_completed_at")


def _check_approval(approval: Any, errors: list[str]) -> dict[str, Any] | None:
    """Validate the approval block and return it with a parsed timestamp."""
    if not isinstance(approval, Mapping):
        errors.append("approval must be an object")
        return None
    absent = [field for field in REQUIRED_APPROVAL_FIELDS if field not in approval]
    if absent:
        errors.append(f"approval missing fields: {absent}")
    status = approval.get("status")
    if status not in APPROVAL_STATUSES:
        errors.append(f"approval.status must be one of {sorted(APPROVAL_STATUSES)}")
    if not _nonempty(approval.get("reason")):
        errors.append("approval.reason must state the approval state")
    approved_at = None
    if status == "not_approved":
        for key in ("approved_at", "approved_by", "approval_reference", "signature"):
            if approval.get(key) is not None:
                errors.append(f"approval.{key} must be null while approval is not_approved; "
                              "a draft timestamp is never an approval")
    elif status == "approved":
        for key in ("approved_by", "approval_reference", "signature"):
            if not _nonempty(approval.get(key)):
                errors.append(f"approval.{key} is required for recorded approval metadata")
        approved_at = _parsed_time(approval.get("approved_at"), "approval.approved_at", errors)
    return {
        "status": status,
        "approved_at": approved_at,
        "approved_by": approval.get("approved_by"),
        "approval_reference": approval.get("approval_reference"),
        "signature": approval.get("signature"),
    }


def _check_offline_controls(
    controls: Any, *, scope: Any, errors: list[str],
) -> list[dict[str, Any]]:
    if controls is None:
        return []
    if not isinstance(controls, list):
        errors.append("offline_controls must be a list")
        return []
    result = []
    for index, control in enumerate(controls):
        label = f"offline_controls[{index}]"
        if not isinstance(control, Mapping) or not _nonempty(control.get("label")):
            errors.append(f"{label} requires a non-empty label")
            continue
        if control.get("validation_scope") != SYNTHETIC_SCOPE:
            errors.append(f"{label}.validation_scope must be {SYNTHETIC_SCOPE!r}")
        if scope == OPERATOR_SCOPE:
            errors.append(f"{label}: offline_control_not_operator_evidence; synthetic controls "
                          "cannot be listed in an operator-scope preregistration")
        result.append({"label": control.get("label"),
                       "validation_scope": control.get("validation_scope")})
    return result


def _configured_source_blockers(
    record: Any, root: Path, blockers: list[str],
) -> None:
    """Cross-check the configured oracle source so study and draft cannot drift."""
    if not isinstance(record, Mapping):
        return
    config_path = root / "config.yaml"
    if not config_path.is_file():
        return
    try:
        configured = (yaml.safe_load(config_path.read_text()) or {}).get("scoring_oracles")
    except (OSError, yaml.YAMLError):
        blockers.append("configured_oracle_source_unreadable")
        return
    if configured is None:
        return
    pinned = Path(str(record.get("path") or ""))
    if not pinned.is_absolute():
        pinned = root / pinned
    if isinstance(configured, str):
        candidate = Path(configured)
        if not candidate.is_absolute():
            candidate = root / candidate
        if candidate.resolve() != pinned.resolve():
            blockers.append("configured_oracle_source_mismatch")
    elif isinstance(configured, list):
        if evidence_hash(configured) != record.get("content_sha256"):
            blockers.append("configured_oracle_source_mismatch")
    else:
        blockers.append("configured_oracle_source_unrecognized")


def assess_draft(
    draft: Mapping[str, Any],
    *,
    root: str | Path = ".",
    checked_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Validate a preregistration draft and report readiness separately.

    Structural or evidence-integrity failures raise
    :class:`PreregistrationValidationError`.  A valid draft may still be not
    preregistered; that is reported as blockers because it is the expected
    state until recorded approval metadata with a timestamp exists.
    """
    if not isinstance(draft, Mapping):
        raise PreregistrationValidationError(["oracle preregistration draft must be a JSON object"])
    errors: list[str] = []
    blockers: list[str] = []
    root_path = Path(root)
    if checked_at is None:
        now = datetime.now(timezone.utc)
    elif isinstance(checked_at, str):
        now = _parsed_time(checked_at, "checked_at", errors) or datetime.now(timezone.utc)
    else:
        now = checked_at
        if now.tzinfo is None:
            errors.append("checked_at requires a timezone")

    if draft.get("artifact_type") != DRAFT_ARTIFACT_TYPE:
        errors.append(f"artifact_type must be {DRAFT_ARTIFACT_TYPE!r}")
    if draft.get("draft_version") != DRAFT_VERSION:
        errors.append(f"draft_version must be {DRAFT_VERSION!r}")
    if not _nonempty(draft.get("draft_id")):
        errors.append("draft_id must be a non-empty string")
    status = draft.get("status")
    if status not in DRAFT_STATUSES:
        errors.append(f"status must be one of {sorted(DRAFT_STATUSES)}")
    claimed_draft = draft.get("not_a_preregistration")
    if status == DRAFT_STATUS and claimed_draft is not True:
        errors.append("status draft_not_preregistered requires not_a_preregistration: true")
    if status == PREREGISTERED_STATUS and claimed_draft is not False:
        errors.append("status preregistered requires not_a_preregistration: false")
    for key in FALSE_CLAIM_KEYS:
        if draft.get(key):
            errors.append(f"top-level {key!r} claim is not allowed; record approval evidence instead")
    scope = draft.get("validation_scope")
    if scope not in VALIDATION_SCOPES:
        errors.append(f"validation_scope must be one of {sorted(VALIDATION_SCOPES)}")
    created_at = _parsed_time(draft.get("created_at"), "created_at", errors)
    if not _nonempty(draft.get("created_at_basis")):
        errors.append("created_at_basis must state what the timestamp does and does not mean")
    try:
        expected_hash = draft_hash(draft)
    except (TypeError, ValueError) as exc:
        errors.append(f"draft is not hashable: {exc}")
    else:
        if draft.get("draft_sha256") != expected_hash:
            errors.append("draft hash mismatch")

    epoch = _check_epoch(draft.get("intended_epoch"), errors)
    fixture = _check_fixture(draft.get("fixture"), errors)
    sources, source_path = _load_source_record(draft.get("source_record"), root_path, errors)
    commitments, commitment_report = _check_commitments(
        draft.get("protocol_commitments"), sources=sources, fixture=fixture, errors=errors,
    )
    attestations = _check_attestations(
        draft.get("collected_attestations"), commitments=commitments,
        epoch=epoch, fixture=fixture, errors=errors,
    )
    approval = _check_approval(draft.get("approval"), errors)
    _check_collection(
        draft.get("collection"), attestations=attestations, created_at=created_at, errors=errors,
    )
    offline_controls = _check_offline_controls(
        draft.get("offline_controls"), scope=scope, errors=errors,
    )
    _configured_source_blockers(draft.get("source_record"), root_path, blockers)

    # Timestamp order: a preregistration cannot predate the protocol it binds,
    # and collected evidence cannot predate either the commitment or approval.
    frozen_times = []
    for source in sources.values():
        document = source.get("document")
        if not isinstance(document, Mapping):
            continue
        frozen_at = _parsed_time(
            document.get("frozen_at"), f"source {source['source_id']}.frozen_at", errors,
        )
        if frozen_at is not None:
            frozen_times.append(frozen_at)
    latest_frozen = max(frozen_times) if frozen_times else None
    approved_at = approval["approved_at"] if approval else None
    epoch_started_at = None
    if epoch and epoch.get("started_at") is not None:
        epoch_started_at = _parsed_time(epoch["started_at"], "intended_epoch.started_at", errors)

    if created_at is not None:
        if created_at > now:
            errors.append("created_at is in the future; the draft clock cannot be backdated forward")
        if latest_frozen is not None and created_at < latest_frozen:
            errors.append("created_at predates a pinned protocol frozen_at; "
                          "preregistration cannot be backdated before its protocol")
        if epoch_started_at is not None and epoch_started_at < created_at:
            blockers.append("epoch_started_before_preregistration")
    if approved_at is not None:
        if approved_at > now:
            errors.append("approval.approved_at is in the future")
        if created_at is not None and approved_at < created_at:
            errors.append("approval.approved_at predates the draft")
        if latest_frozen is not None and approved_at < latest_frozen:
            errors.append("approval.approved_at predates a pinned protocol")

    # Metadata presence plus timestamp order only.  No cryptographic signature
    # validation, approver-authority proof, reference verification, or truth of
    # any attestation is performed.
    signed_timestamped = bool(
        approval and approval["status"] == "approved" and approved_at is not None
        and approval["approved_by"] and approval["approval_reference"] and approval["signature"]
    )
    if approval and approval["status"] == "approved" and status == DRAFT_STATUS:
        errors.append("an approved artifact must not remain draft_not_preregistered; "
                      "approval would be represented as preregistration")
    if status == PREREGISTERED_STATUS and not signed_timestamped:
        errors.append("status preregistered requires recorded approval metadata and a "
                      "timestamp; schemas and source protocols are not a preregistration")
    preregistered = bool(
        signed_timestamped and status == PREREGISTERED_STATUS and claimed_draft is False
    )

    operator_attestations: list[dict[str, Any]] = []
    synthetic_attestations: list[dict[str, Any]] = []
    for attestation in attestations:
        synthetic = scope != OPERATOR_SCOPE or attestation["origin"] != OPERATOR_ORIGIN
        collected_at = attestation["collected_at"]
        if collected_at is not None:
            if collected_at > now:
                errors.append(f"attestation {attestation['attestation_id']}.collected_at is in the future")
            if latest_frozen is not None and collected_at < latest_frozen:
                errors.append(f"attestation {attestation['attestation_id']}.collected_at "
                              "predates a pinned protocol")
            if created_at is not None and collected_at < created_at:
                errors.append(f"attestation {attestation['attestation_id']}.collected_at "
                              "predates the recorded commitment")
            if approved_at is not None and collected_at < approved_at:
                errors.append(f"attestation {attestation['attestation_id']}.collected_at "
                              "precedes the recorded approval; it cannot be preregistered evidence")
        if synthetic:
            synthetic_attestations.append({
                **attestation,
                "label": "synthetic offline control; never operator evidence",
            })
        else:
            operator_attestations.append(attestation)

    if scope == OPERATOR_SCOPE and synthetic_attestations:
        errors.append("offline_control_not_operator_evidence: synthetic attestations are "
                      "not permitted in an operator-scope preregistration")
    if operator_attestations and not preregistered:
        errors.append("operator attestations exist without a signed/timestamped preregistration")

    missing_controls = []
    required_total = 0
    covered_total = 0
    for commitment in commitment_report:
        required = list(commitment["required_controls"])
        covered = sorted({
            control
            for attestation in operator_attestations
            if attestation["source_id"] == commitment["source_id"]
            for control in (attestation["allowed_control"], attestation["denied_control"])
            if isinstance(control, str)
        })
        missing = [control for control in required if control not in covered]
        commitment["covered_controls"] = covered
        commitment["missing_controls"] = missing
        required_total += len(required)
        covered_total += len([control for control in required if control in covered])
        if missing:
            missing_controls.append({
                "source_id": commitment["source_id"],
                "required": required,
                "covered": covered,
                "missing": missing,
            })
    missing_total = required_total - covered_total

    # Starting the epoch before the recorded approval makes the preregistration
    # retrospective even when the draft's own timestamp order is valid.
    if epoch_started_at is not None and approved_at is not None and epoch_started_at < approved_at:
        blockers.append("epoch_started_before_preregistration")
    epoch_retrospective = "epoch_started_before_preregistration" in blockers

    # A protocol commitment/approval and later run-bound proof are separate
    # states.  Missing attestations never invalidate a preregistration that was
    # recorded before the epoch; they leave the corresponding claims unavailable.
    commitment_blockers: list[str] = []
    if not preregistered or epoch_retrospective:
        commitment_blockers.append("oracle_preregistration_missing")
    if not signed_timestamped:
        commitment_blockers.append("signed_timestamped_approval_missing")
    if epoch_retrospective:
        commitment_blockers.append("epoch_started_before_preregistration")
    proof_blockers: list[str] = []
    if not operator_attestations:
        proof_blockers.append("oracle_attestation_not_collected")
    if missing_total:
        proof_blockers.append(f"oracle_control_missing:{missing_total}")
    if synthetic_attestations or scope == SYNTHETIC_SCOPE:
        proof_blockers.append("synthetic_evidence_not_operator_evidence")
    blockers = sorted(set([*blockers, *commitment_blockers, *proof_blockers]))

    if errors:
        raise PreregistrationValidationError(errors)
    return {
        "draft_id": draft.get("draft_id"),
        "status": status,
        "not_a_preregistration": claimed_draft,
        "created_at": draft.get("created_at"),
        "created_at_basis": draft.get("created_at_basis"),
        "validation_scope": scope,
        "synthetic_validation_only": scope == SYNTHETIC_SCOPE,
        "epoch": epoch,
        "fixture": fixture,
        "source_record": {
            "path": str(source_path) if source_path is not None else draft.get("source_record", {}).get("path"),
            "file_sha256": draft.get("source_record", {}).get("file_sha256"),
            "content_sha256": draft.get("source_record", {}).get("content_sha256"),
            "source_count": draft.get("source_record", {}).get("source_count"),
            "sources": sorted(sources),
        },
        "collection_status": (
            draft.get("collection", {}).get("status")
            if isinstance(draft.get("collection"), Mapping) else None
        ),
        "commitments": commitment_report,
        "collected_attestations": {
            "operator": [
                {
                    "attestation_id": item["attestation_id"],
                    "source_id": item["source_id"],
                    "allowed_control": item["allowed_control"],
                    "denied_control": item["denied_control"],
                    "collected_at": item["collected_at"].isoformat() if item["collected_at"] else None,
                }
                for item in operator_attestations
            ],
            "synthetic": [
                {
                    "attestation_id": item["attestation_id"],
                    "source_id": item["source_id"],
                    "label": item["label"],
                }
                for item in synthetic_attestations
            ],
            "operator_count": len(operator_attestations),
            "synthetic_count": len(synthetic_attestations),
        },
        "missing_controls": missing_controls,
        "coverage": {
            "required_control_count": required_total,
            "covered_control_count": covered_total,
            "missing_control_count": missing_total,
        },
        "preregistration": {
            "status": PREREGISTERED_STATUS if preregistered else "not_preregistered",
            "signed_timestamped_approval": signed_timestamped,
            "authenticity_verified": False,
            "approved_by": approval["approved_by"] if approval else None,
            "approval_reference": approval["approval_reference"] if approval else None,
            "approved_at": approved_at.isoformat() if approved_at else None,
        },
        "verification": {
            "checked": [
                "draft and evidence hashes",
                "structure, uniqueness and required schema",
                "fixture/epoch/protocol/source binding",
                "timestamp order and collection window",
            ],
            "not_checked": [
                "cryptographic signature validity",
                "approver identity, authority or intent",
                "approval_reference validity",
                "attestation truth or actual target/provider state",
            ],
            "authenticity_verified": False,
            "approval_reference_note": (
                "approval_reference is non-empty metadata only; the owner must verify it "
                "independently before an approval is treated as authentic"
            ),
        },
        "readiness": {
            "present": preregistered and not epoch_retrospective,
            "ready": (preregistered and not epoch_retrospective and missing_total == 0
                      and scope == OPERATOR_SCOPE and not blockers),
            "blockers": blockers,
            # Commitment/prospective preregistration is decided before the
            # epoch; per-run control coverage is proof that can only arrive
            # during a technically ready execution.
            "commitment": {
                "preregistered": preregistered and not epoch_retrospective,
                "blockers": sorted(set(commitment_blockers)),
            },
            "proof": {
                "operator_attestations": len(operator_attestations),
                "missing_control_count": missing_total,
                "blockers": sorted(set(proof_blockers)),
            },
        },
        "attestation_schema": list(REQUIRED_ATTESTATION_FIELDS),
        "offline_controls": offline_controls,
    }


def validate_draft(
    draft: Mapping[str, Any],
    *,
    root: str | Path = ".",
    checked_at: datetime | str | None = None,
) -> None:
    """Raise :class:`PreregistrationValidationError` unless the draft is valid."""
    assess_draft(draft, root=root, checked_at=checked_at)


def render_report(report: Mapping[str, Any]) -> str:
    epoch = report.get("epoch") or {}
    fixture = report.get("fixture") or {}
    coverage = report["coverage"]
    readiness = report["readiness"]
    preregistration = report["preregistration"]
    lines = [
        f"Draft: {report.get('draft_id')} ({report.get('status')})",
        f"Not a preregistration: {report.get('not_a_preregistration')}; "
        f"validation scope: {report.get('validation_scope')}",
        f"Epoch: {epoch.get('epoch_id')} ({epoch.get('status')}) — fixture "
        f"{fixture.get('fixture_id')} / {fixture.get('protocol_version')}",
        f"Protocol commitments: {len(report['commitments'])} planned "
        f"({', '.join(item['source_id'] for item in report['commitments'])})",
        f"Collected operator attestations: {report['collected_attestations']['operator_count']} "
        f"(synthetic: {report['collected_attestations']['synthetic_count']})",
        f"Missing controls: {coverage['missing_control_count']}/"
        f"{coverage['required_control_count']} required",
        f"Preregistration: {'PRESENT' if preregistration['status'] == 'preregistered' else 'NOT PREREGISTERED'} "
        f"(approval metadata: "
        f"{'present' if preregistration['signed_timestamped_approval'] else 'missing'}; "
        "authenticity: not verified)",
        f"Readiness: commitment "
        f"{'RECORDED' if readiness.get('commitment', {}).get('preregistered') else 'BLOCKED'}; "
        f"collected proof {'COMPLETE' if readiness['ready'] else 'INCOMPLETE'}",
    ]
    commitment = readiness.get("commitment") or {}
    proof = readiness.get("proof") or {}
    if commitment.get("blockers"):
        lines.append("Commitment blockers:")
        for blocker in commitment["blockers"]:
            lines.append(f"  - {blocker}")
    if proof.get("blockers"):
        lines.append("Proof blockers (later run evidence):")
        for blocker in proof["blockers"]:
            lines.append(f"  - {blocker}")
    for item in report["missing_controls"]:
        lines.append(f"  - {item['source_id']}: missing {', '.join(item['missing'])}")
    if readiness["blockers"]:
        lines.append("Blockers:")
        for blocker in readiness["blockers"]:
            lines.append(f"  - {blocker}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draft", default=DEFAULT_DRAFT_PATH)
    parser.add_argument("--root", default=".")
    parser.add_argument("--checked-at", default=None,
                        help="ISO-8601 validation clock; defaults to the current time")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--require-preregistered", action="store_true",
        help="exit 2 unless a recorded, prospective preregistration commitment exists",
    )
    parser.add_argument(
        "--require-controls", action="store_true",
        help="exit 2 unless all committed control coverage has been collected and verified",
    )
    args = parser.parse_args(argv)
    try:
        report = assess_draft(
            load_draft(args.draft), root=args.root, checked_at=args.checked_at,
        )
    except (OSError, json.JSONDecodeError, PreregistrationValidationError) as exc:
        if args.as_json:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
        else:
            print(f"Invalid oracle preregistration draft: {exc}")
        return 1
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_report(report))
    if args.require_preregistered and not report["readiness"]["commitment"]["preregistered"]:
        return 2
    if args.require_controls and not report["readiness"]["ready"]:
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
