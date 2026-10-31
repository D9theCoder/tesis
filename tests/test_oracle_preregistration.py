"""Offline controls for independent-oracle preregistration readiness.

Every draft mutation below is a labelled synthetic fixture.  The synthetic
approval and attestation records are schema probes only: they are never owner
approvals, never collected from DVWA, and never operator evidence.  No target,
provider, runner, planner, collector, or graph code is called here.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from evaluation import oracle_preregistration, ranking_draft
from evaluation.scoring_evidence import evidence_hash

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DRAFT_PATH = REPOSITORY_ROOT / "config/research/autoresearch-oracle-preregistration-draft-2026-10-31.json"
SOURCE_PATH = REPOSITORY_ROOT / "config/oracles/dvwa-source-fee264766667580e5352.json"
CHECKED_AT = datetime(2026, 11, 1, tzinfo=timezone.utc)
SYNTHETIC_APPROVED_AT = "2026-10-31T01:30:00+00:00"


def _draft() -> dict:
    return copy.deepcopy(oracle_preregistration.load_draft(DRAFT_PATH))


def _rehash(draft: dict) -> dict:
    draft["draft_sha256"] = oracle_preregistration.draft_hash(draft)
    return draft


def _assess(draft: dict, root: Path = REPOSITORY_ROOT) -> dict:
    return oracle_preregistration.assess_draft(draft, root=root, checked_at=CHECKED_AT)


def _synthetic_attestation(commitment: dict, *, attestation_id: str = "att-synthetic-1",
                           origin: str = "offline_control",
                           scope: str = "offline_synthetic_fixture", **overrides) -> dict:
    """A labelled schema probe; never a real attestation."""
    entry = {
        "attestation_id": attestation_id,
        "source_id": commitment["source_id"],
        "protocol_version": "ranking-session-acceptance.v1",
        "fixture_id": "dvwa-source-fee264766667580e5352",
        "epoch_id": "autoresearch-primary-2026-10-31",
        "identity": "synthetic alternate principal (test fixture)",
        "object": "synthetic fixture object (test fixture)",
        "action": "read (test fixture)",
        "allowed_control": commitment["required_controls"][0],
        "denied_control": commitment["required_controls"][1],
        "collected_at": "2026-10-31T02:00:00+00:00",
        "recorded_at": "2026-10-31T02:01:00+00:00",
        "collector_sha256": "0" * 64,
        "response_sha256": "1" * 64,
        "origin": origin,
        "validation_scope": scope,
    }
    entry.update(overrides)
    return entry


def _synthetic_preregistered_fixture() -> dict:
    """A fully signed synthetic commitment, clearly labelled as a fixture."""
    draft = _draft()
    draft["status"] = "preregistered"
    draft["not_a_preregistration"] = False
    draft["validation_scope"] = "offline_synthetic_fixture"
    draft["approval"] = {
        "status": "approved",
        "reason": "Synthetic test fixture for schema reachability; never an owner approval.",
        "approved_at": SYNTHETIC_APPROVED_AT,
        "approved_by": "synthetic-test-operator",
        "approval_reference": "synthetic-test-approval-reference",
        "signature": "synthetic-test-signature",
    }
    return _rehash(draft)


def _mark_collected(draft: dict, *, started: str = "2026-10-31T01:50:00+00:00",
                    completed: str = "2026-10-31T02:10:00+00:00") -> dict:
    """Pair synthetic attestations with a labelled synthetic collection record."""
    draft["collection"] = {
        "status": "collected",
        "reason": "Synthetic test fixture; no target or provider access was performed.",
        "collector": "synthetic-test-collector",
        "collector_sha256": "2" * 64,
        "collection_started_at": started,
        "collection_completed_at": completed,
        "target_access_performed": False,
        "provider_access_performed": False,
    }
    return _rehash(draft)


def test_preregistered_draft_binds_operator_protocols_and_keeps_proof_missing():
    draft = _draft()
    report = _assess(draft)

    assert draft["not_a_preregistration"] is False
    assert draft["status"] == "preregistered"
    assert draft["validation_scope"] == "operator_fixture"
    assert draft["collected_attestations"] == []
    assert draft["offline_controls"] == []
    assert draft["approval"]["status"] == "approved"

    assert len(report["commitments"]) == 3
    assert {item["source_id"] for item in report["commitments"]} == {
        "dvwa-session-protocol",
        "dvwa-candidate-permission-protocol-completion-all-frozen-objects",
        "dvwa-causal-dependency-protocol-completion",
    }
    assert all(item["status"] == "planned" for item in report["commitments"])
    assert all(item["matches_fixture"] and item["matches_protocol"] for item in report["commitments"])
    assert all(item["origin"] == "operator_fixture" for item in report["commitments"])

    source_record = json.loads(SOURCE_PATH.read_text())
    pinned = {source["source_id"]: source for source in source_record}
    for commitment in report["commitments"]:
        source = pinned[commitment["source_id"]]
        assert commitment["document_sha256"] == source["sha256"]
        assert commitment["document_sha256"] == evidence_hash(source["document"])
        assert set(commitment["required_controls"]) == set(
            source["document"]["oracle_protocol"]["controls"]
        )

    assert report["source_record"]["file_sha256"] == sha256(SOURCE_PATH.read_bytes()).hexdigest()
    assert report["source_record"]["content_sha256"] == evidence_hash(source_record)
    assert report["source_record"]["source_count"] == 3

    assert report["collected_attestations"] == {
        "operator": [], "synthetic": [], "operator_count": 0, "synthetic_count": 0,
    }
    assert report["coverage"] == {
        "required_control_count": 10,
        "covered_control_count": 0,
        "missing_control_count": 10,
    }
    assert {item["source_id"] for item in report["missing_controls"]} == set(pinned)
    assert all(item["covered_controls"] == [] and len(item["missing_controls"]) > 0
               for item in report["commitments"])
    assert report["preregistration"] == {
        "status": "preregistered",
        "signed_timestamped_approval": True,
        "authenticity_verified": False,
        "approved_by": draft["approval"]["approved_by"],
        "approval_reference": draft["approval"]["approval_reference"],
        "approved_at": draft["approval"]["approved_at"],
    }
    assert report["verification"]["authenticity_verified"] is False
    assert "cryptographic signature validity" in report["verification"]["not_checked"]
    assert "approval_reference validity" in report["verification"]["not_checked"]
    assert report["verification"]["checked"]
    assert report["readiness"]["present"] is True
    assert report["readiness"]["ready"] is False
    assert set(report["readiness"]["blockers"]) == {
        "oracle_attestation_not_collected",
        "oracle_control_missing:10",
    }
    assert report["readiness"]["commitment"] == {
        "preregistered": True,
        "blockers": [],
    }
    assert report["readiness"]["proof"] == {
        "operator_attestations": 0,
        "missing_control_count": 10,
        "blockers": ["oracle_attestation_not_collected", "oracle_control_missing:10"],
    }
    assert report["synthetic_validation_only"] is False

    assert set(ranking_draft.ORACLE_PREREGISTRATION_REQUIRED) <= set(
        oracle_preregistration.REQUIRED_ATTESTATION_FIELDS
    )
    assert report["attestation_schema"] == list(
        oracle_preregistration.REQUIRED_ATTESTATION_FIELDS
    )


def test_source_and_draft_hashes_are_reproducible_and_tamper_detected():
    draft = _draft()
    draft["draft_id"] = "tampered-draft-id"

    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="draft hash mismatch"):
        _assess(draft)

    draft = _draft()
    draft["protocol_commitments"][0]["document_sha256"] = "f" * 64
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="content SHA-256 does not match the pinned protocol"):
        _assess(draft)

    draft = _draft()
    draft["source_record"]["file_sha256"] = "0" * 64
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="file_sha256 does not match"):
        _assess(draft)

    draft = _draft()
    draft["source_record"]["content_sha256"] = "0" * 64
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="content_sha256 does not match"):
        _assess(draft)


def test_fixture_epoch_and_protocol_mismatch_are_rejected(tmp_path):
    draft = _draft()
    draft["protocol_commitments"][0]["fixture_id"] = "other-fixture"
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="differs from the pinned protocol fixture"):
        _assess(draft)

    draft = _draft()
    draft["intended_epoch"]["output_root"] = "results/runs/other-epoch"
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="output_root must be results/runs"):
        _assess(draft)

    # Mutating the pinned protocol's own fixture_id must break the binding even
    # when every hash in the draft is recomputed.
    draft = _draft()
    record = json.loads(SOURCE_PATH.read_text())
    record[0]["document"]["fixture_id"] = "other-fixture"
    record[0]["sha256"] = evidence_hash(record[0]["document"])
    path = tmp_path / "config/oracles/dvwa-source-fee264766667580e5352.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(record, sort_keys=True))
    draft["source_record"]["file_sha256"] = sha256(path.read_bytes()).hexdigest()
    draft["source_record"]["content_sha256"] = evidence_hash(record)
    _rehash(draft)

    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="differs from the pinned protocol fixture"):
        _assess(draft, root=tmp_path)


def test_control_sets_come_from_the_frozen_protocols():
    draft = _draft()
    draft["protocol_commitments"][0]["required_controls"].append("invented_control")
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="differ from the frozen protocol controls"):
        _assess(draft)

    draft = _draft()
    draft["protocol_commitments"][0]["required_controls"].pop()
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="differ from the frozen protocol controls"):
        _assess(draft)

    draft = _draft()
    controls = draft["protocol_commitments"][0]["required_controls"]
    controls.append(controls[0])
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="required_controls contains duplicates"):
        _assess(draft)


def test_duplicate_commitment_and_attestation_ids_are_rejected():
    draft = _draft()
    draft["protocol_commitments"].append(copy.deepcopy(draft["protocol_commitments"][1]))
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="duplicate commitment source_id"):
        _assess(draft)

    draft = _synthetic_preregistered_fixture()
    commitment = draft["protocol_commitments"][0]
    draft["collected_attestations"] = [
        _synthetic_attestation(commitment, attestation_id="att-duplicate"),
        _synthetic_attestation(commitment, attestation_id="att-duplicate",
                               allowed_control=commitment["required_controls"][2],
                               denied_control=commitment["required_controls"][3]),
    ]
    _mark_collected(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="duplicate attestation_id"):
        _assess(draft)


def test_offline_control_cannot_be_promoted_to_operator_evidence():
    draft = _draft()
    draft["collected_attestations"] = [
        _synthetic_attestation(draft["protocol_commitments"][0])
    ]
    _mark_collected(draft)

    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="offline_control_not_operator_evidence"):
        _assess(draft)


def test_synthetic_scope_is_labelled_and_never_counts_as_operator_evidence():
    draft = _synthetic_preregistered_fixture()
    draft["collected_attestations"] = [
        _synthetic_attestation(draft["protocol_commitments"][0]),
        # Even an operator-labelled record is relabelled in a synthetic scope.
        _synthetic_attestation(
            draft["protocol_commitments"][1], attestation_id="att-synthetic-2",
            origin="operator_fixture", scope="operator_fixture",
        ),
    ]
    _mark_collected(draft)

    report = _assess(draft)

    assert report["synthetic_validation_only"] is True
    assert report["collected_attestations"]["operator_count"] == 0
    assert report["collected_attestations"]["synthetic_count"] == 2
    assert all(item["label"] == "synthetic offline control; never operator evidence"
               for item in report["collected_attestations"]["synthetic"])
    assert report["coverage"]["covered_control_count"] == 0
    assert report["coverage"]["missing_control_count"] == 10
    assert "synthetic_evidence_not_operator_evidence" in report["readiness"]["blockers"]
    assert report["readiness"]["ready"] is False


def test_synthetic_commitment_is_preregistered_but_evidence_stays_missing():
    draft = _synthetic_preregistered_fixture()
    report = _assess(draft)

    assert report["synthetic_validation_only"] is True
    assert report["preregistration"]["status"] == "preregistered"
    assert report["preregistration"]["signed_timestamped_approval"] is True
    assert report["preregistration"]["approved_at"] == SYNTHETIC_APPROVED_AT
    assert report["readiness"]["present"] is True
    assert report["readiness"]["ready"] is False
    assert "oracle_preregistration_missing" not in report["readiness"]["blockers"]
    assert "signed_timestamped_approval_missing" not in report["readiness"]["blockers"]
    assert "oracle_attestation_not_collected" in report["readiness"]["blockers"]
    assert "oracle_control_missing:10" in report["readiness"]["blockers"]

    draft["collected_attestations"] = [
        _synthetic_attestation(draft["protocol_commitments"][0])
    ]
    _mark_collected(draft)
    report = _assess(draft)
    assert report["collected_attestations"]["operator_count"] == 0
    assert report["coverage"]["covered_control_count"] == 0


def test_preregistration_state_cannot_be_claimed_without_signed_approval():
    draft = _draft()
    draft["approval"] = {
        "status": "not_approved",
        "reason": "Test fixture: approval deliberately removed.",
        "approved_at": None,
        "approved_by": None,
        "approval_reference": None,
        "signature": None,
    }
    draft["status"] = "preregistered"
    draft["not_a_preregistration"] = False
    _rehash(draft)

    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="requires recorded approval metadata"):
        _assess(draft)

    draft = _draft()
    draft["approval"]["status"] = "not_approved"
    draft["approval"]["approved_at"] = SYNTHETIC_APPROVED_AT
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="must be null while approval is not_approved"):
        _assess(draft)

    draft = _synthetic_preregistered_fixture()
    draft["status"] = "draft_not_preregistered"
    draft["not_a_preregistration"] = True
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="must not remain draft_not_preregistered"):
        _assess(draft)


def test_timestamp_order_rejects_backdating_and_retrospective_evidence():
    draft = _draft()
    draft["created_at"] = "2026-12-01T00:00:00+00:00"
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="created_at is in the future"):
        _assess(draft)

    draft = _draft()
    draft["created_at"] = "2026-10-01T00:00:00+00:00"
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="predates a pinned protocol"):
        _assess(draft)

    draft = _synthetic_preregistered_fixture()
    draft["collected_attestations"] = [
        _synthetic_attestation(
            draft["protocol_commitments"][0], collected_at="2026-10-31T00:30:00+00:00",
        )
    ]
    _mark_collected(draft, started="2026-10-30T00:00:00+00:00",
                    completed="2026-10-31T02:10:00+00:00")
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="predates the recorded commitment"):
        _assess(draft)

    draft = _synthetic_preregistered_fixture()
    draft["collected_attestations"] = [
        _synthetic_attestation(
            draft["protocol_commitments"][0], collected_at="2026-10-31T01:15:00+00:00",
            recorded_at="2026-10-31T01:16:00+00:00",
        )
    ]
    _mark_collected(draft, started="2026-10-31T01:01:00+00:00")
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="precedes the recorded approval"):
        _assess(draft)

    draft = _synthetic_preregistered_fixture()
    draft["approval"]["approved_at"] = "2026-10-31T00:30:00+00:00"
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="approval.approved_at predates the draft"):
        _assess(draft)


def test_epoch_started_before_preregistration_blocks_presence():
    draft = _synthetic_preregistered_fixture()
    draft["intended_epoch"].update({
        "status": "started", "started_at": "2026-10-31T00:30:00+00:00",
    })
    _rehash(draft)

    report = _assess(draft)

    assert "epoch_started_before_preregistration" in report["readiness"]["blockers"]
    assert "oracle_preregistration_missing" in report["readiness"]["blockers"]
    assert report["readiness"]["present"] is False
    assert report["readiness"]["ready"] is False

    draft = _synthetic_preregistered_fixture()
    draft["intended_epoch"].update({
        "status": "started", "started_at": "2026-10-31T02:00:00+00:00",
    })
    _rehash(draft)

    report = _assess(draft)

    assert "epoch_started_before_preregistration" not in report["readiness"]["blockers"]
    assert report["readiness"]["present"] is True


def test_collection_metadata_cannot_contradict_the_attestation_list():
    draft = _draft()
    draft["collection"]["status"] = "collected"
    draft["collection"]["collection_started_at"] = "2026-10-31T02:00:00+00:00"
    draft["collection"]["collection_completed_at"] = "2026-10-31T02:05:00+00:00"
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="no attestation is recorded"):
        _assess(draft)

    draft = _draft()
    draft["collection"]["target_access_performed"] = True
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="claims access"):
        _assess(draft)

    draft = _draft()
    draft["collected_attestations"] = [
        _synthetic_attestation(draft["protocol_commitments"][0])
    ]
    _rehash(draft)
    with pytest.raises(oracle_preregistration.PreregistrationValidationError,
                       match="not_collected but attestations are present"):
        _assess(draft)


def test_configured_oracle_source_drift_is_reported(tmp_path):
    draft = _draft()
    target = tmp_path / "config/oracles"
    target.mkdir(parents=True)
    (target / SOURCE_PATH.name).write_bytes(SOURCE_PATH.read_bytes())
    (tmp_path / "config.yaml").write_text(
        "scoring_oracles: config/oracles/other-source.json\n", encoding="utf-8",
    )

    report = _assess(draft, root=tmp_path)

    assert "configured_oracle_source_mismatch" in report["readiness"]["blockers"]
    assert report["readiness"]["ready"] is False


def test_cli_separates_commitment_from_collected_proof(capsys):
    code = oracle_preregistration.main([
        "--draft", str(DRAFT_PATH), "--root", str(REPOSITORY_ROOT),
        "--checked-at", CHECKED_AT.isoformat(),
    ])
    output = capsys.readouterr().out

    assert code == 0
    assert "Not a preregistration: False" in output
    assert "Preregistration: PRESENT" in output
    assert "Missing controls: 10/10 required" in output
    assert "commitment RECORDED" in output
    assert "collected proof INCOMPLETE" in output

    strict = oracle_preregistration.main([
        "--draft", str(DRAFT_PATH), "--root", str(REPOSITORY_ROOT),
        "--checked-at", CHECKED_AT.isoformat(), "--require-preregistered",
    ])
    assert strict == 0

    controls = oracle_preregistration.main([
        "--draft", str(DRAFT_PATH), "--root", str(REPOSITORY_ROOT),
        "--checked-at", CHECKED_AT.isoformat(), "--require-controls",
    ])
    assert controls == 2


def test_cli_rejects_a_tampered_draft(tmp_path, capsys):
    draft = _draft()
    draft["source_record"]["content_sha256"] = "0" * 64
    _rehash(draft)
    path = tmp_path / "draft.json"
    path.write_text(json.dumps(draft), encoding="utf-8")

    code = oracle_preregistration.main(["--draft", str(path), "--root", str(REPOSITORY_ROOT)])

    assert code == 1
    assert "content_sha256 does not match" in capsys.readouterr().out


def test_validation_does_not_mutate_the_draft():
    draft = _draft()
    before = copy.deepcopy(draft)

    _assess(draft)

    assert draft == before
