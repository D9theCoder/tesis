"""Focused offline regressions for the readiness launch gates.

Every fixture here is a synthetic local file.  No target, provider, runner or
planner code is called; no live probe or experiment result is produced.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from evaluation import experiment_readiness, oracle_preregistration
from evaluation.scoring_evidence import evidence_hash

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRIMARY_DRAFT_PATH = REPOSITORY_ROOT / "config/research/autoresearch-primary-draft-2026-10-31.json"
ORACLE_DRAFT_PATH = (
    REPOSITORY_ROOT / "config/research/autoresearch-oracle-preregistration-draft-2026-10-31.json"
)
ORACLE_SOURCE_PATH = REPOSITORY_ROOT / "config/oracles/dvwa-source-fee264766667580e5352.json"


def _write_json(path: Path, payload) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _profile_digest(profile: dict) -> str:
    return evidence_hash({key: value for key, value in profile.items() if key != "sha256"})


def _frozen_profile(*, profile_id: str = "ranking-approved", candidate_budget: int = 27) -> dict:
    profile = {
        "profile_id": profile_id,
        "version": "ranking-draft-freeze.v1",
        "fixture_id": "fixture-local",
        "protocol_version": "protocol.v1",
        "frozen_at": "2026-10-30T00:00:00+00:00",
        "candidate_budget": candidate_budget,
        "sources": [],
        "scenarios": {},
    }
    profile["sha256"] = _profile_digest(profile)
    return profile


def _policy_draft(profile: dict, *, epoch_id: str = "epoch-1") -> dict:
    digest = _profile_digest(profile)
    return {
        "intended_epoch": {"epoch_id": epoch_id},
        "policy": {
            "rubric_version": "scoring.v4",
            "scoring_profile": {
                "status": "present_frozen_before_selection",
                "profile_id": profile["profile_id"],
                "sha256": digest,
            },
            "scoring_oracles": {},
            "scoring_policy_epoch": {
                "status": "present_frozen",
                "epoch_id": epoch_id,
                "ranking_profile_sha256": digest,
            },
            "ranking_profile": {
                "status": "present_frozen_before_selection",
                "profile_id": profile["profile_id"],
                "sha256": digest,
            },
            "oracle_preregistration": {"status": "preregistered"},
            "candidate_order": {"status": "IMPLEMENTED_AND_FROZEN"},
        },
    }


def _policy_config(profile: dict, *, epoch_id: str = "epoch-1") -> dict:
    oracles = [{"source_id": "oracle-1"}]
    return {
        "scoring_profile": profile,
        "scoring_profile_sha256": evidence_hash(profile),
        "scoring_policy_epoch": {"epoch_id": epoch_id},
        "scoring_oracles": oracles,
        "scoring_oracle_validation": {"valid": True, "reason": None},
        "scoring_oracles_sha256": evidence_hash(oracles),
        "scoring_oracle_source_ids": ["oracle-1"],
        "scoring_mode": "ai",
        "scoring_rubric_version": "scoring.v4",
    }


def _blocker_ids(blockers) -> set[str]:
    return {blocker["id"] for blocker in blockers}


def test_oracle_gate_rejects_a_declared_status_without_an_actual_artifact(tmp_path):
    draft = {"policy": {"oracle_preregistration": {"status": "preregistered"}}}

    result = experiment_readiness._oracle_preregistration(draft, root=tmp_path)

    assert result["draft_declared_status"] == "preregistered"
    assert result["status"] == "missing_not_registered"
    assert result["registered"] is False


def test_oracle_gate_accepts_a_prospective_commitment_without_collected_proof(tmp_path):
    document = json.loads(ORACLE_DRAFT_PATH.read_text(encoding="utf-8"))
    source = json.loads(ORACLE_SOURCE_PATH.read_text(encoding="utf-8"))
    latest_protocol_freeze = max(
        item["document"]["frozen_at"] for item in source
    )
    # Keep the fixture valid on any clock at or after the pinned protocols.
    document["created_at"] = latest_protocol_freeze
    document["approval"]["approved_at"] = latest_protocol_freeze
    document["draft_sha256"] = oracle_preregistration.draft_hash(document)
    _write_json(tmp_path / experiment_readiness.ORACLE_PREREGISTRATION_DRAFT_PATH, document)
    (tmp_path / "config/oracles").mkdir(parents=True)
    shutil.copy(ORACLE_SOURCE_PATH, tmp_path / "config/oracles" / ORACLE_SOURCE_PATH.name)

    result = experiment_readiness._oracle_preregistration(
        {"policy": {"oracle_preregistration": {"status": "preregistered"}}}, root=tmp_path,
    )

    assert result["status"] == "preregistered"
    assert result["registered"] is True
    assert result["commitment"]["preregistered"] is True
    assert result["commitment"]["blockers"] == []
    assert result["proof"]["blockers"]
    assert result["evidence_imported"] is True


def _stub_build(monkeypatch, oracle_result: dict) -> None:
    module = experiment_readiness

    monkeypatch.setattr(module, "validate_design", lambda draft: [])
    monkeypatch.setattr(module, "validate_coordinates", lambda draft: ([], {}))
    monkeypatch.setattr(module, "load_configured", lambda path: {})
    monkeypatch.setattr(
        module, "source_snapshot",
        lambda root, config: (
            {"tree_sha256": "a" * 64, "config_sha256": "b" * 64}, [],
        ),
    )
    monkeypatch.setattr(module, "analyse_models", lambda draft, configured: ([], [], []))
    monkeypatch.setattr(module, "analyse_policy", lambda draft, configured: ({}, []))
    monkeypatch.setattr(module, "analyse_cost", lambda draft, configured: ({}, [], []))
    monkeypatch.setattr(
        module, "analyse_scope", lambda draft, configured, *, repo_root: ({}, []),
    )
    monkeypatch.setattr(
        module, "analyse_study_contract", lambda **kwargs: ({}, []),
    )
    monkeypatch.setattr(
        module, "analyse_planner_status",
        lambda **kwargs: {
            "matrix_launch_ready": True, "build_verify": True, "execution": True,
        },
    )
    monkeypatch.setattr(module, "analyse_output_root", lambda root, draft: ({}, []))
    monkeypatch.setattr(module, "check_discovery", lambda **kwargs: ({}, []))
    monkeypatch.setattr(
        module, "_authorization_gate",
        lambda draft: {"execution_authorized": True, "owner_approval_recorded": True},
    )
    monkeypatch.setattr(module, "_oracle_preregistration", lambda draft, *, root: oracle_result)


def test_launch_gate_blocks_until_the_oracle_commitment_is_actually_registered(monkeypatch, tmp_path):
    missing = {
        "status": "missing_not_registered",
        "registered": False,
        "draft_declared_status": "preregistered",
        "draft_path": experiment_readiness.ORACLE_PREREGISTRATION_DRAFT_PATH,
        "commitment": None,
        "proof": None,
        "detail": "missing fixture artifact",
    }
    _stub_build(monkeypatch, missing)

    report = experiment_readiness.build_readiness_report(
        draft_path=PRIMARY_DRAFT_PATH,
        config_path="config.yaml",
        repo_root=tmp_path,
    )

    assert "oracle_preregistration_uncommitted" in _blocker_ids(report["blockers"])
    assert report["launch_gate"]["matrix_launch_ready"] is False
    assert report["launch_gate"]["oracle_preregistration_committed"] is False
    assert report["execution_authorized"] is False


def test_launch_gate_does_not_require_per_run_oracle_proof(monkeypatch, tmp_path):
    registered = {
        "status": "preregistered",
        "registered": True,
        "draft_declared_status": "preregistered",
        "draft_path": experiment_readiness.ORACLE_PREREGISTRATION_DRAFT_PATH,
        "commitment": {"preregistered": True, "blockers": []},
        "proof": {
            "operator_attestations": 0,
            "missing_control_count": 10,
            "blockers": ["oracle_control_missing:10"],
        },
        "detail": "prospective commitment recorded",
    }
    _stub_build(monkeypatch, registered)

    report = experiment_readiness.build_readiness_report(
        draft_path=PRIMARY_DRAFT_PATH,
        config_path="config.yaml",
        repo_root=tmp_path,
    )

    assert "oracle_preregistration_uncommitted" not in _blocker_ids(report["blockers"])
    assert report["blockers"] == []
    assert report["launch_gate"]["matrix_launch_ready"] is True
    assert report["launch_gate"]["oracle_preregistration_committed"] is True
    assert report["oracle_preregistration"] is registered


def test_policy_accepts_a_configured_profile_bound_to_the_approved_draft():
    profile = _frozen_profile()
    draft = _policy_draft(profile)

    result, blockers = experiment_readiness.analyse_policy(
        draft, _policy_config(profile),
    )

    assert blockers == []
    binding = result["ranking_profile"]["configured_binding"]
    assert binding["digest_match"] is True
    assert binding["profile_id_match"] is True
    assert binding["epoch_match"] is True
    assert result["ranking_profile"]["sha256"] == _profile_digest(profile)


def test_policy_rejects_configured_profile_substitution_instead_of_overwriting_draft():
    approved = _frozen_profile(candidate_budget=27)
    stale = _frozen_profile(candidate_budget=9)
    draft = _policy_draft(approved)
    approved_digest = _profile_digest(approved)

    result, blockers = experiment_readiness.analyse_policy(
        draft, _policy_config(stale),
    )

    assert "ranking_profile_digest_mismatch" in _blocker_ids(blockers)
    assert result["ranking_profile"]["sha256"] == approved_digest
    assert result["ranking_profile"]["configured_binding"]["digest_match"] is False
    assert result["ranking_profile"]["configured_binding"]["configured_canonical_sha256"] != approved_digest


def test_policy_rejects_profile_identity_and_epoch_mismatches():
    approved = _frozen_profile(profile_id="ranking-approved")
    other_identity = _frozen_profile(profile_id="ranking-other")
    draft = _policy_draft(approved)

    _, identity_blockers = experiment_readiness.analyse_policy(
        draft, _policy_config(other_identity),
    )
    _, epoch_blockers = experiment_readiness.analyse_policy(
        draft, _policy_config(approved, epoch_id="epoch-2"),
    )

    assert "ranking_profile_identity_mismatch" in _blocker_ids(identity_blockers)
    assert "scoring_policy_epoch_identity_mismatch" in _blocker_ids(epoch_blockers)


def test_policy_rejects_contradictory_approved_epoch_identities():
    profile = _frozen_profile()
    draft = _policy_draft(profile, epoch_id="epoch-1")
    draft["policy"]["scoring_policy_epoch"]["intended_epoch_id"] = "epoch-2"

    for configured_epoch in ("epoch-1", "epoch-2"):
        _, blockers = experiment_readiness.analyse_policy(
            draft, _policy_config(profile, epoch_id=configured_epoch),
        )
        ids = _blocker_ids(blockers)
        assert "scoring_policy_epoch_identity_conflict" in ids
        assert "scoring_policy_epoch_identity_mismatch" in ids


def _live_draft() -> dict:
    return {
        "intended_epoch": {"epoch_id": "epoch-1"},
        "design": {"models": [{"configured_profile_id": "profile-1"}]},
    }


def _live_document(config_sha, source_sha: str = "a" * 64, *, include_config: bool = True) -> dict:
    check_ids = {
        "containment.http",
        "live.dvwa.authentication",
        "live.dvwa.levels",
        "live.dvwa.surfaces",
        "live.model.profile-1",
    }
    document = {
        "artifact_type": "autoresearch_live_readiness",
        "epoch_id": "epoch-1",
        "target_url": "http://127.0.0.1/dvwa",
        "source_hashes_sha256": source_sha,
        "generated_at": "2026-10-31T10:25:10+00:00",
        "checks": [
            {"id": check_id, "status": "passed", "detail": "synthetic fixture"}
            for check_id in sorted(check_ids)
        ],
    }
    if include_config:
        document["config_sha256"] = config_sha
    return document


def _write_live_document(tmp_path: Path, document: dict) -> None:
    _write_json(
        tmp_path / "results/epochs/epoch-1/live-readiness.json",
        document,
    )


def test_live_readiness_accepts_evidence_bound_to_the_frozen_config(tmp_path):
    _write_live_document(tmp_path, _live_document("b" * 64))
    configured = {
        "_source_tree_sha256": "a" * 64,
        "_config_sha256": "b" * 64,
        "target_url": "http://127.0.0.1/dvwa",
    }

    result, blockers = experiment_readiness.analyse_live_readiness(
        _live_draft(), configured, repo_root=tmp_path,
    )

    assert blockers == []
    assert result["issues"] == []
    assert result["present"] is True


def test_live_readiness_rejects_missing_or_mismatched_config_digest(tmp_path):
    configured = {
        "_source_tree_sha256": "a" * 64,
        "_config_sha256": "b" * 64,
        "target_url": "http://127.0.0.1/dvwa",
    }

    _write_live_document(tmp_path, _live_document("c" * 64))
    mismatch, mismatch_blockers = experiment_readiness.analyse_live_readiness(
        _live_draft(), configured, repo_root=tmp_path,
    )
    assert "config_sha256" in mismatch["issues"]
    assert "live_readiness_identity_mismatch" in _blocker_ids(mismatch_blockers)

    _write_live_document(tmp_path, _live_document("b" * 64, include_config=False))
    missing, missing_blockers = experiment_readiness.analyse_live_readiness(
        _live_draft(), configured, repo_root=tmp_path,
    )
    assert "config_sha256" in missing["issues"]
    assert "live_readiness_identity_mismatch" in _blocker_ids(missing_blockers)

    _write_live_document(tmp_path, _live_document("b" * 64))
    unbound, unbound_blockers = experiment_readiness.analyse_live_readiness(
        _live_draft(),
        {
            "_source_tree_sha256": "a" * 64,
            "target_url": "http://127.0.0.1/dvwa",
        },
        repo_root=tmp_path,
    )
    assert "config_sha256" in unbound["issues"]
    assert "live_readiness_identity_mismatch" in _blocker_ids(unbound_blockers)


def _output_draft() -> dict:
    return {
        "intended_epoch": {
            "epoch_id": "epoch-1",
            "output_root": "results/runs/epoch-1",
        },
    }


def test_output_root_fails_closed_when_existing_root_is_a_regular_file(tmp_path):
    target = tmp_path / "results/runs/epoch-1"
    target.parent.mkdir(parents=True)
    target.write_text("not a directory", encoding="utf-8")

    result, blockers = experiment_readiness.analyse_output_root(tmp_path, _output_draft())

    assert result["readable"] is False
    assert "output_root_not_directory" in _blocker_ids(blockers)


def test_output_root_fails_closed_when_entries_cannot_be_enumerated(tmp_path, monkeypatch):
    target = tmp_path / "results/runs/epoch-1"
    target.mkdir(parents=True)
    original_iterdir = Path.iterdir

    def deny_read(self):
        if self == target:
            raise PermissionError("synthetic unreadable output root")
        return original_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", deny_read)

    result, blockers = experiment_readiness.analyse_output_root(tmp_path, _output_draft())

    assert result["exists"] is True
    assert result["readable"] is False
    assert "output_root_unreadable" in _blocker_ids(blockers)
    assert "error" in result


def test_output_root_allows_only_enumerated_pre_execution_files(tmp_path):
    target = tmp_path / "results/runs/epoch-1"
    target.mkdir(parents=True)
    (target / "research-plan.json").write_text("{}", encoding="utf-8")
    (target / "payload-policy-snapshot.json").write_text("{}", encoding="utf-8")

    result, blockers = experiment_readiness.analyse_output_root(tmp_path, _output_draft())

    assert blockers == []
    assert result["readable"] is True
    assert result["pre_execution_only"] is True
    assert result["non_empty"] is False

    (target / "execution.json").write_text("{}", encoding="utf-8")
    result, blockers = experiment_readiness.analyse_output_root(tmp_path, _output_draft())
    assert "output_root_not_empty" in _blocker_ids(blockers)


def test_output_root_rejects_allowlisted_names_that_are_directories(tmp_path):
    target = tmp_path / "results/runs/epoch-1"
    target.mkdir(parents=True)
    (target / "research-plan.json").mkdir()

    result, blockers = experiment_readiness.analyse_output_root(tmp_path, _output_draft())

    assert result["readable"] is True
    assert result["pre_execution_only"] is False
    assert result["non_empty"] is True
    assert "output_root_not_empty" in _blocker_ids(blockers)
