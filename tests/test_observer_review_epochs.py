"""Offline historical review-epoch binding checks; no graph, provider or network."""
import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from evaluation import observer_reviews, thesis_scoring
from evaluation.research_metrics import SCORING_SOURCE_FILES
from tests.test_execution_security_status import evidence_artifact
from tesis.artifact_catalog import ArtifactCatalog


HISTORICAL_HASHES = {
    path: sha256(f"historical:{path}".encode()).hexdigest()
    for path in SCORING_SOURCE_FILES
}
HISTORICAL_DIGEST = sha256(
    "".join(HISTORICAL_HASHES[path] for path in SCORING_SOURCE_FILES).encode()
).hexdigest()


def source_set_digest(value):
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def make_source(tmp_path, *, anchors=True, source_hashes=None, epoch_digest=None):
    artifact = evidence_artifact()
    row = artifact["final_state"]["response_evidence"][0]
    row["verification_reason"] = "verified_error_extraction"
    row["signal_detected"] = True
    artifact["final_state"]["verifier_history"][0]["decision"] = "confirmed"
    if anchors:
        hashes = dict(source_hashes or HISTORICAL_HASHES)
        identity_digest = source_set_digest(hashes)
        artifact["source_identity"] = {
            "identity_version": 'source-identity',
            "source_hashes": hashes,
            "source_hashes_sha256": identity_digest,
            "config_sha256": "c" * 64,
        }
        artifact["source_hashes_sha256"] = identity_digest
        artifact["score_epoch"] = {
            "runtime_provisional": "runtime-scoring",
            "thesis_final": "thesis-scoring",
            "final_status": "pending_review",
            "metrics_epoch": "research-metrics",
            "scoring_policy_version": "scoring-policy",
            "scoring_rule_sha256": epoch_digest or HISTORICAL_DIGEST,
        }
    path = tmp_path / "source.json"
    path.write_text(json.dumps(artifact))
    return path


def make_queue(source):
    queue = thesis_scoring.review_queue(source)
    queue["components"].update(Smethod=3, Soutput=3)
    queue["component_pending_reasons"] = {}
    return queue


def decisions_for(queue):
    return [{
        "decision_id": f"human:{row['candidate_id']}",
        "run_id": queue["run_id"],
        "source_sha256": queue["source_sha256"],
        "rubric_version": queue["rubric_version"],
        "scoring_mode": "human",
        "candidate_id": row["candidate_id"],
        "score": 2,
        "reason": "Reviewed candidate-linked execution evidence",
        "evidence_refs": row["evidence_refs"],
        "reviewer_id": "offline-reviewer",
        "review_version": "manual-assessment",
        "timestamp": "2026-10-31T00:00:00+00:00",
    } for row in queue["candidates"] if row["status"] == "pending_review"]


def finalize_fixture(tmp_path, monkeypatch, *, anchors=True, with_decisions=True,
                     epoch_digest=None):
    source = make_source(tmp_path, anchors=anchors, epoch_digest=epoch_digest)
    queue = make_queue(source)
    monkeypatch.setattr(thesis_scoring, "review_queue", lambda _source: deepcopy(queue))
    monkeypatch.setattr(observer_reviews, "review_queue", lambda _source: deepcopy(queue))
    review_dir = tmp_path / "review-out"
    result = thesis_scoring.finalize_reviews(
        source,
        decisions_for(queue) if with_decisions else [],
        output_dir=review_dir,
        isolated_output=True,
    )
    return source, queue, review_dir, result


def historicalize(path, *, source_hashes=None, digest=None):
    document = json.loads(Path(path).read_text())
    hashes = dict(source_hashes or HISTORICAL_HASHES)
    recorded = digest or HISTORICAL_DIGEST
    document["scoring_rule_sha256"] = recorded
    policy = document["scoring_policy"]
    policy["source_hashes"] = hashes
    policy["scoring_rule_sha256"] = recorded
    policy["recorded_scoring_rule_sha256"] = recorded
    Path(path).write_text(json.dumps(document))


def discover(source, review_dir):
    catalog = ArtifactCatalog({"source": source}, {"reviews": review_dir})
    catalog.scan()
    entry = next(iter(catalog.runs))
    return entry, observer_reviews.discover_reviews(catalog, entry)


def invalid_reasons(entry):
    return {
        diagnostic["reason"]
        for diagnostic in entry.diagnostics
        if diagnostic.get("code") == "invalid_review_binding"
    }


def test_historical_final_receipt_and_status_survive_live_digest_drift(tmp_path, monkeypatch):
    source, queue, review_dir, result = finalize_fixture(tmp_path, monkeypatch)
    assert queue["scoring_rule_sha256"] != HISTORICAL_DIGEST
    receipt = Path(result["receipts"]["human"])
    status = next(review_dir.glob("*.review-status.json"))
    historicalize(receipt)
    historicalize(status)

    entry, discovered = discover(source, review_dir)

    assert discovered["human"]["status"] == "final"
    assert discovered["human"]["Srun_final"] == 2.5
    assert discovered["human"]["scoring_rule_sha256"] == HISTORICAL_DIGEST
    assert invalid_reasons(entry) == set()


def test_historical_pending_status_survives_live_digest_drift(tmp_path, monkeypatch):
    source, queue, review_dir, result = finalize_fixture(
        tmp_path, monkeypatch, with_decisions=False
    )
    assert queue["scoring_rule_sha256"] != HISTORICAL_DIGEST
    assert result["receipts"] == {}
    status = next(review_dir.glob("*.review-status.json"))
    historicalize(status)

    entry, discovered = discover(source, review_dir)

    assert discovered["human"]["status"] == "pending"
    assert discovered["human"]["reason"] == "pending_candidate_grades"
    assert discovered["human"]["scoring_rule_sha256"] == HISTORICAL_DIGEST
    assert invalid_reasons(entry) == set()


def test_forged_historical_digest_is_rejected(tmp_path, monkeypatch):
    source, _queue, review_dir, result = finalize_fixture(tmp_path, monkeypatch)
    forged = "f" * 64
    historicalize(Path(result["receipts"]["human"]), digest=forged)
    historicalize(next(review_dir.glob("*.review-status.json")), digest=forged)

    entry, discovered = discover(source, review_dir)

    assert discovered["human"]["status"] == "missing"
    assert invalid_reasons(entry) == {"scoring_rule_epoch_anchor_digest_mismatch"}


def test_forged_source_hashes_are_rejected(tmp_path, monkeypatch):
    source, _queue, review_dir, result = finalize_fixture(tmp_path, monkeypatch)
    forged_hashes = dict(HISTORICAL_HASHES)
    forged_hashes[SCORING_SOURCE_FILES[0]] = "e" * 64
    forged_digest = sha256(
        "".join(forged_hashes[path] for path in SCORING_SOURCE_FILES).encode()
    ).hexdigest()
    historicalize(Path(result["receipts"]["human"]),
                  source_hashes=forged_hashes, digest=forged_digest)
    historicalize(next(review_dir.glob("*.review-status.json")),
                  source_hashes=forged_hashes, digest=forged_digest)

    entry, discovered = discover(source, review_dir)

    assert discovered["human"]["status"] == "missing"
    assert invalid_reasons(entry) == {"source_identity_hash_mismatch"}


def test_raw_scoring_epoch_mismatch_is_rejected(tmp_path, monkeypatch):
    source, _queue, review_dir, result = finalize_fixture(
        tmp_path, monkeypatch, epoch_digest="d" * 64
    )
    historicalize(Path(result["receipts"]["human"]))
    historicalize(next(review_dir.glob("*.review-status.json")))

    entry, discovered = discover(source, review_dir)

    assert discovered["human"]["status"] == "missing"
    assert invalid_reasons(entry) == {"scoring_epoch_digest_mismatch"}


def test_missing_source_anchor_is_rejected(tmp_path, monkeypatch):
    source, _queue, review_dir, result = finalize_fixture(
        tmp_path, monkeypatch, anchors=False
    )
    historicalize(Path(result["receipts"]["human"]))
    historicalize(next(review_dir.glob("*.review-status.json")))

    entry, discovered = discover(source, review_dir)

    assert discovered["human"]["status"] == "missing"
    assert invalid_reasons(entry) == {"source_identity_missing"}


@pytest.mark.parametrize(("failure", "reason"), [
    ("arithmetic", "receipt_arithmetic_mismatch"),
    ("component_refs", "component_reference_mismatch"),
])
def test_historical_anchor_does_not_bypass_receipt_evidence_checks(
        tmp_path, monkeypatch, failure, reason):
    source, _queue, review_dir, result = finalize_fixture(tmp_path, monkeypatch)
    receipt_path = Path(result["receipts"]["human"])
    status = next(review_dir.glob("*.review-status.json"))
    historicalize(receipt_path)
    historicalize(status)
    receipt = json.loads(receipt_path.read_text())
    if failure == "arithmetic":
        receipt["Srun_final"] = round(receipt["Srun_final"] + 0.1, 4)
    else:
        receipt["component_evidence_refs"] = []
    receipt_path.write_text(json.dumps(receipt))

    entry, discovered = discover(source, review_dir)

    assert discovered["human"]["status"] != "final"
    assert reason in invalid_reasons(entry)
