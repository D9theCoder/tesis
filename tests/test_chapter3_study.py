"""Dedicated offline tests for the Chapter 3 study plan and analysis modules.

No provider call, no HTTP request, no live DVWA, and no test of the frozen
``scoring_v4_matrix`` design. Score grouping is stubbed at the scorer boundary so
these tests exercise study-owned logic only: declared axes, planned statuses,
coordinate matching, fixture-epoch eligibility, pairing, statistics policy, and
null-with-reason behaviour.
"""
from pathlib import Path
from statistics import median

import pytest

import evaluation.research_analysis as analysis
import evaluation.research_plan as plan_mod
from evaluation.research_plan import (
    PRIMARY_CONDITIONS,
)

RULE = "a" * 64


# --------------------------------------------------------------------------- #
# fixtures and helpers
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# declared research config
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# plan construction and freeze
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# analysis: coordinate matching, statuses, exclusions
# --------------------------------------------------------------------------- #

class FakeEntry:
    def __init__(self, record, sha):
        self.record = record
        self.source = {"root_id": "r", "path": f"{sha}.json", "sha256": sha}
        self.path = Path(f"/fake/{sha}.json")
        self.ambiguous = False


def _receipt(condition, mode, *, base=2.0, rubric="scoring.v4", rule=RULE,
             metrics_epoch="scoring-policy.v4.2", **components):
    vector = {
        "Smethod": components.get("Smethod", base),
        "Spayload": components.get("Spayload", base),
        "Sexploit": components.get("Sexploit", base),
        "Schain": components.get("Schain", base),
        "Soutput": components.get("Soutput", base),
    }
    return {
        "artifact_type": "thesis_score_receipt",
        "status": "final",
        "scoring_mode": mode,
        "components": vector,
        "Srun_final": round(
            0.2 * vector["Smethod"] + 0.2 * vector["Spayload"] + 0.3 * vector["Sexploit"]
            + 0.1 * vector["Schain"] + 0.2 * vector["Soutput"], 4
        ),
        "rubric_version": rubric,
        "scoring_rule_sha256": rule,
        "metrics_epoch": metrics_epoch,
        "config": {
            "experiment_condition": condition,
            "scoring_profile": {"sha256": "profile"},
            "fixture_id": "dvfx",
            "protocol_version": "protov1",
            "candidate_budget": 3,
        },
        "metrics": {"metrics_epoch": metrics_epoch},
    }


def _reviews(*, receipt=None, modes=("human",), pending_reason=None):
    result = {}
    for mode in ("human", "ai"):
        if mode in modes and receipt is not None:
            result[mode] = {
                "status": "final",
                "components": receipt["components"],
                "Srun_final": receipt["Srun_final"],
                "rubric_version": receipt["rubric_version"],
                "scoring_rule_sha256": receipt["scoring_rule_sha256"],
                "scoring_mode": mode,
                "metrics_epoch": receipt["metrics_epoch"],
                "receipt": {"root_id": "r", "path": f"{id(receipt)}-{mode}.json"},
                "reason": None,
            }
        else:
            result[mode] = {
                "status": "pending" if pending_reason else "missing",
                "reason": pending_reason or "missing_review",
                "components": None,
                "Srun_final": None,
                "receipt": None,
            }
    return result


def _record(condition, repeat, *, block="selection", target=None, epoch="chapter3-2026-10-28",
            fixture="dvfx", protocol="protov1", budget=3, provider="profile-a", model="model-a",
            readiness=True, status="completed", profile="profile"):
    readiness_receipt = {
        "status": "ready",
        "requested_level": "low",
        "observed_level": "low",
        "fixture_restoration": {"equivalence": "attested"} if readiness else {"equivalence": "unknown"},
    }
    return {
        "execution_id": f"run-{block}-{condition}-{repeat}-{target}",
        "run_id": f"runid-{block}-{condition}-{repeat}-{target}",
        "execution_status": status,
        "execution_reason": {"code": "RUNTIME_FAILURE"} if status == "failed" else None,
        "provider": provider,
        "model": model,
        "surface": "sqli",
        "security_level": "low",
        "payload_mode": "hybrid",
        "experiment_condition": condition,
        "experiment_block": block,
        "target_method": target,
        "repeat_index": repeat,
        "policy_epoch": {"epoch_id": epoch, "source_hashes_sha256": "h"},
        "readiness": readiness_receipt,
        "config": {
            "provider": provider, "model": model, "surface": "sqli", "security_level": "low",
            "payload_mode": "hybrid", "experiment_condition": condition,
            "experiment_block": block, "target_method": target, "repeat_index": repeat,
            "fixture_id": fixture, "protocol_version": protocol, "candidate_budget": budget,
            "scoring_profile": {"sha256": profile},
        },
    }


def _coordinate(condition, repeat, *, block="selection", target=None, epoch="chapter3-2026-10-28"):
    row = {
        "coordinate_index": repeat, "block": block, "provider": "profile-a", "surface": "sqli",
        "security_level": "low", "payload_mode": "hybrid",
        "experiment_condition": condition, "target_method": target,
        "repeat_index": repeat, "candidate_budget": 3,
        "fixture_id": "dvfx", "protocol_version": "protov1",
        "policy_epoch_id": epoch, "status": "planned",
    }
    row["coordinate_id"] = plan_mod._coordinate_id(row)
    return row


def _plan(coordinates, *, repeats=3):
    return {
        "artifact_type": "chapter3_research_plan",
        "plan_version": "chapter3-research-plan.v2",
        "plan_sha256": "p" * 64,
        "epoch_id": "chapter3-2026-10-28",
        "policy_versions": {"experiment": "chapter3-flow.v2"},
        "policy_epoch": {"epoch_id": "chapter3-2026-10-28"},
        "source_hashes_sha256": "h",
        "constraints": {
            "primary_conditions": list(PRIMARY_CONDITIONS),
            "payload_mode": "hybrid",
            "repeats": repeats,
            "fixture_id": "dvfx",
            "protocol_version": "protov1",
            "candidate_budget": 3,
            "scoring_rubric_version": "scoring.v4",
            "scoring_profile_sha256": "profile",
        },
        "blocks": {"selection": [c for c in coordinates if c["block"] == "selection"],
                   "forced": [c for c in coordinates if c["block"] == "forced"]},
    }


def _analyze(monkeypatch, entries, coordinates, *, compare=None, documents=None):
    catalog_runs = entries
    receipts = documents or {}

    class FakeCatalog:
        def __init__(self, source_roots, review_roots):
            assert source_roots
            self.roots = {"r": Path("/fake-root")}
            self.runs = catalog_runs
            self.reviews = []

        def scan(self):
            return None

        def read(self, path):
            return receipts[Path(path).name]

    monkeypatch.setattr(analysis, "ArtifactCatalog", FakeCatalog)
    monkeypatch.setattr(
        analysis, "discover_reviews", lambda catalog, entry: entry.record["_reviews"]
    )
    monkeypatch.setattr(analysis, "pair_compatibility_key", lambda document: "key")
    monkeypatch.setattr(analysis, "pair_compatibility_mismatches", lambda left, right: [])
    monkeypatch.setattr(
        analysis, "aggregate_research_metrics",
        lambda summaries: {"n": len(summaries),
                           "marker": [row.get("metrics_epoch") for row in summaries]},
    )
    if compare is not None:
        monkeypatch.setattr(analysis, "compare_receipts", compare)
    return analysis.analyze_plan(
        _plan(coordinates), source_roots={"main": "/fake-root"}, review_roots={}
    )


def _stub_compare(paths, *, planned_repeats=None):
    return {"groups": [{"scoring_mode": "human", "n_final": len(paths),
                        "planned_repeats": planned_repeats, "sources": [str(p) for p in paths]}]}


def test_analysis_counts_planned_missing_and_matched(monkeypatch):
    coordinates = [
        _coordinate(condition, repeat)
        for condition in PRIMARY_CONDITIONS
        for repeat in range(3)
    ]
    entries, documents = [], {}
    for repeat in range(2):
        for condition in PRIMARY_CONDITIONS:
            receipt = _receipt(condition, "human")
            record = _record(condition, repeat)
            record["_reviews"] = _reviews(receipt=receipt)
            entry = FakeEntry(record, sha=f"{condition}-{repeat}")
            entries.append(entry)
            documents[f"{id(receipt)}-human.json"] = receipt
    result = _analyze(monkeypatch, entries, coordinates, compare=_stub_compare, documents=documents)

    assert result["planned"] == 6
    assert result["status_counts"]["final"] == 4
    assert result["status_counts"]["missing"] == 2
    assert result["exclusions"] == {"no_execution_artifact": 2}
    assert result["planned_by_block"] == {"forced": 0, "selection": 6}
    assert result["unmatched_artifacts"] == 0
    assert len(result["groups"]) == 1
    assert result["groups"][0]["block"] == "selection"
    assert result["groups"][0]["planned_repeats"] == 3
    assert result["groups"][0]["research_metrics"]["n"] == 4


# --------------------------------------------------------------------------- #
# paired analysis
# --------------------------------------------------------------------------- #

def _pair_records(monkeypatch, *, left_base=3.0, right_base=1.0, readiness=True,
                  rubric_left="scoring.v4"):
    coordinates, entries, documents = [], [], {}
    for repeat in range(3):
        for condition, base in (("linear_hybrid", left_base), ("akg_guided_hybrid", right_base)):
            coordinates.append(_coordinate(condition, repeat))
            receipt = _receipt(
                condition, "human", base=base,
                rubric=rubric_left if condition == "linear_hybrid" else "scoring.v4",
            )
            record = _record(condition, repeat, readiness=readiness)
            record["_reviews"] = _reviews(receipt=receipt)
            entries.append(FakeEntry(record, sha=f"{condition}-{repeat}"))
            documents[f"{id(receipt)}-human.json"] = receipt
    result = _analyze(
        monkeypatch, entries, coordinates, compare=_stub_compare, documents=documents
    )
    return result


def test_paired_analysis_pools_repeats_and_reports_declared_statistics(monkeypatch):
    outcome = _pair_records(monkeypatch)

    paired = outcome["paired"]
    assert paired["n_pair_units"] == 3
    assert paired["n_eligible_pairs"] == 3
    assert paired["direction"] == analysis.DIFFERENCE_DIRECTION
    assert len(paired["results"]) == 1
    comparison = paired["results"][0]
    assert comparison["n_pairs"] == 3
    assert comparison["direction"] == analysis.DIFFERENCE_DIRECTION
    for name in ("Smethod", "Spayload", "Sexploit", "Schain", "Soutput", "Srun_final"):
        row = comparison["metrics"][name]
        assert row["n_pairs"] == 3
        assert row["median_difference"]["estimate"] == pytest.approx(2.0)
        assert row["median_difference"]["method"] == "bootstrap_percentile"
        assert row["holm_adjusted_p"] is not None
        assert row["exploratory_rank_sum"]["status"] == "exploratory"
        assert row["exploratory_rank_sum"]["independent"] is False
    # Exact two-sided signed-rank p for 3/3 positive differences.
    assert comparison["metrics"]["Smethod"]["p_value"] == pytest.approx(0.25)


def test_paired_analysis_requires_attested_fixture_restoration(monkeypatch):
    result = _pair_analysis_with(monkeypatch, readiness=False)
    paired = result["paired"]

    assert paired["results"] == []
    assert paired["n_pair_units"] == 0
    assert {row["reason"] for row in paired["unmatched"]} == {"fixture_restoration_not_attested"}


def _pair_analysis_with(monkeypatch, **overrides):
    coordinates, entries, documents = [], [], {}
    for repeat in range(2):
        for condition, base in (("linear_hybrid", 3.0), ("akg_guided_hybrid", 1.0)):
            coordinates.append(_coordinate(condition, repeat))
            receipt = _receipt(condition, "human", base=base)
            record = _record(condition, repeat, **overrides)
            record["_reviews"] = _reviews(receipt=receipt)
            entries.append(FakeEntry(record, sha=f"{condition}-{repeat}-{base}"))
            documents[f"{id(receipt)}-human.json"] = receipt
    return _analyze(monkeypatch, entries, coordinates, compare=_stub_compare, documents=documents)


# --------------------------------------------------------------------------- #
# statistics helpers and policy text
# --------------------------------------------------------------------------- #

def test_signed_rank_handles_zero_and_tied_differences():
    all_zero = analysis._wilcoxon_signed_rank([0.0, 0.0])
    assert all_zero["p_value"] is None
    assert all_zero["reason"] == "all_differences_zero"

    tied = analysis._wilcoxon_signed_rank([1.0, -1.0, 1.0, -1.0])
    assert tied["n_nonzero"] == 4
    assert 0.0 <= tied["p_value"] <= 1.0
    assert tied["zero_differences"] == "dropped"


def test_holm_adjustment_is_monotone_and_ignores_nulls():
    adjusted = analysis._holm([0.01, None, 0.04, 0.03])
    assert adjusted[1] is None
    assert adjusted[0] <= adjusted[2] <= adjusted[3]
    assert all(value is None or 0 <= value <= 1 for value in adjusted)


def test_bootstrap_median_ci_is_seeded_and_reports_empty_input():
    empty = analysis._bootstrap_median_ci([])
    assert empty["estimate"] is None
    assert empty["reason"] == "no_pairs"

    first = analysis._bootstrap_median_ci([1.0, 2.0, 3.0])
    second = analysis._bootstrap_median_ci([1.0, 2.0, 3.0])
    assert first == second
    estimate, low, high = first["estimate"], first["low"], first["high"]
    assert estimate is not None and low is not None and high is not None
    assert estimate == round(median([1.0, 2.0, 3.0]), 4)
    assert low <= estimate <= high
