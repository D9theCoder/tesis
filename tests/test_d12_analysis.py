"""Offline regressions for D12 outcome spread and model contrasts.

These tests exercise study-owned aggregation only: planned repeats, explicit
missing/failed/pending availability, grader-mode separation, receipt
compatibility, and exploratory model contrasts. No provider, target, runner,
or historical result is used.
"""
from pathlib import Path
from typing import Any, cast

import pytest

import evaluation.research_analysis as analysis
import evaluation.research_plan as plan_mod
from evaluation.scoring_evidence import evidence_hash

RULE = "a" * 64
PRICE = {"effective_at": "2026-10-31T00:00:00+00:00", "prices": {}}
COMPONENTS = ("Smethod", "Spayload", "Sexploit", "Schain", "Soutput")


class FakeEntry:
    def __init__(self, record, sha):
        self.record = record
        self.source = {"root_id": "r", "path": f"{sha}.json", "sha256": sha}
        self.path = Path(f"/fake/{sha}.json")
        self.ambiguous = False


def _receipt(condition, mode, *, base=2.0, components=None,
             metrics_epoch="scoring-policy", reviewer=None,
             review_version=None):
    vector = {name: base for name in COMPONENTS}
    vector.update(components or {})
    if reviewer is None:
        reviewer = "ai/independent-judge" if mode == "ai" else "human-reviewer-a"
    if review_version is None:
        review_version = "artifact-judge" if mode == "ai" else "manual-assessment"
    return {
        "artifact_type": "thesis_score_receipt",
        "status": "final",
        "scoring_mode": mode,
        "components": vector,
        "Srun_final": round(
            0.2 * vector["Smethod"] + 0.2 * vector["Spayload"]
            + 0.3 * vector["Sexploit"] + 0.1 * vector["Schain"]
            + 0.2 * vector["Soutput"],
            4,
        ),
        "rubric_version": "thesis-scoring",
        "scoring_rule_sha256": RULE,
        "metrics_epoch": metrics_epoch,
        "review_history": [{
            "candidate_id": "candidate-1",
            "decision_id": f"decision-{mode}",
            "scoring_mode": mode,
            "reviewer_id": reviewer,
            "review_version": review_version,
            "score": 3,
        }],
        "config": {
            "experiment_condition": condition,
            "fixture_id": "fx",
            "protocol_version": "pv",
            "candidate_budget": 3,
            "scoring_profile": {"sha256": "profile"},
            "guardrail_retry_enabled": True,
            "guardrail_handling": "reactive",
            "token_price_schedule": PRICE,
        },
    }


def _reviews(receipt, modes, *, review_status):
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
            }
        elif review_status == "pending":
            result[mode] = {
                "status": "pending", "reason": "pending_candidate_grades",
                "components": None, "Srun_final": None, "receipt": None,
            }
        else:
            result[mode] = {
                "status": "missing", "reason": "missing_review",
                "components": None, "Srun_final": None, "receipt": None,
            }
    return result


def _record(condition, repeat, *, model="model-a", provider="profile-a",
            surface="sqli", level="low", status="completed", readiness=True,
            modes=("human",), base=2.0, components=None,
            metrics_epoch="scoring-policy", review_status="final",
            reviewer=None, review_version=None):
    receipt = None
    mode = modes[0] if modes else "human"
    if review_status == "final" and modes:
        receipt = _receipt(
            condition, mode, base=base, components=components,
            metrics_epoch=metrics_epoch, reviewer=reviewer,
            review_version=review_version,
        )
    record = {
        "execution_id": f"run-{provider}-{model}-{surface}-{level}-{condition}-{repeat}",
        "run_id": f"runid-{provider}-{model}-{surface}-{level}-{condition}-{repeat}",
        "execution_status": status,
        "execution_reason": {"code": "RUNTIME_FAILURE"} if status == "failed" else None,
        "provider": provider,
        "model": model,
        "surface": surface,
        "security_level": level,
        "payload_mode": "hybrid",
        "experiment_condition": condition,
        "experiment_block": "selection",
        "target_method": None,
        "repeat_index": repeat,
        "policy_epoch": {"epoch_id": "e1", "source_hashes_sha256": "h"},
        "readiness": {
            "status": "ready" if readiness else "blocked",
            "requested_level": level,
            "observed_level": level,
            "fixture_restoration": {
                "equivalence": "attested" if readiness else "unknown"
            },
        },
        "config": {
            "provider": provider,
            "model": model,
            "surface": surface,
            "security_level": level,
            "payload_mode": "hybrid",
            "experiment_condition": condition,
            "experiment_block": "selection",
            "target_method": None,
            "repeat_index": repeat,
            "fixture_id": "fx",
            "protocol_version": "pv",
            "candidate_budget": 3,
            "scoring_profile": {"sha256": "profile"},
            "guardrail_retry_enabled": True,
            "guardrail_handling": "reactive",
            "token_price_schedule": PRICE,
        },
        "_reviews": _reviews(receipt, modes, review_status=review_status),
    }
    return receipt, record


def _coordinate(condition, repeat, *, model="model-a", provider="profile-a",
                surface="sqli", level="low"):
    row = {
        "coordinate_index": repeat,
        "block": "selection",
        "provider": provider,
        "model": model,
        "surface": surface,
        "security_level": level,
        "payload_mode": "hybrid",
        "experiment_condition": condition,
        "target_method": None,
        "repeat_index": repeat,
        "candidate_budget": 3,
        "fixture_id": "fx",
        "protocol_version": "pv",
        "policy_epoch_id": "e1",
        "status": "planned",
        "guardrail_retry_enabled": True,
        "guardrail_handling": "reactive",
    }
    row["coordinate_id"] = plan_mod._coordinate_id(row)
    return row


def _plan(coordinates, *, repeats=3):
    return {
        "artifact_type": "chapter3_research_plan",
        "plan_version": 'study-plan',
        "plan_sha256": "p" * 64,
        "epoch_id": "e1",
        "policy_versions": {},
        "policy_epoch": {"epoch_id": "e1"},
        "source_hashes_sha256": "h",
        "prerequisites": [],
        "constraints": {
            "primary_conditions": list(analysis.PRIMARY_CONDITIONS),
            "payload_mode": "hybrid",
            "repeats": repeats,
            "fixture_id": "fx",
            "protocol_version": "pv",
            "candidate_budget": 3,
            "scoring_rubric_version": "thesis-scoring",
            "scoring_profile_sha256": "profile",
            "token_price_schedule_sha256": evidence_hash(PRICE),
            "guardrail_retry_enabled": True,
            "guardrail_handling": "reactive",
        },
        "blocks": {"selection": coordinates, "forced": []},
    }


def _make_entry(condition, repeat, **overrides):
    receipt, record = _record(condition, repeat, **overrides)
    entry = FakeEntry(record, sha=record["execution_id"])
    documents = {}
    reviews = cast(dict[str, dict[str, Any]], record["_reviews"])
    for workflow in reviews.values():
        binding = workflow.get("receipt")
        if isinstance(binding, dict):
            documents[Path(binding["path"]).name] = receipt
    return entry, documents


def _analyze(monkeypatch, entries, plan, documents):
    class FakeCatalog:
        def __init__(self, source_roots, review_roots):
            self.roots = {"r": Path("/fake-root")}
            self.runs = entries
            self.reviews = []

        def scan(self):
            return None

        def read(self, path):
            return documents[Path(path).name]

    monkeypatch.setattr(analysis, "ArtifactCatalog", FakeCatalog)
    monkeypatch.setattr(
        analysis, "discover_reviews", lambda catalog, entry: entry.record["_reviews"]
    )
    monkeypatch.setattr(
        analysis, "aggregate_research_metrics",
        lambda summaries: {"n": len(summaries)},
    )
    monkeypatch.setattr(
        analysis, "compare_receipts",
        lambda paths, *, planned_repeats=None: {
            "groups": [{"scoring_mode": "human", "n_final": len(paths)}],
            "selection_groups": [],
        },
    )
    return analysis.analyze_plan(
        plan, source_roots={"main": "/fake-root"}, review_roots={}
    )


def test_outcome_spread_preserves_planned_repeats_and_reasons(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", repeat) for repeat in range(4)]
    entries, documents = [], {}
    repeat_states = ("final", "failed", "pending", "missing")
    for repeat, state in enumerate(repeat_states):
        if state == "missing":
            continue
        overrides = {}
        if state == "failed":
            overrides = {"status": "failed", "modes": ()}
        elif state == "pending":
            overrides = {"review_status": "pending"}
        entry, entry_documents = _make_entry("linear_hybrid", repeat, **overrides)
        entries.append(entry)
        documents.update(entry_documents)

    result = _analyze(
        monkeypatch, entries, _plan(coordinates, repeats=4), documents
    )

    assert len(result["outcome_spread"]["cells"]) == 1
    cell = result["outcome_spread"]["cells"][0]
    assert cell["planned_repeats"] == 4
    assert cell["planned_repeat_indices"] == [0, 1, 2, 3]
    assert cell["n_final_repeats"] == 1
    assert cell["n_ready_final_repeats"] == 1
    assert cell["n_unavailable_repeats"] == 3
    assert cell["repeat_coverage"] == "partial"
    assert cell["observation_states"] == {
        "error": 1, "final": 1, "missing": 1, "pending_review": 1
    }
    assert cell["unavailable_reasons"] == {
        "RUNTIME_FAILURE": 1,
        "no_execution_artifact": 1,
        "pending_candidate_grades": 1,
    }

    mode = cell["modes"]["human"]
    assert mode["n_planned"] == 4
    assert mode["n_final"] == 1
    assert mode["n_with_values"] == 1
    assert [row["state"] for row in mode["repeats"]] == [
        "final", "error", "pending_review", "missing"
    ]
    assert mode["repeats"][1]["reason"] == "RUNTIME_FAILURE"
    assert mode["repeats"][2]["reason"] == "pending_candidate_grades"
    assert mode["repeats"][3]["reason"] == "no_execution_artifact"

    # One observed final repeat has a value but no sample spread; the missing
    # repeats never become zero-valued observations.
    smethod = mode["metrics"]["Smethod"]
    assert smethod["n"] == 1
    assert smethod["mean"] == pytest.approx(2.0)
    assert smethod["spread_available"] is False
    assert smethod["spread_reason"] == "fewer_than_two_final_repeats"


def test_outcome_spread_counts_zero_and_nonzero_variance(monkeypatch):
    coordinates, entries, documents = [], [], {}
    values = {
        ("sqli", 0): 3.0, ("sqli", 1): 3.0, ("sqli", 2): 3.0,
        ("brute_force", 0): 1.0, ("brute_force", 1): 2.0, ("brute_force", 2): 3.0,
    }
    for (surface, repeat), base in values.items():
        coordinates.append(_coordinate("linear_hybrid", repeat, surface=surface))
        entry, entry_documents = _make_entry(
            "linear_hybrid", repeat, surface=surface, base=base
        )
        entries.append(entry)
        documents.update(entry_documents)

    result = _analyze(monkeypatch, entries, _plan(coordinates), documents)

    summary = result["outcome_spread"]["summary"]["by_metric"]["Smethod"]
    assert summary["n_cell_modes"] == 2
    assert summary["n_zero_variance"] == 1
    assert summary["n_nonzero_variance"] == 1
    assert summary["n_spread_unavailable"] == 0

    by_surface = {
        cell["coordinate"]["surface"]: cell["modes"]["human"]["metrics"]["Smethod"]
        for cell in result["outcome_spread"]["cells"]
    }
    assert by_surface["sqli"]["variance"] == pytest.approx(0.0)
    assert by_surface["sqli"]["all_equal"] is True
    assert by_surface["brute_force"]["variance"] == pytest.approx(1.0)
    assert by_surface["brute_force"]["all_equal"] is False
    assert by_surface["brute_force"]["iqr"] == pytest.approx(1.0)


def test_outcome_spread_n2_uses_inclusive_iqr(monkeypatch):
    coordinates, entries, documents = [], [], {}
    for repeat, base in ((0, 1.0), (1, 3.0)):
        coordinates.append(_coordinate(
            "linear_hybrid", repeat, surface="access_control"
        ))
        entry, entry_documents = _make_entry(
            "linear_hybrid", repeat, surface="access_control", base=base
        )
        entries.append(entry)
        documents.update(entry_documents)

    result = _analyze(
        monkeypatch, entries, _plan(coordinates, repeats=2), documents
    )

    smethod = result["outcome_spread"]["cells"][0]["modes"]["human"]["metrics"]["Smethod"]
    assert smethod["n"] == 2
    assert smethod["median"] == pytest.approx(2.0)
    assert smethod["variance"] == pytest.approx(2.0)
    assert smethod["iqr"] == pytest.approx(1.0)
    assert 0 <= smethod["iqr"] <= smethod["range"]
    assert smethod["all_equal"] is False
    assert "inclusive-quartile" in smethod["method"]


def test_outcome_spread_refuses_incompatible_receipts(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", repeat) for repeat in range(2)]
    entries, documents = [], {}
    for repeat, epoch in enumerate(("scoring-policy", "changed-rate-population")):
        entry, entry_documents = _make_entry(
            "linear_hybrid", repeat, metrics_epoch=epoch
        )
        entries.append(entry)
        documents.update(entry_documents)

    result = _analyze(monkeypatch, entries, _plan(coordinates, repeats=2), documents)

    mode = result["outcome_spread"]["cells"][0]["modes"]["human"]
    assert mode["status"] == "incompatible"
    assert mode["reason"] == "receipt_compatibility_mismatch"
    assert len(mode["compatibility_keys"]) == 2
    assert "metrics_epoch" in mode["receipt_compatibility_mismatches"]
    assert mode["n_final"] == 2
    for name in analysis.COMPONENT_NAMES:
        distribution = mode["metrics"][name]
        assert distribution["availability"] is False
        assert distribution["unavailable_reason"] == "receipt_compatibility_mismatch"
        assert distribution["n"] == 2


def test_outcome_spread_keeps_same_grader_repeats_stable(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", repeat) for repeat in range(2)]
    entries, documents = [], {}
    for repeat, base in ((0, 1.0), (1, 3.0)):
        entry, entry_documents = _make_entry(
            "linear_hybrid", repeat, base=base,
            reviewer="human-reviewer-a", review_version="manual-assessment",
        )
        entries.append(entry)
        documents.update(entry_documents)

    result = _analyze(monkeypatch, entries, _plan(coordinates, repeats=2), documents)

    mode = result["outcome_spread"]["cells"][0]["modes"]["human"]
    assert mode["status"] == "final"
    assert mode["reason"] is None
    assert mode["receipt_compatibility_mismatches"] == []
    assert mode["grader_identity"] == {
        "status": "recorded",
        "graders": [{
            "reviewer_id": "human-reviewer-a",
            "review_version": "manual-assessment",
        }],
    }
    smethod = mode["metrics"]["Smethod"]
    assert smethod["n"] == 2
    assert smethod["variance"] == pytest.approx(2.0)


@pytest.mark.parametrize(
    ("reviewer_a", "reviewer_b", "version_a", "version_b", "expected"),
    [
        ("human-reviewer-a", "human-reviewer-b", "manual-assessment", "manual-assessment", {"reviewer_id"}),
        ("human-reviewer-a", "human-reviewer-a", "manual-assessment", "human.v2", {"review_version"}),
    ],
)
def test_outcome_spread_refuses_distinct_grader_repeats(
        monkeypatch, reviewer_a, reviewer_b, version_a, version_b, expected):
    coordinates = [_coordinate("linear_hybrid", repeat) for repeat in range(2)]
    entries, documents = [], {}
    for repeat, reviewer, version in (
        (0, reviewer_a, version_a), (1, reviewer_b, version_b),
    ):
        entry, entry_documents = _make_entry(
            "linear_hybrid", repeat, reviewer=reviewer, review_version=version,
        )
        entries.append(entry)
        documents.update(entry_documents)

    result = _analyze(monkeypatch, entries, _plan(coordinates, repeats=2), documents)

    mode = result["outcome_spread"]["cells"][0]["modes"]["human"]
    assert mode["status"] == "incompatible"
    assert mode["reason"] == "receipt_grader_identity_mismatch"
    assert expected <= set(mode["receipt_compatibility_mismatches"])
    assert mode["grader_identity"]["status"] == "recorded"
    assert {
        (row["reviewer_id"], row["review_version"])
        for row in mode["grader_identity"]["graders"]
    } == {(reviewer_a, version_a), (reviewer_b, version_b)}
    for distribution in mode["metrics"].values():
        assert distribution["availability"] is False
        assert distribution["unavailable_reason"] == "receipt_grader_identity_mismatch"


@pytest.mark.parametrize(
    ("history_state", "problem"),
    [
        ("missing", "review_history_missing"),
        ("empty", "review_history_empty"),
    ],
)
def test_outcome_spread_refuses_receipts_without_grader_identity(
        monkeypatch, history_state, problem):
    coordinates = [_coordinate("linear_hybrid", repeat) for repeat in range(2)]
    entries, documents = [], {}
    for repeat in range(2):
        entry, entry_documents = _make_entry("linear_hybrid", repeat)
        for document in entry_documents.values():
            if history_state == "missing":
                document.pop("review_history", None)
            else:
                document["review_history"] = []
        entries.append(entry)
        documents.update(entry_documents)

    result = _analyze(monkeypatch, entries, _plan(coordinates, repeats=2), documents)

    mode = result["outcome_spread"]["cells"][0]["modes"]["human"]
    expected_reason = f"receipt_grader_identity_unavailable:{problem}"
    assert mode["status"] == "incompatible"
    assert mode["reason"] == expected_reason
    assert mode["grader_identity"] == {
        "status": "unavailable",
        "graders": [],
        "reasons": [problem],
    }
    assert {"grader_identity", problem} <= set(mode["receipt_compatibility_mismatches"])
    for distribution in mode["metrics"].values():
        assert distribution["availability"] is False
        assert distribution["unavailable_reason"] == expected_reason


def test_ai_only_repeats_never_require_a_human_reviewer(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", repeat) for repeat in range(2)]
    entries, documents = [], {}
    for repeat in range(2):
        entry, entry_documents = _make_entry(
            "linear_hybrid", repeat, modes=("ai",),
            reviewer="ai/independent-judge", review_version="artifact-judge",
        )
        entries.append(entry)
        documents.update(entry_documents)

    result = _analyze(monkeypatch, entries, _plan(coordinates, repeats=2), documents)

    mode = result["outcome_spread"]["cells"][0]["modes"]["ai"]
    assert mode["status"] == "final"
    assert mode["reason"] is None
    assert mode["grader_identity"]["status"] == "recorded"
    assert mode["grader_identity"]["graders"] == [{
        "reviewer_id": "ai/independent-judge",
        "review_version": "artifact-judge",
    }]
    assert "human" not in result["outcome_spread"]["cells"][0]["modes"]


def test_outcome_spread_refuses_duplicate_repeat_identity(monkeypatch):
    coordinates = [
        _coordinate("linear_hybrid", 0),
        _coordinate("linear_hybrid", 0),
    ]
    entry, documents = _make_entry("linear_hybrid", 0)
    result = _analyze(monkeypatch, [entry], _plan(coordinates, repeats=1), documents)

    cell = result["outcome_spread"]["cells"][0]
    assert cell["planned_repeats"] == 2
    assert cell["planned_repeat_indices"] == [0, 0]
    assert cell["status"] == "incompatible"
    assert cell["reason"] == "duplicate_repeat_index"
    assert cell["modes"] == {}
    assert result["outcome_spread"]["summary"]["n_cells_without_final"] == 0
    assert result["outcome_spread"]["summary"]["n_cells_without_modes"] == 1


def _two_model_setup(*, include_model_a=True, modes=None,
                     base_a=3.0, base_b=1.0, conditions=None,
                     metrics_epoch_a="scoring-policy",
                     metrics_epoch_b="scoring-policy",
                     readiness_a=True, readiness_b=True,
                     reviewer_a=None, reviewer_b=None,
                     review_version_a=None, review_version_b=None):
    conditions = conditions or list(analysis.PRIMARY_CONDITIONS)
    coordinates, entries, documents = [], [], {}
    for condition in conditions:
        for repeat in range(3):
            for model, provider, base, epoch, model_modes, include, ready, reviewer, version in (
                ("model-a", "profile-a", base_a, metrics_epoch_a,
                 ("human",) if modes is None else modes[0], include_model_a, readiness_a,
                 reviewer_a, review_version_a),
                ("model-b", "profile-b", base_b, metrics_epoch_b,
                 ("human",) if modes is None else modes[1], True, readiness_b,
                 reviewer_b, review_version_b),
            ):
                coordinates.append(_coordinate(
                    condition, repeat, model=model, provider=provider
                ))
                if not include:
                    continue
                entry, entry_documents = _make_entry(
                    condition, repeat, model=model, provider=provider,
                    base=base, metrics_epoch=epoch, modes=model_modes,
                    readiness=ready, reviewer=reviewer,
                    review_version=version,
                )
                entries.append(entry)
                documents.update(entry_documents)
    return coordinates, entries, documents


def test_model_contrasts_report_all_strata_without_pairing(monkeypatch):
    coordinates, entries, documents = _two_model_setup()
    result = _analyze(monkeypatch, entries, _plan(coordinates), documents)

    contrasts = result["model_contrasts"]
    assert contrasts["supported"] is True
    assert contrasts["n_models"] == 2
    assert contrasts["reason"] is None
    assert contrasts["n_contrast_rows"] == 2
    assert contrasts["status_counts"] == {"analyzed": 2, "unsupported": 0}

    assert {
        row["coordinate"]["experiment_condition"] for row in contrasts["results"]
    } == set(analysis.PRIMARY_CONDITIONS)
    for row in contrasts["results"]:
        assert row["status"] == "analyzed"
        assert row["paired"] is False
        assert row["scoring_mode"] == "human"
        assert row["n_planned_model_a"] == 3
        assert row["n_planned_model_b"] == 3
        assert row["n_final_model_a"] == 3
        assert row["n_final_model_b"] == 3
        assert row["coverage_model_a"] == "complete"
        assert row["coverage_model_b"] == "complete"
        assert row["partial"] is False
        smethod = row["metrics"]["Smethod"]
        assert smethod["status"] == "exploratory"
        assert smethod["independent"] is False
        assert smethod["n_left"] == 3
        assert smethod["n_right"] == 3
        assert smethod["u"] == pytest.approx(9.0)
        assert smethod["effect_size"] == pytest.approx(1.0)
        assert smethod["holm_adjusted_p"] is not None
        assert smethod["model_a"]["median"] == pytest.approx(3.0)
        assert smethod["model_b"]["median"] == pytest.approx(1.0)
        assert smethod["model_a"]["variance"] == pytest.approx(0.0)
        assert smethod["model_b"]["variance"] == pytest.approx(0.0)


def test_model_contrast_reports_missing_model_with_denominators(monkeypatch):
    coordinates, entries, documents = _two_model_setup(
        include_model_a=False
    )
    result = _analyze(monkeypatch, entries, _plan(coordinates), documents)

    contrasts = result["model_contrasts"]
    assert contrasts["status_counts"] == {"analyzed": 0, "unsupported": 2}
    assert contrasts["unsupported_reasons"] == {"model_a_no_final_receipts": 2}
    for row in contrasts["results"]:
        assert row["status"] == "unsupported"
        assert row["reason"] == "model_a_no_final_receipts"
        assert row["n_planned_model_a"] == 3
        assert row["n_final_model_a"] == 0
        assert row["n_planned_model_b"] == 3
        assert row["n_final_model_b"] == 3
        assert row["coverage_model_a"] == "none"
        assert row["coverage_model_b"] == "complete"
        assert row["partial"] is True
        assert row["observation_states_model_b"] == {"final": 3}
        assert row["metrics"] == {}


def test_model_contrast_does_not_analyze_unready_runs(monkeypatch):
    coordinates, entries, documents = _two_model_setup(
        conditions=["linear_hybrid"], readiness_a=False
    )
    result = _analyze(
        monkeypatch, entries, _plan(coordinates, repeats=3), documents
    )

    row = result["model_contrasts"]["results"][0]
    assert row["status"] == "unsupported"
    assert row["reason"] == "model_a_readiness_not_satisfied"
    assert row["n_final_model_a"] == 0
    assert row["n_unready_final_model_a"] == 3
    assert row["n_observed_final_model_a"] == 3
    assert row["coverage_model_a"] == "none"
    assert row["observed_coverage_model_a"] == "complete"
    assert row["n_final_model_b"] == 3
    assert row["partial"] is True
    assert row["metrics"] == {}


def test_model_contrasts_never_pool_grader_modes(monkeypatch):
    coordinates, entries, documents = _two_model_setup(
        modes=(("human",), ("ai",)), conditions=["linear_hybrid"]
    )
    result = _analyze(
        monkeypatch, entries,
        _plan(coordinates, repeats=3), documents,
    )

    rows = result["model_contrasts"]["results"]
    assert len(rows) == 2
    by_mode = {row["scoring_mode"]: row for row in rows}
    assert set(by_mode) == {"ai", "human"}
    for mode, row in by_mode.items():
        assert row["status"] == "unsupported"
        assert row["metrics"] == {}
        if mode == "ai":
            assert row["reason"] == "model_a_grader_mode_missing"
            assert row["n_final_model_a"] == 0
            assert row["n_final_model_b"] == 3
        else:
            assert row["reason"] == "model_b_grader_mode_missing"
            assert row["n_final_model_a"] == 3
            assert row["n_final_model_b"] == 0


def test_model_contrast_reports_cross_model_receipt_mismatch(monkeypatch):
    coordinates, entries, documents = _two_model_setup(
        conditions=["linear_hybrid"],
        metrics_epoch_a="scoring-policy",
        metrics_epoch_b="changed-rate-population",
    )
    result = _analyze(
        monkeypatch, entries, _plan(coordinates, repeats=3), documents
    )

    row = result["model_contrasts"]["results"][0]
    assert row["status"] == "unsupported"
    assert row["reason"] == "model_contrast_metrics_epoch_mismatch"
    assert row["metrics"] == {}
    assert row["n_final_model_a"] == 3
    assert row["n_final_model_b"] == 3


def test_model_contrast_refuses_distinct_graders_across_models(monkeypatch):
    coordinates, entries, documents = _two_model_setup(
        conditions=["linear_hybrid"],
        reviewer_a="human-reviewer-a", reviewer_b="human-reviewer-b",
        review_version_a="manual-assessment", review_version_b="manual-assessment",
    )
    result = _analyze(
        monkeypatch, entries, _plan(coordinates, repeats=3), documents
    )

    row = result["model_contrasts"]["results"][0]
    assert row["status"] == "unsupported"
    assert row["reason"] == "model_contrast_receipt_reviewer_id_mismatch"
    assert row["metrics"] == {}
    assert row["grader_identity_model_a"]["graders"] == [{
        "reviewer_id": "human-reviewer-a", "review_version": "manual-assessment",
    }]
    assert row["grader_identity_model_b"]["graders"] == [{
        "reviewer_id": "human-reviewer-b", "review_version": "manual-assessment",
    }]


def test_model_contrast_refuses_receipts_without_grader_identity(monkeypatch):
    coordinates, entries, documents = _two_model_setup(
        conditions=["linear_hybrid"]
    )
    for document in documents.values():
        document.pop("review_history", None)
    result = _analyze(
        monkeypatch, entries, _plan(coordinates, repeats=3), documents
    )

    row = result["model_contrasts"]["results"][0]
    assert row["status"] == "unsupported"
    assert row["reason"] == (
        "model_a_receipt_grader_identity_unavailable:review_history_missing"
    )
    assert row["metrics"] == {}
    assert row["grader_identity_model_a"] == {
        "status": "unavailable",
        "graders": [],
        "reasons": ["review_history_missing"],
    }
    assert row["grader_identity_model_b"] == {
        "status": "unavailable",
        "graders": [],
        "reasons": ["review_history_missing"],
    }


def test_model_contrast_refuses_repeat_grader_mixing(monkeypatch):
    coordinates, entries, documents = [], [], {}
    for repeat in range(3):
        for condition in ("linear_hybrid",):
            coordinates.append(_coordinate(
                condition, repeat, model="model-a", provider="profile-a"
            ))
            coordinates.append(_coordinate(
                condition, repeat, model="model-b", provider="profile-b"
            ))
            entry_a, docs_a = _make_entry(
                condition, repeat, model="model-a", provider="profile-a",
                reviewer=f"human-reviewer-{repeat}", review_version="manual-assessment",
            )
            entry_b, docs_b = _make_entry(
                condition, repeat, model="model-b", provider="profile-b",
                reviewer="human-reviewer-stable", review_version="manual-assessment",
            )
            entries.extend((entry_a, entry_b))
            documents.update(docs_a)
            documents.update(docs_b)

    result = _analyze(
        monkeypatch, entries, _plan(coordinates, repeats=3), documents
    )

    row = result["model_contrasts"]["results"][0]
    assert row["status"] == "unsupported"
    assert row["reason"] == "model_a_receipt_grader_identity_mismatch"
    assert row["metrics"] == {}
    assert row["n_final_model_a"] == 3
    assert row["n_final_model_b"] == 3
    assert {
        (grader["reviewer_id"], grader["review_version"])
        for grader in row["grader_identity_model_a"]["graders"]
    } == {
        ("human-reviewer-0", "manual-assessment"),
        ("human-reviewer-1", "manual-assessment"),
        ("human-reviewer-2", "manual-assessment"),
    }


def test_paired_analysis_refuses_distinct_graders(monkeypatch):
    coordinates, entries, documents = [], [], {}
    for repeat in range(2):
        for condition, reviewer in (
            ("linear_hybrid", "human-reviewer-a"),
            ("akg_guided_hybrid", "human-reviewer-b"),
        ):
            coordinates.append(_coordinate(condition, repeat))
            entry, entry_documents = _make_entry(
                condition, repeat, reviewer=reviewer, review_version="manual-assessment",
            )
            entries.append(entry)
            documents.update(entry_documents)

    result = _analyze(
        monkeypatch, entries, _plan(coordinates, repeats=2), documents
    )

    paired = result["paired"]
    assert paired["results"] == []
    assert paired["n_eligible_pairs"] == 0
    assert {row["reason"] for row in paired["unmatched"]} == {
        "receipt_reviewer_id_mismatch"
    }


def test_paired_analysis_refuses_receipts_without_grader_identity(monkeypatch):
    coordinates, entries, documents = [], [], {}
    for repeat in range(2):
        for condition, base in (
            ("linear_hybrid", 3.0), ("akg_guided_hybrid", 1.0),
        ):
            coordinates.append(_coordinate(condition, repeat))
            entry, entry_documents = _make_entry(
                condition, repeat, base=base,
            )
            entries.append(entry)
            documents.update(entry_documents)
    for document in documents.values():
        document["review_history"] = []

    result = _analyze(
        monkeypatch, entries, _plan(coordinates, repeats=2), documents
    )

    paired = result["paired"]
    assert paired["results"] == []
    assert paired["n_eligible_pairs"] == 0
    assert {row["reason"] for row in paired["unmatched"]} == {
        "receipt_grader_identity_unavailable:review_history_empty"
    }


def test_paired_analysis_never_pools_repeats_graded_by_different_reviewers(monkeypatch):
    coordinates, entries, documents = [], [], {}
    for repeat in range(2):
        for condition, base in (
            ("linear_hybrid", 3.0), ("akg_guided_hybrid", 1.0),
        ):
            coordinates.append(_coordinate(condition, repeat))
            entry, entry_documents = _make_entry(
                condition, repeat, base=base,
                reviewer=f"human-reviewer-{repeat}", review_version="manual-assessment",
            )
            entries.append(entry)
            documents.update(entry_documents)

    result = _analyze(
        monkeypatch, entries, _plan(coordinates, repeats=2), documents
    )

    paired = result["paired"]
    assert paired["n_eligible_pairs"] == 2
    assert len(paired["results"]) == 2
    assert all(row["n_pairs"] == 1 for row in paired["results"])
    assert {
        tuple(
            (grader["reviewer_id"], grader["review_version"])
            for grader in row["grader_identity"]["graders"]
        )
        for row in paired["results"]
    } == {
        (("human-reviewer-0", "manual-assessment"),),
        (("human-reviewer-1", "manual-assessment"),),
    }


@pytest.mark.parametrize(
    ("left", "right", "expected_u", "expected_p"),
    [
        ([1, 2, 3], [4, 5, 6], 0.0, 0.08085559837005224),
        ([1, 1, 2], [2, 3, 3], 0.5, 0.11014892418594699),
        ([2, 2, 2], [2, 2, 2], 4.5, 1.0),
    ],
)
def test_rank_sum_ties_and_group_reversal(left, right, expected_u, expected_p):
    forward = analysis._mann_whitney_exploratory(left, right)
    reverse = analysis._mann_whitney_exploratory(right, left)

    assert forward["u"] == pytest.approx(expected_u)
    assert forward["p_value"] == pytest.approx(expected_p)
    assert reverse["u"] == pytest.approx(len(left) * len(right) - expected_u)
    assert reverse["p_value"] == pytest.approx(forward["p_value"])
    assert reverse["effect_size"] == pytest.approx(-forward["effect_size"])
    assert forward["left"]["n"] == len(left)
    assert forward["left"]["median"] is not None
    assert forward["left"]["iqr"] is not None
    assert forward["independent"] is False
    assert "dependence" in forward["limitations"]


def test_rank_sum_empty_group_preserves_unavailability():
    result = analysis._mann_whitney_exploratory([], [2, 3, 4])
    assert result["status"] == "unavailable"
    assert result["n_left"] == 0
    assert result["n_right"] == 3
    assert result["u"] is None
    assert result["p_value"] is None
    assert result["effect_size"] is None
    assert result["left"]["median"] is None
    assert result["right"]["median"] == 3


def test_condition_rank_sum_keeps_unmatched_final_repeats(monkeypatch):
    coordinates, entries, documents = [], [], {}
    for condition in analysis.PRIMARY_CONDITIONS:
        for repeat in range(3):
            coordinates.append(_coordinate(condition, repeat))
            if condition == "akg_guided_hybrid" and repeat == 1:
                continue
            entry, entry_documents = _make_entry(
                condition, repeat, base=float(repeat + 1), modes=("ai",),
            )
            entries.append(entry)
            documents.update(entry_documents)
    result = _analyze(monkeypatch, entries, _plan(coordinates), documents)

    contrasts = result["condition_contrasts"]
    assert contrasts["role"] == "declared_exploratory_analysis"
    assert len(contrasts["results"]) == 1
    row = contrasts["results"][0]
    assert row["status"] == "analyzed"
    assert row["scoring_mode"] == "ai"
    assert row["coverage"]["akg_guided_hybrid"]["states"] == {"final": 2, "missing": 1}
    assert row["coverage"]["linear_hybrid"]["included_repeat_indices"] == [0, 1, 2]
    assert row["metrics"]["Srun_final"]["n_left"] == 3
    assert row["metrics"]["Srun_final"]["n_right"] == 2
    assert row["metrics"]["Srun_final"]["left"]["median"] == 2.0
    assert row["metrics"]["Srun_final"]["left"]["iqr"] == 1.0
    assert result["paired"]["n_eligible_pairs"] == 2
    assert result["paired"]["role"] == "supplementary"
    assert "Mann-Whitney" in result["statistics_policy"]["primary"]


@pytest.mark.parametrize("unready", [False, True])
def test_condition_rank_sum_refuses_incompatible_or_unready_receipts(monkeypatch, unready):
    coordinates, entries, documents = [], [], {}
    for condition in analysis.PRIMARY_CONDITIONS:
        coordinates.append(_coordinate(condition, 0))
        entry, entry_documents = _make_entry(
            condition, 0, readiness=not (unready and condition == "akg_guided_hybrid"),
            reviewer="reviewer-a" if condition == "linear_hybrid" else "reviewer-b",
        )
        entries.append(entry)
        documents.update(entry_documents)
    result = _analyze(monkeypatch, entries, _plan(coordinates, repeats=1), documents)
    row = result["condition_contrasts"]["results"][0]
    assert row["status"] == "unsupported"
    assert row["metrics"] == {}
    assert row["reason"] == (
        "akg_guided_hybrid:no_ready_final_receipts" if unready
        else "receipt_reviewer_id_mismatch"
    )
