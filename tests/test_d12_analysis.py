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
             metrics_epoch="scoring-policy.v4.2"):
    vector = {name: base for name in COMPONENTS}
    vector.update(components or {})
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
        "rubric_version": "scoring.v4",
        "scoring_rule_sha256": RULE,
        "metrics_epoch": metrics_epoch,
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
            metrics_epoch="scoring-policy.v4.2", review_status="final"):
    receipt = None
    mode = modes[0] if modes else "human"
    if review_status == "final" and modes:
        receipt = _receipt(
            condition, mode, base=base, components=components,
            metrics_epoch=metrics_epoch,
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
        "plan_version": "chapter3-research-plan.v2",
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
            "scoring_rubric_version": "scoring.v4",
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
    for repeat, epoch in enumerate(("scoring-policy.v4.2", "scoring-policy.v4.3")):
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
                     metrics_epoch_a="scoring-policy.v4.2",
                     metrics_epoch_b="scoring-policy.v4.2",
                     readiness_a=True, readiness_b=True):
    conditions = conditions or list(analysis.PRIMARY_CONDITIONS)
    coordinates, entries, documents = [], [], {}
    for condition in conditions:
        for repeat in range(3):
            for model, provider, base, epoch, model_modes, include, ready in (
                ("model-a", "profile-a", base_a, metrics_epoch_a,
                 ("human",) if modes is None else modes[0], include_model_a, readiness_a),
                ("model-b", "profile-b", base_b, metrics_epoch_b,
                 ("human",) if modes is None else modes[1], True, readiness_b),
            ):
                coordinates.append(_coordinate(
                    condition, repeat, model=model, provider=provider
                ))
                if not include:
                    continue
                entry, entry_documents = _make_entry(
                    condition, repeat, model=model, provider=provider,
                    base=base, metrics_epoch=epoch, modes=model_modes,
                    readiness=ready,
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
        metrics_epoch_a="scoring-policy.v4.2",
        metrics_epoch_b="scoring-policy.v4.3",
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
