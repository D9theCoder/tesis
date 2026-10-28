"""Dedicated offline tests for the Chapter 3 study plan and analysis modules.

No provider call, no HTTP request, no live DVWA, and no test of the frozen
``scoring_v4_matrix`` design. Score grouping is stubbed at the scorer boundary so
these tests exercise study-owned logic only: declared axes, planned statuses,
coordinate matching, fixture-epoch eligibility, pairing, statistics policy, and
null-with-reason behaviour.
"""
import json
from pathlib import Path
from statistics import median
from types import SimpleNamespace
from typing import Any

import pytest

import evaluation.research_analysis as analysis
import evaluation.research_plan as plan_mod
from evaluation.research_plan import (
    MIN_REPEATS,
    PRIMARY_CONDITIONS,
    RESEARCH_CONFIG_VERSION,
    build_research_plan,
    freeze_ranking_profile,
    load_research_config,
    planned_coordinates,
    run_research_plan,
    verify_plan,
)

REPO = Path(__file__).resolve().parents[1]
STUDY_CONFIG = REPO / "config" / "research" / "chapter3_study.json"
RULE = "a" * 64


# --------------------------------------------------------------------------- #
# fixtures and helpers
# --------------------------------------------------------------------------- #

def _declaration(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(STUDY_CONFIG.read_bytes())
    document.update(overrides)
    return document


def _stub_config(**overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = dict(
        payload_mode="hybrid",
        scoring_profile={
            "profile_id": "profile",
            "version": "v1",
            "fixture_id": "dvwa-source-fee264766667580e5352",
            "protocol_version": "ranking-session-acceptance.v1",
            "candidate_budget": 3,
            "frozen_at": "2026-10-28T00:00:00+00:00",
            "sources": [{"origin": "operator_fixture"}],
            "sha256": "profile-sha",
        },
        scoring_oracles=[{"source_id": "session", "origin": "operator_fixture"}],
        scoring_rubric_version="scoring.v4",
        fixture_id="dvwa-source-fee264766667580e5352",
        protocol_version="ranking-session-acceptance.v1",
        candidate_budget=3,
        scoring_policy_epoch={"epoch_id": "chapter3-2026-10-28", "frozen_at": "2026-10-28T00:00:00+00:00"},
        token_price_schedule={"effective_at": "2026-10-28T00:00:00+00:00", "prices": {}},
        providers=["profile-a"],
        provider="profile-a",
        levels=["low"],
        surfaces=["sqli"],
        evasion_enabled=False,
        evasion_mode="reactive",
        iterations=1,
        stop_policy="impact",
        coverage_target=0.7,
        enriched_reporting=False,
        diagnose=False,
        evasion_max_retries=1,
        evasion_cooldown_threshold=1,
        models={},
        llm_max_concurrency=1,
        llm_cache=False,
        llm_runtime=SimpleNamespace(roles={}),
        scoring_mode="human",
        scoring_evaluator={},
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _plan_config(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("target_url: http://172.19.48.1/dvwa\n", encoding="utf-8")
    return config


@pytest.fixture()
def plan_env(monkeypatch, tmp_path):
    config_path = _plan_config(tmp_path)

    def fake_load(config_path=None, cli_args=None):
        return _stub_config()

    monkeypatch.setattr(plan_mod, "load_and_resolve_config", fake_load)
    monkeypatch.setattr(plan_mod, "validate_evidence_config", lambda *args, **kwargs: None)
    monkeypatch.setattr(plan_mod, "_repository_root", lambda path: tmp_path)
    monkeypatch.setattr(plan_mod, "source_tree_hashes", lambda root: {"core/x.py": "h"})
    return config_path


def _build(config_path: Path, tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = dict(
        config_path=str(config_path),
        output_epoch=str(tmp_path / "epoch"),
        epoch_id="chapter3-2026-10-28",
        repeats=3,
        providers=["profile-a"],
    )
    kwargs.update(overrides)
    return build_research_plan(**kwargs)


# --------------------------------------------------------------------------- #
# declared research config
# --------------------------------------------------------------------------- #

def test_declared_study_config_is_valid():
    declaration = load_research_config(STUDY_CONFIG)

    assert declaration["research_config_version"] == RESEARCH_CONFIG_VERSION
    assert sorted(declaration["primary_conditions"]) == sorted(PRIMARY_CONDITIONS)
    assert declaration["payload_mode"] == "hybrid"
    assert declaration["repeats"] >= MIN_REPEATS
    assert declaration["blocks"]["selection"]["target_method"] is None
    assert declaration["blocks"]["forced"]["target_method"] == "per_method"
    assert declaration["design"]["multiple_comparisons"]
    assert declaration["design"]["pairing"]


@pytest.mark.parametrize(
    "mutate,message",
    [
        (lambda d: d.update(research_config_version="v0"), "version"),
        (lambda d: d.pop("repeats"), "missing"),
        (lambda d: d.update(repeats=2), "repeats"),
        (lambda d: d.update(primary_conditions=["linear_hybrid"]), "primary conditions"),
        (lambda d: d.update(payload_mode="static_only"), "payload mode"),
        (lambda d: d["blocks"]["selection"].update(target_method="sqli_union"), "selection block"),
        (lambda d: d["blocks"]["forced"].update(target_method=None), "forced block"),
        (lambda d: d.update(levels=["impossible"]), "levels"),
        (lambda d: d.update(surfaces=["graphql"]), "surfaces"),
        (lambda d: d.update(frozen_inputs_required=[]), "frozen epoch inputs"),
        (lambda d: d["design"].pop("multiple_comparisons"), "multiple-comparison"),
        (lambda d: d.update(extra_axis=True), "unknown keys"),
    ],
)
def test_research_config_rejects_invalid_declarations(tmp_path, mutate, message):
    declaration = _declaration()
    mutate(declaration)
    path = tmp_path / "declaration.json"
    path.write_text(json.dumps(declaration), encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        load_research_config(path)

    assert message in str(excinfo.value)


# --------------------------------------------------------------------------- #
# plan construction and freeze
# --------------------------------------------------------------------------- #

def test_plan_declares_both_blocks_with_stable_coordinates(plan_env, tmp_path):
    plan = _build(plan_env, tmp_path)

    selection = plan["blocks"]["selection"]
    forced = plan["blocks"]["forced"]
    # 1 model x 1 surface x 1 level x 2 conditions x 3 repeats.
    assert len(selection) == 6
    # Four SQli methods x 2 conditions x 3 repeats.
    assert len(forced) == 24
    assert plan["planned_counts"] == {"selection": 6, "forced": 24, "total": 30}
    assert all(row["target_method"] is None for row in selection)
    assert {row["target_method"] for row in forced} == {
        "sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind"
    }
    assert all(row["status"] == "planned" for row in selection + forced)
    ids = [row["coordinate_id"] for row in selection + forced]
    assert len(ids) == len(set(ids))
    assert plan["plan_sha256"] == plan_mod._json_hash({k: v for k, v in plan.items() if k != "plan_sha256"})
    assert planned_coordinates(plan) == selection + forced
    assert (tmp_path / "epoch" / "research-plan.json").is_file()


def test_plan_uses_declared_research_config(plan_env, tmp_path):
    declaration = _declaration(repeats=4, levels=["low", "high"], surfaces=["sqli"])
    declaration_path = tmp_path / "declaration.json"
    declaration_path.write_text(json.dumps(declaration), encoding="utf-8")

    plan = _build(plan_env, tmp_path, repeats=3, research_config_path=str(declaration_path))

    assert plan["constraints"]["repeats"] == 4
    # Four SQli methods x two levels x two conditions x four repeats.
    assert plan["planned_counts"]["forced"] == 4 * 2 * 2 * 4
    assert plan["research_config"]["declaration"]["repeats"] == 4
    assert len(plan["research_config"]["sha256"]) == 64


def test_plan_rejects_research_config_epoch_mismatch(plan_env, tmp_path):
    declaration_path = tmp_path / "declaration.json"
    declaration_path.write_text(json.dumps(_declaration(epoch_id="other-epoch")), encoding="utf-8")

    with pytest.raises(ValueError, match="declared research config epoch"):
        _build(plan_env, tmp_path, research_config_path=str(declaration_path))


@pytest.mark.parametrize("repeats", [0, 1, 2])
def test_plan_requires_at_least_three_repeats(plan_env, tmp_path, repeats):
    with pytest.raises(ValueError, match="at least 3 repeats"):
        _build(plan_env, tmp_path, repeats=repeats)


def test_plan_requires_frozen_scoring_inputs(plan_env, tmp_path, monkeypatch):
    monkeypatch.setattr(
        plan_mod, "load_and_resolve_config", lambda **kwargs: _stub_config(scoring_profile={})
    )
    with pytest.raises(ValueError, match="frozen scoring_profile"):
        _build(plan_env, tmp_path)


def test_plan_requires_hybrid_primary_mode(plan_env, tmp_path, monkeypatch):
    monkeypatch.setattr(
        plan_mod, "load_and_resolve_config", lambda **kwargs: _stub_config(payload_mode="static_only")
    )
    with pytest.raises(ValueError, match="hybrid payload mode"):
        _build(plan_env, tmp_path)


def test_plan_requires_matching_epoch_and_profile_axes(plan_env, tmp_path, monkeypatch):
    profile = dict(_stub_config().scoring_profile, candidate_budget=9)
    monkeypatch.setattr(
        plan_mod, "load_and_resolve_config", lambda **kwargs: _stub_config(scoring_profile=profile)
    )
    with pytest.raises(ValueError, match="candidate budget"):
        _build(plan_env, tmp_path)


def test_verify_plan_refuses_source_drift(plan_env, tmp_path, monkeypatch):
    plan_path = tmp_path / "epoch" / "research-plan.json"
    _build(plan_env, tmp_path)
    assert verify_plan(plan_path)["plan_sha256"]

    monkeypatch.setattr(plan_mod, "source_tree_hashes", lambda root: {"core/x.py": "changed"})
    with pytest.raises(ValueError, match="source tree changed"):
        verify_plan(plan_path)


def test_verify_plan_refuses_content_tampering(plan_env, tmp_path):
    plan_path = tmp_path / "epoch" / "research-plan.json"
    _build(plan_env, tmp_path)
    document = json.loads(plan_path.read_bytes())
    document["constraints"]["repeats"] = 9
    plan_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="content hash mismatch"):
        verify_plan(plan_path)


def test_freeze_profile_records_lineage_and_epoch(tmp_path, monkeypatch):
    config_path = _plan_config(tmp_path)
    candidate = {
        "profile_id": "pilot",
        "version": "v1",
        "fixture_id": "dvwa-source-fee264766667580e5352",
        "protocol_version": "ranking-session-acceptance.v1",
        "candidate_budget": 3,
        "frozen_at": "2026-10-28T00:00:00+00:00",
        "sources": [{"origin": "operator_fixture"}],
        "scenarios": {},
        "sha256": "candidate-sha",
    }
    candidate_path = tmp_path / "pilot.json"
    candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
    monkeypatch.setattr(plan_mod, "load_and_resolve_config", lambda **kwargs: _stub_config())
    monkeypatch.setattr(plan_mod, "validate_profile", lambda profile: None)
    monkeypatch.setattr(plan_mod, "validate_evidence_config", lambda *args, **kwargs: None)
    monkeypatch.setattr(plan_mod, "_repository_root", lambda path: tmp_path)
    monkeypatch.setattr(plan_mod, "source_tree_hashes", lambda root: {"core/x.py": "h"})

    receipt = freeze_ranking_profile(
        config_path=str(config_path),
        candidate_profile_path=str(candidate_path),
        output_epoch=str(tmp_path / "frozen"),
        epoch_id="chapter3-2026-10-28",
    )

    frozen = json.loads(Path(receipt["frozen_profile"]).read_bytes())
    assert frozen["parent_profile_sha256"] == "candidate-sha"
    assert frozen["profile_id"].endswith("+chapter3-2026-10-28")
    assert frozen["freeze_epoch"]["payload_policy_version"]
    assert frozen["sha256"] == plan_mod.evidence_hash({k: v for k, v in frozen.items() if k != "sha256"})
    assert receipt["policy_epoch"]["ranking_profile_sha256"] == frozen["sha256"]
    assert Path(receipt["config_path"]).is_file()


def test_freeze_profile_refuses_repeat_and_axis_mismatch(tmp_path, monkeypatch):
    config_path = _plan_config(tmp_path)
    candidate = {
        "profile_id": "pilot", "version": "v1",
        "fixture_id": "different-fixture",
        "protocol_version": "ranking-session-acceptance.v1",
        "candidate_budget": 3,
        "frozen_at": "2026-10-28T00:00:00+00:00",
        "sources": [{"origin": "operator_fixture"}], "sha256": "x",
    }
    candidate_path = tmp_path / "pilot.json"
    candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
    monkeypatch.setattr(plan_mod, "load_and_resolve_config", lambda **kwargs: _stub_config())
    monkeypatch.setattr(plan_mod, "validate_profile", lambda profile: None)
    monkeypatch.setattr(plan_mod, "validate_evidence_config", lambda *args, **kwargs: None)

    with pytest.raises(ValueError, match="at least 3 repeats"):
        freeze_ranking_profile(
            config_path=str(config_path), candidate_profile_path=str(candidate_path),
            output_epoch=str(tmp_path / "frozen"), epoch_id="e", repeats=2,
        )
    with pytest.raises(ValueError, match="fixture/protocol"):
        freeze_ranking_profile(
            config_path=str(config_path), candidate_profile_path=str(candidate_path),
            output_epoch=str(tmp_path / "frozen2"), epoch_id="e", repeats=3,
        )


def test_run_plan_verifies_before_executing(plan_env, tmp_path, monkeypatch):
    plan_path = tmp_path / "epoch" / "research-plan.json"
    _build(plan_env, tmp_path)
    monkeypatch.setattr(plan_mod, "_run_block", lambda plan, block, output_epoch: {
        "block": block, "planned": plan["planned_counts"][block], "observed": 0,
    })
    summary = run_research_plan(plan_path)

    assert summary["observed_counts"] == {"selection": 0, "forced": 0}
    assert summary["score_epoch"]["final_status"] == "pending_review"
    assert set(summary["blocks"]) == {"selection", "forced"}

    monkeypatch.setattr(plan_mod, "verify_plan", lambda path: (_ for _ in ()).throw(ValueError("drift")))
    with pytest.raises(ValueError, match="drift"):
        run_research_plan(plan_path)


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


def test_analysis_refuses_cross_epoch_artifact(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", 0)]
    record = _record("linear_hybrid", 0, epoch="other-epoch")
    record["_reviews"] = _reviews(receipt=_receipt("linear_hybrid", "human"))
    result = _analyze(
        monkeypatch, [FakeEntry(record, sha="e1")], coordinates, compare=_stub_compare,
    )
    # A cross-epoch artifact never consumes the coordinate's slot.
    assert result["status_counts"]["missing"] == 1
    assert result["groups"] == []
    assert result["exclusions"] == {"no_execution_artifact": 1}


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"fixture": "other-fixture"}, "no_execution_artifact"),
        ({"protocol": "other-protocol"}, "no_execution_artifact"),
        ({"budget": 9}, "no_execution_artifact"),
        ({"profile": "other-profile"}, "scoring_profile_mismatch"),
        ({"epoch": "other-epoch"}, "no_execution_artifact"),
    ],
)
def test_analysis_refuses_incomparable_identity(monkeypatch, overrides, reason):
    coordinates = [_coordinate("linear_hybrid", 0)]
    record = _record("linear_hybrid", 0, **overrides)
    result = _analyze(monkeypatch, [FakeEntry(record, sha="e1")], coordinates, compare=_stub_compare)
    assert result["status_counts"]["final"] == 0
    assert result["groups"] == []
    assert any(key.startswith(reason) for key in result["exclusions"])


def test_analysis_keeps_pending_and_failed_as_counts(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", 0), _coordinate("akg_guided_hybrid", 0)]
    pending_record = _record("linear_hybrid", 0)
    pending_record["_reviews"] = _reviews(pending_reason="candidate_pending")
    failed_record = _record("akg_guided_hybrid", 0, status="failed")
    failed_record["_reviews"] = _reviews()
    result = _analyze(
        monkeypatch,
        [FakeEntry(pending_record, sha="p"), FakeEntry(failed_record, sha="f")],
        coordinates,
        compare=_stub_compare,
    )
    assert result["status_counts"]["pending_review"] == 1
    assert result["status_counts"]["error"] == 1
    assert result["exclusions"]["candidate_pending"] == 1
    assert result["exclusions"]["RUNTIME_FAILURE"] == 1
    assert result["groups"] == []


def test_analysis_records_scorer_group_refusal(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", 0)]
    receipt = _receipt("linear_hybrid", "human")
    record = _record("linear_hybrid", 0)
    record["_reviews"] = _reviews(receipt=receipt)

    def refuse(paths, *, planned_repeats=None):
        raise ValueError("Cannot compare mixed rubric versions")

    result = _analyze(
        monkeypatch, [FakeEntry(record, sha="e")], coordinates, compare=refuse,
        documents={f"{id(receipt)}-human.json": receipt},
    )
    assert result["groups"] == []
    assert result["group_exclusions"][0]["reason"].startswith("receipt_comparison_refused")
    assert "mixed rubric" in result["group_exclusions"][0]["detail"]


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


def test_paired_analysis_requires_matching_receipt_axes(monkeypatch):
    result = _pair_records(monkeypatch, rubric_left="scoring.v3")
    paired = result["paired"]
    assert paired["results"] == []
    assert {row["reason"] for row in paired["unmatched"]} == {"receipt_rubric_version_mismatch"}


def test_paired_analysis_requires_shared_grader_mode(monkeypatch):
    coordinates, entries, documents = [], [], {}
    for repeat in range(2):
        for condition, modes in (("linear_hybrid", ("human",)), ("akg_guided_hybrid", ("ai",))):
            coordinates.append(_coordinate(condition, repeat))
            receipt = _receipt(condition, modes[0])
            record = _record(condition, repeat)
            record["_reviews"] = _reviews(receipt=receipt, modes=modes)
            entries.append(FakeEntry(record, sha=f"{condition}-{repeat}"))
            documents[f"{id(receipt)}-{modes[0]}.json"] = receipt
    result = _analyze(monkeypatch, entries, coordinates, compare=_stub_compare, documents=documents)
    assert result["paired"]["results"] == []
    assert {row["reason"] for row in result["paired"]["unmatched"]} == {"grader_mode_missing"}


def test_paired_analysis_reports_condition_missing(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", 0)]
    receipt = _receipt("linear_hybrid", "human")
    record = _record("linear_hybrid", 0)
    record["_reviews"] = _reviews(receipt=receipt)
    result = _analyze(
        monkeypatch, [FakeEntry(record, sha="e")], coordinates, compare=_stub_compare,
        documents={f"{id(receipt)}-human.json": receipt},
    )
    assert result["paired"]["results"] == []
    assert {row["reason"] for row in result["paired"]["unmatched"]} == {"condition_missing"}


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


def test_rank_averages_ties():
    assert analysis._rank([12.0, 7.0, 12.0, 3.0]) == [3.5, 2.0, 3.5, 1.0]


def test_analysis_output_declares_statistics_policy(monkeypatch):
    result = _pair_analysis_with(monkeypatch)
    policy = result["statistics_policy"]
    assert policy["direction"] == analysis.DIFFERENCE_DIRECTION
    assert "Wilcoxon" in policy["paired_test"]
    assert "Holm" in policy["multiple_comparisons"]
    assert "no_imputation" in policy
    assert result["schema_version"] == analysis.ANALYSIS_SCHEMA_VERSION
    assert result["score_epoch"]["final_status"] == "review_receipts_only"
