"""Offline controls for freeze-input safety and the synthetic ranking profile.

Every profile/artifact below is a labelled synthetic fixture.  It is not a
research ranking, it is never counted as a run, and it must never enter a table.
The controls prove reachability only: the profile schema (B1), a post-freeze
selection grade of 2/3/4 (B2), and the same numeric ``Smethod`` through
``review_queue`` (B3), plus the non-empty token-price-schedule guard at freeze,
plan-build and plan-verification boundaries (F7).

No provider, DVWA, graph execution, epoch freeze or review finalization happens
here.
"""
from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.knowledge_graph import AttackKnowledgeGraph
from core.state import METHODS_BY_SURFACE
from evaluation import ranking_draft, research_plan
from evaluation.research_plan import (
    PRICE_SCHEDULE_REQUIRED,
    RESEARCH_PLAN_VERSION,
    build_research_plan,
    freeze_ranking_profile,
    require_frozen_token_price_schedule,
    verify_plan,
)
from evaluation.scoring_evidence import evidence_hash, selection_grade, validate_profile
from evaluation.thesis_scoring import review_queue
from tesis.config_loader import load_yaml_config

FROZEN_AT = "2026-10-01T00:00:00+00:00"
SELECTED_AT = "2026-10-02T00:00:00+00:00"
FIXTURE_SCOPE = "offline_synthetic_fixture"
SCENARIOS = (
    ("access_control", "low"),
    ("access_control", "medium"),
    ("access_control", "high"),
    ("brute_force", "medium"),
    ("sqli", "high"),
)


def _protocol_source(origin: str = "operator_fixture") -> dict:
    document = {
        "kind": "offline_synthetic_control",
        "note": "synthetic schema-control stand-in for a frozen protocol source",
    }
    return {
        "source_id": "protocol",
        "origin": origin,
        "document": document,
        "sha256": evidence_hash(document),
    }


def synthetic_profile(*, source_origin: str = "operator_fixture") -> dict:
    """A complete five-scenario / fifteen-entry schema fixture, never research."""
    source = _protocol_source(source_origin)
    scenarios: dict[str, dict] = {}
    for surface, level in SCENARIOS:
        entries = {}
        for index, method in enumerate(METHODS_BY_SURFACE[surface]):
            preconditions = AttackKnowledgeGraph.METHOD_PRECONDITIONS[method]
            entries[method] = {
                "preconditions": preconditions,
                "planned_request_count": 5 + 3 * index,
                "protocol_refs": ["protocol"],
                "fit_predicates": [{"key": preconditions[0], "equals": True}],
                "allowed_plans": ["stop_after_target", "stop_at_budget", "continue_same_surface"],
                "reference_status": "confirmed",
                "reference_fit": 2,
                "reference_reason": "synthetic offline control; not a research fit judgement",
            }
        scenarios[f"{surface}:{level}"] = entries
    profile = {
        "profile_id": "offline-synthetic-schema-control",
        "version": "ranking.synthetic.v1",
        "fixture_id": "synthetic-dwva",
        "protocol_version": "offline.v1",
        "frozen_at": FROZEN_AT,
        "candidate_budget": 5,
        "sources": [source],
        "scenarios": scenarios,
        "fixture_scope": FIXTURE_SCOPE,
        "fixture_note": "synthetic schema/reachability control; never a research ranking or a run",
    }
    profile["sha256"] = evidence_hash(profile)
    return profile


def _selection(profile: dict, method: str, plan: dict) -> dict:
    entries = profile["scenarios"]["access_control:low"]
    observations = {}
    for entry in entries.values():
        observations.update({key: True for key in entry["preconditions"]})
        observations.update({predicate["key"]: True for predicate in entry["fit_predicates"]})
    return {
        "dimension": "Smethod",
        "method": method,
        "surface": "access_control",
        "visit_id": "offline-synthetic-visit",
        "observations": observations,
        "precondition_status": {key: "true" for key in observations},
        "reason_refs": [AttackKnowledgeGraph.METHOD_PRECONDITIONS[method][0]],
        "plan": plan,
        "selected_at": SELECTED_AT,
        "profile_sha256": profile["sha256"],
        "selection_source": "model_orchestrator",
        "decision_origin": "model",
    }


def _artifact(profile: dict, method: str, plan: dict) -> dict:
    """A labelled offline fixture, deliberately outside every run population."""
    return {
        "execution_id": f"offline-synthetic-{method}",
        "run_id": "offline-synthetic-fixture",
        "selected_method": method,
        "validation_scope": FIXTURE_SCOPE,
        "score_epoch": {"thesis_final": "scoring.v4"},
        "config": {
            "scoring_rubric_version": "scoring.v4",
            "scoring_mode": "human",
            "scoring_evaluator": {},
            "scoring_profile": profile,
            "scoring_oracles": [],
            "fixture_id": profile["fixture_id"],
            "protocol_version": profile["protocol_version"],
            "candidate_budget": profile["candidate_budget"],
            "security_level": "low",
            "surface": "access_control",
            "experiment_condition": "linear_hybrid",
        },
        "final_state": {
            "selected_method": method,
            "scoring_decisions": [_selection(profile, method, plan)],
            "payload_candidates": {},
            "response_evidence": [],
            "timing_evidence": [],
            "verifier_history": [],
        },
    }


def test_b1_validate_profile_accepts_complete_synthetic_schema():
    profile = synthetic_profile()

    validate_profile(profile)

    assert len(profile["scenarios"]) == 5
    assert sum(len(entries) for entries in profile["scenarios"].values()) == 15
    assert set(profile["scenarios"]) == {
        "access_control:low",
        "access_control:medium",
        "access_control:high",
        "brute_force:medium",
        "sqli:high",
    }
    assert profile["fixture_scope"] == FIXTURE_SCOPE
    assert profile["sha256"] == evidence_hash(
        {key: value for key, value in profile.items() if key != "sha256"}
    )
    for coordinate, entries in profile["scenarios"].items():
        surface = coordinate.split(":", 1)[0]
        assert set(entries) == set(METHODS_BY_SURFACE[surface])
        for entry in entries.values():
            assert entry["reference_status"] == "confirmed"
            assert entry["reference_fit"] in (1, 2, 3)
            assert entry["reference_reason"]
    assert all(source["origin"] == "operator_fixture" for source in profile["sources"])


@pytest.mark.parametrize(
    ("method", "plan", "expected"),
    (
        ("ac_vertical_escalation", {"kind": "stop_at_budget"}, 2),
        ("ac_idor", {"kind": "not_a_declared_plan"}, 3),
        ("ac_idor", {"kind": "stop_at_budget"}, 4),
    ),
)
def test_b2_selection_grade_returns_post_freeze_numeric(method, plan, expected):
    profile = synthetic_profile(source_origin="offline_control")
    artifact = _artifact(profile, method, plan)

    grade, detail = selection_grade(artifact, method)

    assert grade == expected
    assert detail["status"] == "assessed"
    assert detail["profile_sha256"] == profile["sha256"]
    assert detail["reason"] in {"higher_ranked_comparison_exists", "top_ranked"}


def test_b2_pre_freeze_selection_stays_unavailable():
    profile = synthetic_profile(source_origin="offline_control")
    artifact = _artifact(profile, "ac_idor", {"kind": "stop_at_budget"})
    artifact["final_state"]["scoring_decisions"][0]["selected_at"] = "2026-09-30T00:00:00+00:00"

    grade, detail = selection_grade(artifact, "ac_idor")

    assert grade is None
    assert detail["reason"] == "profile_not_frozen_before_selection"


@pytest.mark.parametrize(
    ("method", "plan", "expected"),
    (
        ("ac_vertical_escalation", {"kind": "stop_at_budget"}, 2),
        ("ac_idor", {"kind": "not_a_declared_plan"}, 3),
        ("ac_idor", {"kind": "stop_at_budget"}, 4),
    ),
)
def test_b3_review_queue_returns_numeric_smethod_without_ranking_unavailable(
    tmp_path, method, plan, expected,
):
    artifact = _artifact(synthetic_profile(source_origin="offline_control"), method, plan)
    path = tmp_path / f"{FIXTURE_SCOPE}-{method}.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")

    queue = review_queue(path)

    assert queue["components"]["Smethod"] == expected
    assert queue["component_pending_reasons"].get("Smethod") is None
    assert "ranking_unavailable" not in json.dumps(queue["component_pending_reasons"])
    assert queue["selection_evidence"]["status"] == "assessed"


def _valid_schedule() -> dict:
    return {
        "schedule_id": "offline-synthetic-price",
        "version": "prices.v1",
        "currency": "USD",
        "effective_at": "2026-09-01T00:00:00+00:00",
        "prices": {
            "offline/fixture": {"input_per_million": 1.0, "output_per_million": 2.0},
        },
    }


@pytest.mark.parametrize(
    "schedule",
    (
        {},
        {"schedule_id": "missing-required-fields"},
        {
            "schedule_id": "bad-time",
            "version": "prices.v1",
            "currency": "USD",
            "effective_at": "not-a-timestamp",
            "prices": {"offline/fixture": {"input_per_million": 1.0, "output_per_million": 2.0}},
        },
        {
            "schedule_id": "empty-prices",
            "version": "prices.v1",
            "currency": "USD",
            "effective_at": "2026-09-01T00:00:00+00:00",
            "prices": {},
        },
    ),
)
def test_f7_freeze_and_build_reject_empty_or_malformed_schedule(
    monkeypatch, tmp_path, schedule,
):
    config = SimpleNamespace(token_price_schedule=schedule)
    monkeypatch.setattr(research_plan, "load_and_resolve_config", lambda **_kwargs: config)
    epoch = tmp_path / "epoch"

    with pytest.raises(ValueError, match=PRICE_SCHEDULE_REQUIRED):
        freeze_ranking_profile(
            config_path="config.yaml",
            candidate_profile_path=str(tmp_path / "missing-profile.json"),
            output_epoch=str(epoch),
            epoch_id="offline-control",
        )
    assert not epoch.exists()

    with pytest.raises(ValueError, match=PRICE_SCHEDULE_REQUIRED):
        build_research_plan(
            config_path="config.yaml",
            output_epoch=str(epoch),
            epoch_id="offline-control",
        )
    assert not epoch.exists()


def test_f7_verify_plan_rejects_empty_schedule_before_any_plan_use(monkeypatch, tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("scoring_rubric_version: scoring.v4\n", encoding="utf-8")
    plan = {
        "artifact_type": "chapter3_research_plan",
        "plan_version": RESEARCH_PLAN_VERSION,
        "config_path": str(config_path),
        "config_sha256": sha256(config_path.read_bytes()).hexdigest(),
        "source_hashes": {},
    }
    plan["plan_sha256"] = sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    plan_path = tmp_path / "research-plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(
        research_plan,
        "load_and_resolve_config",
        lambda **_kwargs: SimpleNamespace(token_price_schedule={}),
    )
    monkeypatch.setattr(research_plan, "_repository_root", lambda _path: tmp_path)
    monkeypatch.setattr(research_plan, "source_tree_hashes", lambda _root: {})

    with pytest.raises(ValueError, match=PRICE_SCHEDULE_REQUIRED):
        verify_plan(plan_path)


def test_f7_valid_schedule_freezes_and_embeds_resolved_prices(monkeypatch, tmp_path):
    profile = synthetic_profile()
    config = SimpleNamespace(
        token_price_schedule=_valid_schedule(),
        scoring_oracles=[_protocol_source()],
        scoring_rubric_version="scoring.v4",
        fixture_id=profile["fixture_id"],
        protocol_version=profile["protocol_version"],
        candidate_budget=profile["candidate_budget"],
    )
    prices_path = tmp_path / "prices.json"
    stale_schedule = {
        **_valid_schedule(),
        "prices": {"offline/fixture": {"input_per_million": 99.0, "output_per_million": 99.0}},
    }
    prices_path.write_text(json.dumps(stale_schedule), encoding="utf-8")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "scoring_rubric_version: scoring.v4\ntoken_price_schedule: prices.json\n",
        encoding="utf-8",
    )
    candidate_path = tmp_path / "ranking-profile.json"
    candidate_path.write_text(json.dumps(profile), encoding="utf-8")
    epoch = tmp_path / "epoch"
    monkeypatch.setattr(research_plan, "load_and_resolve_config", lambda **_kwargs: config)
    monkeypatch.setattr(research_plan, "_repository_root", lambda _path: tmp_path)
    monkeypatch.setattr(
        research_plan, "source_tree_hashes", lambda _root: {"offline.py": "0" * 64},
    )

    assert require_frozen_token_price_schedule(config) == _valid_schedule()
    receipt = freeze_ranking_profile(
        config_path=str(config_path),
        candidate_profile_path=str(candidate_path),
        output_epoch=str(epoch),
        epoch_id="offline-control",
    )

    frozen_path = Path(receipt["frozen_profile"])
    frozen = json.loads(frozen_path.read_text(encoding="utf-8"))
    validate_profile(frozen)
    assert frozen["sha256"] == evidence_hash(
        {key: value for key, value in frozen.items() if key != "sha256"}
    )
    assert sum(len(entries) for entries in frozen["scenarios"].values()) == 15
    assert frozen["parent_profile_sha256"] == profile["sha256"]
    assert frozen["fixture_scope"] == FIXTURE_SCOPE
    assert Path(receipt["config_path"]).is_file()
    assert (epoch / "payload-policy-snapshot.json").is_file()
    assert (epoch / "policy-epoch.json").is_file()
    frozen_config = load_yaml_config(receipt["config_path"])
    assert frozen_config["token_price_schedule"] == _valid_schedule()
    assert frozen_config["token_price_schedule"] != stale_schedule
    relocated_path = tmp_path / "relocated" / "config.frozen.yaml"
    relocated_path.parent.mkdir()
    relocated_path.write_text(
        Path(receipt["config_path"]).read_text(encoding="utf-8"), encoding="utf-8",
    )
    prices_path.unlink()
    relocated = load_yaml_config(relocated_path)
    assert relocated["token_price_schedule"] == _valid_schedule()


# --- Owner-review ranking draft (coverage != freeze readiness) -----------------
DRAFT_PATH = (
    Path(__file__).resolve().parents[1]
    / "config/research/autoresearch-ranking-draft-2026-10-31.json"
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _draft() -> dict:
    return copy.deepcopy(ranking_draft.load_draft(DRAFT_PATH))


def test_ranking_draft_covers_registry_and_is_not_a_scoring_profile():
    draft = _draft()
    report = ranking_draft.assess_draft(draft, root=REPOSITORY_ROOT)

    assert report["coverage"]["complete"] is True
    assert report["coverage"]["scenario_count"] == 9
    assert report["coverage"]["entry_count"] == 27
    assert report["coverage"]["confirmed_entries"] == 23
    assert report["coverage"]["pending_entries"] == 0
    assert report["coverage"]["deferred_entries"] == 4
    assert report["freeze_readiness"]["ready"] is True
    assert "owner_approval_missing" not in report["freeze_readiness"]["blockers"]

    assert draft["status"] == "draft_approved_unfrozen"
    assert draft["not_a_scoring_profile"] is True
    assert draft["runtime_selector_eligible"] is False
    for forbidden in ("frozen_at", "profile_id", "version", "sha256"):
        assert forbidden not in draft

    for coordinate, entries in draft["scenarios"].items():
        surface = coordinate.split(":", 1)[0]
        assert set(entries) == set(METHODS_BY_SURFACE[surface])
        for method, entry in entries.items():
            assert entry["preconditions"] == AttackKnowledgeGraph.METHOD_PRECONDITIONS[method]
            assert entry["reference_reason"].strip()


def test_ranking_draft_evidence_pins_resolve_and_pending_reasons_are_explicit():
    draft = _draft()
    sources = {source["source_id"]: source for source in draft["sources"]}
    report = ranking_draft.assess_draft(draft, root=REPOSITORY_ROOT)

    assert all(source["origin"] == "operator_fixture" for source in sources.values())
    assert not any(
        marker in str(source.get("path") or "")
        for source in sources.values()
        for marker in ("results/runs/", "remediation-2026-10-30", "full-2026-10-30")
    )
    for coordinate, entries in draft["scenarios"].items():
        for method, entry in entries.items():
            assert entry["evidence_refs"]
            for ref in entry["evidence_refs"]:
                resolved = ranking_draft.resolve_pointer(
                    sources[ref["source_id"]]["document"], ref["pointer"],
                )
                for key, expected in ref["expect"].items():
                    assert resolved[key] == expected

    for deferred in report["coverage"]["deferred"]:
        entry = draft["scenarios"][deferred["scenario"]][deferred["method"]]
        assert entry["reference_status"] == "pending"
        assert entry["reference_fit"] is None
        assert entry["reference_reason"].strip()
        assert entry.get("proposed_reference_fit") == 3
    assert {item["scenario"] for item in report["coverage"]["deferred"]} == {
        "access_control:low",
        "access_control:medium",
    }


def test_ranking_draft_missing_count_stays_pending_and_never_claims_freeze_readiness():
    draft = _draft()
    entry = draft["scenarios"]["sqli:low"]["sqli_union"]
    entry["reference_status"] = "pending"
    entry["reference_fit"] = None
    entry["planned_request_count"] = None
    entry["reference_reason"] = (
        "Independent fixture request count is not available for this scenario; "
        "keep pending rather than inventing a positive count for the runtime validator."
    )
    entry["evidence_refs"] = [
        ref for ref in entry["evidence_refs"] if "count" not in ref.get("roles", [])
    ]
    draft["draft_sha256"] = ranking_draft.draft_hash(draft)

    report = ranking_draft.assess_draft(draft, root=REPOSITORY_ROOT)

    assert report["coverage"]["complete"] is True
    assert report["coverage"]["pending_entries"] == 1
    assert any(
        item["scenario"] == "sqli:low" and item["method"] == "sqli_union"
        for item in report["coverage"]["pending"]
    )
    assert report["freeze_readiness"]["ready"] is False
    assert "pending_evidence:1" in report["freeze_readiness"]["blockers"]


def test_ranking_draft_invented_count_fails_evidence_cross_check():
    draft = _draft()
    entry = draft["scenarios"]["sqli:low"]["sqli_union"]
    entry["planned_request_count"] += 1
    draft["draft_sha256"] = ranking_draft.draft_hash(draft)

    with pytest.raises(ranking_draft.DraftValidationError, match="count claim does not match"):
        ranking_draft.assess_draft(draft, root=REPOSITORY_ROOT)


def test_ranking_draft_synthetic_source_cannot_confirm_a_reference():
    draft = _draft()
    source = next(
        item for item in draft["sources"]
        if item["source_id"] == "ranking-calibration-cells-2026-10-11"
    )
    source["origin"] = "offline_control"
    draft["draft_sha256"] = ranking_draft.draft_hash(draft)

    with pytest.raises(ranking_draft.DraftValidationError, match="cannot confirm"):
        ranking_draft.assess_draft(draft, root=REPOSITORY_ROOT)
