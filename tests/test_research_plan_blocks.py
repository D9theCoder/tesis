"""Declared-block planning controls: selection-only studies and plan integrity.

Every config, profile, oracle and provider below is synthetic and offline.  No
provider, DVWA, matrix runner or live request is touched; the runner-iteration
checks replace ``_run_block`` entirely.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from core.state import METHODS_BY_SURFACE
from evaluation import research_plan
from evaluation.research_plan import (
    BLOCKS,
    PRIMARY_REASONING_EFFORT,
    build_research_plan,
    load_research_config,
    verify_plan,
)
from tests.test_autoresearch_profile import _protocol_source, synthetic_profile

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
STUDY_PATH = REPOSITORY_ROOT / "config/research/autoresearch-primary-study-2026-10-31.json"
EPOCH = "autoresearch-primary-2026-10-31"
DEEPSEEK_PROFILE = "river-ai__deepseek-ai-deepseek-v4-1-flash-1017_15efb2abf693"
LUNA_PROFILE = "openai_codex_auth"


def _schedule() -> dict[str, Any]:
    return {
        "schedule_id": "offline-planner-control",
        "version": "prices.v1",
        "currency": "USD",
        "effective_at": "2026-09-01T00:00:00+00:00",
        "prices": {
            "offline/model": {"input_per_million": 1.0, "output_per_million": 2.0},
        },
    }


def _resolved_config(
    profile: dict[str, Any],
    *,
    deepseek_effort: str | None = PRIMARY_REASONING_EFFORT,
    luna_effort: str | None = PRIMARY_REASONING_EFFORT,
) -> SimpleNamespace:
    models = {
        DEEPSEEK_PROFILE: SimpleNamespace(
            provider="openai_compatible",
            model_name="deepseek-ai/DeepSeek-V4.1-Flash-1017",
            reasoning_effort=deepseek_effort,
        ),
        LUNA_PROFILE: SimpleNamespace(
            provider="openai_codex_auth",
            model_name="gpt-6-luna",
            reasoning_effort=luna_effort,
        ),
    }
    return SimpleNamespace(
        token_price_schedule=_schedule(),
        payload_mode="hybrid",
        scoring_profile=profile,
        scoring_oracles=[_protocol_source()],
        scoring_rubric_version="scoring.v4",
        scoring_mode="ai",
        fixture_id=profile["fixture_id"],
        protocol_version=profile["protocol_version"],
        candidate_budget=profile["candidate_budget"],
        scoring_policy_epoch={"epoch_id": EPOCH},
        models=models,
        providers=[DEEPSEEK_PROFILE, LUNA_PROFILE],
        provider=DEEPSEEK_PROFILE,
        levels=["low", "medium", "high"],
        surfaces=["sqli", "access_control", "brute_force"],
        evasion_enabled=True,
        evasion_mode="reactive",
    )


def _write_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "reasoning_catalog:\n"
        "  deepseek-ai/DeepSeek-V4.1-Flash-1017: [low, max]\n"
        "  gpt-6-luna: [low, max]\n",
        encoding="utf-8",
    )
    return config_path


def _study_document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(STUDY_PATH.read_text(encoding="utf-8"))
    document["fixture_restoration"] = None
    document.update(overrides)
    return document


def _write_study(tmp_path: Path, document: dict[str, Any]) -> Path:
    path = tmp_path / "study.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("filesystem cannot create a directory symlink")


@pytest.fixture
def offline(monkeypatch, tmp_path):
    monkeypatch.setattr(research_plan, "_repository_root", lambda _path: tmp_path)
    return tmp_path


def _build(monkeypatch, tmp_path, config_path, *, study=None, output_epoch=None,
           config=None):
    profile = synthetic_profile()
    monkeypatch.setattr(
        research_plan,
        "load_and_resolve_config",
        lambda **_kwargs: config or _resolved_config(profile),
    )
    study_path = study
    if study is not None:
        document = json.loads(Path(study).read_text(encoding="utf-8"))
        # The synthetic repository has no operator fixture documents; the
        # evidence-binding path is covered separately against real files.
        document["fixture_restoration"] = None
        study_path = _write_study(tmp_path, document)
    return build_research_plan(
        config_path=str(config_path),
        output_epoch=str(output_epoch or tmp_path / "results/runs" / EPOCH),
        epoch_id=EPOCH,
        research_config_path=str(study_path) if study_path else None,
    )


# --------------------------------------------------------------------------- #
# study contract
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    ("blocks", "match"),
    (
        ({}, "at least one execution block"),
        (
            {"forced": {"target_method": "per_method", "unit": "coverage"}},
            "must declare the selection block",
        ),
        (
            {"selection": {"target_method": "per_method", "unit": "x"}},
            "must declare target_method=None",
        ),
        (
            {
                "selection": {"target_method": None, "unit": "x"},
                "forced": {"target_method": None, "unit": "y"},
            },
            "must declare target_method='per_method'",
        ),
        (
            {
                "selection": {"target_method": None, "unit": "x"},
                "other": {"target_method": None, "unit": "z"},
            },
            "unknown execution blocks",
        ),
        (
            {"selection": {"unit": "missing target"}},
            "must declare target_method",
        ),
    ),
)
def test_study_rejects_forced_only_empty_or_malformed_blocks(
    tmp_path, blocks: dict[str, Any], match: str,
):
    path = _write_study(tmp_path, _study_document(blocks=blocks))

    with pytest.raises(ValueError, match=match):
        load_research_config(path)


@pytest.mark.parametrize(
    ("field", "values"),
    (
        ("levels", ["low", "low", "high"]),
        ("surfaces", ["sqli", "sqli", "brute_force"]),
    ),
)
def test_study_rejects_duplicate_axes(tmp_path, field, values):
    path = _write_study(tmp_path, _study_document(**{field: values}))

    with pytest.raises(ValueError, match="unique"):
        load_research_config(path)


def test_study_rejects_non_max_model_reasoning(tmp_path):
    document = _study_document()
    document["model_profiles"][0] = {
        **document["model_profiles"][0], "reasoning_effort": "low",
    }
    path = _write_study(tmp_path, document)

    with pytest.raises(ValueError, match=PRIMARY_REASONING_EFFORT):
        load_research_config(path)


@pytest.mark.parametrize("output_root", ("../runs/x", "/tmp/runs/x", "results/x", "results/runs"))
def test_study_rejects_unbounded_output_root(tmp_path, output_root):
    path = _write_study(tmp_path, _study_document(output_root=output_root))

    with pytest.raises(ValueError):
        load_research_config(path)


# --------------------------------------------------------------------------- #
# builder
# --------------------------------------------------------------------------- #

def test_selection_only_plan_emits_exactly_108_coordinates(monkeypatch, offline):
    config_path = _write_config(offline)

    plan = _build(monkeypatch, offline, config_path, study=STUDY_PATH)

    assert set(plan["blocks"]) == {"selection"}
    assert "forced" not in plan["blocks"]
    assert "forced" not in plan["planned_counts"]
    assert plan["planned_counts"] == {"selection": 108, "total": 108}
    assert plan["output_root"] == f"results/runs/{EPOCH}"
    rows = plan["blocks"]["selection"]
    assert len(rows) == 108
    assert len({row["coordinate_id"] for row in rows}) == 108
    assert [row["coordinate_index"] for row in rows] == list(range(108))
    assert {row["provider"] for row in rows} == {DEEPSEEK_PROFILE, LUNA_PROFILE}
    assert {row["reasoning_effort"] for row in rows} == {PRIMARY_REASONING_EFFORT}
    assert {row["target_method"] for row in rows} == {None}
    assert {row["status"] for row in rows} == {"planned"}
    assert {
        (row["surface"], row["security_level"], row["experiment_condition"])
        for row in rows
    } == {
        (surface, level, condition)
        for surface in ("sqli", "access_control", "brute_force")
        for level in ("low", "medium", "high")
        for condition in ("linear_hybrid", "akg_guided_hybrid")
    }
    assert plan["constraints"]["declared_axes"]["blocks"] == {"selection": None}
    assert plan["web_manifest"]["status"] == "emitted_at_run"

    verified = verify_plan(offline / "results/runs" / EPOCH / "research-plan.json")
    assert verified["plan_sha256"] == plan["plan_sha256"]
    assert verified["planned_counts"] == {"selection": 108, "total": 108}


def test_planned_model_identities_reach_offline_analysis(monkeypatch, offline):
    from evaluation.research_analysis import analyze_plan

    config_path = _write_config(offline)
    plan = _build(monkeypatch, offline, config_path, study=STUDY_PATH)
    empty_sources = offline / "empty-sources"
    empty_sources.mkdir()

    report = analyze_plan(
        plan, source_roots={"empty": empty_sources}, review_roots={},
    )

    assert len(report["observations"]) == 108
    assert {row["state"] for row in report["observations"]} == {"missing"}
    assert report["model_contrasts"]["n_models"] == 2
    assert report["model_contrasts"]["missing_model_identity"] == []
    assert report["model_contrasts"]["status_counts"]["analyzed"] == 0
    assert report["model_contrasts"]["status_counts"]["unsupported"] == 18


def test_default_plan_still_emits_both_blocks(monkeypatch, offline):
    config_path = _write_config(offline)
    profile = synthetic_profile()
    config = _resolved_config(profile)
    config.providers = [DEEPSEEK_PROFILE]
    config.provider = DEEPSEEK_PROFILE

    plan = _build(
        monkeypatch, offline, config_path,
        output_epoch=offline / "default-epoch", config=config,
    )

    expected_forced = (
        sum(len(methods) for methods in METHODS_BY_SURFACE.values())
        * 3 * 2 * 3
    )
    assert set(plan["blocks"]) == set(BLOCKS)
    assert plan["planned_counts"] == {
        "selection": 54,
        "forced": expected_forced,
        "total": 54 + expected_forced,
    }
    assert plan["output_root"] is None


@pytest.mark.parametrize(
    ("attribute", "values"),
    (
        ("levels", ["low", "low", "high"]),
        ("surfaces", ["sqli", "sqli", "brute_force"]),
    ),
)
def test_build_rejects_duplicate_configured_axes(monkeypatch, offline, attribute, values):
    config_path = _write_config(offline)
    config = _resolved_config(synthetic_profile())
    setattr(config, attribute, values)

    with pytest.raises(ValueError, match="unique"):
        _build(
            monkeypatch, offline, config_path,
            output_epoch=offline / "default-epoch", config=config,
        )


def test_build_rejects_configured_reasoning_mismatch(monkeypatch, offline):
    config_path = _write_config(offline)
    profile = synthetic_profile()
    config = _resolved_config(profile, luna_effort="low")

    with pytest.raises(ValueError, match="reasoning_effort"):
        _build(monkeypatch, offline, config_path, study=STUDY_PATH, config=config)


def test_build_rejects_configured_model_or_provider_mismatch(monkeypatch, offline):
    config_path = _write_config(offline)
    profile = synthetic_profile()
    config = _resolved_config(profile)
    config.models[LUNA_PROFILE].model_name = "gpt-5.6"

    with pytest.raises(ValueError, match="configured with model"):
        _build(monkeypatch, offline, config_path, study=STUDY_PATH, config=config)

    config = _resolved_config(profile)
    config.models[LUNA_PROFILE].provider = "openai_compatible"
    with pytest.raises(ValueError, match="configured with provider"):
        _build(monkeypatch, offline, config_path, study=STUDY_PATH, config=config)


def test_build_rejects_output_epoch_outside_declared_root(monkeypatch, offline):
    config_path = _write_config(offline)

    with pytest.raises(ValueError, match="declared run root"):
        _build(
            monkeypatch, offline, config_path, study=STUDY_PATH,
            output_epoch=offline / "results/runs/elsewhere",
        )


def test_build_rejects_symlinked_results_escape(monkeypatch, offline):
    config_path = _write_config(offline)
    outside = offline.parent / f"{offline.name}-outside-results"
    outside.mkdir()
    (offline / "results").mkdir()
    _symlink_or_skip(offline / "results/runs", outside)

    with pytest.raises(ValueError, match="repository root"):
        _build(monkeypatch, offline, config_path, study=STUDY_PATH)


def test_build_rejects_symlinked_epoch_escape(monkeypatch, offline):
    config_path = _write_config(offline)
    outside = offline.parent / f"{offline.name}-outside-epoch"
    outside.mkdir()
    (offline / "results/runs").mkdir(parents=True)
    _symlink_or_skip(offline / "results/runs" / EPOCH, outside)

    with pytest.raises(ValueError, match="repository root"):
        _build(monkeypatch, offline, config_path, study=STUDY_PATH)


# --------------------------------------------------------------------------- #
# plan verification
# --------------------------------------------------------------------------- #

def _rehash(path: Path) -> None:
    plan = json.loads(path.read_text(encoding="utf-8"))
    plan["plan_sha256"] = research_plan._json_hash(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    )
    path.write_text(json.dumps(plan), encoding="utf-8")


def test_verify_rejects_missing_and_duplicate_coordinates(monkeypatch, offline):
    config_path = _write_config(offline)
    _build(monkeypatch, offline, config_path, study=STUDY_PATH)
    plan_path = offline / "results/runs" / EPOCH / "research-plan.json"
    original = json.loads(plan_path.read_text(encoding="utf-8"))

    missing = copy.deepcopy(original)
    missing["blocks"]["selection"].pop()
    missing["planned_counts"] = {"selection": 107, "total": 107}
    plan_path.write_text(json.dumps(missing), encoding="utf-8")
    _rehash(plan_path)
    with pytest.raises(ValueError, match="declared axes"):
        verify_plan(plan_path)

    duplicate = copy.deepcopy(original)
    duplicate["blocks"]["selection"].append(
        copy.deepcopy(duplicate["blocks"]["selection"][0])
    )
    duplicate["planned_counts"] = {"selection": 109, "total": 109}
    plan_path.write_text(json.dumps(duplicate), encoding="utf-8")
    _rehash(plan_path)
    with pytest.raises(ValueError, match="duplicates a coordinate"):
        verify_plan(plan_path)


def test_verify_rejects_forced_only_plan(monkeypatch, offline):
    config_path = _write_config(offline)
    _build(monkeypatch, offline, config_path, study=STUDY_PATH)
    plan_path = offline / "results/runs" / EPOCH / "research-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["blocks"] = {"forced": plan["blocks"]["selection"]}
    plan["planned_counts"] = {"forced": 108, "total": 108}
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    _rehash(plan_path)

    with pytest.raises(ValueError, match="must declare the selection block"):
        verify_plan(plan_path)


def test_verify_accepts_legacy_plan_without_declared_axes(monkeypatch, offline):
    config_path = _write_config(offline)
    profile = synthetic_profile()
    config = _resolved_config(profile)
    config.providers = [DEEPSEEK_PROFILE]
    config.provider = DEEPSEEK_PROFILE
    _build(
        monkeypatch, offline, config_path,
        output_epoch=offline / "default-epoch", config=config,
    )
    plan_path = offline / "default-epoch" / "research-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["constraints"].pop("declared_axes")
    plan["constraints"].pop("model_profiles")
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    _rehash(plan_path)

    verified = verify_plan(plan_path)

    assert set(verified["blocks"]) == set(BLOCKS)


def test_verify_rejects_changed_research_config(monkeypatch, offline):
    config_path = _write_config(offline)
    study = _write_study(offline, _study_document())
    _build(monkeypatch, offline, config_path, study=study)
    document = json.loads(study.read_text(encoding="utf-8"))
    document["payload_mode"] = "static_only"
    study.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="research config declaration changed"):
        verify_plan(offline / "results/runs" / EPOCH / "research-plan.json")


# --------------------------------------------------------------------------- #
# runner boundaries (never executes a block)
# --------------------------------------------------------------------------- #

def _summary_plan(block_names: list[str]) -> dict[str, Any]:
    return {
        "epoch_id": "offline-run",
        "blocks": {name: [{"block": name}] for name in block_names},
        "planned_counts": {**{name: 1 for name in block_names}, "total": len(block_names)},
        "constraints": {"scoring_rubric_version": "scoring.v4"},
        "output_root": None,
    }


@pytest.mark.parametrize("block_names", (["selection"], ["selection", "forced"]))
def test_runner_executes_exactly_the_declared_blocks(monkeypatch, tmp_path, block_names):
    plan = _summary_plan(block_names)
    calls: list[str] = []
    epoch = tmp_path / "epoch"
    epoch.mkdir()

    def fake_block(_plan, block, *, output_epoch):
        calls.append(block)
        reconciliation = {
            "coordinates": [],
            "missing": [],
            "extra": [],
            "duplicates": [],
        }
        path = Path(output_epoch) / block / "coordinate-reconciliation.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(reconciliation), encoding="utf-8")
        receipt = {
            "observed": 0,
            "coordinate_reconciliation_path": str(path),
        }
        return receipt, [], [], None

    monkeypatch.setattr(research_plan, "verify_plan", lambda _path: plan)
    monkeypatch.setattr(research_plan, "_run_block", fake_block)
    monkeypatch.setattr(
        research_plan, "_write_epoch_manifest",
        lambda _root, **_kwargs: epoch / "experiment.manifest.json",
    )
    (epoch / "experiment.manifest.json").write_text("{}", encoding="utf-8")

    summary = research_plan.run_research_plan(
        tmp_path / "plan.json", output_epoch=str(epoch),
    )

    assert calls == block_names
    assert summary["status"] == "completed"
    assert (epoch / "research-run-summary.json").is_file()


def test_runner_rejects_forced_only_before_any_block(monkeypatch, tmp_path):
    plan = _summary_plan(["forced"])
    calls: list[str] = []
    monkeypatch.setattr(research_plan, "verify_plan", lambda _path: plan)
    monkeypatch.setattr(
        research_plan,
        "_run_block",
        lambda _plan, block, *, output_epoch: calls.append(block),
    )

    with pytest.raises(ValueError, match="must declare the selection block"):
        research_plan.run_research_plan(
            tmp_path / "plan.json", output_epoch=str(tmp_path / "epoch"),
        )

    assert calls == []
    assert not (tmp_path / "epoch" / "research-run-summary.json").exists()


def test_runner_rejects_symlinked_plan_output_root(monkeypatch, offline):
    config_path = _write_config(offline)
    outside = offline.parent / f"{offline.name}-outside-run"
    outside.mkdir()
    (offline / "results").mkdir()
    _symlink_or_skip(offline / "results/runs", outside)
    plan = {
        "epoch_id": "offline-run",
        "config_path": str(config_path),
        "blocks": {
            "selection": [{"block": "selection"}],
            "forced": [{"block": "forced"}],
        },
        "planned_counts": {"selection": 1, "forced": 1, "total": 2},
        "constraints": {"scoring_rubric_version": "scoring.v4"},
        "output_root": f"results/runs/{EPOCH}",
    }
    calls: list[str] = []
    monkeypatch.setattr(research_plan, "verify_plan", lambda _path: plan)
    monkeypatch.setattr(
        research_plan,
        "_run_block",
        lambda _plan, block, *, output_epoch: calls.append(block) or {"observed": 1},
    )

    with pytest.raises(ValueError, match="repository root"):
        research_plan.run_research_plan(
            offline / "plan.json",
            output_epoch=str(offline / "results/runs" / EPOCH),
        )

    assert calls == []

