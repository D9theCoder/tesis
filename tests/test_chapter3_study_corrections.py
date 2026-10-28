"""Behavior regressions for the peer-correction release (slice A study modules).

Covers grader-mode separation in paired pooling, complete-identity matching,
duplicate/ambiguity detection, source/guardrail/price identity, prerequisite
reporting, declaration/policy-epoch rehashing, and truthful partial-block
receipts.  No provider, HTTP, or DVWA call is made and no check is executed.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import evaluation.research_analysis as analysis
import evaluation.research_plan as plan_mod
from evaluation.research_plan import build_research_plan, verify_plan

REPO = Path(__file__).resolve().parents[1]
STUDY_CONFIG = REPO / "config" / "research" / "chapter3_study.json"


def _stub_config(**overrides):
    base = dict(
        target_url="http://172.19.48.1/dvwa",
        payload_mode="hybrid",
        scoring_profile={
            "profile_id": "profile", "version": "v1",
            "fixture_id": "fx", "protocol_version": "pv", "candidate_budget": 3,
            "frozen_at": "2026-10-28T00:00:00+00:00",
            "sources": [{"origin": "operator_fixture"}], "sha256": "profile",
        },
        scoring_oracles=[{"source_id": "session", "origin": "operator_fixture"}],
        scoring_rubric_version="scoring.v4",
        fixture_id="fx", protocol_version="pv", candidate_budget=3,
        scoring_policy_epoch={"epoch_id": "e1", "frozen_at": "2026-10-28T00:00:00+00:00"},
        token_price_schedule={"effective_at": "2026-10-28T00:00:00+00:00", "prices": {}},
        providers=["profile-a"], provider="profile-a", levels=["low"], surfaces=["sqli"],
        evasion_enabled=True, evasion_mode="reactive", iterations=1, stop_policy="impact",
        coverage_target=0.7, enriched_reporting=False, diagnose=False,
        evasion_max_retries=1, evasion_cooldown_threshold=1, models={},
        llm_max_concurrency=1, llm_cache=False,
        llm_runtime=SimpleNamespace(roles={}), scoring_mode="human", scoring_evaluator={},
    )
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture()
def plan_env(monkeypatch, tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("target_url: http://172.19.48.1/dvwa\n", encoding="utf-8")
    monkeypatch.setattr(plan_mod, "load_and_resolve_config", lambda **kwargs: _stub_config())
    monkeypatch.setattr(plan_mod, "validate_evidence_config", lambda *args, **kwargs: None)
    monkeypatch.setattr(plan_mod, "_repository_root", lambda path: tmp_path)
    monkeypatch.setattr(plan_mod, "source_tree_hashes", lambda root: {"core/x.py": "h"})
    return config_path


def _build_plan(config_path, tmp_path, *, research_config=None, epoch_dir="epoch"):
    return build_research_plan(
        config_path=str(config_path),
        output_epoch=str(tmp_path / epoch_dir),
        epoch_id="e1",
        repeats=3,
        providers=["profile-a"],
        research_config_path=research_config,
    )


def _declaration(tmp_path, **overrides):
    document = json.loads(STUDY_CONFIG.read_bytes())
    document.update({"epoch_id": "e1"})
    document.update(overrides)
    path = tmp_path / "declaration.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_verify_plan_rehashes_declaration_and_policy_epoch(plan_env, tmp_path, monkeypatch):
    declaration = _declaration(tmp_path)
    plan_path = tmp_path / "epoch" / "research-plan.json"
    _build_plan(plan_env, tmp_path, research_config=str(declaration))
    assert verify_plan(plan_path)["research_config"]["sha256"]

    document = json.loads(declaration.read_bytes())
    document["repeats"] = 4
    declaration.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="research config declaration changed"):
        verify_plan(plan_path)

    declaration_ok = _declaration(tmp_path)
    second = _build_plan(plan_env, tmp_path, research_config=str(declaration_ok), epoch_dir="epoch2")
    assert second["plan_sha256"]
    monkeypatch.setattr(
        plan_mod, "load_and_resolve_config",
        lambda **kwargs: _stub_config(scoring_policy_epoch={
            "epoch_id": "e1", "frozen_at": "2026-10-29T00:00:00+00:00",
        }),
    )
    with pytest.raises(ValueError, match="scoring policy epoch changed"):
        verify_plan(tmp_path / "epoch2" / "research-plan.json")


def test_plan_reports_missing_fixture_restoration_prerequisite(plan_env, tmp_path):
    plan = _build_plan(plan_env, tmp_path)
    prerequisites = plan["prerequisites"]
    assert prerequisites[0]["name"] == "fixture_restoration_attestation"
    assert prerequisites[0]["status"] == "missing_external_input"
    assert prerequisites[0]["reason"] == "fixture_restoration_attestation_missing"
    assert plan["constraints"]["fixture_restoration"] is None


def test_block_failure_writes_truthful_receipt_and_keeps_attempt(monkeypatch, tmp_path):
    import evaluation.multi_llm_runner as matrix

    def explode(**_kwargs):
        raise RuntimeError("matrix exploded")

    monkeypatch.setattr(matrix, "run_provider_matrix", explode)
    monkeypatch.setattr(plan_mod, "load_and_resolve_config", lambda **kwargs: _stub_config())
    plan = {
        "config_path": str(tmp_path / "config.yaml"),
        "epoch_id": "e1",
        "source_hashes_sha256": "h",
        "constraints": {"repeats": 3},
        "blocks": {"selection": [{
            "provider": "profile-a", "surface": "sqli", "security_level": "low",
            "guardrail_retry_enabled": True, "guardrail_handling": "reactive",
        }]},
    }
    (tmp_path / "config.yaml").write_text("target_url: http://x\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="matrix exploded"):
        plan_mod._run_block(plan, "selection", output_epoch=tmp_path / "epoch")

    receipt = json.loads((tmp_path / "epoch" / "selection" / "block-run-receipt.json").read_bytes())
    assert receipt["status"] == "failed"
    assert receipt["aggregate_path"] is None
    assert receipt["aggregate_sha256"] is None
    assert "RuntimeError" in receipt["error"]
    # A rerun must not overwrite the retained attempt.
    with pytest.raises(ValueError, match="already has an attempt"):
        plan_mod._run_block(plan, "selection", output_epoch=tmp_path / "epoch")


# ------------------------------ analysis ---------------------------------- #

class FakeEntry:
    def __init__(self, record, sha):
        self.record = record
        self.source = {"root_id": "r", "path": f"{sha}.json", "sha256": sha}
        self.path = Path(f"/fake/{sha}.json")
        self.ambiguous = False


def _receipt(condition, mode, *, base=2.0):
    vector = {"Smethod": base, "Spayload": base, "Sexploit": base, "Schain": base, "Soutput": base}
    return {
        "artifact_type": "thesis_score_receipt", "status": "final", "scoring_mode": mode,
        "components": vector,
        "Srun_final": round(sum(0.2 * vector[k] for k in ("Smethod", "Spayload", "Soutput"))
                            + 0.3 * vector["Sexploit"] + 0.1 * vector["Schain"], 4),
        "rubric_version": "scoring.v4", "scoring_rule_sha256": "a" * 64,
        "metrics_epoch": "scoring-policy.v4.2",
        "config": {
            "experiment_condition": condition,
            "fixture_id": "fx",
            "protocol_version": "pv",
            "candidate_budget": 3,
            "scoring_profile": {"sha256": "profile"},
            "guardrail_retry_enabled": True,
            "guardrail_handling": "reactive",
            "token_price_schedule": {"effective_at": "2026-10-28T00:00:00+00:00", "prices": {}},
        },
    }


def _reviews(receipt, modes=("human",)):
    result = {}
    for mode in ("human", "ai"):
        if mode in modes:
            result[mode] = {
                "status": "final", "components": receipt["components"],
                "Srun_final": receipt["Srun_final"], "rubric_version": receipt["rubric_version"],
                "scoring_rule_sha256": receipt["scoring_rule_sha256"], "scoring_mode": mode,
                "metrics_epoch": receipt["metrics_epoch"],
                "receipt": {"root_id": "r", "path": f"{id(receipt)}-{mode}.json"},
            }
        else:
            result[mode] = {"status": "missing", "reason": "missing_review",
                            "components": None, "Srun_final": None, "receipt": None}
    return result


def _record(condition, repeat, *, mode="human", base=2.0, epoch="e1", fixture="fx", protocol="pv",
            guardrail=(True, "reactive"), price="price", source_hash="h"):
    receipt = _receipt(condition, mode, base=base)
    return receipt, {
        "execution_id": f"run-{condition}-{repeat}-{base}",
        "run_id": f"runid-{condition}-{repeat}-{base}",
        "execution_status": "completed",
        "provider": "profile-a", "model": "model-a", "surface": "sqli",
        "security_level": "low", "payload_mode": "hybrid",
        "experiment_condition": condition, "experiment_block": "selection",
        "target_method": None, "repeat_index": repeat,
        "policy_epoch": {"epoch_id": epoch, "source_hashes_sha256": source_hash},
        "readiness": {"status": "ready", "requested_level": "low", "observed_level": "low",
                      "fixture_restoration": {"equivalence": "attested"}},
        "config": {
            "provider": "profile-a", "model": "model-a", "surface": "sqli",
            "security_level": "low", "payload_mode": "hybrid",
            "experiment_condition": condition, "experiment_block": "selection",
            "target_method": None, "repeat_index": repeat,
            "fixture_id": fixture, "protocol_version": protocol, "candidate_budget": 3,
            "scoring_profile": {"sha256": "profile"},
            "guardrail_retry_enabled": guardrail[0], "guardrail_handling": guardrail[1],
            "token_price_schedule": {"effective_at": "2026-10-28T00:00:00+00:00", "prices": {}},
        },
        "_reviews": _reviews(receipt, modes=(mode,)),
        "_price": price,
    }


def _coordinate(condition, repeat, *, epoch="e1", guardrail=(True, "reactive")):
    row = {
        "coordinate_index": repeat, "block": "selection", "provider": "profile-a",
        "surface": "sqli", "security_level": "low", "payload_mode": "hybrid",
        "experiment_condition": condition, "target_method": None, "repeat_index": repeat,
        "candidate_budget": 3, "fixture_id": "fx", "protocol_version": "pv",
        "policy_epoch_id": epoch, "status": "planned",
        "guardrail_retry_enabled": guardrail[0], "guardrail_handling": guardrail[1],
    }
    row["coordinate_id"] = plan_mod._coordinate_id(row)
    return row


def _price_hash():
    from evaluation.scoring_evidence import evidence_hash
    return evidence_hash({"effective_at": "2026-10-28T00:00:00+00:00", "prices": {}})


def _plan(coordinates, *, constraints=None, source_hash="h", prerequisites=None):
    from evaluation.scoring_evidence import evidence_hash
    base_constraints = {
        "primary_conditions": list(analysis.PRIMARY_CONDITIONS), "payload_mode": "hybrid",
        "repeats": 3, "fixture_id": "fx", "protocol_version": "pv", "candidate_budget": 3,
        "scoring_rubric_version": "scoring.v4", "scoring_profile_sha256": "profile",
        "token_price_schedule_sha256": _price_hash(),
        "guardrail_retry_enabled": True, "guardrail_handling": "reactive",
    }
    base_constraints.update(constraints or {})
    return {
        "artifact_type": "chapter3_research_plan", "plan_version": "chapter3-research-plan.v2",
        "plan_sha256": "p" * 64, "epoch_id": "e1", "policy_versions": {},
        "policy_epoch": {"epoch_id": "e1"},
        "source_hashes_sha256": source_hash,
        "prerequisites": prerequisites or [],
        "constraints": base_constraints,
        "blocks": {"selection": coordinates, "forced": []},
    }


def _analyze(monkeypatch, entries, plan, *, documents, compare=None):
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
    monkeypatch.setattr(analysis, "discover_reviews", lambda catalog, entry: entry.record["_reviews"])
    monkeypatch.setattr(analysis, "pair_compatibility_key", lambda document: "key")
    monkeypatch.setattr(analysis, "pair_compatibility_mismatches", lambda left, right: [])
    monkeypatch.setattr(analysis, "aggregate_research_metrics",
                        lambda summaries: {"n": len(summaries)})
    monkeypatch.setattr(analysis, "compare_receipts",
                        compare or (lambda paths, *, planned_repeats=None:
                                    {"groups": [{"scoring_mode": "human", "n_final": len(paths)}]}))
    return analysis.analyze_plan(plan, source_roots={"main": "/fake-root"}, review_roots={})


def _entry(condition, repeat, **overrides):
    receipt, record = _record(condition, repeat, **overrides)
    return FakeEntry(record, sha=f"{condition}-{repeat}-{record['execution_id']}"), receipt


def _documents(receipts):
    documents = {}
    for _entry_obj, receipt in receipts:
        for _mode, workflow in _reviews(receipt, modes=(receipt["scoring_mode"],)).items():
            binding = workflow.get("receipt")
            if isinstance(binding, dict):
                documents[binding["path"]] = receipt
    return documents


def test_paired_pooling_separates_grader_modes(monkeypatch):
    coordinates, entries, receipts = [], [], []
    for repeat in range(3):
        for condition, base in (("linear_hybrid", 3.0), ("akg_guided_hybrid", 1.0)):
            coordinates.append(_coordinate(condition, repeat))
            entry, receipt = _entry(condition, repeat, base=base)
            entries.append(entry)
            receipts.append((entry, receipt))
    result = _analyze(monkeypatch, entries, _plan(coordinates), documents=_documents(receipts))

    paired = result["paired"]
    assert len(paired["results"]) == 1
    assert paired["results"][0]["scoring_mode"] == "human"
    assert paired["results"][0]["n_pairs"] == 3
    assert paired["n_pair_units"] == 3
    assert paired["grader_mode_pooling"].startswith("separate analyses")


def test_ambiguous_matching_is_not_assessed(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", 0)]
    entries = [_entry("linear_hybrid", 0)[0], _entry("linear_hybrid", 0)[0]]
    result = _analyze(monkeypatch, entries, _plan(coordinates), documents={})

    assert result["status_counts"]["ambiguous_match"] == 1
    assert result["groups"] == []


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"epoch": "e2"}, "no_execution_artifact"),
        ({"fixture": "other"}, "no_execution_artifact"),
        ({"protocol": "other"}, "no_execution_artifact"),
        ({"guardrail": (False, "reactive")}, "no_execution_artifact"),
        ({"source_hash": "other"}, "source_hash_mismatch"),
    ],
)
def test_matching_enforces_full_identity(monkeypatch, overrides, reason):
    coordinates = [_coordinate("linear_hybrid", 0)]
    entry, _receipt_doc = _entry("linear_hybrid", 0, **overrides)
    plan = _plan(coordinates, source_hash="h")
    result = _analyze(monkeypatch, [entry], plan, documents={})

    assert result["status_counts"]["final"] == 0
    assert any(key == reason for key in result["exclusions"])


def test_missing_source_identity_is_explicit(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", 0)]
    entry, _receipt_doc = _entry("linear_hybrid", 0, source_hash=None)
    result = _analyze(monkeypatch, [entry], _plan(coordinates, source_hash="h"), documents={})
    assert "missing_source_identity" in result["exclusions"]


def test_plan_prerequisites_are_echoed(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", 0)]
    entry, receipt = _entry("linear_hybrid", 0)
    prerequisites = [{"name": "fixture_restoration_attestation",
                      "status": "missing_external_input", "reason": "fixture_restoration_attestation_missing"}]
    result = _analyze(
        monkeypatch, [entry], _plan(coordinates, prerequisites=prerequisites),
        documents=_documents([(entry, receipt)]),
    )
    assert result["prerequisites"] == prerequisites


def test_paired_fixture_restoration_gate_stays_strict(monkeypatch):
    coordinates, entries, receipts = [], [], []
    for repeat in range(2):
        for condition, base in (("linear_hybrid", 3.0), ("akg_guided_hybrid", 1.0)):
            coordinates.append(_coordinate(condition, repeat))
            entry, receipt = _entry(condition, repeat, base=base)
            entry.record["readiness"]["fixture_restoration"] = {"equivalence": "unknown"}
            entries.append(entry)
            receipts.append((entry, receipt))
    result = _analyze(monkeypatch, entries, _plan(coordinates), documents=_documents(receipts))

    assert result["paired"]["results"] == []
    assert {row["reason"] for row in result["paired"]["unmatched"]} == {"fixture_restoration_not_attested"}

def _fixture_document(source_hash: str, level: str = "low") -> dict:
    return {
        "policy_version": "fixture-restoration.v1",
        "evidence_id": f"op-restoration-{level}",
        "kind": "operator_attestation",
        "fixture_id": "fx",
        "protocol_version": "pv",
        "security_level": level,
        "epoch_id": "e1",
        "source_hashes_sha256": source_hash,
        "restoration": "reset",
        "authorized_protocol": "dvwa-contained-reset.v1",
        "evidence_refs": [f"operator-log:{level}"],
        "evidence_sha256": "a" * 64,
        "observed_at": "2026-10-28T00:00:00+00:00",
        "operator": "fixture-operator",
    }


def test_plan_freezes_raw_fixture_documents_and_provenance_outside(
    plan_env, tmp_path, monkeypatch
):
    source_hash = plan_mod._json_hash({"core/x.py": "h"})
    document = _fixture_document(source_hash)
    declaration = _declaration(tmp_path, fixture_restoration=document)
    plan = _build_plan(plan_env, tmp_path, research_config=str(declaration))

    restoration = plan["constraints"]["fixture_restoration"]
    frozen = restoration["by_level"]["low"]
    # The forwarded evidence is the exact closed operator document: no
    # freeze-time metadata may look like attested content.
    assert set(frozen) == set(plan_mod.FIXTURE_RESTORATION_REQUIRED_KEYS)
    provenance = restoration["provenance"]["low"]
    assert provenance["identity_sha256"] and provenance["source_path"] is None
    assert provenance["sha256"] is None

    from foundation.readiness import validate_fixture_restoration_evidence

    validate_fixture_restoration_evidence(
        frozen,
        fixture_id="fx",
        protocol_version="pv",
        security_level="low",
        epoch_id="e1",
        source_hashes_sha256=source_hash,
    )
    tampered = {**frozen, "identity_sha256": provenance["identity_sha256"]}
    with pytest.raises(ValueError, match="unknown keys"):
        validate_fixture_restoration_evidence(
            tampered,
            fixture_id="fx",
            protocol_version="pv",
            security_level="low",
            epoch_id="e1",
            source_hashes_sha256=source_hash,
        )
    assert verify_plan(tmp_path / "epoch" / "research-plan.json")["plan_sha256"]

    import evaluation.multi_llm_runner as matrix

    captured: dict = {}

    def fake_matrix(**kwargs):
        captured.update(kwargs)
        root = Path(kwargs["output_dir"])
        (root / f"{kwargs['execution_id']}.matrix.json").write_text("{}", encoding="utf-8")
        return [], {"execution_id": kwargs["execution_id"]}

    monkeypatch.setattr(matrix, "run_provider_matrix", fake_matrix)
    receipt = plan_mod._run_block(plan, "selection", output_epoch=tmp_path / "run-epoch")
    assert receipt["status"] == "completed"
    assert captured["fixture_restoration_evidence"] == {"low": frozen}
    assert captured["payload_policy_snapshot"]["snapshot_sha256"] == (
        plan["payload_policy_snapshot"]["snapshot_sha256"]
    )

