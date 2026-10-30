"""Behavior regressions for the peer-correction release (slice A study modules).

Covers grader-mode separation in paired pooling, complete-identity matching,
duplicate/ambiguity detection, source/guardrail/price identity, prerequisite
reporting, declaration/policy-epoch rehashing, and truthful partial-block
receipts.  No provider, HTTP, or DVWA call is made and no check is executed.
"""
from pathlib import Path


import evaluation.research_analysis as analysis
import evaluation.research_plan as plan_mod



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


def test_missing_source_identity_is_explicit(monkeypatch):
    coordinates = [_coordinate("linear_hybrid", 0)]
    entry, _receipt_doc = _entry("linear_hybrid", 0, source_hash=None)
    result = _analyze(monkeypatch, [entry], _plan(coordinates, source_hash="h"), documents={})
    assert "missing_source_identity" in result["exclusions"]


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
