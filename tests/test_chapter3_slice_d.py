"""Slice D behavior controls: modes, blocks, epoch metadata, telemetry.

Offline only: no HTTP, provider, graph-node, or experiment execution.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.payload_policy import PAYLOAD_MODE_LABELS, PAYLOAD_MODES, STRICT_PAYLOAD_MODES
from core.scorer import build_score_report
from evaluation.multi_llm_runner import _build_matrix_aggregate
from evaluation.runner import _payload_generation_failure, run_single_engagement
from llm.cache_metrics import cache_performance_summary
from tesis.artifact_repository import ArtifactRepository
from tesis.config_fields import field_choice_label, get_field_spec, payload_mode_label
from tesis.config_loader import ConfigError, _validate_token_price_schedule, load_and_resolve_config
from tesis.model_config import EXPERIMENT_BLOCKS, PAYLOAD_MODES as MODEL_PAYLOAD_MODES


def test_payload_modes_include_template_and_labels() -> None:
    assert set(PAYLOAD_MODES) == {"static_only", "hybrid", "llm_mutation_only", "llm_template"}
    assert MODEL_PAYLOAD_MODES == frozenset(PAYLOAD_MODES)
    assert STRICT_PAYLOAD_MODES == {"llm_mutation_only", "llm_template"}
    assert PAYLOAD_MODE_LABELS["llm_template"] == "Template"
    assert payload_mode_label("llm_template") == "Template"
    assert EXPERIMENT_BLOCKS == ("selection", "forced")


def test_config_field_labels_and_choices_include_template() -> None:
    spec = get_field_spec("payload_mode")
    assert "llm_template" in spec.choice_values()
    assert field_choice_label(spec, "llm_template") == "Template"
    matrix = get_field_spec("payload_modes")
    assert "llm_template" in matrix.choice_values()
    assert field_choice_label(matrix, "llm_template") == "Template"


def test_owner_config_defaults_are_not_changed() -> None:
    config = load_and_resolve_config(config_path="config.yaml", cli_args={})
    assert config.payload_mode == "static_only"
    assert config.repeats == 1
    assert config.scoring_profile == {}
    assert config.token_price_schedule == {}
    assert config.scoring_policy_epoch == {}


def test_token_price_schedule_uses_canonical_validator() -> None:
    good = {
        "schedule_id": "unit-test", "version": "1", "effective_at": "2026-10-28T00:00:00+00:00",
        "currency": "USD",
        "prices": {"provider/model": {"input_per_million": 1.0, "output_per_million": 2.0,
                                      "cached_input_per_million": 0.5}},
    }
    _validate_token_price_schedule(good)
    bad = json.loads(json.dumps(good))
    bad["currency"] = "US"
    with pytest.raises(ConfigError):
        _validate_token_price_schedule(bad)


def test_runner_refuses_block_target_mismatch_before_execution() -> None:
    common = dict(
        target_url="http://localhost/dvwa", security_level="low",
        llm_provider="openai", surface="sqli", payload_mode="static_only",
    )
    with pytest.raises(ValueError, match="selection-block"):
        run_single_engagement(**common, experiment_block="selection", target_method="sqli_error")
    with pytest.raises(ValueError, match="forced-method"):
        run_single_engagement(**common, experiment_block="forced", target_method=None)
    with pytest.raises(ValueError, match="experiment_block"):
        run_single_engagement(**common, experiment_block="unknown")


def test_payload_failure_dispatch_separates_provider_from_strict() -> None:
    provider = _payload_generation_failure({"fallback_events": [{
        "event": "payload_generation.provider_failure", "reason": "llm_error",
        "method": "sqli_error", "visit_id": "v1", "payload_mode": "hybrid",
    }]})
    assert provider is not None and provider["reason"] == "llm_error"
    strict = _payload_generation_failure({"fallback_events": [{
        "event": "payload_generation.strict_no_candidate", "reason": "guardrail_refusal",
        "method": "sqli_error", "visit_id": "v1", "payload_mode": "llm_mutation_only",
    }]})
    assert strict is None
    template = _payload_generation_failure({"fallback_events": [{
        "event": "payload_generation.template_unavailable", "reason": "template_unavailable",
        "method": "bf_dictionary", "visit_id": "v1", "payload_mode": "llm_template",
    }]})
    assert template is None


def test_scorer_counts_only_attempted_methods() -> None:
    state = {
        "attempted_agents": ["sqli_error"],
        "scores": {"sqli_error": 4},
        "method_scores": {"sqli_error": 4},
        "payload_scores": {},
        "selected_method": "sqli_error",
        "chain_history": [],
        "current_chain": [],
        "confirmed_vulns": [],
        "achieved_outcomes": [],
        "guardrail_activations": [],
        "payload_validation_results": {},
        "payload_provenance": {},
        "tried_payloads": {},
        "iteration_count": 1,
    }
    report = build_score_report(state)
    assert report.summary.total_modules_tested == 1
    assert report.summary.score_distribution[4] == 1
    assert sum(report.summary.score_distribution.values()) == 1


def test_environment_no_call_keeps_readiness_and_quarantine_outcomes() -> None:
    from evaluation.runner import _environment_no_call_outcome

    assert _environment_no_call_outcome({"llm_skip_reason": "READINESS_NOT_READY"})
    assert _environment_no_call_outcome({"llm_skip_reason": "RUN_QUARANTINED"})
    assert _environment_no_call_outcome({"execution_status": "failed"})
    assert _environment_no_call_outcome({"security_outcome": "fixture_limited"})
    assert not _environment_no_call_outcome({
        "llm_skip_reason": "NO_VIABLE_METHODS",
        "execution_status": "completed",
        "security_outcome": "unconfirmed",
    })


def test_request_failure_is_scoped_to_final_candidate_execution() -> None:
    from evaluation.runner import _terminal_incomplete_reason

    state = {
        "selected_method": "sqli_error",
        "selected_visit_id": "sqli_error:visit:2",
        "task_result": "SUCCESS",
        "execution_status": "completed",
        "response_evidence": [
            {"method": "sqli_error", "visit_id": "sqli_error:visit:1",
             "identity_kind": "candidate", "stage": "exploit", "status_code": None},
            {"method": "sqli_error", "visit_id": "sqli_error:visit:2",
             "identity_kind": "derived_control", "stage": "probe", "status_code": None},
        ],
    }
    assert _terminal_incomplete_reason(state) is None
    state["response_evidence"].append({
        "method": "sqli_error", "visit_id": "sqli_error:visit:2",
        "identity_kind": "candidate", "stage": "exploit", "status_code": None,
    })
    assert _terminal_incomplete_reason(state) == "TARGET_REQUEST_FAILURE"


def test_opportunity_export_is_generation_only_and_unique() -> None:
    from evaluation.runner import (generation_opportunity_coverage,
                                   _unique_opportunities)

    rows = [
        {"opportunity_id": "o1", "role": "payload_generator",
         "receipt_stage": "generation", "status": "completed"},
        {"opportunity_id": "o1", "role": "payload_generator",
         "receipt_stage": "validation", "status": "completed"},
        {"opportunity_id": "o1", "role": "payload_generator",
         "receipt_stage": "generation", "status": "completed"},
        {"opportunity_id": "o2", "role": "payload_generator",
         "receipt_stage": "validation", "status": "completed"},
        {"opportunity_id": "selection-1", "role": "orchestrator",
         "status": "completed"},
    ]
    generation = _unique_opportunities(rows, stage="generation", role="payload_generator")
    validation = _unique_opportunities(rows, stage="validation", role="payload_generator")
    assert [row["opportunity_id"] for row in generation] == ["o1"]
    assert [row["opportunity_id"] for row in validation] == ["o1", "o2"]
    coverage = generation_opportunity_coverage({
        "payload_generation_opportunities": [],
        "payload_validation_opportunities": validation,
        "config": {"payload_mode": "llm_mutation_only"},
    })
    assert coverage["status"] == "unavailable"
    assert coverage["reason"] == "generation_receipt_missing"
    assert generation_opportunity_coverage({
        "config": {"payload_mode": "static_only"},
    })["status"] == "not_applicable"
    assert generation_opportunity_coverage({
        "payload_generation_opportunities": generation,
        "payload_validation_opportunities": validation,
        "config": {"payload_mode": "hybrid"},
    })["status"] == "recorded"


def test_recorded_payload_policy_snapshot_is_hash_pinned() -> None:
    from evaluation.runner import recorded_payload_policy_snapshot, resolve_recorded_payload_policy

    snapshot = recorded_payload_policy_snapshot()
    assert snapshot["snapshot_version"] == "payload-policy-snapshot.v1"
    assert snapshot["policy_version"] == "payload-policy.v2"
    assert snapshot["template_registry_version"] == "dvwa-neutral-template.v1"
    assert snapshot["template_registry"]
    assert len(snapshot["template_registry_sha256"]) == 64
    assert len(snapshot["snapshot_sha256"]) == 64
    key = next(iter(snapshot["template_registry"]))
    assert key.startswith("template.")
    assert snapshot["template_registry"][key]["template_sha256"]
    assert resolve_recorded_payload_policy(snapshot) == snapshot
    with pytest.raises(ValueError, match="payload_policy_snapshot invalid"):
        resolve_recorded_payload_policy({"policy_version": "payload-policy.v2"})


def test_terminal_fixture_limit_survives_finalization() -> None:
    from evaluation.runner import _preserve_evidence_backed_fixture_limit

    reason = {"code": "READINESS_FAILED", "detail": "no readiness", "evidence_refs": []}
    preserved = _preserve_evidence_backed_fixture_limit(
        {"security_outcome": "unconfirmed", "security_outcome_reason": {"code": "NO_CANDIDATE_CONFIRMATION"}},
        {"security_outcome": "fixture_limited", "security_outcome_reason": reason},
    )
    assert preserved["security_outcome"] == "fixture_limited"
    assert preserved["security_outcome_reason"] == reason
    # Positive proof always wins over a stale limitation label.
    confirmed = _preserve_evidence_backed_fixture_limit(
        {"security_outcome": "confirmed", "security_outcome_reason": None},
        {"security_outcome": "fixture_limited", "security_outcome_reason": reason},
    )
    assert confirmed["security_outcome"] == "confirmed"
    # An unexplained limitation label never overrides classification.
    assert _preserve_evidence_backed_fixture_limit(
        {"security_outcome": "unconfirmed"}, {"security_outcome": "fixture_limited"},
    )["security_outcome"] == "unconfirmed"


def test_fixture_evidence_accepts_list_and_envelope() -> None:
    from evaluation.runner import fixture_documents, fixture_evidence_for_level

    low = {"policy_version": "fixture-restoration.v1", "security_level": "low"}
    medium = {"policy_version": "fixture-restoration.v1", "security_level": "medium"}
    assert fixture_evidence_for_level([low, medium], "medium") == medium
    assert fixture_documents([low, medium]) == {"low": low, "medium": medium}
    envelope = {"by_level": {"low": low}, "metadata": {"document_count": 1}}
    assert fixture_evidence_for_level(envelope, "low") == low
    with pytest.raises(ValueError, match="duplicate"):
        fixture_documents([low, dict(low)])
    with pytest.raises(ValueError, match="metadata"):
        fixture_documents([{**low, "identity_sha256": "a" * 64}])


def test_source_identity_is_real_for_normal_runs() -> None:
    from evaluation.runner import default_source_identity, default_source_hashes_sha256

    identity = default_source_identity()
    assert identity["identity_version"] == "chapter3-source-identity.v1"
    assert isinstance(identity["source_hashes"], dict) and identity["source_hashes"]
    assert len(identity["source_hashes_sha256"]) == 64
    assert default_source_hashes_sha256() == identity["source_hashes_sha256"]


def test_doctor_payload_scope_uses_configured_coordinates(monkeypatch) -> None:
    import tesis.doctor as doctor
    from tesis.model_config import EngagementConfig

    seen: dict[str, list] = {}

    def fake_contracts(methods, levels, modes, *, candidate_budget: int = 5):
        seen["methods"] = list(methods)
        seen["levels"] = list(levels)
        seen["modes"] = list(modes)
        return {"checked_coordinates": 4, "issues": [], "limitations": [],
                "manifest_problems": []}

    monkeypatch.setattr("tesis.offline_contracts.check_payload_contracts", fake_contracts)
    config = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai", level="low",
        surface="sqli", payload_mode="static_only",
    )
    check = doctor._check_static_seeds(config)
    assert check.status == "passed"
    assert seen["levels"] == ["low"]
    assert seen["modes"] == ["static_only"]
    assert set(seen["methods"]) == {"sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind"}
    assert "scope=single" in check.details


def test_matrix_aggregate_exposes_guardrail_axis_and_null_means() -> None:
    artifact = _aggregate_artifact("linear_hybrid", "selection", None, 2)
    artifact["execution_status"] = "failed"
    aggregate = _build_matrix_aggregate([artifact])
    assert "guardrail_retry_enabled" in aggregate["matrix"]["grouping"]
    assert "guardrail_handling" in aggregate["matrix"]["grouping"]
    group = next(iter(aggregate["by_provider_surface_level"]["openai"]["sqli"].values()))
    assert group["provisional_avg_score"] is None
    assert group["avg_score_reason"] == "no_completed_runs"
    assert "avg_score" not in aggregate["by_provider"]["openai"]


def test_fixture_evidence_selects_matrix_level() -> None:
    from evaluation.runner import fixture_evidence_for_level

    document = {"policy_version": "fixture-restoration.v1", "security_level": "low"}
    assert fixture_evidence_for_level(document, "low") == document
    assert fixture_evidence_for_level(document, "high") == {}
    by_level = {"by_level": {"low": document, "medium": {"policy_version": "fixture-restoration.v1",
                                                        "security_level": "medium"}}}
    assert fixture_evidence_for_level(by_level, "medium")["security_level"] == "medium"
    assert fixture_evidence_for_level(by_level, "high") == {}


def test_fixture_restoration_evidence_is_validated_and_kept() -> None:
    from tesis.config_loader import ConfigError, _validate_engagement_config
    from tesis.model_config import EngagementConfig

    valid = {
        "policy_version": "fixture-restoration.v1",
        "evidence_id": "fixture-reset-1",
        "kind": "operator_attestation",
        "fixture_id": "fixture-1",
        "protocol_version": "protocol-1",
        "security_level": "low",
        "epoch_id": "epoch-1",
        "source_hashes_sha256": "a" * 64,
        "restoration": "reset",
        "authorized_protocol": "operator-reset.v1",
        "evidence_refs": ["evidence:fixture-reset-1"],
        "evidence_sha256": "b" * 64,
        "observed_at": "2026-10-28T00:00:00+00:00",
        "operator": "operator-1",
    }
    config = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai", level="low",
        fixture_id="fixture-1", protocol_version="protocol-1",
        fixture_restoration_evidence=valid,
    )
    _validate_engagement_config(config)
    assert config.fixture_restoration_evidence["by_level"] == {"low": valid}
    assert config.fixture_restoration_evidence["missing_levels"] == []
    envelope_config = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai", level="low",
        fixture_id="fixture-1", protocol_version="protocol-1",
        fixture_restoration_evidence={"by_level": {"low": valid}},
    )
    _validate_engagement_config(envelope_config)
    assert envelope_config.fixture_restoration_evidence["by_level"] == {"low": valid}
    list_config = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai", level="low",
        fixture_id="fixture-1", protocol_version="protocol-1",
        fixture_restoration_evidence=[valid],
    )
    _validate_engagement_config(list_config)
    assert list_config.fixture_restoration_evidence["levels"] == ["low"]
    with pytest.raises(ConfigError, match="outside the attestation document"):
        _validate_engagement_config(EngagementConfig(
            target_url="http://localhost/dvwa", provider="openai", level="low",
            fixture_id="fixture-1", protocol_version="protocol-1",
            fixture_restoration_evidence={**valid, "identity_sha256": "c" * 64},
        ))
    # A document for a level this invocation does not run is filtered out of the
    # canonical envelope rather than rejected (D8: a fixture-wide attestation must
    # stay usable by a single-level run), so the only remaining refusal is the
    # level the run actually needs being unattested.
    with pytest.raises(ConfigError, match="no attestation for level 'low'"):
        _validate_engagement_config(EngagementConfig(
            target_url="http://localhost/dvwa", provider="openai", level="low",
            fixture_id="fixture-1", protocol_version="protocol-1",
            fixture_restoration_evidence=[dict(valid, security_level="high")],
        ))
    wide = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai", level="low",
        fixture_id="fixture-1", protocol_version="protocol-1",
        fixture_restoration_evidence=[
            valid,
            dict(valid, security_level="medium", evidence_id="fixture-reset-2"),
            dict(valid, security_level="high", evidence_id="fixture-reset-3"),
        ],
    )
    _validate_engagement_config(wide)
    assert list(wide.fixture_restoration_evidence["by_level"]) == ["low"]
    assert wide.fixture_restoration_evidence["missing_levels"] == []
    invalid = dict(valid, evidence_refs=[])
    with pytest.raises(ConfigError):
        _validate_engagement_config(EngagementConfig(
            target_url="http://localhost/dvwa", provider="openai", level="low",
            fixture_id="fixture-1", protocol_version="protocol-1",
            fixture_restoration_evidence=invalid,
        ))


def test_no_call_cache_rate_is_null_not_zero() -> None:
    summary = cache_performance_summary([])
    assert summary["response_cache_hit_rate"] is None
    assert summary["response_cache_hit_rate_status"] == "no_calls"
    assert summary["response_cache_hit_rate_denominator"] == 0


def test_artifact_metadata_exposes_study_identity(tmp_path: Path) -> None:
    artifact = {
        "schema_version": "tui.v1",
        "execution_id": "exec-1",
        "run_id": "run-1",
        "status": "success",
        "experiment_condition": "akg_guided_hybrid",
        "experiment_block": "forced",
        "target_method": "sqli_error",
        "policy_epoch": {"epoch_id": "epoch-1"},
        "readiness": {"status": "ready",
                      "fixture_restoration": {"equivalence": "attested"}},
        "source_hashes_sha256": "a" * 64,
        "config": {
            "provider": "openai", "surface": "sqli", "security_level": "low",
            "payload_mode": "hybrid", "repeat_index": 2,
        },
        "final_state": {},
        "report": {},
    }
    path = tmp_path / "exec-1.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")
    items = ArtifactRepository(tmp_path).scan()
    assert len(items) == 1
    item = items[0]
    assert item.experiment_condition == "akg_guided_hybrid"
    assert item.experiment_block == "forced"
    assert item.target_method == "sqli_error"
    assert item.repeat_index == 2
    assert item.policy_epoch == "epoch-1"
    assert item.readiness_status == "ready"
    assert item.fixture_restoration_status == "attested"
    assert item.source_hashes_sha256 == "a" * 64
    assert ArtifactRepository(tmp_path).filter(experiment_block="forced") == [item]
    assert ArtifactRepository(tmp_path).filter(experiment_block="selection") == []


def _aggregate_artifact(condition: str, block: str, target: str, score: int) -> dict:
    return {
        "status": "success",
        "execution_id": f"{condition}-{block}-{target}".replace("_", "-"),
        "config": {
            "provider": "openai", "surface": "sqli", "security_level": "low",
            "payload_mode": "hybrid", "experiment_condition": condition,
            "experiment_block": block, "target_method": target,
            "repeat_index": 0, "fixture_id": "fixture-1",
            "protocol_version": "protocol-1",
        },
        "policy_epoch": {"epoch_id": "epoch-1"},
        "final_state": {},
        "report": {"summary": {"chain_exploits_achieved": 0, "total_iterations_used": 1},
                   "module_scores": {"sqli_error": {"score": score}}},
        "llm_performance": [],
    }


def test_matrix_aggregate_does_not_pool_condition_or_block() -> None:
    aggregate = _build_matrix_aggregate([
        _aggregate_artifact("linear_hybrid", "selection", None, 2),
        _aggregate_artifact("akg_guided_hybrid", "selection", None, 4),
        _aggregate_artifact("linear_hybrid", "forced", "sqli_error", 3),
    ])
    leaf_keys = [key for surfaces in aggregate["by_provider_surface_level"].values()
                 for levels in surfaces.values() for key in levels]
    assert len(leaf_keys) == 3
    assert all("linear_hybrid" in key or "akg_guided_hybrid" in key for key in leaf_keys)
    assert aggregate["matrix"]["pooling_note"]


def test_tui_summary_shows_template_and_block() -> None:
    from tesis.model_config import EngagementConfig
    from tesis.tui_widgets import execution_summary

    config = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai", level="low",
        surface="sqli", payload_mode="llm_template",
    )
    text = execution_summary(config).plain
    assert "Template" in text
    assert "selection" in text
    assert "llm_template" not in text


def test_candidate_budget_receipts_are_derived_from_lifecycle() -> None:
    from evaluation.runner import _candidate_budget_receipts

    state = {
        "candidate_budget": 2,
        "candidate_lifecycle": [
            {"method": "sqli_error", "visit_id": "v1", "candidate_id": "c1",
             "origin_kind": "seed_mutation", "status": "generated"},
            {"method": "sqli_error", "visit_id": "v1", "candidate_id": "c1",
             "origin_kind": "seed_mutation", "status": "valid"},
            {"method": "sqli_error", "visit_id": "v1", "candidate_id": "c1",
             "origin_kind": "seed_mutation", "status": "executed"},
            {"method": "sqli_error", "visit_id": "v1", "candidate_id": "c2",
             "origin_kind": "static_seed", "status": "budget_excluded"},
        ],
        "probe_controls": {"sqli_error": {"requests_used": 2, "physical_requests_used": 3}},
        "control_events": [{"method": "sqli_error", "visit_id": "v1"}],
        "response_evidence": [],
    }
    receipts = _candidate_budget_receipts(state)
    assert len(receipts) == 1
    receipt = receipts[0]
    assert receipt["candidate_budget"] == 2
    assert receipt["generated"] == ["c1"]
    assert receipt["valid"] == ["c1"]
    assert receipt["executed"] == ["c1"]
    assert receipt["budget_excluded"] == ["c2"]
    assert receipt["control_requests"] == 2


def test_derived_docx_preserves_source_and_math(tmp_path) -> None:
    from hashlib import sha256
    from evaluation.rubric_document import update_document

    source = Path("bab 3 only.docx")
    before = sha256(source.read_bytes()).hexdigest()
    result = update_document(
        source, Path("docs/reference/thesis_scoring.md"), tmp_path / "derived.docx",
    )
    assert result["tables"] == 7
    assert result["examples"] == 35
    assert result["math_preserved"] is True
    assert result["other_package_parts_preserved"] is True
    assert result["output_sha256"] == sha256((tmp_path / "derived.docx").read_bytes()).hexdigest()
    assert sha256(source.read_bytes()).hexdigest() == before


def test_matrix_rejects_block_coordinate_mismatch() -> None:
    from evaluation.multi_llm_runner import run_provider_matrix

    common = dict(
        target_url="http://localhost/dvwa", providers=["openai"],
        security_levels=["low"], surfaces=["sqli"], payload_modes=["hybrid"],
        repeats=3,
    )
    with pytest.raises(ValueError, match="selection-block"):
        run_provider_matrix(**common, experiment_block="selection",
                            target_method="sqli_error")
    with pytest.raises(ValueError, match="forced-block"):
        run_provider_matrix(**common, experiment_block="forced")
    with pytest.raises(ValueError, match="experiment_block"):
        run_provider_matrix(**common, experiment_block="unknown")


def test_policy_epoch_requires_timezone_and_identity() -> None:
    from tesis.config_loader import _validate_policy_epoch

    good = {"epoch_id": "e1", "policy_version": "chapter3-flow.v2",
            "frozen_at": "2026-10-28T00:00:00+00:00"}
    _validate_policy_epoch(good)
    with pytest.raises(ConfigError):
        _validate_policy_epoch({**good, "epoch_id": ""})
    with pytest.raises(ConfigError):
        _validate_policy_epoch({**good, "frozen_at": "2026-10-28T00:00:00"})


def test_dry_run_validates_each_mode_contract(monkeypatch, capsys) -> None:
    import tesis.cli as cli
    import tesis.config_loader as config_loader
    import tesis.offline_contracts as offline_contracts
    import core.graph_builder as graph_builder
    import core.knowledge_graph as knowledge_graph
    from tesis.model_config import EngagementConfig

    config = EngagementConfig(
        target_url="http://localhost/dvwa", provider="openai", level="low",
        surface="sqli", payload_mode="llm_template", matrix=False,
    )
    seen: dict[str, object] = {}

    def fake_contracts(methods, levels, modes, *, candidate_budget: int = 5):
        seen["methods"] = list(methods)
        seen["modes"] = list(modes)
        return {
            "checked_coordinates": len(list(methods)) * len(list(levels)) * len(list(modes)),
            "issues": [],
            "limitations": [{"method": "bf_dictionary", "security_level": "high",
                             "payload_mode": "llm_template", "code": "template_limited"}],
            "manifest_problems": [],
        }

    monkeypatch.setattr(config_loader, "load_and_resolve_config", lambda **_: config)
    monkeypatch.setattr(graph_builder, "build_framework", lambda **_: object())
    monkeypatch.setattr(knowledge_graph, "AttackKnowledgeGraph", lambda: object())
    monkeypatch.setattr(offline_contracts, "check_payload_contracts", fake_contracts)

    assert cli._dry_run("config.yaml") == cli.EXIT_OK
    assert seen["modes"] == ["llm_template"]
    output = capsys.readouterr().out
    assert "offline contract check" in output
    assert "explicit template limitations=1" in output


def test_preflight_checks_only_requested_prompts_and_all_iterator_coordinates(monkeypatch):
    from llm.prompts.manifests import PROMPT_MANIFESTS, TEMPLATE_PROMPT_ID
    from tesis.offline_contracts import check_payload_contracts

    monkeypatch.delitem(PROMPT_MANIFESTS, TEMPLATE_PROMPT_ID)
    for mode in ("static_only", "hybrid", "llm_mutation_only"):
        result = check_payload_contracts(
            iter(["sqli_union", "sqli_error"]), iter(["low", "medium"]), iter([mode]))
        assert result["checked_coordinates"] == 4
        assert result["issues"] == []
    template = check_payload_contracts(["sqli_union"], ["low"], ["llm_template"])
    assert any(row["code"] == "prompt_manifest_invalid" for row in template["issues"])
