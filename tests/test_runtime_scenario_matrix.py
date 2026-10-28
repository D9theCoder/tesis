"""Offline regression matrix for all supported runtime scenario coordinates.

Every coordinate runs the real selection, payload-builder, validator, control
freeze and routing contracts. Provider dispatch is replaced by a local fixture;
DVWA HTTP is never touched.
"""

from __future__ import annotations

import copy

import pytest

from agents.orchestrator import orchestrator
from core.graph_builder import route_from_payload_validator
from core.payload_policy import (
    CONTROL_POLICY_VERSION,
    MUTATION_PROMPT_ID,
    PAYLOAD_POLICY_VERSION,
    PAYLOAD_SCHEMA_VERSION,
    PAYLOAD_TEMPLATE_SCHEMA_VERSION,
    TEMPLATE_MUTATION_TYPE,
    TEMPLATE_PROMPT_ID,
    is_strict_mode,
    requires_model_candidate,
)
from core.state import (
    METHODS_BY_SURFACE,
    PAYLOAD_MODES,
    SECURITY_LEVELS,
    new_default_state,
)
from evaluation.scoring_evidence import evidence_hash
from foundation.payload_generator import build_payload_candidates
from foundation.payload_templates import (
    load_template,
    template_feasibility,
    template_reference,
)
from foundation.payload_validator import payload_validator_node, validate_probe_controls
from foundation.preconditions import make_observation_fact, observation_update
from llm.prompts.payload_generation_prompt import payload_generation_prompt_seeds
from tests.support import READY_RECEIPT

METHOD_CASES = [
    (surface, method)
    for surface, methods in METHODS_BY_SURFACE.items()
    for method in methods
]
GUARDRAIL_CASES = (
    pytest.param(False, "reactive", id="guardrail-off"),
    pytest.param(True, "reactive", id="guardrail-reactive"),
    pytest.param(True, "proactive", id="guardrail-proactive"),
    pytest.param(True, "disabled", id="guardrail-disabled"),
)
CONDITIONS = ("linear_hybrid", "akg_guided_hybrid")
PRECONDITION_OBSERVATIONS = (
    "union_select_possible",
    "error_messages_enabled",
    "response_diff_detectable",
    "response_delay_measurable",
    "object_ids_enumerable",
    "role_based_access_present",
    "force_browse_endpoints_visible",
    "no_rate_limit",
)
SESSION_PRINCIPAL = "admin"
SESSION_FINGERPRINT = "scenario-fixture-session"


class _ScenarioLLM:
    def __init__(self, method: str, refuse_once: bool) -> None:
        self.method = method
        self.refuse_once = refuse_once
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        if self.refuse_once and self.calls == 1:
            return type("Response", (), {"content": "I cannot assist with that request."})()
        return type("Response", (), {"content": f'{{"next_agent": "{self.method}"}}'})()


def _ready_receipt(security_level: str) -> dict:
    """Return an explicit, level-matched readiness receipt with session scope."""
    receipt = copy.deepcopy(READY_RECEIPT)
    receipt["requested_level"] = security_level
    receipt["observed_level"] = security_level
    receipt["session"] = {
        "principal": SESSION_PRINCIPAL,
        "fingerprint": SESSION_FINGERPRINT,
    }
    return receipt


def _scenario_state(
    security_level: str,
    surface: str,
    payload_mode: str,
    experiment_condition: str,
    evasion_enabled: bool,
    evasion_mode: str,
) -> dict:
    """Build current-contract evidence: scoped facts, derived tri-state, readiness."""
    state = new_default_state()
    state.update({
        "target_url": "http://localhost/dvwa",
        "security_level": security_level,
        "current_surface": surface,
        "payload_mode": payload_mode,
        "experiment_condition": experiment_condition,
        "evasion_enabled": evasion_enabled,
        "evasion_mode": evasion_mode,
        "evasion_max_retries": 1,
        "evasion_cooldown_threshold": 5,
        "readiness": _ready_receipt(security_level),
    })
    facts = [
        make_observation_fact(
            key,
            True,
            source="scenario_fixture",
            fixture_id=state.get("fixture_id"),
            protocol_version=state.get("protocol_version"),
            security_level=security_level,
            principal_id=SESSION_PRINCIPAL,
            session_fingerprint=SESSION_FINGERPRINT,
            session_scope="session",
            phase="recon",
        )
        for key in PRECONDITION_OBSERVATIONS
    ]
    state.update(observation_update(state, facts))
    return state


def _fake_generate(
    *,
    state,
    method,
    seeds,
    profile,
    budget,
):
    """Return one generated candidate through the current generator contract."""
    mode = state["payload_mode"]
    prompt_event = {
        "method": method,
        "payload_mode": mode,
        "visit_id": state.get("selected_visit_id"),
        "provider": "offline",
        "origin_kind": "template_generation" if mode == "llm_template" else "seed_mutation",
        "policy_version": PAYLOAD_POLICY_VERSION,
        "candidate_budget": budget,
        "model_candidate_budget": 1,
        "call_id": f"fixture-call-{method}-{state.get('security_level')}",
        "parsed_candidate_ids": [],
    }
    if mode == "llm_template":
        template = load_template(method, state["security_level"])
        prompt_event.update({
            "template_reference": template_reference(template),
            "template_feasibility": template_feasibility(template),
            "template_id": template["template_id"],
            "template_version": template["template_version"],
            "template_sha256": template["template_sha256"],
            "prompt_id": TEMPLATE_PROMPT_ID,
            "schema_version": PAYLOAD_TEMPLATE_SCHEMA_VERSION,
            "prompt_visible_seed_ids": [],
            "prompt_visible_seeds": [],
            "prompt_visible_seeds_sha256": evidence_hash([]),
        })
        payload_value = (
            "fixture_user:fixture_password"
            if template["target_param"] == "credential_pair"
            else "constructed-neutral-value"
        )
        generated = {
            "method": method,
            "stage": "exploit",
            "origin_kind": "template_generation",
            "payload_or_logic": payload_value,
            "target_param": template["target_param"],
            "expected_signal": template["expected_signal"],
            "mutation_type": TEMPLATE_MUTATION_TYPE,
        }
        return [generated], prompt_event, []

    visible = payload_generation_prompt_seeds(seeds)
    if not visible:
        prompt_event["failure_reason"] = "no_supplied_seed"
        return [], prompt_event, []
    seed = visible[0]
    prompt_event.update({
        "prompt_id": MUTATION_PROMPT_ID,
        "schema_version": PAYLOAD_SCHEMA_VERSION,
        "prompt_visible_seed_ids": [seed["source_seed_id"]],
        "prompt_visible_seeds": [seed],
        "prompt_visible_seeds_sha256": evidence_hash([seed]),
    })
    generated = {
        "method": method,
        "stage": "exploit",
        "source_seed_id": seed["source_seed_id"],
        "payload_or_logic": seed["payload_or_logic"],
        "target_param": seed["target_param"],
        "expected_signal": seed["expected_signal"],
        "mutation_type": profile["allowed_mutation_types"][0],
    }
    return [generated], prompt_event, []


@pytest.mark.parametrize("security_level", SECURITY_LEVELS)
@pytest.mark.parametrize("payload_mode", PAYLOAD_MODES)
@pytest.mark.parametrize("evasion_enabled,evasion_mode", GUARDRAIL_CASES)
@pytest.mark.parametrize("experiment_condition", CONDITIONS)
@pytest.mark.parametrize("surface,method", METHOD_CASES)
def test_runtime_coordinate_selects_and_validates_method_payloads(
    monkeypatch,
    security_level: str,
    payload_mode: str,
    evasion_enabled: bool,
    evasion_mode: str,
    experiment_condition: str,
    surface: str,
    method: str,
):
    """Every supported coordinate remains contained and dispatchable offline."""
    fake_llm = _ScenarioLLM(
        method,
        refuse_once=evasion_enabled and evasion_mode == "reactive",
    )
    monkeypatch.setattr("agents.orchestrator.get_llm", lambda *args, **kwargs: fake_llm)
    monkeypatch.setattr("foundation.payload_generator.generate_llm_variants", _fake_generate)

    state = _scenario_state(
        security_level,
        surface,
        payload_mode,
        experiment_condition,
        evasion_enabled,
        evasion_mode,
    )
    selection = orchestrator(state)

    assert selection["selected_method"] == method
    assert selection["next_agent"] == "payload_candidate_builder"
    if evasion_enabled and evasion_mode == "reactive":
        assert fake_llm.calls == 2
    else:
        assert fake_llm.calls == 1

    visit_id = selection["selected_visit_id"]
    assert visit_id
    method_receipts = [
        row for row in selection.get("scoring_decisions", [])
        if row.get("dimension") == "Smethod" and row.get("method") == method
    ]
    assert len(method_receipts) == 1
    method_receipt = method_receipts[0]
    assert method_receipt["visit_id"] == visit_id
    assert method_receipt["decision_origin"] == "model"
    assert method_receipt["first_choice"] is True
    assert method_receipt["candidate_set_source"] == (
        "viable" if experiment_condition == "akg_guided_hybrid" else "canonical"
    )
    assert method_receipt["precondition_status"]
    assert all(
        value == "true"
        for value in method_receipt["precondition_status"].values()
    )
    assert all(
        key in method_receipt["precondition_status"]
        for key in method_receipt["preconditions"]
    )
    readiness = selection.get("readiness") or state["readiness"]
    assert readiness["status"] == "ready"
    assert readiness["requested_level"] == readiness["observed_level"] == security_level

    selected_state = {**state, **selection}
    built = build_payload_candidates(selected_state)
    validated = payload_validator_node({**selected_state, **built})
    final = {**selected_state, **built, **validated}
    # Emulate the graph's append reducers for the receipt lists this scenario
    # checks; a plain dict merge would drop the builder's generation receipt.
    for key in ("candidate_lifecycle", "model_call_requirements"):
        final[key] = [
            *selected_state.get(key, []),
            *built.get(key, []),
            *validated.get(key, []),
        ]

    accepted = final["payload_candidates"][method]
    assert accepted
    assert all(candidate["method"] == method for candidate in accepted)
    assert all(candidate["target_param"] for candidate in accepted)
    assert all(candidate["visit_id"] == visit_id for candidate in accepted)
    accepted_ids = {candidate["candidate_id"] for candidate in accepted}
    origins = {candidate["origin_kind"] for candidate in accepted}
    queued_ids = {
        row["candidate_id"]
        for row in final["candidate_lifecycle"]
        if row.get("status") == "queued" and row.get("visit_id") == visit_id
    }
    assert queued_ids == accepted_ids

    generated = final.get("generated_payloads", {}).get(method, [])
    if payload_mode == "static_only":
        assert origins == {"static_seed"}
        assert not built["generation_prompts"]
        assert not generated
    elif payload_mode == "hybrid":
        assert "static_seed" in origins
        assert generated, "hybrid must attempt one model candidate"
    elif payload_mode == "llm_mutation_only":
        assert origins == {"seed_mutation"}
    else:
        assert origins == {"template_generation"}
        assert all("source_seed_id" not in candidate for candidate in accepted)
        template_ref = final["payload_provenance"][accepted[0]["candidate_id"]]["origin_ref"]
        assert template_ref["template_id"] == accepted[0]["origin_ref"]["template_id"]
        assert template_ref["template_sha256"]

    opportunities = final.get("model_call_requirements", [])
    generation_rows = [
        row for row in opportunities if row.get("receipt_stage") == "generation"
    ]
    assert len(generation_rows) == 1
    generation_row = generation_rows[0]
    assert generation_row["role"] == "payload_generator"
    assert generation_row["method"] == method
    assert generation_row["visit_id"] == visit_id
    if requires_model_candidate(payload_mode):
        assert generation_row["required"] is True
        assert generation_row["status"] == "completed"
        assert generation_row["call_id"]
        validation_rows = [
            row for row in opportunities if row.get("receipt_stage") == "validation"
        ]
        assert len(validation_rows) == 1
        assert validation_rows[0]["opportunity_id"] == generation_row["opportunity_id"]
        assert validation_rows[0]["call_id"] == generation_row["call_id"]
    else:
        assert generation_row["required"] is False
        assert generation_row["status"] == "not_required"

    provenance = final["payload_provenance"]
    assert provenance
    for candidate_id, row in provenance.items():
        assert row["visit_id"] == visit_id
        assert row["policy_version"] == PAYLOAD_POLICY_VERSION
        if row["origin_kind"] in {"seed_mutation", "template_generation"}:
            assert row["model_call_id"] == generation_row["call_id"]
    if is_strict_mode(payload_mode):
        assert all(row["model_call_id"] for row in provenance.values())
        if payload_mode == "llm_mutation_only":
            assert all(row["copy_of_supplied_seed"] is True for row in provenance.values())

    controls = final.get("probe_controls", {}).get(method)
    assert controls
    assert controls["policy_version"] == CONTROL_POLICY_VERSION
    assert controls["visit_id"] == visit_id
    control_ids = {row["candidate_id"] for row in controls["candidates"]}
    assert not (control_ids & accepted_ids)
    assert all(row["stage"] == "probe" for row in controls["candidates"])
    assert all(row["establishes_exploit"] is False for row in controls["candidates"])
    control_results = validate_probe_controls(final, controls)
    assert all(row.get("valid") is True for row in control_results)
    if controls["candidates"]:
        assert len(control_results) == len(controls["candidates"])

    assert route_from_payload_validator(final) == method
