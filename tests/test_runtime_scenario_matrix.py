"""Offline regression matrix for all supported runtime scenario coordinates."""

from __future__ import annotations

from itertools import product

import pytest

from agents.orchestrator import orchestrator
from core.graph_builder import route_from_payload_validator
from core.state import METHODS_BY_SURFACE, PAYLOAD_MODES, SECURITY_LEVELS, new_default_state
from foundation.payload_generator import build_payload_candidates
from foundation.payload_validator import validate_payload_candidates


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
        "observations": {
            "union_select_possible": True,
            "error_messages_enabled": True,
            "response_diff_detectable": True,
            "response_delay_measurable": True,
            "object_ids_enumerable": True,
            "role_based_access_present": True,
            "force_browse_endpoints_visible": True,
            "no_rate_limit": True,
        },
    })
    selection = orchestrator(state)

    assert selection["selected_method"] == method
    assert selection["next_agent"] == "payload_candidate_builder"
    if evasion_enabled and evasion_mode == "reactive":
        assert fake_llm.calls == 2

    selected_state = {**state, **selection}

    def fake_generate(*, seeds, profile, **kwargs):
        seed = dict(seeds[0])
        generated = {
            **seed,
            "candidate_id": f"{method}-generated-{security_level}",
            "source": "llm_generated",
            "source_seed_id": seed["candidate_id"],
            "mutation_type": profile["allowed_mutation_types"][0],
        }
        return [generated], {"provider": "offline"}, []

    monkeypatch.setattr("foundation.payload_generator.generate_llm_variants", fake_generate)
    built = build_payload_candidates(selected_state)
    validated = validate_payload_candidates({**selected_state, **built})

    accepted = validated["payload_candidates"][method]
    assert accepted
    assert all(candidate["method"] == method for candidate in accepted)
    assert all(candidate["target_param"] for candidate in accepted)
    assert route_from_payload_validator({**selected_state, **validated}) == method


def test_runtime_scenario_matrix_cardinality_is_explicit():
    """Keep the finite supported matrix visible for future coverage changes."""
    assert len(METHOD_CASES) == 9
    assert len(SECURITY_LEVELS) * len(PAYLOAD_MODES) * len(GUARDRAIL_CASES) * len(CONDITIONS) * len(METHOD_CASES) == 648
