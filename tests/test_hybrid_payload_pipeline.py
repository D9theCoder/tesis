"""Regression tests for the DVWA payload pipeline.

This module verifies current behavior for state handling, payload generation,
validation, and mode-aware fallback semantics without running providers or HTTP.
"""
from typing import Any

import pytest

from agents.state_utils import candidate_payloads_for_stage
from core.knowledge_graph import AttackKnowledgeGraph
from core.payload_policy import PAYLOAD_POLICY_VERSION
from core.state import new_default_state
from foundation.payload_generator import (
    _stamp_static_candidates,
)
from foundation.payload_library import PayloadLibrary
from foundation.payload_validator import validate_payload_candidates


def _exploit_seed(method: str, security_level: str = "low") -> dict[str, Any]:
    return next(
        candidate
        for candidate in PayloadLibrary().load_seed_candidates(method, security_level)
        if candidate["stage"] in {"exploit", "bypass"}
    )


def _live_static(method: str, level: str = "low", visit: str | None = None) -> list[dict[str, Any]]:
    visit = visit or f"{method}:visit:1"
    seeds = [
        candidate for candidate in PayloadLibrary().load_seed_candidates(method, level)
        if candidate["stage"] in {"exploit", "bypass"}
    ]
    return _stamp_static_candidates(method, level, visit, seeds)


def _strict_state(
    method: str, mode: str = "llm_mutation_only", **overrides: Any
) -> dict[str, Any]:
    return {
        **new_default_state(),
        "selected_method": method,
        "payload_mode": mode,
        "security_level": "low",
        "selected_visit_id": f"{method}:visit:1",
        **overrides,
    }


def test_strict_mode_rejected_generated_candidate_queues_nothing():
    """An out-of-scope model candidate never revives a static seed."""
    seed = _exploit_seed("ac_force_browse")
    generated = {
        **seed,
        "candidate_id": "generated-out-of-scope",
        "source": "llm_generated",
        "origin_kind": "seed_mutation",
        "visit_id": "ac_force_browse:visit:1",
        "policy_version": PAYLOAD_POLICY_VERSION,
        "mutation_type": "path_normalization",
        "payload_or_logic": "vulnerabilities/../security.php",
    }
    update = validate_payload_candidates(
        _strict_state(
            "ac_force_browse",
            payload_candidates={"ac_force_browse": [generated]},
        )
    )

    assert any(
        row["reason"] == "out_of_scope_target"
        for row in update["payload_validation_results"]["ac_force_browse"]
    )
    assert update["payload_candidates"]["ac_force_browse"] == []
    events = [row["event"] for row in update["fallback_events"]]
    assert "payload_validation.strict_no_candidate" in events
    assert "payload_generation.static_seed_fallback" not in events


def test_hybrid_rejected_generated_candidate_keeps_validated_static_seed():
    """Hybrid keeps its documented static coverage and records the reason."""
    seed = _exploit_seed("ac_force_browse")
    static_rows = _live_static("ac_force_browse")
    generated = {
        **seed,
        "candidate_id": "generated-out-of-scope",
        "source": "llm_generated",
        "origin_kind": "seed_mutation",
        "visit_id": "ac_force_browse:visit:1",
        "policy_version": PAYLOAD_POLICY_VERSION,
        "mutation_type": "path_normalization",
        "payload_or_logic": "vulnerabilities/../security.php",
    }
    update = validate_payload_candidates({
        **new_default_state(),
        "selected_method": "ac_force_browse",
        "payload_mode": "hybrid",
        "security_level": "low",
        "selected_visit_id": "ac_force_browse:visit:1",
        "payload_candidates": {"ac_force_browse": [generated, *static_rows]},
    })

    queue = update["payload_candidates"]["ac_force_browse"]
    # Hybrid keeps its validated static coverage: the rejected model candidate
    # cannot remove any valid static seed from the queue.
    assert queue
    assert seed["candidate_id"] in {candidate["source_seed_id"] for candidate in queue}
    assert all(candidate["origin_kind"] == "static_seed" for candidate in queue)
    fallback = [
        row for row in update["fallback_events"]
        if row["event"] == "payload_generation.static_seed_fallback"
    ]
    assert fallback
    assert fallback[0]["candidate_ids"] == [candidate["candidate_id"] for candidate in queue]
    assert fallback[0]["origin_kind"] == "static_seed"
    assert fallback[0]["visit_id"] is None or isinstance(fallback[0]["visit_id"], str)


def test_method_queue_uses_only_validated_candidate_ids():
    """Accumulated rejected candidates remain audit data, never execution data."""
    seed = PayloadLibrary().load_seed_candidates("sqli_union", "low")[0]
    safe = {
        **seed,
        "candidate_id": "safe-candidate",
        "stage": "exploit",
        "payload_or_logic": "1 UNION SELECT user,password FROM users-- -",
    }
    blocked = {**safe, "candidate_id": "blocked-candidate", "payload_or_logic": "//external.invalid"}
    state = {
        **new_default_state(),
        "payload_candidates": {"sqli_union": [blocked, safe]},
        "payload_validation_results": {
            "sqli_union": [
                {"candidate_id": "blocked-candidate", "valid": False, "reason": "out_of_scope_target"},
                {"candidate_id": "safe-candidate", "valid": True, "reason": "ok"},
            ],
        },
    }

    assert candidate_payloads_for_stage(state, "sqli_union", "low", "exploit") == [
        safe["payload_or_logic"]
    ]


def test_validator_rejects_wrong_target_param_and_keeps_valid_seed():
    """A wrong parameter is rejected while a valid static seed stays queued."""
    seed = _exploit_seed("sqli_union")
    live_seed = _live_static("sqli_union")[0]
    state = {
        **new_default_state(),
        "selected_method": "sqli_union",
        "payload_mode": "hybrid",
        "selected_visit_id": "sqli_union:visit:1",
        "payload_candidates": {
            "sqli_union": [
                {
                    "candidate_id": "bad",
                    "source_seed_id": seed["candidate_id"],
                    "source": "llm_generated",
                    "origin_kind": "seed_mutation",
                    "visit_id": "sqli_union:visit:1",
                    "policy_version": PAYLOAD_POLICY_VERSION,
                    "method": "sqli_union",
                    "mutation_type": "encoding",
                    "payload_or_logic": "1' UNION SELECT user,password FROM users-- -",
                    "target_param": "username",
                    "expected_signal": "data_extraction_evidence",
                },
                live_seed,
            ]
        },
    }
    update = validate_payload_candidates(state)
    results = update["payload_validation_results"]["sqli_union"]
    assert any(row["reason"] == "wrong_target_param" for row in results)
    assert update["payload_candidates"]["sqli_union"][0]["source"] == "static_seed"


def test_validator_rejects_brute_payload_without_credential_pair():
    """Brute-force candidates must contain an executable credential prefix."""
    seed = _exploit_seed("bf_spray", "high")
    candidate = {
        **seed,
        "candidate_id": "invalid-credential-logic",
        "source": "llm_generated",
        "origin_kind": "seed_mutation",
        "source_seed_id": seed["candidate_id"],
        "mutation_type": AttackKnowledgeGraph().get_payload_profile("bf_spray")["allowed_mutation_types"][0],
        "payload_or_logic": "wait 8-12s between attempts",
    }
    update = validate_payload_candidates({
        **new_default_state(),
        "selected_method": "bf_spray",
        "payload_mode": "llm_mutation_only",
        "security_level": "high",
        "payload_candidates": {"bf_spray": [candidate]},
    })
    assert update["payload_candidates"]["bf_spray"] == []
    assert update["payload_validation_results"]["bf_spray"][0]["reason"] == "invalid_credential_pair"


@pytest.mark.parametrize("external_value", ["//example.invalid/escape", "../../setup.php", "..\\\\setup.php"])
def test_validator_rejects_external_or_traversal_payloads(external_value):
    """Payload validation blocks external targets and base-path escapes."""
    seed = _exploit_seed("ac_force_browse", "low")
    candidate = {**seed, "candidate_id": f"blocked-{external_value}", "payload_or_logic": external_value}
    state = {
        **new_default_state(),
        "selected_method": "ac_force_browse",
        "security_level": "low",
        "payload_candidates": {"ac_force_browse": [candidate]},
    }
    update = validate_payload_candidates(state)
    assert update["payload_candidates"]["ac_force_browse"] == []
    assert update["payload_validation_results"]["ac_force_browse"][0]["reason"] == "out_of_scope_target"
