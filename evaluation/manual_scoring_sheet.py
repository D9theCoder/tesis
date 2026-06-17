"""Manual scoring sheet export helpers for payload evidence review."""

from __future__ import annotations

from typing import Any


def manual_scoring_rows(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    """Handles manual scoring rows behavior for this module.

    Args:
        artifact: Value used by this function."""
    config = artifact.get("config", {}) if isinstance(artifact.get("config"), dict) else {}
    final_state = artifact.get("final_state", {}) if isinstance(artifact.get("final_state"), dict) else {}
    provenance = final_state.get("payload_provenance", {})
    if not isinstance(provenance, dict):
        return []

    rows: list[dict[str, Any]] = []
    for candidate_id, details in sorted(provenance.items()):
        details = details if isinstance(details, dict) else {}
        rows.append({
            "run_id": artifact.get("run_id"),
            "provider": config.get("provider"),
            "surface": config.get("surface"),
            "security_level": config.get("security_level"),
            "payload_mode": config.get("payload_mode"),
            "method_node": details.get("method"),
            "candidate_id": candidate_id,
            "payload_source": details.get("source"),
            "source_seed_id": details.get("source_seed_id"),
            "mutation_type": details.get("mutation_type"),
            "target_param": details.get("target_param"),
            "expected_signal": details.get("expected_signal"),
            "payload_score_0_4": final_state.get("payload_scores", {}).get(candidate_id),
            "method_score_0_4": final_state.get("method_scores", {}).get(details.get("method")),
            "exploitation_score_0_4": final_state.get("exploitation_scores", {}).get(details.get("method")),
            "chain_score_0_4": final_state.get("chain_scores", {}).get(details.get("method")),
            "scoring_reason": "",
        })
    return rows

