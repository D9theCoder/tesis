"""Stage 6 metric helpers for method-level scoring analysis."""

from __future__ import annotations

from collections import Counter

from core.state import ALL_METHOD_AGENTS, SURFACES, METHODS_BY_SURFACE


def clamp_score(raw: object) -> int:
    try:
        score = int(raw)
    except (TypeError, ValueError):
        return 0
    return max(0, min(4, score))


def normalize_method_scores(scores: dict[str, object]) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for agent_id in ALL_METHOD_AGENTS:
        normalized[agent_id] = clamp_score(scores.get(agent_id, 0))
    return normalized


def score_distribution(scores: dict[str, int]) -> dict[int, int]:
    counter = Counter(scores.values())
    return {bucket: int(counter.get(bucket, 0)) for bucket in range(5)}


_IMPACT_SEVERITY_ORDER: tuple[str, ...] = (
    "admin_session_obtained",
    "data_exfiltrated",
    "credentials_extracted",
)


def highest_impact_outcome(confirmed: list[str], achieved: list[str]) -> str | None:
    known = set(confirmed) | set(achieved)
    for outcome in _IMPACT_SEVERITY_ORDER:
        if outcome in known:
            return outcome
    return None


def chain_exploit_count(scores: dict[str, int]) -> int:
    return sum(1 for value in scores.values() if value == 4)


def method_selection_accuracy(scores: dict[str, int], attempted: list[str]) -> float:
    if not attempted:
        return 0.0
    first = attempted[0]
    return 1.0 if scores.get(first, 0) >= 3 else 0.0


def adaptation_rate(scores: dict[str, int], attempted: list[str]) -> float:
    if len(attempted) < 2:
        return 0.0
    first = attempted[0]
    if scores.get(first, 0) >= 3:
        return 0.0
    return 1.0 if any(scores.get(agent_id, 0) >= 3 for agent_id in attempted[1:]) else 0.0


def mean_attempts_to_success(tried_payloads: dict[str, list[str]], scores: dict[str, int]) -> float:
    attempts = []
    for agent_id, payloads in tried_payloads.items():
        if scores.get(agent_id, 0) >= 3 and payloads:
            attempts.append(len(payloads))
    return sum(attempts) / len(attempts) if attempts else 0.0


def payload_validity_rate(validation_results: dict[str, list[dict]]) -> float:
    rows = [
        row
        for results in validation_results.values()
        for row in results
        if isinstance(row, dict)
    ]
    if not rows:
        return 0.0
    return sum(1 for row in rows if row.get("valid") is True) / len(rows)


def payload_execution_success_rate(payload_scores: dict[str, int]) -> float:
    if not payload_scores:
        return 0.0
    return sum(1 for score in payload_scores.values() if clamp_score(score) >= 3) / len(payload_scores)


def payload_improvement_rate(
    payload_scores: dict[str, int],
    payload_provenance: dict[str, dict],
) -> float:
    """Return 1.0 when any generated candidate outperforms the static seed baseline."""
    best_static: dict[str, int] = {}
    best_generated: dict[str, int] = {}
    for candidate_id, score in payload_scores.items():
        info = payload_provenance.get(candidate_id, {})
        method = str(info.get("method") or "")
        if not method:
            continue
        source = str(info.get("source") or "")
        bucket = best_static if source == "static_seed" else best_generated
        bucket[method] = max(bucket.get(method, 0), clamp_score(score))

    if not best_generated:
        return 0.0
    improved_methods = sum(
        1
        for method, generated_score in best_generated.items()
        if generated_score > best_static.get(method, 0)
    )
    return improved_methods / len(best_generated)


def guardrail_activation_rate(guardrail_activations: list[dict], total_iterations: int) -> float:
    if total_iterations <= 0:
        return 0.0
    return min(len(guardrail_activations) / total_iterations, 1.0)


def aggregate_runs(run_artifacts: list[dict]) -> dict:
    completed = [r for r in run_artifacts if r.get("status") == "success"]
    return {
        "total_runs": len(run_artifacts),
        "successful_runs": len(completed),
        "error_runs": sum(1 for r in run_artifacts if r.get("status") == "error"),
        "skipped_runs": sum(1 for r in run_artifacts if r.get("status") == "skipped"),
    }
