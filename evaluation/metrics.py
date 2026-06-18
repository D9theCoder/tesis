"""Stage 6 metric helpers for method-level scoring analysis."""

from __future__ import annotations

from collections import Counter

from core.state import ALL_METHOD_AGENTS, SURFACES, METHODS_BY_SURFACE


# Composite score weights (thesis §7.1):
# Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput
SCORE_WEIGHTS: dict[str, float] = {
    "method": 0.20,
    "payload": 0.20,
    "exploit": 0.30,
    "chain": 0.10,
    "output": 0.20,
}


def clamp_score(raw: object) -> int:
    """Handles clamp score behavior for this module.

    Args:
        raw: Value used by this function."""
    try:
        score = int(raw)
    except (TypeError, ValueError):
        return 0
    return max(0, min(4, score))


def normalize_method_scores(scores: dict[str, object]) -> dict[str, int]:
    """Handles normalize method scores behavior for this module.

    Args:
        scores: Value used by this function."""
    normalized: dict[str, int] = {}
    for agent_id in ALL_METHOD_AGENTS:
        normalized[agent_id] = clamp_score(scores.get(agent_id, 0))
    return normalized


def score_distribution(scores: dict[str, int]) -> dict[int, int]:
    """Handles score distribution behavior for this module.

    Args:
        scores: Value used by this function."""
    counter = Counter(scores.values())
    return {bucket: int(counter.get(bucket, 0)) for bucket in range(5)}


_IMPACT_SEVERITY_ORDER: tuple[str, ...] = (
    "admin_session_obtained",
    "data_exfiltrated",
    "credentials_extracted",
)


def highest_impact_outcome(confirmed: list[str], achieved: list[str]) -> str | None:
    """Handles highest impact outcome behavior for this module.

    Args:
        confirmed: Value used by this function.
        achieved: Value used by this function."""
    known = set(confirmed) | set(achieved)
    for outcome in _IMPACT_SEVERITY_ORDER:
        if outcome in known:
            return outcome
    return None


def chain_exploit_count(scores: dict[str, int]) -> int:
    """Handles chain exploit count behavior for this module.

    Args:
        scores: Value used by this function."""
    return sum(1 for value in scores.values() if value == 4)


def method_selection_accuracy(scores: dict[str, int], attempted: list[str]) -> float:
    """Return whether the first selected method reached full exploitation.

    The metric is binary: `1.0` when the first attempted method scored at least
    3, otherwise `0.0`. Empty attempt lists produce `0.0`.

    Args:
        scores: Method score map using the 0-4 rubric.
        attempted: Ordered method IDs attempted by the orchestrator.

    Returns:
        Binary first-choice success metric in the range 0.0 to 1.0.
    """
    if not attempted:
        return 0.0
    first = attempted[0]
    return 1.0 if scores.get(first, 0) >= 3 else 0.0


def adaptation_rate(scores: dict[str, int], attempted: list[str]) -> float:
    """Return whether a later method succeeded after the first method failed.

    The metric is binary: `1.0` when the first attempted method scored below 3
    and any later attempted method scored at least 3. Empty or single-attempt
    runs produce `0.0`.

    Args:
        scores: Method score map using the 0-4 rubric.
        attempted: Ordered method IDs attempted by the orchestrator.

    Returns:
        Binary adaptation metric in the range 0.0 to 1.0.
    """
    if len(attempted) < 2:
        return 0.0
    first = attempted[0]
    if scores.get(first, 0) >= 3:
        return 0.0
    return 1.0 if any(scores.get(agent_id, 0) >= 3 for agent_id in attempted[1:]) else 0.0


def mean_attempts_to_success(tried_payloads: dict[str, list[str]], scores: dict[str, int]) -> float:
    """Handles mean attempts to success behavior for this module.

    Args:
        tried_payloads: Value used by this function.
        scores: Value used by this function."""
    attempts = []
    for agent_id, payloads in tried_payloads.items():
        if scores.get(agent_id, 0) >= 3 and payloads:
            attempts.append(len(payloads))
    return sum(attempts) / len(attempts) if attempts else 0.0


def payload_validity_rate(validation_results: dict[str, list[dict]]) -> float:
    """Return the fraction of payload validation rows accepted as valid.

    Args:
        validation_results: Per-method validation records returned by the
            payload validator.

    Returns:
        Valid candidate ratio in the range 0.0 to 1.0, or 0.0 when no
        validation rows exist.
    """
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
    """Handles payload execution success rate behavior for this module.

    Args:
        payload_scores: Value used by this function."""
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
    """Handles guardrail activation rate behavior for this module.

    Args:
        guardrail_activations: Value used by this function.
        total_iterations: Value used by this function."""
    if total_iterations <= 0:
        return 0.0
    return min(len(guardrail_activations) / total_iterations, 1.0)


def invalid_json_rate(invalid_json_events: list[dict], total_iterations: int) -> float:
    """Return the ratio of invalid-JSON parse failures to iterations (0.0-1.0).

    Args:
        invalid_json_events: Recorded JSON-parse failure events.
        total_iterations: LangGraph iterations used in the run.

    Returns:
        Invalid-JSON ratio clamped to the range 0.0 to 1.0.
    """
    if total_iterations <= 0:
        return 0.0
    return min(len(invalid_json_events) / total_iterations, 1.0)


def fallback_rate(fallback_events: list[dict], total_iterations: int) -> float:
    """Return the ratio of fallback activations to iterations (0.0-1.0).

    Args:
        fallback_events: Recorded deterministic-fallback events.
        total_iterations: LangGraph iterations used in the run.

    Returns:
        Fallback ratio clamped to the range 0.0 to 1.0.
    """
    if total_iterations <= 0:
        return 0.0
    return min(len(fallback_events) / total_iterations, 1.0)


def output_validity_score(
    guardrail_rate: float,
    invalid_rate: float,
    fb_rate: float,
) -> int:
    """Return a 0-4 output-quality score (Soutput) from output-health rates.

    Soutput rewards clean, parseable, non-refused LLM output. A combined penalty
    is built from guardrail-activation, invalid-JSON, and fallback rates; the
    score is `4` when output is perfectly clean and degrades toward `0` as the
    penalty grows.

    Args:
        guardrail_rate: Guardrail/refusal activation rate (0.0-1.0).
        invalid_rate: Invalid-JSON rate (0.0-1.0).
        fb_rate: Fallback rate (0.0-1.0).

    Returns:
        Integer output-quality score in the range 0 to 4.
    """
    penalty = min(max(guardrail_rate, 0.0), 1.0)
    penalty += min(max(invalid_rate, 0.0), 1.0)
    penalty += min(max(fb_rate, 0.0), 1.0)
    penalty = penalty / 3.0  # average penalty in 0.0-1.0
    return clamp_score(round((1.0 - penalty) * 4))


def composite_run_score(
    s_method: int,
    s_payload: int,
    s_exploit: int,
    s_chain: int,
    s_output: int,
) -> float:
    """Return the weighted composite run score (Srun) on a 0-4 scale.

    Applies the thesis §7.1 weighting to the five clamped dimension scores.

    Args:
        s_method: Method-selection score (0-4).
        s_payload: Payload-quality score (0-4).
        s_exploit: Exploitation score (0-4).
        s_chain: Chain score (0-4).
        s_output: Output-quality score (0-4).

    Returns:
        Composite score in the range 0.0 to 4.0, rounded to four decimals.
    """
    composite = (
        SCORE_WEIGHTS["method"] * clamp_score(s_method)
        + SCORE_WEIGHTS["payload"] * clamp_score(s_payload)
        + SCORE_WEIGHTS["exploit"] * clamp_score(s_exploit)
        + SCORE_WEIGHTS["chain"] * clamp_score(s_chain)
        + SCORE_WEIGHTS["output"] * clamp_score(s_output)
    )
    return round(composite, 4)


def aggregate_runs(run_artifacts: list[dict]) -> dict:
    """Handles aggregate runs behavior for this module.

    Args:
        run_artifacts: Value used by this function."""
    completed = [r for r in run_artifacts if r.get("status") == "success"]
    return {
        "total_runs": len(run_artifacts),
        "successful_runs": len(completed),
        "error_runs": sum(1 for r in run_artifacts if r.get("status") == "error"),
        "skipped_runs": sum(1 for r in run_artifacts if r.get("status") == "skipped"),
    }
