"""Stage 6 metric helpers for method-level scoring analysis."""

from __future__ import annotations

from collections import Counter
import math

from core.state import ALL_METHOD_AGENTS, SURFACES, METHODS_BY_SURFACE
NOT_COMPUTED = "not_computed"
UNAVAILABLE_METRICS = ("consistency_score", "token_cost", "token_cost_per_success")


def metric_reading(summary: dict, name: str) -> tuple[float | None, bool, str | None]:
    """Dual-read one availability-tracked metric from a score summary dict.

    Returns (value, available, reason). New artifacts carry explicit
    ``metric_availability``/``metric_unavailable_reason`` maps alongside null
    values; legacy artifacts carry a bare numeric (0.0) with no maps and are
    treated as unavailable with reason ``"legacy_numeric"``. Explicit
    ``True`` availability returns the stored value coerced to float.
    """
    if not isinstance(summary, dict):
        return None, False, NOT_COMPUTED
    availability = summary.get("metric_availability")
    reasons = summary.get("metric_unavailable_reason")
    if isinstance(availability, dict) and name in availability:
        available = bool(availability[name])
        if available:
            value = summary.get(name)
            # ponytail: fail closed — available + null/non-numeric/nonfinite is
            # a producer bug; never hand None/inf/nan to arithmetic.
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                reason = reasons.get(name) if isinstance(reasons, dict) else None
                return None, False, str(reason or NOT_COMPUTED)
            if not math.isfinite(value):
                reason = reasons.get(name) if isinstance(reasons, dict) else None
                return None, False, str(reason or "nonfinite")
            return float(value), True, None
        reason = reasons.get(name) if isinstance(reasons, dict) else None
        return None, False, str(reason or NOT_COMPUTED)
    value = summary.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None, False, NOT_COMPUTED
    # ponytail: legacy numeric artifacts read as unavailable, not zero.
    return None, False, "legacy_numeric"


def format_metric(summary: dict, name: str) -> str:
    """Render one availability-tracked metric for display.

    Available readings render as a compact number; anything unavailable
    renders as ``"N/A"``. Never formats ``None`` as a number and never
    converts ``null`` back to ``0.0``.
    """
    value, available, _reason = metric_reading(summary, name)
    if available and value is not None:
        return f"{value:g}"
    return "N/A"


def aggregate_metric(summaries: list[dict], name: str) -> dict:
    """Aggregate one availability-tracked metric across score summaries.

    Only available readings contribute to the mean; unavailable readings are
    counted by reason, never averaged as zero. An all-unavailable aggregate
    reports ``mean=None`` (rendered as ``N/A``), not ``0.0``.
    """
    values: list[float] = []
    reasons: dict[str, int] = {}
    for summary in summaries:
        value, available, reason = metric_reading(summary, name)
        if available and value is not None:
            values.append(value)
        else:
            key = str(reason or NOT_COMPUTED)
            reasons[key] = reasons.get(key, 0) + 1
    return {
        "n_available": len(values),
        "n_unavailable": sum(reasons.values()),
        "mean": round(sum(values) / len(values), 4) if values else None,
        "unavailable_reasons": reasons,
    }


def artifact_summary(artifact: dict) -> dict:
    """Return the score-summary mapping for a run artifact.

    Prefers the nested ``report.summary``; stub nested summaries (skipped or
    cancelled coordinates) carry no metric keys, so top-level metric keys
    backfill them instead of being shadowed. The nested mapping wins on
    conflict; flattened artifacts without a nested summary return as-is.
    """
    if not isinstance(artifact, dict):
        return {}
    report = artifact.get("report")
    nested = report.get("summary") if isinstance(report, dict) else None
    if not isinstance(nested, dict):
        return artifact
    base = {
        key: artifact[key]
        for key in (*UNAVAILABLE_METRICS, "metric_availability", "metric_unavailable_reason")
        if key in artifact
    }
    if not base:
        return nested
    return {**base, **nested}


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


def aggregate_runs(run_artifacts: list[dict]) -> dict:
    """Handles aggregate runs behavior for this module.

    Args:
        run_artifacts: Value used by this function."""
    completed = [r for r in run_artifacts if r.get("status") == "success"]
    summaries = [artifact_summary(artifact) for artifact in run_artifacts]
    return {
        "total_runs": len(run_artifacts),
        "successful_runs": len(completed),
        "error_runs": sum(1 for r in run_artifacts if r.get("status") == "error"),
        "skipped_runs": sum(1 for r in run_artifacts if r.get("status") == "skipped"),
        "cancelled_runs": sum(1 for r in run_artifacts if r.get("status") == "cancelled"),
        "metrics": {name: aggregate_metric(summaries, name) for name in UNAVAILABLE_METRICS},
    }
