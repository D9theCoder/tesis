"""Stage 6 metric helpers for method-level scoring analysis."""

from __future__ import annotations

from collections import Counter

from core.run_status import terminal_status, lifecycle_alias, EXECUTION_STATUSES, SECURITY_OUTCOMES
import math

from core.state import ALL_METHOD_AGENTS, SURFACES, METHODS_BY_SURFACE
NOT_COMPUTED = "not_computed"
UNAVAILABLE_METRICS = ("consistency_score", "token_cost", "token_cost_per_success")
#: Report rates whose empty denominator must stay null. They are the same names
#: the score summary persists, so a stub nested summary cannot shadow them.
RATE_METRICS = (
    "method_selection_accuracy",
    "adaptation_rate",
    "mean_attempts_to_success",
    "payload_validity_rate",
    "payload_execution_success_rate",
    "payload_improvement_rate",
    "guardrail_activation_rate",
)
# Canonical availability-tracked metric names (see evaluation/research_metrics.py).
# The legacy rate helpers below now return ``(value, unavailable_reason)`` so an
# empty denominator stays null; they are never used to fill a research metric or
# a final v4 component.
from evaluation.research_metrics import RESEARCH_METRIC_NAMES  # noqa: E402


def rate_metric(numerator, denominator, *, reason="no_denominator"):
    """Return (value, available, reason) for one rate without inventing zero."""
    if not isinstance(denominator, int) or isinstance(denominator, bool) or denominator <= 0:
        return None, False, reason
    if not isinstance(numerator, int) or isinstance(numerator, bool) or numerator < 0:
        return None, False, "invalid_numerator"
    return round(numerator / denominator, 6), True, None


def aggregate_research_metrics(summaries: list[dict], names=RESEARCH_METRIC_NAMES) -> dict:
    """Aggregate every research metric with availability and reasons preserved."""
    return {name: aggregate_metric(summaries, name) for name in names}


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
        for key in (*UNAVAILABLE_METRICS, *RATE_METRICS, "metric_availability", "metric_unavailable_reason")
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


def method_selection_accuracy(scores: dict[str, int], attempted: list[str]) -> tuple[float | None, str | None]:
    """Return whether the first selected method reached full exploitation.

    The metric is binary: `1.0` when the first attempted method scored at least
    3, otherwise a legitimate `0.0`. With no attempt there is no denominator,
    so the reading is `None` with reason ``"no_attempted_method"``.

    Args:
        scores: Method score map using the 0-4 rubric.
        attempted: Ordered method IDs attempted by the orchestrator.

    Returns:
        ``(value, unavailable_reason)``; value is in the range 0.0 to 1.0.
    """
    if not attempted:
        return None, "no_attempted_method"
    first = attempted[0]
    return (1.0 if scores.get(first, 0) >= 3 else 0.0), None


def adaptation_rate(scores: dict[str, int], attempted: list[str]) -> tuple[float | None, str | None]:
    """Return whether a later method succeeded after the first method failed.

    The metric is binary: `1.0` when the first attempted method scored below 3
    and any later attempted method scored at least 3. A run with fewer than two
    attempts has no re-selection opportunity and reports `None` with reason
    ``"no_adaptation_opportunity"``; an observed non-adaptation stays `0.0`.

    Args:
        scores: Method score map using the 0-4 rubric.
        attempted: Ordered method IDs attempted by the orchestrator.

    Returns:
        ``(value, unavailable_reason)``; value is in the range 0.0 to 1.0.
    """
    if len(attempted) < 2:
        return None, "no_adaptation_opportunity"
    first = attempted[0]
    if scores.get(first, 0) >= 3:
        return 0.0, None
    return 1.0 if any(scores.get(agent_id, 0) >= 3 for agent_id in attempted[1:]) else 0.0, None


def mean_attempts_to_success(tried_payloads: dict[str, list[str]], scores: dict[str, int]) -> tuple[float | None, str | None]:
    """Return the mean payload attempt count of successful methods.

    With no successful method carrying tracked payload attempts there is no
    denominator, so the reading is `None` with reason
    ``"no_successful_payload_attempt"`` rather than a fabricated 0.

    Args:
        tried_payloads: Value used by this function.
        scores: Value used by this function.

    Returns:
        ``(value, unavailable_reason)``.
    """
    attempts = []
    for agent_id, payloads in tried_payloads.items():
        if scores.get(agent_id, 0) >= 3 and payloads:
            attempts.append(len(payloads))
    if not attempts:
        return None, "no_successful_payload_attempt"
    return sum(attempts) / len(attempts), None


def payload_validity_rate(validation_results: dict[str, list[dict]]) -> tuple[float | None, str | None]:
    """Return the fraction of payload validation rows accepted as valid.

    Args:
        validation_results: Per-method validation records returned by the
            payload validator.

    Returns:
        ``(value, unavailable_reason)``. An empty row population is `None`
        with reason ``"no_validation_rows"``; a measured all-invalid
        population is a legitimate `0.0`.
    """
    rows = [
        row
        for results in validation_results.values()
        for row in results
        if isinstance(row, dict)
    ]
    if not rows:
        return None, "no_validation_rows"
    return sum(1 for row in rows if row.get("valid") is True) / len(rows), None


def payload_execution_success_rate(payload_scores: dict[str, int]) -> tuple[float | None, str | None]:
    """Handles payload execution success rate behavior for this module.

    Args:
        payload_scores: Value used by this function.

    Returns:
        ``(value, unavailable_reason)``. An empty score population is `None`
        with reason ``"no_payload_scores"``.
    """
    if not payload_scores:
        return None, "no_payload_scores"
    return sum(1 for score in payload_scores.values() if clamp_score(score) >= 3) / len(payload_scores), None


def payload_improvement_rate(
    payload_scores: dict[str, int],
    payload_provenance: dict[str, dict],
) -> tuple[float | None, str | None]:
    """Return 1.0 when any generated candidate outperforms the static seed baseline.

    Returns ``(value, unavailable_reason)``. Without a generated candidate
    attributed to a method there is no denominator, so the reading is `None`
    with reason ``"no_generated_candidate_with_method"``.
    """
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
        return None, "no_generated_candidate_with_method"
    improved_methods = sum(
        1
        for method, generated_score in best_generated.items()
        if generated_score > best_static.get(method, 0)
    )
    return improved_methods / len(best_generated), None


def guardrail_activation_rate(guardrail_activations: list[dict], total_iterations: int) -> tuple[float | None, str | None]:
    """Handles guardrail activation rate behavior for this module.

    Args:
        guardrail_activations: Value used by this function.
        total_iterations: Value used by this function.

    Returns:
        ``(value, unavailable_reason)``. Zero iterations is no denominator, so
        the reading is `None` with reason ``"no_iterations"``.
    """
    if total_iterations <= 0:
        return None, "no_iterations"
    return min(len(guardrail_activations) / total_iterations, 1.0), None


def aggregate_runs(run_artifacts: list[dict]) -> dict:
    """Handles aggregate runs behavior for this module.

    Args:
        run_artifacts: Value used by this function."""
    statuses = [terminal_status(r) for r in run_artifacts]
    completed = [r for r, fields in zip(run_artifacts, statuses) if fields["execution_status"] == "completed"]
    summaries = [artifact_summary(artifact) for artifact in run_artifacts]
    return {
        "total_runs": len(run_artifacts),
        "successful_runs": len(completed),  # compatibility alias: completed executions
        "completed_runs": len(completed),
        "execution_status_counts": {key: sum(s["execution_status"] == key for s in statuses) for key in EXECUTION_STATUSES},
        "execution_unknown_runs": sum(s["execution_status"] is None and r.get("status") != "skipped" for r,s in zip(run_artifacts, statuses)),
        "security_outcome_counts": {key: sum(s["security_outcome"] == key for s in statuses if s["execution_status"] is not None) for key in SECURITY_OUTCOMES},
        "confirmed_runs": sum(s["security_outcome"] == "confirmed" for s in statuses if s["execution_status"] is not None),
        "error_runs": sum(s["execution_status"] == "failed" for s in statuses),
        "skipped_runs": sum(1 for r in run_artifacts if r.get("status") == "skipped"),
        "cancelled_runs": sum(s["execution_status"] == "interrupted" for s in statuses),
        "metrics": {name: aggregate_metric(summaries, name) for name in UNAVAILABLE_METRICS},
    }
