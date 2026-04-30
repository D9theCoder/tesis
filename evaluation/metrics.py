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
    "rce_achieved",
    "admin_session_obtained",
    "user_compromised",
    "data_exfiltrated",
    "credentials_extracted",
    "log_access_confirmed",
    "session_hijack",
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
    return sum(1 for a in attempted if scores.get(a, 0) >= 3) / len(attempted)


def adaptation_rate(scores: dict[str, int]) -> float:
    if not SURFACES:
        return 0.0
    adapted = 0
    for surface in SURFACES:
        if any(scores.get(m, 0) >= 3 for m in METHODS_BY_SURFACE.get(surface, [])):
            adapted += 1
    return adapted / len(SURFACES)


def mean_attempts_to_success(tried_payloads: dict[str, list[str]], scores: dict[str, int]) -> float:
    attempts = []
    for agent_id, payloads in tried_payloads.items():
        if scores.get(agent_id, 0) >= 3 and payloads:
            attempts.append(len(payloads))
    return sum(attempts) / len(attempts) if attempts else 0.0


def aggregate_runs(run_artifacts: list[dict]) -> dict:
    completed = [r for r in run_artifacts if r.get("status") == "success"]
    return {
        "total_runs": len(run_artifacts),
        "successful_runs": len(completed),
        "error_runs": sum(1 for r in run_artifacts if r.get("status") == "error"),
        "skipped_runs": sum(1 for r in run_artifacts if r.get("status") == "skipped"),
    }
