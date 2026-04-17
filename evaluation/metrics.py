"""Stage 6 metric helpers for run-level and aggregate scoring analysis."""

from __future__ import annotations

from collections import Counter

from core.state import MODULE_NAMES


def clamp_score(raw: object) -> int:
    try:
        score = int(raw)
    except (TypeError, ValueError):
        return 0
    return max(0, min(4, score))


def normalize_module_scores(scores: dict[str, object]) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for module in MODULE_NAMES:
        normalized[module] = clamp_score(scores.get(module, 0))
    return normalized


def score_distribution(scores: dict[str, int]) -> dict[int, int]:
    counter = Counter(scores.values())
    return {bucket: int(counter.get(bucket, 0)) for bucket in range(5)}


# Severity ranking: highest impact first (matches AGENTS.md example where
# rce_achieved is the highest-impact outcome).
_IMPACT_SEVERITY_ORDER: tuple[str, ...] = (
    "rce_achieved",
    "admin_session_obtained",
    "user_compromised",
    "data_exfiltrated",
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


def aggregate_runs(run_artifacts: list[dict]) -> dict:
    completed = [r for r in run_artifacts if r.get("status") == "success"]
    return {
        "total_runs": len(run_artifacts),
        "successful_runs": len(completed),
        "error_runs": sum(1 for r in run_artifacts if r.get("status") == "error"),
        "skipped_runs": sum(1 for r in run_artifacts if r.get("status") == "skipped"),
    }
