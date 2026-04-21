"""Prompt builder for orchestration decisions."""

from __future__ import annotations


def build_orchestrator_prompt(
    *,
    confirmed_vulns: list[str],
    achieved_outcomes: list[str],
    viable_paths: list[list[str]],
    security_level: str,
    iteration_count: int,
    max_iterations: int,
    stop_policy: str,
    coverage_ratio: float,
    coverage_target: float,
) -> str:
    """Build a deterministic orchestration prompt for the LLM planner."""
    remaining = max(max_iterations - iteration_count, 0)
    top_paths = viable_paths[:5]
    normalized_policy = stop_policy if stop_policy in {"impact", "coverage"} else "impact"

    return (
        "You are the orchestrator for a DVWA exploitation workflow.\n"
        f"Security level: {security_level}\n"
        f"Confirmed vulnerabilities: {confirmed_vulns}\n"
        f"Achieved outcomes: {achieved_outcomes}\n"
        f"Remaining iteration budget: {remaining}\n"
        f"Stop policy: {normalized_policy}\n"
        f"Coverage ratio: {coverage_ratio:.3f}\n"
        f"Coverage target: {coverage_target:.3f}\n"
        f"Candidate paths: {top_paths}\n"
        "Return only executable runtime node names (e.g. sqli_agent, brute_agent, "
        "xss_reflected_agent, sqli_to_creds_chain, scorer). Do not return KG state "
        "node names like credentials_extracted.\n"
        "Return strict JSON with exactly one key: {\"next_agent\": \"<agent_name>\"}."
    )
