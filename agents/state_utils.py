"""Shared helpers for Stage 5 vulnerability and chain agents."""

from __future__ import annotations

from typing import Any


def normalize_security_level(level: str | None) -> str:
    normalized = (level or "low").strip().lower()
    return normalized if normalized in {"low", "medium", "high"} else "low"


def merge_scores(state: dict[str, Any], module_name: str, new_score: int) -> dict[str, int]:
    scores = dict(state.get("scores", {}))
    scores[module_name] = max(int(scores.get(module_name, 0)), int(new_score))
    return scores


def merge_tried_payloads(
    state: dict[str, Any],
    module_name: str,
    payloads: list[str],
) -> dict[str, list[str]]:
    tried_payloads = dict(state.get("tried_payloads", {}))
    module_payloads = list(tried_payloads.get(module_name, []))
    for payload in payloads:
        if payload not in module_payloads:
            module_payloads.append(payload)
    tried_payloads[module_name] = module_payloads
    return tried_payloads


def module_endpoint(state: dict[str, Any], module_name: str, fallback_path: str) -> str:
    endpoints = state.get("endpoints", [])
    for endpoint in endpoints:
        if endpoint.get("module_name") == module_name:
            return str(endpoint.get("url") or fallback_path)

    fallback_tokens = {
        "sqli": "sqli",
        "sqli_blind": "sqli_blind",
        "xss_r": "xss_r",
        "xss_s": "xss_s",
        "xss_d": "xss_d",
        "cmdi": "exec",
        "brute": "brute",
        "lfi": "fi",
        "upload": "upload",
        "csrf": "csrf",
        "weak_session": "weak_id",
        "idor": "idor",
    }
    token = fallback_tokens.get(module_name, module_name)
    for endpoint in endpoints:
        url = str(endpoint.get("url", "")).lower()
        if token in url:
            return str(endpoint.get("url") or fallback_path)

    return fallback_path


def make_update(
    *,
    state: dict[str, Any],
    module_name: str,
    score: int,
    tried_payloads: list[str],
    confirmed_vulns: list[str] | None = None,
    achieved_outcomes: list[str] | None = None,
    found_credentials: list[dict[str, str]] | None = None,
    next_agent: str = "orchestrator",
) -> dict[str, Any]:
    update: dict[str, Any] = {
        "scores": merge_scores(state, module_name, score),
        "tried_payloads": merge_tried_payloads(state, module_name, tried_payloads),
        "iteration_count": state.get("iteration_count", 0) + 1,
        "next_agent": next_agent,
    }

    if confirmed_vulns:
        dedup_confirmed = list(dict.fromkeys(confirmed_vulns))
        update["confirmed_vulns"] = dedup_confirmed
    if achieved_outcomes:
        dedup_outcomes = list(dict.fromkeys(achieved_outcomes))
        update["achieved_outcomes"] = dedup_outcomes
    if found_credentials:
        update["found_credentials"] = found_credentials

    return update
