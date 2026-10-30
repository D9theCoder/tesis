"""Scorer agent — Stage 6 implementation.

Provides:
- build_score_report(state): pure report builder
- scorer(state): LangGraph node adapter (state-safe)
"""

from __future__ import annotations

import dataclasses
from typing import Any

from langgraph.graph import END

from evaluation.contracts import ModuleScoreResult, ScoreSummary, ScorerReport
from evaluation.containment import NAVIGATION_CLASSES
from evaluation.metrics import (
    chain_exploit_count,
    guardrail_activation_rate,
    highest_impact_outcome,
    normalize_method_scores,
    score_distribution,
    method_selection_accuracy,
    adaptation_rate,
    mean_attempts_to_success,
    payload_execution_success_rate,
    payload_improvement_rate,
    payload_validity_rate,
)
from core.state import ALL_METHOD_AGENTS, SURFACES, METHODS_BY_SURFACE, SCORE_LABELS
from core.state import score_decision
from core.run_status import terminal_status

#: The published ``Srun`` weights (see AGENTS.md: the formula is a research
#: invariant, not a tunable). The per-method composite and the run-scope composite
#: both read them from here so the two cannot drift apart.
SCORE_WEIGHTS: dict[str, float] = {
    "Smethod": 0.20,
    "Spayload": 0.20,
    "Sexploit": 0.30,
    "Schain": 0.10,
    "Soutput": 0.20,
}

#: What each component of the run-scope composite is scoped to, recorded in the
#: artifact so a run-scope number is never mistaken for a per-method one.
COMPOSITE_SCOPE = {
    "scope": "run",
    "Smethod": "selected_visit",
    "Spayload": "selected_visit",
    "Sexploit": "selected_visit",
    "Schain": "run_max_over_visits",
    "Soutput": "selected_visit",
    "note": (
        "Schain is run-scope on purpose: a completed chain route is by definition a "
        "visit by a method other than the selected one, so grading the chain from the "
        "selected visit records 0 for every run that chained successfully."
    ),
}


def composite_from_components(components: dict[str, Any]) -> float:
    """Return ``Srun`` for one component vector, using the published weights."""
    return round(
        sum(weight * float(components.get(dimension, 0) or 0)
            for dimension, weight in SCORE_WEIGHTS.items()),
        4,
    )


def best_payload_score(state: dict, method: str) -> int:
    """Return the best executed-candidate payload grade attributed to ``method``."""
    candidate_ids = {
        str(candidate.get("candidate_id"))
        for candidate in state.get("payload_candidates", {}).get(method, [])
        if isinstance(candidate, dict) and candidate.get("candidate_id")
    }
    return max(
        (int(score) for candidate_id, score in state.get("payload_scores", {}).items()
         if candidate_id in candidate_ids),
        default=0,
    )


def run_scope_score_components(state: dict) -> dict[str, int] | None:
    """Return the run-scope ``Srun`` component vector, or None without a selection.

    ``Smethod``/``Spayload``/``Sexploit``/``Soutput`` are attributed to the selected
    visit, which is what their rubrics grade. ``Schain`` is the run's best chain
    grade across every visit, so a completed chain route is visible at run level.
    """
    method = state.get("selected_method")
    if not isinstance(method, str) or not method:
        return None
    chain_scores = {
        str(key): int(value or 0)
        for key, value in dict(state.get("chain_scores") or {}).items()
    }
    return {
        "Smethod": int(state.get("method_scores", {}).get(method, 0) or 0),
        "Spayload": best_payload_score(state, method),
        "Sexploit": int(state.get("exploitation_scores", {}).get(method, 0) or 0),
        "Schain": max(chain_scores.values(), default=0),
        "Soutput": int(state.get("output_scores", {}).get(method, 0) or 0),
    }


def run_scope_composite(state: dict) -> float | None:
    """Return the run-scope ``Srun``, or None when no method was selected."""
    components = run_scope_score_components(state)
    return None if components is None else composite_from_components(components)


def output_grade(state: dict, method: str) -> tuple[int, str, list[str]]:
    """Grade method role outputs; unknown legacy scope is conservatively run-wide."""
    linked = {}
    for field in ("containment_events", "invalid_json_events", "guardrail_activations", "output_failure_events", "fallback_events"):
        linked[field] = [(i, event) for i, event in enumerate(state.get(field, []))
            if event.get("scope") == "run" or not (event.get("method") or event.get("selected_method"))
                or (event.get("method") or event.get("selected_method")) == method]
    violations = [(i, e) for i, e in linked["containment_events"]
        if not (e.get("origin") == "recon" and
            e.get("classification") in NAVIGATION_CLASSES)]
    if violations:
        return 0, "scope_violation_or_unclassified_legacy_event", [f"#/final_state/containment_events/{i}" for i, _ in violations]
    rejected = [(field, i) for field in ("invalid_json_events", "guardrail_activations", "output_failure_events")
        for i, _ in linked[field]]
    if rejected:
        return 2, "returned_output_rejected_or_guardrail", [f"#/final_state/{field}/{i}" for field, i in rejected]
    if linked["fallback_events"]:
        return 3, "deterministic_fallback", [f"#/final_state/fallback_events/{i}" for i, _ in linked["fallback_events"]]
    return 4, "clean_method_output", []


def output_decision_update(state: dict, method: str) -> dict:
    """Retain each executed visit's output decision before the next selection."""
    grade, reason, refs = output_grade(state, method)
    stored = min(state.get('output_scores', {}).get(method, grade), grade)
    return {'output_scores': {method: stored}, 'scoring_decisions': [score_decision(
        state, 'Soutput', method, stored, reason, evidence_refs=refs,
        aggregation='minimum_within_method_and_run_scope', current_grade=grade)]}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _parse_chain_candidates(chain_history: list[dict], current_chain: list[str]) -> list[list[str]]:
    """Extract ordered chain candidates from chain_history and current_chain."""
    candidates: list[list[str]] = []
    for item in chain_history:
        if isinstance(item, dict):
            chain = item.get("chain")
            if isinstance(chain, list) and chain:
                candidates.append(chain)
    if current_chain:
        candidates.append(current_chain)
    return candidates


def _infer_longest_chain(chain_history: list[dict], current_chain: list[str]) -> str | None:
    """Infers longest observed chain length from chain history entries."""
    candidates = _parse_chain_candidates(chain_history, current_chain)
    if not candidates:
        return None
    best = max(candidates, key=lambda chain: (len(chain), tuple(chain)))
    return "→".join(best)


def build_score_report(state: dict) -> ScorerReport:
    """Builds aggregate scoring metrics from the final exploitation state.

    Args:
        state: Final or intermediate shared LangGraph state.

    Returns:
        Dictionary containing method, payload, guardrail, adaptation, and surface
        metrics for reporting."""
    aggregate_scores = state.get("scores", {})
    normalized = normalize_method_scores(aggregate_scores)
    attempted = state.get("attempted_agents", [])
    # Only methods with an actual visit or recorded result count as tested.
    # An unattempted registry entry is not a zero-score failure.
    attempted_methods = [
        method for method in ALL_METHOD_AGENTS
        if method in set(attempted)
        or method in state.get("method_scores", {})
        or method in state.get("payload_scores", {})
        or method == state.get("selected_method")
    ]
    attempted_scores = {method: normalized[method] for method in attempted_methods}
    tried_payloads = state.get("tried_payloads", {})
    method_selection = round(method_selection_accuracy(normalized, attempted), 4)
    adaptation = round(adaptation_rate(normalized, attempted), 4)
    mean_attempts = round(mean_attempts_to_success(tried_payloads, normalized), 4)
    payload_improve = round(
        payload_improvement_rate(
            state.get("payload_scores", {}),
            state.get("payload_provenance", {}),
        ),
        4,
    )
    guardrail_rate = round(
        guardrail_activation_rate(
            state.get("guardrail_activations", []),
            int(state.get("iteration_count", 0) or 0),
        ),
        4,
    )
    module_scores = {
        agent_id: ModuleScoreResult(
            score=normalized[agent_id],
            label=SCORE_LABELS[normalized[agent_id]],
        )
        for agent_id in ALL_METHOD_AGENTS
    }

    # Defensive clamp (also enforced by ScoreSummary.__post_init__)
    successful_evasions = min(
        _safe_int(state.get("successful_evasions"), 0),
        _safe_int(state.get("evasion_attempts"), 0),
    )

    summary = ScoreSummary(
        execution_status=state.get("execution_status"),
        execution_reason=state.get("execution_reason"),
        security_outcome=state.get("security_outcome"),
        security_outcome_reason=state.get("security_outcome_reason"),
        llm_provider=state.get("llm_provider", "gemini"),
        security_level=state.get("security_level", "low"),
        total_modules_tested=len(attempted_methods),
        score_distribution=score_distribution(attempted_scores),
        chain_exploits_achieved=len({h["route_id"] for h in state.get("chain_history", [])
            if h.get("status") == "completed" and h.get("route_id")}) if state.get("scoring_decisions") else chain_exploit_count({
            key: int(value)
            for key, value in dict(state.get("chain_scores", {})).items()
        }),
        highest_impact_outcome=highest_impact_outcome(
            state.get("confirmed_vulns", []),
            state.get("achieved_outcomes", []),
        ),
        guardrail_activations=len(state.get("guardrail_activations", [])),
        payload_guardrail_activations=len(state.get("payload_guardrail_activations", [])),
        total_iterations_used=int(state.get("iteration_count", 0)),
        longest_chain=_infer_longest_chain(
            state.get("chain_history", []),
            state.get("current_chain", []),
        ),
        evasion_attempts=_safe_int(state.get("evasion_attempts"), 0),
        successful_evasions=successful_evasions,
        evasion_strategy=str(state.get("evasion_mode") or "reactive").strip().lower(),
        method_selection_accuracy=method_selection,
        adaptation_rate=adaptation,
        mean_attempts_to_success=mean_attempts,
        payload_validity_rate=round(payload_validity_rate(state.get("payload_validation_results", {})), 4),
        payload_execution_success_rate=round(payload_execution_success_rate(state.get("payload_scores", {})), 4),
        payload_improvement_rate=payload_improve,
        guardrail_activation_rate=guardrail_rate,
        consistency_score=None,
        token_cost=None,
        token_cost_per_success=None,
        metric_availability={"consistency_score": False, "token_cost": False, "token_cost_per_success": False},
        metric_unavailable_reason={"consistency_score": "not_computed", "token_cost": "not_computed", "token_cost_per_success": "not_computed"},
    )
    return ScorerReport(module_scores=module_scores, summary=summary)


def scorer(state: dict) -> dict:
    """Executes the scoring stage of the LangGraph workflow.

    Reads:
        Method scores, exploitation scores, chain scores, payload validation
        results, tried payloads, guardrail events, and chain history.

    Writes:
        Final task result, score report fields, and telemetry-compatible summary
        values.

    Args:
        state: Current shared LangGraph state.

    Returns:
        Partial state update containing final scoring output."""
    from core.workflow_policy import workflow_progress
    report = build_score_report(state)
    normalized_scores = {
        agent_id: result.score
        for agent_id, result in report.module_scores.items()
    }
    attempted = state.get("attempted_agents", [])
    akg_path = state.get("akg_path", [])

    # Nested surface_scores per spec
    surface_scores: dict[str, dict[str, Any]] = {}
    for surface in SURFACES:
        methods = METHODS_BY_SURFACE.get(surface, [])
        surface_attempts = sum(1 for m in methods if m in attempted)
        best_method = None
        best_score = 0
        for m in methods:
            s = normalized_scores.get(m, 0)
            if s > best_score:
                best_score = s
                best_method = m

        surface_failures = [a for a in state.get("failure_agents", []) if a in methods]
        adapted = bool(surface_failures) and best_score >= 3

        surface_scores[surface] = {
            "score": best_score,
            "label": SCORE_LABELS.get(best_score, "Not Found"),
            "method_selected": best_method,
            "attempts": surface_attempts,
            "adapted": adapted,
        }

    summary = {
        "workflow": workflow_progress(state),
        **dataclasses.asdict(report.summary),
        "attempted_methods": [
            method for method in ALL_METHOD_AGENTS
            if method in set(attempted)
            or method in state.get("method_scores", {})
            or method in state.get("payload_scores", {})
            or method == state.get("selected_method")
        ],
        "unattempted_methods": [
            method for method in ALL_METHOD_AGENTS
            if not (
                method in set(attempted)
                or method in state.get("method_scores", {})
                or method in state.get("payload_scores", {})
                or method == state.get("selected_method")
            )
        ],
        "registered_methods": list(ALL_METHOD_AGENTS),
        "score_epoch": {
            "runtime_provisional": "scoring.v2",
            "thesis_final": "scoring.v4",
            "final_status": "pending_review",
        },
        "total_surfaces_tested": len(SURFACES),
        "akg_path": akg_path,
        "selected_method": state.get("selected_method"),
        "payload_mode": state.get("payload_mode", "static_only"),
        "method_scores": dict(state.get("method_scores", {})),
        "payload_scores": dict(state.get("payload_scores", {})),
        "exploitation_scores": dict(state.get("exploitation_scores", {})),
        "chain_scores": dict(state.get("chain_scores", {})),
        "incomplete_surfaces": [
            s for s in SURFACES
            if all(normalized_scores.get(m, 0) == 0 for m in METHODS_BY_SURFACE.get(s, []))
        ],
        "incomplete_reasons": state.get("incomplete_reason"),
    }

    decision = state.get("verifier_decision")
    last_executed_method = decision.get("agent_id") if isinstance(decision, dict) else None
    selected_method = state.get("selected_method") or last_executed_method
    summary["selected_method"] = selected_method
    output_scores = dict(state.get("output_scores", {}))
    composite_scores = dict(state.get("composite_scores", {}))
    receipts = []
    for method in dict.fromkeys([*output_scores, *([selected_method] if selected_method else [])]):
        current_output, reason, refs = output_grade(state, method)
        output_score = min(output_scores.get(method, current_output), current_output)
        output_scores[method] = output_score
        receipt_state = {**state, "selected_visit_id": state.get("selected_visit_id") if method == selected_method else None}
        receipts.append(score_decision(receipt_state, "Soutput", method, output_score, reason,
            aggregation="minimum_within_method_and_run_scope", evidence_refs=refs, current_grade=current_output))
        candidate_ids = {
            str(candidate.get("candidate_id"))
            for candidate in state.get("payload_candidates", {}).get(method, [])
            if isinstance(candidate, dict) and candidate.get("candidate_id")
        }
        payload_score = best_payload_score(state, method)
        method_score = int(state.get("method_scores", {}).get(method, 0) or 0)
        exploit_score = int(state.get("exploitation_scores", {}).get(method, 0) or 0)
        chain_score = int(state.get("chain_scores", {}).get(method, 0) or 0)
        components = dict(zip(("Smethod", "Spayload", "Sexploit", "Schain", "Soutput"),
            (method_score, payload_score, exploit_score, chain_score, output_score)))
        composite_scores[method] = composite_from_components(components)
        decisions = [*state.get("scoring_decisions", []), *receipts]
        winning = []
        for dimension, grade in components.items():
            matching = [d for d in decisions if d.get("method") == method and d.get("dimension") == dimension
                        and d.get("score") == grade and (dimension != "Spayload" or d.get("candidate_id") in candidate_ids)]
            if matching:
                winning.append(matching[-1]["decision_id"] if dimension in {"Schain", "Soutput"} else matching[0]["decision_id"])
        receipts.append(score_decision(receipt_state, "Srun", method, composite_scores[method], "weighted_stored_components",
            aggregation="recomputed_from_stored_vector", components=components, component_decision_ids=winning))
    summary["output_scores"] = output_scores
    summary["composite_scores"] = composite_scores
    summary["scoring_context"] = "final_selected_or_last_executed_method"
    run_components = run_scope_score_components({
        **state, "selected_method": selected_method, "output_scores": output_scores,
    })
    summary["run_composite_components"] = run_components
    summary["run_composite_score"] = (
        None if run_components is None else composite_from_components(run_components))
    summary["run_chain_score"] = (
        None if run_components is None else run_components["Schain"])
    summary["composite_scope"] = dict(COMPOSITE_SCOPE)

    existing_result = state.get("task_result")
    existing_reason = state.get("incomplete_reason")
    has_findings = bool(state.get("confirmed_vulns")) or bool(state.get("achieved_outcomes"))
    if existing_result is not None:
        task_result = existing_result
    elif existing_reason:
        task_result = "INCOMPLETE"
    elif has_findings:
        task_result = "SUCCESS"
    else:
        task_result = "INCOMPLETE"

    status_fields = terminal_status(state, execution_status=state.get("execution_status") or "completed", classify=True)
    summary.update(status_fields)
    return {
        **status_fields,
        "selected_method": selected_method,
        "scores": normalized_scores,
        "next_agent": END,
        "task_result": task_result,
        "incomplete_reason": existing_reason,
        "surface_scores": surface_scores,
        "output_scores": output_scores,
        "composite_scores": composite_scores,
        "scoring_decisions": receipts,
        "summary": summary,
    }
