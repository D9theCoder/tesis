"""Single-engagement Stage 6 evaluation runner."""

from __future__ import annotations

from datetime import datetime, timezone
from time import perf_counter
from traceback import format_exc

from core.graph_builder import build_framework
from core.scorer import build_score_report
from core.state import new_default_state


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_single_engagement(
    *,
    target_url: str,
    security_level: str,
    llm_provider: str,
    max_iterations: int = 30,
    repeat_index: int = 0,
) -> dict:
    started_at = _now_iso()
    started_clock = perf_counter()

    try:
        app = build_framework(llm_provider=llm_provider)
        init_state = {
            **new_default_state(),
            "target_url": target_url,
            "security_level": security_level,
            "llm_provider": llm_provider,
            "max_iterations": max_iterations,
        }

        final_state = app.invoke(init_state)
        report = build_score_report(final_state).to_dict()
        status = "success"
        error = None
    except Exception as exc:
        final_state = {
            "iteration_count": 0,
            "confirmed_vulns": [],
            "achieved_outcomes": [],
            "guardrail_activations": [],
        }
        report = build_score_report(final_state).to_dict()
        status = "error"
        error = f"{type(exc).__name__}: {exc}\n{format_exc()}"

    ended_at = _now_iso()
    duration_ms = int((perf_counter() - started_clock) * 1000)
    run_id = f"{llm_provider}-{security_level}-{repeat_index}"

    return {
        "schema_version": "stage6.v1",
        "run_id": run_id,
        "status": status,
        "config": {
            "target_url": target_url,
            "provider": llm_provider,
            "security_level": security_level,
            "max_iterations": max_iterations,
            "repeat_index": repeat_index,
        },
        "timing": {
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_ms": duration_ms,
        },
        "final_state": {
            "iteration_count": final_state.get("iteration_count", 0),
            "confirmed_vulns": list(final_state.get("confirmed_vulns", [])),
            "achieved_outcomes": list(final_state.get("achieved_outcomes", [])),
            "guardrail_activations": list(final_state.get("guardrail_activations", [])),
        },
        "report": report,
        "error": error,
    }
