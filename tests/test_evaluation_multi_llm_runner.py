"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from evaluation.multi_llm_runner import run_provider_matrix


def test_run_provider_matrix_zero_success_avg_score_is_null(monkeypatch):
    """Failed-only groups expose null provisional means, never a fake zero."""
    def failed_engagement(**kwargs):
        """Supports regression tests for test evaluation multi llm runner."""
        return {
            "schema_version": "stage8.v1",
            "run_id": "openai_compatible-sqli-low-0",
            "status": "error",
            "config": {"provider": "openai_compatible", "surface": "sqli", "security_level": "low"},
            "timing": {},
            "final_state": {},
            "report": {
                "summary": {
                    "total_modules_tested": 9,
                    "score_distribution": {},
                    "chain_exploits_achieved": 0,
                    "guardrail_activations": 0,
                    "total_iterations_used": 0,
                },
                "module_scores": {},
            },
            "error": "boom",
        }

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", failed_engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["openai_compatible"])

    _, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["openai_compatible"],
        security_levels=["low"],
        surfaces=["sqli"],
        repeats=1,
        include_aggregate=True,
    )

    group = next(iter(aggregate["by_provider_surface_level"]["openai_compatible"]["sqli"].values()))
    assert group["legacy_runtime"]["mean_module_score_sum"] is None
    assert group["provisional_avg_iterations"] is None
    assert group["legacy_runtime"]["unavailable_reason"] == "no_completed_runs"
    assert "avg_score" not in aggregate["by_provider"]["openai_compatible"]
    assert aggregate["by_provider"]["openai_compatible"]["score_aggregation"] == "not_computed_pooled_coordinates"


def test_run_provider_matrix_rejects_cross_surface_target_method():
    """A method-level run cannot silently evaluate a method on another surface."""
    import pytest

    with pytest.raises(ValueError, match="target_method"):
        run_provider_matrix(
            target_url="http://localhost/dvwa",
            providers=["openai_compatible"],
            security_levels=["low"],
            surfaces=["access_control"],
            payload_modes=["static_only"],
            target_method="sqli_union",
        )
