from evaluation.multi_llm_runner import run_provider_matrix


def test_run_provider_matrix_skips_unsupported_provider(monkeypatch):
    def fail_engagement(**kwargs):
        raise RuntimeError("should not be called for unsupported provider")

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", fail_engagement)

    artifacts = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["nonexistent_provider"],
        security_levels=["low"],
        repeats=1,
    )

    assert len(artifacts) == 1
    assert artifacts[0]["status"] == "skipped"
    assert "Unsupported provider" in artifacts[0]["error"]


def test_run_provider_matrix_deterministic_ordering(monkeypatch):
    call_order = []

    def track_engagement(
        *,
        target_url,
        security_level,
        llm_provider,
        max_iterations,
        repeat_index,
        stop_policy="impact",
        coverage_target=0.70,
        enriched_reporting=False,
        diagnose=False,
        output_dir=None,
    ):
        call_order.append((llm_provider, security_level, repeat_index))
        return {
            "schema_version": "stage6.v1",
            "run_id": f"{llm_provider}-{security_level}-{repeat_index}",
            "status": "success",
            "config": {},
            "timing": {},
            "final_state": {},
            "report": {},
            "error": None,
        }

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", track_engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])

    artifacts = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["high", "low", "medium"],
        repeats=2,
    )

    # Levels must be sorted alphabetically: high, low, medium
    assert call_order[0] == ("gemini", "high", 0)
    assert call_order[1] == ("gemini", "high", 1)
    assert call_order[2] == ("gemini", "low", 0)
    assert call_order[3] == ("gemini", "low", 1)
    assert call_order[4] == ("gemini", "medium", 0)
    assert call_order[5] == ("gemini", "medium", 1)
