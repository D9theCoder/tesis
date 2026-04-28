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
        evasion_enabled=False,
        evasion_strategy="pipeline",
        simulator_model=None,
        simulator_provider=None,
        max_concurrency=None,
        live_display=False,
    ):
        call_order.append((llm_provider, security_level, repeat_index, evasion_enabled, evasion_strategy))
        return {
            "schema_version": "stage6.v1",
            "run_id": f"{llm_provider}-{security_level}-{repeat_index}",
            "status": "success",
            "config": {},
            "timing": {},
            "final_state": {
                "evasion_attempts": 0,
                "successful_evasions": 0,
            },
            "report": {
                "summary": {
                    "total_modules_tested": 12,
                    "score_distribution": {},
                    "chain_exploits_achieved": 0,
                    "guardrail_activations": 0,
                    "total_iterations_used": 0,
                },
                "module_scores": {},
            },
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
    assert call_order[0] == ("gemini", "high", 0, False, "pipeline")
    assert call_order[1] == ("gemini", "high", 1, False, "pipeline")
    assert call_order[2] == ("gemini", "low", 0, False, "pipeline")
    assert call_order[3] == ("gemini", "low", 1, False, "pipeline")
    assert call_order[4] == ("gemini", "medium", 0, False, "pipeline")
    assert call_order[5] == ("gemini", "medium", 1, False, "pipeline")


def test_run_provider_matrix_include_aggregate(monkeypatch):
    def mock_engagement(**kwargs):
        return {
            "schema_version": "stage6.v1",
            "run_id": "gemini-low-0",
            "status": "success",
            "config": {"provider": "gemini", "security_level": "low"},
            "timing": {},
            "final_state": {
                "evasion_attempts": 0,
                "successful_evasions": 0,
            },
            "report": {
                "summary": {
                    "total_modules_tested": 12,
                    "score_distribution": {},
                    "chain_exploits_achieved": 0,
                    "guardrail_activations": 0,
                    "total_iterations_used": 0,
                },
                "module_scores": {},
            },
            "error": None,
        }

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", mock_engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])

    artifacts, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low"],
        repeats=1,
        include_aggregate=True,
    )

    assert isinstance(artifacts, list)
    assert isinstance(aggregate, dict)
    assert "by_provider" in aggregate
    assert "by_provider_level" in aggregate
    assert "totals" in aggregate


def test_run_provider_matrix_evasion_forwarding(monkeypatch):
    captured = []

    def mock_engagement(*, evasion_enabled, evasion_strategy, **kwargs):
        captured.append((evasion_enabled, evasion_strategy))
        return {
            "schema_version": "stage6.v1",
            "run_id": "gemini-low-0",
            "status": "success",
            "config": {},
            "timing": {},
            "final_state": {},
            "report": {},
            "error": None,
        }

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", mock_engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])

    artifacts = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low"],
        repeats=1,
        evasion_enabled=True,
        evasion_strategy="prompt_injection",
    )

    assert len(captured) == 1
    assert captured[0] == (True, "prompt_injection")
