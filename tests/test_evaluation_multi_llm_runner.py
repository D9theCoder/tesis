from evaluation.multi_llm_runner import run_provider_matrix


def test_run_provider_matrix_skips_unsupported_provider(monkeypatch):
    def fail_engagement(**kwargs):
        raise RuntimeError("should not be called for unsupported provider")

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", fail_engagement)

    artifacts = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["nonexistent_provider"],
        security_levels=["low"],
        surfaces=["sqli"],
        repeats=1,
    )

    assert len(artifacts) == 2
    assert all(item["status"] == "skipped" for item in artifacts)
    assert all("Unsupported provider" in item["error"] for item in artifacts)


def test_run_provider_matrix_deterministic_ordering(monkeypatch):
    call_order = []

    def track_engagement(
        *,
        target_url,
        security_level,
        llm_provider,
        surface,
        max_iterations,
        repeat_index,
        stop_policy="impact",
        coverage_target=0.70,
        enriched_reporting=False,
        diagnose=False,
        output_dir=None,
        evasion_enabled=False,
        evasion_mode="reactive",
        evasion_max_retries=3,
        evasion_cooldown_threshold=5,
        live_display=False,
        model_config=None,
    ):
        call_order.append((llm_provider, surface, security_level, repeat_index, evasion_enabled, evasion_mode))
        return {
            "schema_version": "stage8.v1",
            "run_id": f"{llm_provider}-{surface}-{security_level}-{repeat_index}",
            "status": "success",
            "config": {},
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
            "error": None,
        }

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", track_engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])

    artifacts = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["high", "low", "medium"],
        surfaces=["sqli"],
        repeats=2,
    )

    # Levels must be sorted alphabetically: high, low, medium.
    # Payload modes default to static_only + hybrid, so each repeat is invoked twice.
    expected = [
        ("gemini", "sqli", "high", 0, False, "reactive"),
        ("gemini", "sqli", "high", 1, False, "reactive"),
        ("gemini", "sqli", "high", 0, False, "reactive"),
        ("gemini", "sqli", "high", 1, False, "reactive"),
        ("gemini", "sqli", "low", 0, False, "reactive"),
        ("gemini", "sqli", "low", 1, False, "reactive"),
        ("gemini", "sqli", "low", 0, False, "reactive"),
        ("gemini", "sqli", "low", 1, False, "reactive"),
        ("gemini", "sqli", "medium", 0, False, "reactive"),
        ("gemini", "sqli", "medium", 1, False, "reactive"),
        ("gemini", "sqli", "medium", 0, False, "reactive"),
        ("gemini", "sqli", "medium", 1, False, "reactive"),
    ]
    assert call_order == expected


def test_run_provider_matrix_include_aggregate(monkeypatch):
    def mock_engagement(**kwargs):
        return {
            "schema_version": "stage8.v1",
            "run_id": "gemini-sqli-low-0",
            "status": "success",
            "config": {"provider": "gemini", "security_level": "low", "surface": "sqli"},
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
            "error": None,
        }

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", mock_engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])

    artifacts, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low"],
        surfaces=["sqli"],
        repeats=1,
        include_aggregate=True,
    )

    assert isinstance(artifacts, list)
    assert isinstance(aggregate, dict)
    assert "by_provider" in aggregate
    assert "by_provider_surface_level" in aggregate
    assert "totals" in aggregate


def test_run_provider_matrix_zero_success_avg_score_is_zero(monkeypatch):
    def failed_engagement(**kwargs):
        return {
            "schema_version": "stage8.v1",
            "run_id": "gemini-sqli-low-0",
            "status": "error",
            "config": {"provider": "gemini", "surface": "sqli", "security_level": "low"},
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
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])

    _, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low"],
        surfaces=["sqli"],
        repeats=1,
        include_aggregate=True,
    )

    assert aggregate["by_provider"]["gemini"]["avg_score"] == 0.0
    assert aggregate["by_provider"]["gemini"]["guardrail_per_iteration"] == 0.0


def test_run_provider_matrix_evasion_forwarding(monkeypatch):
    captured = []

    def mock_engagement(*, evasion_enabled, evasion_mode, **kwargs):
        captured.append((evasion_enabled, evasion_mode))
        return {
            "schema_version": "stage8.v1",
            "run_id": "gemini-sqli-low-0",
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
        surfaces=["sqli"],
        repeats=1,
        evasion_enabled=True,
        evasion_mode="proactive",
    )

    assert len(captured) == 2
    assert captured == [(True, "proactive"), (True, "proactive")]
