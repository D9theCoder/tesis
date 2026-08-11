"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from evaluation.multi_llm_runner import run_provider_matrix
from tesis.runtime_events import CancellationToken, CollectingEventSink


def test_run_provider_matrix_skips_unsupported_provider(monkeypatch):
    """Verifies run provider matrix skips unsupported provider behavior."""
    def fail_engagement(**kwargs):
        """Supports regression tests for test evaluation multi llm runner."""
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
    """Verifies run provider matrix deterministic ordering behavior."""
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
        """Supports regression tests for test evaluation multi llm runner."""
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
    """Verifies run provider matrix include aggregate behavior."""
    def mock_engagement(**kwargs):
        """Supports regression tests for test evaluation multi llm runner."""
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
    """Verifies run provider matrix zero success avg score is zero behavior."""
    def failed_engagement(**kwargs):
        """Supports regression tests for test evaluation multi llm runner."""
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


def test_run_provider_matrix_aggregate_reports_error_for_any_failed_child(monkeypatch):
    def engagement_with_one_failure(**kwargs):
        status = "error" if kwargs["security_level"] == "low" else "success"
        return {
            "schema_version": "tui.v1",
            "run_id": f"{kwargs['security_level']}-run",
            "status": status,
            "config": {
                "provider": kwargs["llm_provider"],
                "surface": kwargs["surface"],
                "security_level": kwargs["security_level"],
                "payload_mode": kwargs["payload_mode"],
            },
            "timing": {},
            "final_state": {},
            "report": {},
            "error": "child failed" if status == "error" else None,
        }

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", engagement_with_one_failure)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])

    artifacts, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low", "medium"],
        surfaces=["sqli"],
        payload_modes=["hybrid"],
        repeats=1,
        include_aggregate=True,
    )

    assert [artifact["status"] for artifact in artifacts] == ["error", "success"]
    assert aggregate["status"] == "error"
    assert aggregate["totals"]["error_runs"] == 1


def test_run_provider_matrix_aggregate_cancellation_takes_precedence_over_child_error(
    monkeypatch,
):
    token = CancellationToken()

    def cancel_after_child_failure(**kwargs):
        token.cancel("stop matrix")
        return {
            "schema_version": "tui.v1",
            "run_id": "failed-before-cancel",
            "status": "error",
            "config": {
                "provider": kwargs["llm_provider"],
                "surface": kwargs["surface"],
                "security_level": kwargs["security_level"],
                "payload_mode": kwargs["payload_mode"],
            },
            "timing": {},
            "final_state": {},
            "report": {},
            "error": "child failed before cancellation",
        }

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", cancel_after_child_failure)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])

    _, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low", "medium"],
        surfaces=["sqli"],
        payload_modes=["hybrid"],
        repeats=1,
        include_aggregate=True,
        cancellation_token=token,
    )

    assert aggregate["status"] == "cancelled"
    assert aggregate["totals"]["error_runs"] == 1


def test_run_provider_matrix_evasion_forwarding(monkeypatch):
    """Verifies run provider matrix evasion forwarding behavior."""
    captured = []

    def mock_engagement(*, evasion_enabled, evasion_mode, **kwargs):
        """Supports regression tests for test evaluation multi llm runner."""
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


def test_run_provider_matrix_expands_conditions_methods_and_guardrails(monkeypatch):
    """The production matrix can cover every supported scenario axis explicitly."""
    captured: list[dict] = []

    def mock_engagement(**kwargs):
        captured.append(kwargs)
        return {
            "schema_version": "tui.v1",
            "run_id": "coordinate",
            "status": "success",
            "config": {
                "provider": kwargs["llm_provider"],
                "surface": kwargs["surface"],
                "security_level": kwargs["security_level"],
                "payload_mode": kwargs["payload_mode"],
                "experiment_condition": kwargs["experiment_condition"],
                "target_method": kwargs["target_method"],
            },
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
        payload_modes=["static_only"],
        repeats=1,
        experiment_conditions=["linear_hybrid", "akg_guided_hybrid"],
        method_level_matrix=True,
        guardrail_configurations=[(False, "reactive"), (True, "reactive")],
    )

    # Four SQLi methods × two thesis conditions × two guardrail cases.
    assert len(artifacts) == len(captured) == 16
    assert {item["target_method"] for item in captured} == {
        "sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind",
    }
    assert {item["experiment_condition"] for item in captured} == {
        "linear_hybrid", "akg_guided_hybrid",
    }
    assert {(item["evasion_enabled"], item["evasion_mode"]) for item in captured} == {
        (False, "reactive"), (True, "reactive"),
    }


def test_run_provider_matrix_rejects_cross_surface_target_method():
    """A method-level run cannot silently evaluate a method on another surface."""
    import pytest

    with pytest.raises(ValueError, match="target_method"):
        run_provider_matrix(
            target_url="http://localhost/dvwa",
            providers=["gemini"],
            security_levels=["low"],
            surfaces=["access_control"],
            payload_modes=["static_only"],
            target_method="sqli_union",
        )


def test_matrix_cancellation_stops_later_coordinates_and_persists_aggregate(monkeypatch, tmp_path):
    token = CancellationToken()
    calls: list[str] = []

    def cancel_first(**kwargs):
        calls.append(kwargs["security_level"])
        token.cancel("stop matrix")
        return {
            "schema_version": "tui.v1",
            "execution_id": kwargs["execution_id"],
            "run_id": "first",
            "status": "cancelled",
            "config": {
                "provider": kwargs["llm_provider"],
                "surface": kwargs["surface"],
                "security_level": kwargs["security_level"],
                "payload_mode": kwargs["payload_mode"],
            },
            "timing": {},
            "final_state": {},
            "report": {},
        }

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", cancel_first)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])
    sink = CollectingEventSink()

    artifacts, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low", "medium"],
        surfaces=["sqli"],
        payload_modes=["hybrid"],
        repeats=2,
        output_dir=str(tmp_path),
        include_aggregate=True,
        event_sink=sink,
        cancellation_token=token,
    )

    assert len(calls) == 1
    assert len(artifacts) == 1
    assert aggregate["status"] == "cancelled"
    assert aggregate["totals"]["cancelled_runs"] == 1
    assert (tmp_path / f"{aggregate['execution_id']}.matrix.json").exists()
    assert any(event.event_type == "matrix.cancelled" for event in sink.events)
