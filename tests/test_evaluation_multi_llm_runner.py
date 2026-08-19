"""Regression tests for the DVWA LangGraph framework.

This module verifies current behavior for state handling, routing, payloads,
LLM adapters, agents, evaluation, or CLI integration without changing runtime
code."""
from evaluation.multi_llm_runner import _build_matrix_aggregate, run_provider_matrix
from tesis.runtime_events import CancellationToken, CollectingEventSink
import threading
import time


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


def test_skipped_artifacts_preserve_runtime_metadata_and_empty_contract(monkeypatch):
    def fail_engagement(**kwargs):
        raise RuntimeError("should not be called for unsupported provider")

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", fail_engagement)

    artifacts = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["nonexistent_provider"],
        security_levels=["low"],
        surfaces=["sqli"],
        payload_modes=["hybrid"],
        repeats=1,
        llm_max_concurrency=2,
        llm_cache_scope="run",
        llm_role_configs={
            "orchestrator": {
                "model_profile": "openai_compatible",
                "model_name": "orchestrator-test",
            },
        },
        model_configs={
            "openai_compatible": {
                "model_name": "provider-test",
                "api_key": "secret-value",
            },
        },
    )

    assert len(artifacts) == 1
    artifact = artifacts[0]
    required = {
        "llm_activity",
        "llm_performance",
        "llm_performance_summary",
        "viable_methods",
        "akg_path",
        "payload_candidates",
        "payload_validation_results",
        "payload_provenance",
        "execution_log",
        "response_evidence",
        "timing_evidence",
        "verifier_decision",
        "confirmed_vulns",
        "achieved_outcomes",
        "guardrail_activations",
        "invalid_json_events",
        "fallback_events",
        "containment_events",
        "method_score",
        "payload_scores",
        "exploitation_score",
        "chain_score",
        "output_score",
        "composite_score",
        "final_state",
    }
    assert required <= artifact.keys()
    assert artifact["config"]["llm_max_concurrency"] == 2
    assert artifact["config"]["llm_cache_scope"] == "run"
    assert artifact["config"]["llm_role_configs"]["orchestrator"]["model_name"] == (
        "orchestrator-test"
    )
    assert "secret-value" not in str(artifact["config"])
    assert artifact["llm_activity"] == {"started": 0, "completed": 0, "failed": 0, "tokens": 0}
    assert artifact["llm_performance_summary"]["calls"] == 0
    assert artifact["invalid_json_events"] == []
    assert artifact["final_state"]["containment_events"] == []


def test_cancelled_artifacts_preserve_runtime_metadata_and_empty_contract(monkeypatch):
    def fail_engagement(**kwargs):
        raise RuntimeError("worker stopped")

    def interrupt_wait(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", fail_engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.wait", interrupt_wait)

    artifacts, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low"],
        surfaces=["sqli"],
        payload_modes=["hybrid"],
        repeats=1,
        llm_max_concurrency=2,
        llm_cache_scope="none",
        llm_role_configs={"payload_generator": {"model_profile": "gemini"}},
        include_aggregate=True,
    )

    assert aggregate["status"] == "cancelled"
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact["status"] == "cancelled"
    assert artifact["incomplete_reason"] == "CANCELLED"
    assert artifact["config"]["llm_max_concurrency"] == 2
    assert artifact["config"]["llm_cache_scope"] == "none"
    assert artifact["config"]["llm_role_configs"]["payload_generator"]["model_profile"] == "gemini"
    assert artifact["llm_performance"] == []
    assert artifact["fallback_events"] == []
    assert artifact["final_state"]["invalid_json_events"] == []


def test_matrix_aggregate_counts_audit_events_from_every_status():
    artifacts = [
        {
            "status": "skipped",
            "config": {"provider": "gemini", "surface": "sqli", "security_level": "low"},
            "invalid_json_events": [{"event": "invalid"}],
            "guardrail_activations": [{"event": "guardrail"}],
            "containment_events": [],
            "fallback_events": [{"event": "fallback"}],
        },
        {
            "status": "cancelled",
            "config": {"provider": "gemini", "surface": "sqli", "security_level": "low"},
            "final_state": {
                "invalid_json_events": [{"event": "invalid"}],
                "guardrail_activations": [{"event": "guardrail"}],
                "containment_events": [{"event": "containment"}],
                "fallback_events": [],
            },
        },
        {
            "status": "error",
            "config": {"provider": "gemini", "surface": "sqli", "security_level": "low"},
            "report": {"summary": {"guardrail_activations": 2}},
        },
        {
            "status": "success",
            "config": {"provider": "gemini", "surface": "sqli", "security_level": "low"},
            "invalid_json_events": [{"event": "invalid"}],
            "guardrail_activations": [],
            "containment_events": [{"event": "containment"}],
            "fallback_events": [{"event": "fallback"}],
        },
    ]

    aggregate = _build_matrix_aggregate(artifacts)

    expected = {
        "invalid_json_events": 3,
        "fallback_events": 2,
        "containment_events": 2,
        "containment_failures": 0,
        "guardrail_activations": 4,
    }
    assert aggregate["audit_totals"] == expected
    assert all(aggregate["totals"][key] == value for key, value in expected.items())
    level = aggregate["by_provider"]["gemini"]
    assert level["guardrail_activations"] == 4
    assert level["containment_events"] == 2


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


def test_matrix_keyboard_interrupt_during_wait_drains_workers_and_persists_partial_aggregate(
    monkeypatch, tmp_path,
):
    token = CancellationToken()

    def cancellable_engagement(**kwargs):
        while not token.is_cancelled:
            time.sleep(0.001)
        return {
            "schema_version": "tui.v1",
            "execution_id": kwargs["execution_id"],
            "run_id": "cancelled-worker",
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

    def interrupt_wait(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", cancellable_engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])
    monkeypatch.setattr("evaluation.multi_llm_runner.wait", interrupt_wait)

    artifacts, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low", "medium"],
        surfaces=["sqli"],
        payload_modes=["hybrid"],
        repeats=1,
        llm_max_concurrency=1,
        output_dir=str(tmp_path),
        include_aggregate=True,
        cancellation_token=token,
    )

    assert token.is_cancelled
    assert aggregate["status"] == "cancelled"
    assert len(artifacts) == 1
    assert aggregate["cancellation"]["reason"] == "keyboard interrupt"
    assert aggregate["cancellation"]["not_started_runs"] == 1
    assert (tmp_path / f"{aggregate['execution_id']}.matrix.json").exists()


def test_matrix_workers_overlap_and_store_artifacts_in_coordinate_order(monkeypatch):
    active = 0
    peak = 0
    lock = threading.Lock()

    def delayed_engagement(**kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        # The canonical first coordinate finishes last.
        time.sleep(0.06 if kwargs["security_level"] == "high" else 0.01)
        with lock:
            active -= 1
        return {
            "schema_version": "tui.v1",
            "execution_id": kwargs["execution_id"],
            "run_id": kwargs["security_level"],
            "status": "success",
            "config": {
                "provider": kwargs["llm_provider"],
                "surface": kwargs["surface"],
                "security_level": kwargs["security_level"],
                "payload_mode": kwargs["payload_mode"],
            },
            "llm_performance": [],
            "timing": {},
            "final_state": {},
            "report": {},
        }

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", delayed_engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["gemini"])

    artifacts = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["gemini"],
        security_levels=["low", "high"],
        surfaces=["sqli"],
        payload_modes=["hybrid"],
        repeats=1,
        llm_max_concurrency=2,
    )

    assert peak == 2
    assert [artifact["config"]["security_level"] for artifact in artifacts] == ["high", "low"]
