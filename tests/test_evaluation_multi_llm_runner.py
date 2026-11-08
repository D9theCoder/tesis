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
            "schema_version": 'matrix-execution',
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


def _completed_artifact(**kwargs):
    return {
        "schema_version": "execution",
        "execution_id": kwargs["execution_id"],
        "run_id": "synthetic-run",
        "status": "success",
        "execution_status": "completed",
        "execution_reason": None,
        "security_outcome": "unconfirmed",
        "security_outcome_reason": {
            "code": "NO_CANDIDATE_CONFIRMATION", "detail": "", "evidence_refs": []},
        "config": {
            "provider": kwargs["llm_provider"], "surface": kwargs["surface"],
            "security_level": kwargs["security_level"], "payload_mode": kwargs["payload_mode"],
            "experiment_condition": kwargs["experiment_condition"],
            "repeat_index": kwargs["repeat_index"],
        },
        "final_state": {}, "timing": {},
        "report": {"summary": {"chain_exploits_achieved": 0,
                               "guardrail_activations": 0,
                               "total_iterations_used": 0,
                               "score_distribution": {}},
                   "module_scores": {}},
    }


def test_scheduler_reports_submitted_and_unstarted_not_directory_allocations(
    monkeypatch, tmp_path,
):
    def engagement(**kwargs):
        return _completed_artifact(**kwargs)

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["openai_compatible"])
    directories: list[str] = []

    def allocate(_coordinate, _index):
        path = tmp_path / f"run-{len(directories) + 1:03d}"
        path.mkdir()
        directories.append(str(path))
        return path

    _, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["openai_compatible"],
        security_levels=["low", "medium"],
        surfaces=["sqli"],
        payload_modes=["static_only"],
        repeats=1,
        include_aggregate=True,
        llm_max_concurrency=1,
        run_output_dir_factory=allocate,
    )

    scheduler = aggregate["scheduler"]
    assert len(directories) == 2
    assert scheduler["planned"] == 2
    assert scheduler["prepared"] == 2
    assert scheduler["submitted"] == 2
    assert scheduler["observed"] == 2
    assert scheduler["completed"] == 2
    assert scheduler["failed"] == 0
    assert scheduler["unstarted"] == 0
    assert aggregate["not_started_runs"] == 0
    assert all(row["state"] == "completed" for row in scheduler["coordinate_states"])


def test_scheduler_exception_retains_submitted_observed_and_unstarted(
    monkeypatch, tmp_path,
):
    import pytest

    calls = {"n": 0}

    def engagement(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _completed_artifact(**kwargs)
        raise RuntimeError("synthetic scheduler failure")

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["openai_compatible"])
    directories: list[str] = []

    def allocate(_coordinate, _index):
        path = tmp_path / f"run-{len(directories) + 1:03d}"
        path.mkdir()
        directories.append(str(path))
        return path

    with pytest.raises(RuntimeError, match="synthetic scheduler failure"):
        run_provider_matrix(
            target_url="http://localhost/dvwa",
            providers=["openai_compatible"],
            security_levels=["low", "medium", "high"],
            surfaces=["sqli"],
            payload_modes=["static_only"],
            repeats=1,
            include_aggregate=True,
            output_dir=str(tmp_path),
            llm_max_concurrency=1,
            run_output_dir_factory=allocate,
        )

    partial = next(tmp_path.glob("*.scheduler-partial.json"))
    import json
    scheduler = json.loads(partial.read_text())["scheduler"]
    assert len(directories) == 3
    assert scheduler["planned"] == 3
    assert scheduler["prepared"] == 3
    assert scheduler["submitted"] == 2  # allocations are not submissions
    assert scheduler["observed"] == 1
    assert scheduler["completed"] == 1
    assert scheduler["failed"] == 1
    assert scheduler["unstarted"] == 1


def test_matrix_passes_the_frozen_plan_identity_to_every_execution(monkeypatch):
    captured = []

    def engagement(**kwargs):
        captured.append(kwargs["research_plan_identity"])
        artifact = _completed_artifact(**kwargs)
        artifact["research_plan_identity"] = kwargs["research_plan_identity"]
        return artifact

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["openai_compatible"])
    identity = {"plan_sha256": "a" * 64, "epoch_id": "offline-epoch"}
    artifacts = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["openai_compatible"],
        security_levels=["low", "medium"],
        surfaces=["sqli"],
        payload_modes=["static_only"],
        repeats=1,
        llm_max_concurrency=1,
        research_plan_identity=identity,
    )
    assert captured == [identity, identity]
    assert [artifact["research_plan_identity"] for artifact in artifacts] == [
        identity, identity]


def test_matrix_refuses_malformed_plan_identity():
    import pytest

    with pytest.raises(ValueError, match="research_plan_identity"):
        run_provider_matrix(
            target_url="http://localhost/dvwa",
            providers=["openai_compatible"],
            security_levels=["low"],
            surfaces=["sqli"],
            payload_modes=["static_only"],
            research_plan_identity={"plan_sha256": "not-a-hash", "epoch_id": "e"},
        )


def test_scheduler_interruption_retains_in_flight_and_unstarted(
    monkeypatch, tmp_path,
):
    calls = {"n": 0}

    def engagement(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _completed_artifact(**kwargs)
        raise KeyboardInterrupt("synthetic interruption")

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["openai_compatible"])
    directories: list[str] = []

    def allocate(_coordinate, _index):
        path = tmp_path / f"run-{len(directories) + 1:03d}"
        path.mkdir()
        directories.append(str(path))
        return path

    artifacts, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["openai_compatible"],
        security_levels=["low", "medium", "high"],
        surfaces=["sqli"],
        payload_modes=["static_only"],
        repeats=1,
        include_aggregate=True,
        output_dir=str(tmp_path),
        llm_max_concurrency=1,
        run_output_dir_factory=allocate,
    )

    scheduler = aggregate["scheduler"]
    assert len(directories) == 3
    assert scheduler["planned"] == 3
    assert scheduler["prepared"] == 3
    assert scheduler["submitted"] == 2
    assert scheduler["observed"] == 2
    assert scheduler["completed"] == 1
    assert scheduler["interrupted"] == 1
    assert scheduler["failed"] == 0
    assert scheduler["unstarted"] == 1
    assert [row["state"] for row in scheduler["coordinate_states"]] == [
        "completed", "interrupted", "unstarted"]
    assert any(artifact.get("status") == "cancelled" for artifact in artifacts)


def test_fully_reconciled_grid_with_failed_child_stays_failed(
    monkeypatch, tmp_path,
):
    calls = {"n": 0}

    def engagement(**kwargs):
        calls["n"] += 1
        artifact = _completed_artifact(**kwargs)
        if calls["n"] == 2:
            artifact.update(status="error", execution_status="failed",
                            failure={"failure_class": "RUNTIME_FAILURE", "error": "synthetic"},
                            execution_reason={"code": "RUNTIME_FAILURE", "detail": "",
                                              "evidence_refs": []})
        return artifact

    monkeypatch.setattr("evaluation.multi_llm_runner.run_single_engagement", engagement)
    monkeypatch.setattr("evaluation.multi_llm_runner.SUPPORTED_PROVIDERS", ["openai_compatible"])

    artifacts, aggregate = run_provider_matrix(
        target_url="http://localhost/dvwa",
        providers=["openai_compatible"],
        security_levels=["low", "medium"],
        surfaces=["sqli"],
        payload_modes=["static_only"],
        repeats=1,
        include_aggregate=True,
        llm_max_concurrency=1,
    )

    assert len(artifacts) == 2
    assert aggregate["status"] == "error"
    assert aggregate["execution_status"] == "failed"
    assert aggregate["scheduler"]["completed"] == 1
    assert aggregate["scheduler"]["failed"] == 1
    assert aggregate["scheduler"]["unstarted"] == 0
