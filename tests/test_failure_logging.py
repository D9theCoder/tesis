import json

from evaluation.failure_logger import write_failure_artifact
from evaluation.runner import run_single_engagement


def test_failure_artifact_written_on_runner_error(monkeypatch, tmp_path):
    def fail_framework(llm_provider):
        raise RuntimeError("boom")

    monkeypatch.setattr("evaluation.runner.build_framework", fail_framework)

    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        max_iterations=5,
        repeat_index=0,
        enriched_reporting=True,
        output_dir=str(tmp_path),
    )

    assert artifact["status"] == "error"
    failure_path = tmp_path / "gemini-sqli-low-0.failure.json"
    assert failure_path.exists()


def test_failure_artifact_contains_recent_events_tail(tmp_path):
    path = write_failure_artifact(
        output_dir=tmp_path,
        run_id="sample",
        error="RuntimeError: boom",
        final_state={"iteration_count": 2},
        recent_events=[{"seq": 3}, {"seq": 4}],
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["run_id"] == "sample"
    assert payload["recent_events"][-1]["seq"] == 4
