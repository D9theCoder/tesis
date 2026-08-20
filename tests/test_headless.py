"""Offline contracts for the terminal execution layer."""

from __future__ import annotations

import json
from pathlib import Path

from tesis.headless import run_headless
from tesis.runtime_events import RunEvent


def _single_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: gemini\n"
        "level: low\n"
        "surface: sqli\n"
        "payload_mode: static_only\n"
        "models:\n"
        "  gemini:\n"
        "    model_name: test-model\n"
        "    api_key: provider-secret-key\n"
        f"output_dir: {tmp_path / 'results'}\n",
        encoding="utf-8",
    )
    return config_path


def test_headless_single_run_allocates_dated_layout(monkeypatch, tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: gemini\n"
        "level: low\n"
        "surface: sqli\n"
        "payload_mode: static_only\n"
        f"output_dir: {tmp_path / 'results'}\n",
        encoding="utf-8",
    )

    def fake_run(**kwargs):
        output_dir = Path(kwargs["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "exec-test.json").write_text(
            json.dumps({"execution_id": "exec-test", "run_id": "run-test", "status": "success"}),
            encoding="utf-8",
        )
        return {
            "execution_id": "exec-test",
            "run_id": "run-test",
            "status": "success",
            "config": {
                "provider": kwargs["llm_provider"],
                "surface": kwargs["surface"],
                "security_level": kwargs["security_level"],
                "payload_mode": kwargs["payload_mode"],
            },
        }

    monkeypatch.setattr("tesis.headless.run_single_engagement", fake_run)

    code, result, root = run_headless(config_path=str(config_path), cli_args={})

    assert code == 0
    assert result["status"] == "success"
    assert root.name.startswith("single-run-2026-")
    manifest = json.loads((root / "experiment.manifest.json").read_text(encoding="utf-8"))
    assert manifest["mode"] == "single-run"
    assert manifest["runs"][0]["artifact"] == "exec-test.json"


def test_headless_single_run_writes_active_then_terminal_descriptor_and_journal(
    monkeypatch, tmp_path: Path
) -> None:
    config_path = _single_config(tmp_path)
    status_at_invoke: dict[str, str] = {}

    def fake_run(**kwargs):
        output_dir = Path(kwargs["output_dir"])
        execution_id = kwargs["execution_id"]
        # Active descriptor must exist before the runner is invoked.
        status_at_invoke["active"] = json.loads(
            (output_dir / "runtime.json").read_text(encoding="utf-8")
        )["status"]
        sink = kwargs["event_sink"]
        sink.emit(RunEvent("run.started", execution_id=execution_id, run_id="run-j", data={"n": 1}))
        sink.emit(RunEvent("graph.node.started", data={"node": "sqli"}))
        return {
            "execution_id": execution_id,
            "run_id": "run-j",
            "status": "success",
            "config": {"provider": "gemini", "surface": "sqli", "security_level": "low"},
        }

    monkeypatch.setattr("tesis.headless.run_single_engagement", fake_run)

    code, result, root = run_headless(config_path=str(config_path), cli_args={})

    assert code == 0
    assert status_at_invoke["active"] == "active"

    desc = json.loads((root / "runtime.json").read_text(encoding="utf-8"))
    assert desc["status"] == "finished"
    assert desc["execution_id"] == result["execution_id"]
    assert desc["run_id"] == "run-j"
    assert desc["mode"] == "single-run"

    journal_path = root / "runtime.events.jsonl"
    lines = [line for line in journal_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    types = [json.loads(line)["event_type"] for line in lines]
    assert "run.started" in types
    assert "graph.node.started" in types
    # Secrets must never reach the journal.
    assert "provider-secret-key" not in journal_path.read_text(encoding="utf-8")

    assert (root / "akg.snapshot.json").exists()
    akg = json.loads((root / "akg.snapshot.json").read_text(encoding="utf-8"))
    assert akg["schema_version"] == "akg-snapshot.v1"
    assert akg["node_count"] == len(akg["nodes"])
    assert akg["edge_count"] == len(akg["edges"])


def test_headless_runner_exception_writes_terminal_failed_descriptor(
    monkeypatch, tmp_path: Path
) -> None:
    config_path = _single_config(tmp_path)

    def failing_run(**_kwargs):
        raise RuntimeError("provider boom")

    monkeypatch.setattr("tesis.headless.run_single_engagement", failing_run)

    code, result, root = run_headless(config_path=str(config_path), cli_args={})

    assert code == 1
    assert result["status"] == "error"
    assert "provider boom" in result["error"]

    desc = json.loads((root / "runtime.json").read_text(encoding="utf-8"))
    assert desc["status"] == "failed"
    # Journal exists and closed safely even on failure.
    assert (root / "runtime.events.jsonl").exists()
    assert (root / "akg.snapshot.json").exists()


def test_headless_keyboard_interrupt_persists_cancelled_matrix(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: gemini\n"
        "level: low\n"
        "matrix: true\n"
        "providers: [gemini]\n"
        "levels: [low]\n"
        "surfaces: [sqli]\n"
        "payload_modes: [hybrid]\n"
        "repeats: 1\n"
        f"output_dir: {tmp_path / 'results'}\n",
        encoding="utf-8",
    )

    def interrupting_matrix(**_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("tesis.headless.run_provider_matrix", interrupting_matrix)

    code, result, root = run_headless(config_path=str(config_path), cli_args={})

    assert code == 0
    assert result["status"] == "cancelled"
    aggregate_path = root / f"{result['execution_id']}.matrix.json"
    assert aggregate_path.exists()
    manifest = json.loads((root / "experiment.manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "cancelled"
    assert manifest["aggregate"]["artifact"] == aggregate_path.name

    # Cancellation still lands a terminal descriptor.
    desc = json.loads((root / "runtime.json").read_text(encoding="utf-8"))
    assert desc["status"] == "cancelled"
    assert (root / "runtime.events.jsonl").exists()
    assert (root / "akg.snapshot.json").exists()
