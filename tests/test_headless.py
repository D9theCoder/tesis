"""Offline contracts for the terminal execution layer."""

from __future__ import annotations

import json
from pathlib import Path

from tesis.headless import run_headless


def _single_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target_url: http://localhost/dvwa\n"
        "provider: openai_compatible\n"
        "level: low\n"
        "surface: sqli\n"
        "payload_mode: static_only\n"
        "models:\n"
        "  openai_compatible:\n"
        "    model_name: test-model\n"
        "    base_url: http://localhost:9999/v1\n"
        "    api_key: provider-secret-key\n"
        f"output_dir: {tmp_path / 'results'}\n",
        encoding="utf-8",
    )
    return config_path


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
