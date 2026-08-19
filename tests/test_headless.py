"""Offline contracts for the terminal execution layer."""

from __future__ import annotations

import json
from pathlib import Path

from tesis.headless import run_headless


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
