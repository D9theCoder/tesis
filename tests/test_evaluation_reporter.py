import json
from pathlib import Path

from evaluation.reporter import build_markdown_summary, write_json_report, write_markdown_report


def test_markdown_summary_contains_totals():
    text = build_markdown_summary(
        {
            "totals": {
                "total_runs": 9,
                "successful_runs": 8,
                "error_runs": 1,
                "skipped_runs": 0,
            }
        }
    )
    assert "Total runs: 9" in text
    assert "Successful runs: 8" in text


def test_write_json_report_round_trip(tmp_path):
    payload = {"schema_version": "stage6.v1", "status": "success"}
    out = write_json_report(tmp_path / "report.json", payload)
    assert out.exists()
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["status"] == "success"


def test_write_markdown_report_creates_file(tmp_path):
    aggregate = {
        "totals": {
            "total_runs": 3,
            "successful_runs": 2,
            "error_runs": 1,
            "skipped_runs": 0,
        }
    }
    out = write_markdown_report(tmp_path / "summary.md", aggregate)
    assert out.exists()
    assert "Total runs: 3" in out.read_text(encoding="utf-8")
