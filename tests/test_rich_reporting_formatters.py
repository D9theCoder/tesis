import json

from tesis.report_formatters import format_rich_report_sections, parse_artifact_or_matrix


def test_report_includes_prompt_response_section_when_rich_sidecar_present(tmp_path):
    artifact = {
        "run_id": "gemini-low-0",
        "report": {"summary": {}},
    }
    rich = {
        "schema_version": "stage7.rich.v1",
        "events_count": 3,
        "prompt_response_hashes": [
            {"event_type": "orchestrator.prompt.generated", "hash": "sha256:abc"},
        ],
    }

    artifact_path = tmp_path / "gemini-low-0.json"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
    (tmp_path / "gemini-low-0.rich.json").write_text(json.dumps(rich), encoding="utf-8")

    data = parse_artifact_or_matrix(artifact_path)
    rendered = format_rich_report_sections(data)
    assert "Rich Trace Summary" in rendered
    assert "orchestrator.prompt.generated" in rendered


def test_report_includes_diagnostics_when_present():
    data = {
        "rich_sidecar": {
            "schema_version": "stage7.rich.v1",
            "events_count": 1,
            "prompt_response_hashes": [],
        },
        "report": {
            "summary": {
                "diagnostics": {
                    "coverage_ratio": 0.2,
                    "flags": ["low_module_coverage"],
                }
            }
        },
    }

    rendered = format_rich_report_sections(data)
    assert "Diagnostics" in rendered
    assert "low_module_coverage" in rendered
