"""Opt-in, saved-artifact CLI publication E2E; no HTTP/provider execution."""
from hashlib import sha256
import json

from evaluation.reporter import write_json_report
from evaluation.thesis_scoring import finalize_reviews
from tesis.cli import main
from tests.test_execution_security_status import evidence_artifact


def test_saved_source_review_export_cli_preserves_original_bytes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Code epoch paths are package-relative, so export works outside the checkout.
    source = tmp_path / "saved.json"
    write_json_report(source, evidence_artifact())
    digest = sha256(source.read_bytes()).hexdigest()
    reviews = tmp_path / "review-epoch"
    finalize_reviews(source, [], output_dir=reviews, isolated_output=True)
    output = tmp_path / "results" / "observer.json"
    assert main(["export-observer", "--source-root", f"saved={source}",
                 "--review-root", f"epoch={reviews}", "--output", str(output)]) == 0
    projection = json.loads(output.read_bytes())
    row = projection["runs"][0]
    assert row["source"]["sha256"] == digest == sha256(source.read_bytes()).hexdigest()
    assert row["thesis_review"]["human"]["status"] == "pending"
    assert row["thesis_review"]["human"]["Srun_final"] is None
    assert projection["coverage"]["completed_runs"] == 1
    assert not list(output.parent.glob("*.tmp"))
