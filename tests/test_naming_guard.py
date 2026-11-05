"""Naming lint distinguishes active producers from data and external facts."""
from pathlib import Path

import pytest

from tesis.naming_guard import check_repository, inspect_file, main


@pytest.mark.parametrize("source", [
    "def score_v2(): pass\n",
    "from evaluation.scoring_v4_matrix import build_plan\n",
    "RUBRIC_VERSION = 'scoring.v4'\n",
    "receipt = {'schema_version': 'receipt.v1'}\n",
    "receipt = dict(policy_version='policy.v3')\n",
    "def emit(*, schema_version='receipt.v1'): pass\n",
    "parser.add_parser('score-v2')\n",
    "receipt = {'schema_version': f'receipt.v{number}'}\n",
    "CATALOG_VERSION = '2.0.0'\n",
    "schema = artifact.get('schema_version', 'receipt.v1')\n",
    "SUPPORTED_SCHEMA_VERSIONS = ('receipt.v1',)\n",
    "_REFERENCE = 'checkpoint.v1'\n",
    "manifest = {'format': 'checkpoint.v1'}\n",
    "SCHEMA_VERSION = 'receipt.v.x'\n",
])
def test_guard_rejects_active_versioned_names(tmp_path, source):
    path = tmp_path / "producer.py"
    path.write_text(source)
    assert inspect_file(path)


def test_guard_rejects_versioned_file_name(tmp_path):
    path = tmp_path / "scorer_v3.py"
    path.write_text("def score(): return 3\n")
    assert any(row.location == "file name" for row in inspect_file(path))


def test_guard_allows_payloads_external_models_numbers_and_read_only_historical_keys(tmp_path):
    path = tmp_path / "reader.py"
    path.write_text(
        "payload = 'route.v1 AND sleep(2)'\n"
        "model = 'DeepSeek-V4.1-Flash-1017'\n"
        "models = {'model_name': 'DeepSeek-V4.1-Flash-1017'}\n"
        "historical_labels = {'scoring.v4': 'thesis-scoring'}\n"
        "if artifact['schema_version'] == 'receipt.v1': pass\n"
        "elapsed = 1.24\n"
        "SCORE_WEIGHTS = {'Smethod': 0.20, 'Sexploit': 0.30}\n"
    )
    assert inspect_file(path) == []


def test_guard_rejects_configuration_contracts_but_not_provider_versions(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "model: DeepSeek-V4.1-Flash-1017\n"
        "api_version: v1\n"
        "budget: 10\n"
        "policy_epoch:\n  schema_version: epoch.v2\n"
    )
    findings = inspect_file(path)
    assert len(findings) == 1
    assert findings[0].value == "epoch.v2"


def test_repository_guard_excludes_immutable_results_and_historical_inputs(tmp_path):
    for relative in (
        "results/runs/old/receipt.json",
        "config/research/autoresearch-ranking-draft-2026-10-31.json",
        "docs/completed/handoff.md",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"schema_version": "historical.v1"}')
    source = tmp_path / "core" / "contracts.py"
    source.parent.mkdir()
    source.write_text("RUBRIC_VERSION = 'thesis-scoring'\n")
    assert check_repository(tmp_path) == []
    assert main(["--root", str(tmp_path)]) == 0
    source.write_text("RUBRIC_VERSION = 'scoring.v4'\n")
    assert main(["--root", str(tmp_path)]) == 1
