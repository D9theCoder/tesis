from hashlib import sha256
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from evaluation.scoring_v4_matrix import (
    _apply_evaluator_budget, _fixture_policy_pin, _planned_coordinates,
    _validate_output_epoch,
)


@pytest.fixture
def offline_matrix_plan(monkeypatch, tmp_path):
    import evaluation.scoring_v4_matrix as matrix

    for key in os.environ:
        if key.startswith('TESIS_'):
            monkeypatch.delenv(key)
    config_path = tmp_path / 'config.yaml'
    config_path.write_text('''target_url: http://localhost/dvwa
provider: openai_compatible
guardrail_retry_enabled: false
default_max_iterations: 10
dvwa_password: fixture-dvwa-secret
models:
  openai_compatible:
    model_name: fixture-model
    api_key: fixture-provider-secret
    base_url: http://localhost:8000/v1
scoring_evaluator:
  provider: openai_compatible
  model: fixture-model
  max_attempts: 2
  max_tokens: 1024
  timeout: 60
''')
    monkeypatch.setattr(matrix, '__file__', str(tmp_path / 'evaluation' / 'scoring_v4_matrix.py'))
    # Only external research pins are fixtures; environment resolution and
    # frozen-plan serialization/verification use the production implementation.
    pins = {'target': {}, 'profile': {}, 'oracle_sources': [],
        'fixture_id': None, 'protocol_version': None, 'evaluator': {}}
    monkeypatch.setattr(matrix, '_validate_config', lambda config: dict(pins))
    monkeypatch.setattr(matrix, '_source_hashes', lambda root: {'runtime.py': 'unchanged'})
    policy = tmp_path / 'policy.json'
    monkeypatch.setattr(matrix, '_fixture_policy_pin', lambda path, **kwargs: {
        'path': str(policy), 'sha256': 'unchanged'})
    epoch = tmp_path / 'results' / 'validation' / 'scoring-v4-remediation-review-controls'
    plan = matrix.create_plan(config_path, epoch, fixture_policy_evidence=policy,
        evaluator_max_tokens_override=4096)
    return matrix, plan, epoch / 'pre-run-manifest.json'


def test_matrix_frozen_settings_are_sanitized_and_include_effective_budget(offline_matrix_plan):
    matrix, plan, manifest = offline_matrix_plan
    verified, config, epoch = matrix._verify_plan(manifest)

    assert verified == plan
    assert config.iterations == plan['resolved_execution_settings']['iterations'] == 10
    assert plan['resolved_execution_settings']['scoring_evaluator']['max_tokens'] == 4096
    assert 'fixture-dvwa-secret' not in manifest.read_text()
    assert 'fixture-provider-secret' not in manifest.read_text()
    assert not (epoch / 'matrix-run-start.json').exists()


@pytest.mark.parametrize('variable,value', [
    ('TESIS_MAX_ITERATIONS', '11'),
    ('TESIS_GUARDRAIL_RETRY_ENABLED', 'true'),
    ('TESIS_CANDIDATE_BUDGET', '6'),
    ('TESIS_GUARDRAIL_RETRY_MAX', '4'),
])
def test_matrix_environment_drift_stops_before_launch(monkeypatch, offline_matrix_plan, variable, value):
    matrix, plan, manifest = offline_matrix_plan
    monkeypatch.setenv(variable, value)
    _, current = matrix._load_snapshot(Path(plan['input_hashes']['config']['path']),
        Path(plan['repository_root']), evaluator_max_tokens_override=4096)
    assert current['pins'] == plan['pins']
    assert current['input_hashes'] == plan['input_hashes']
    assert current['source_hashes'] == plan['source_hashes']
    assert current['config_fingerprint'] != plan['config_fingerprint']

    with pytest.raises(ValueError, match='Resolved execution settings changed'):
        matrix.run_plan(manifest)
    assert list(manifest.parent.iterdir()) == [manifest]


def test_legacy_matrix_plan_without_resolved_settings_requires_replanning(offline_matrix_plan):
    matrix, plan, manifest = offline_matrix_plan
    plan.pop('resolved_execution_settings')
    plan['plan_sha256'] = matrix._canonical_hash({
        key: value for key, value in plan.items() if key != 'plan_sha256'})
    manifest.write_text(json.dumps(plan))

    with pytest.raises(ValueError, match='were not frozen'):
        matrix._verify_plan(manifest)


def test_fresh_matrix_plan_expands_to_the_exact_108_unique_identities():
    coordinates = _planned_coordinates(guardrail_enabled=False, guardrail_mode="reactive")

    assert len(coordinates) == len({row["coordinate_id"] for row in coordinates}) == 108
    assert {row["provider"] for row in coordinates} == {"openai_compatible"}
    assert {row["experiment_condition"] for row in coordinates} == {
        "linear_hybrid", "akg_guided_hybrid"
    }
    assert {row["security_level"] for row in coordinates} == {"low", "medium", "high"}
    assert {row["payload_mode"] for row in coordinates} == {"hybrid", "llm_mutation_only"}
    assert {row["target_method"] for row in coordinates} == {
        "sqli_union", "sqli_error", "sqli_boolean_blind", "sqli_time_blind",
        "ac_idor", "ac_vertical_escalation", "ac_force_browse",
        "bf_dictionary", "bf_spray",
    }
    assert {row["repeat_index"] for row in coordinates} == {0}


def test_matrix_output_epoch_rejects_historical_or_non_validation_paths():
    repository_root = Path(__file__).resolve().parents[1]

    with pytest.raises(ValueError, match="results/validation"):
        _validate_output_epoch(Path("results/scoring-v4-remediation-2026-10-12"),
            repository_root, must_not_exist=False)
    with pytest.raises(ValueError, match="scoring-v4-remediation"):
        _validate_output_epoch(Path("results/validation/scoring-v4-completion-2026-10-11/retry"),
            repository_root, must_not_exist=False)


def test_matrix_budget_override_is_explicit_bounded_and_keeps_source_settings():
    source = {"provider": "openai_compatible", "model": "deepseek-v4.1-flash",
        "max_attempts": 2, "max_tokens": 1024, "timeout": 60}
    config = SimpleNamespace(scoring_evaluator=source)

    with pytest.raises(ValueError, match="exceed the source budget"):
        _apply_evaluator_budget(config, 1024)
    with pytest.raises(ValueError, match="at most 8192"):
        _apply_evaluator_budget(config, 8193)
    assert config.scoring_evaluator is source

    budget = _apply_evaluator_budget(config, 4096)
    assert budget == {"source_max_tokens": 1024, "requested_max_tokens": 4096,
        "override_reason": "observed_length_truncation"}
    assert source["max_tokens"] == 1024
    assert config.scoring_evaluator["max_tokens"] == 4096


def test_matrix_fixture_pin_rechecks_deployed_source_before_launch(tmp_path):
    security = tmp_path / "security.php"
    helper = tmp_path / "dvwaPage.inc.php"
    security.write_bytes(b"authenticated security page")
    helper.write_bytes(b"authentication helper")
    source_hash = sha256(security.read_bytes()).hexdigest()
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({
        "fixture_id": "dvwa-fixture", "protocol_version": "protocol.v1",
        "target_url": "http://127.0.0.1/dvwa", "permission_matrix": [{"action": "GET"}],
        "deployed_source_binding": {
            "readable_mount": str(security), "auth_helper_path": str(helper),
            "operator_supplied_sha256": source_hash,
            "locally_verified_worktree_sha256": source_hash,
            "auth_helper_worktree_sha256": sha256(helper.read_bytes()).hexdigest(),
            "hash_match": True, "dvwa_git_head": "source-revision",
        },
    }))

    pin = _fixture_policy_pin(policy, fixture_id="dvwa-fixture",
        protocol_version="protocol.v1", target_url="http://127.0.0.1/dvwa")
    assert pin["security_php_sha256"] == source_hash
    security.write_bytes(b"changed security page")
    with pytest.raises(ValueError, match="source changed"):
        _fixture_policy_pin(policy, fixture_id="dvwa-fixture",
            protocol_version="protocol.v1", target_url="http://127.0.0.1/dvwa")
