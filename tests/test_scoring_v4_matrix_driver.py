import os

import pytest


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
