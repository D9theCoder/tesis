"""Graph/export/replay controls declared before the probe snapshot repair.

Failures: mutation-only probes escape validation and candidate attribution;
replay restores today's seeds; probe controls enter the exploit denominator;
changed value, provenance, stage, method, visit, or order reaches HTTP;
missing historical stages are silently repaired; a replay invokes a provider.
External HTTP and model responses are offline fixtures, never live acceptance.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import pytest

from core.state import METHODS_BY_SURFACE
from evaluation.payload_replay import replay_method_inputs
from evaluation.reporter import write_json_report
from evaluation.thesis_scoring import review_queue
from tests.test_method_agents_e2e import run_control


ROOT = Path('results/validation/scoring-v4-probe-replay-2026-10-11/offline')
METHODS = [m for methods in METHODS_BY_SURFACE.values() for m in methods]


def save(artifact, label):
    path = ROOT / f'{label}-{uuid4().hex}' / 'execution.json'
    write_json_report(path, artifact)
    return path


@pytest.mark.parametrize('condition', ['linear_hybrid', 'akg_guided_hybrid'])
@pytest.mark.parametrize('level', ['low', 'medium', 'high'])
@pytest.mark.parametrize('method', METHODS)
def test_mutation_only_graph_export_saved_probe_replay(monkeypatch, condition, level, method):
    artifact, fixture = run_control(monkeypatch, method, level, 'generated_valid',
        condition, payload_mode='llm_mutation_only')
    frozen = artifact['method_execution_inputs'][0]['state']
    queue = frozen['payload_candidates'][method]
    assert queue and all(c['source'] == 'llm_generated' for c in queue)
    controls = frozen['probe_controls'][method]
    assert controls['visit_id'] == frozen['selected_visit_id']
    assert controls['candidates'] and all(r['valid'] for r in controls['validation_results'])
    probe_ids = {c['candidate_id'] for c in controls['candidates']}
    assert all(c['source'] == 'static_seed' and c['source_seed_id'] == c['candidate_id']
        and c['method'] == method and c['stage'] == 'probe' for c in controls['candidates'])
    exploit_ids = {c['candidate_id'] for c in queue}
    assert not probe_ids & exploit_ids
    probes = [r for r in artifact['response_evidence'] if r['stage'] == 'probe']
    assert probes and all(r.get('candidate_id') in probe_ids for r in probes)
    artifact['config']['scoring_rubric_version'] = 'scoring.v4'
    artifact['validation_scope'] = 'offline_synthetic_fixture'
    source = save(artifact, f'{condition}-{method}-{level}')
    before = source.read_bytes()
    requests, providers = len(fixture.requests), fixture.provider_calls
    replay_path = source.parent / 'replay.json'
    replay = replay_method_inputs(source, output_path=replay_path)
    assert replay['validation_rejections'] == []
    assert len(fixture.requests) > requests
    assert replay['fresh_provider_calls'] == 0 and fixture.provider_calls == providers
    assert source.read_bytes() == before
    assert all(r.get('candidate_id') in probe_ids | exploit_ids for r in replay['response_evidence'])
    assert [r['payload'] for r in replay['response_evidence']] == [r['payload'] for r in artifact['response_evidence']]
    queue_review = review_queue(source)
    assert queue_review['rubric_version'] == 'scoring.v4'
    assert not probe_ids & {c['candidate_id'] for c in queue_review['candidates']}
    write_json_report(source.parent / 'control.json', {
        'validation_scope': 'offline_synthetic_fixture', 'source_sha256': sha256(before).hexdigest(),
        'method': method, 'level': level, 'condition': condition,
        'probe_ids': sorted(probe_ids), 'exploit_ids': sorted(exploit_ids),
        'fresh_provider_calls': 0, 'mock_http_transactions': len(fixture.requests) - requests,
        'replay_path': str(replay_path), 'queue_review': queue_review,
    })


@pytest.mark.parametrize('mutation', ['payload', 'stage', 'source', 'seed', 'method',
    'visit', 'order', 'missing', 'legacy', 'malformed'])
def test_changed_or_missing_saved_probes_stop_before_http(monkeypatch, mutation):
    artifact, fixture = run_control(monkeypatch, 'sqli_union', 'low', 'generated_valid',
        payload_mode='llm_mutation_only')
    state = artifact['method_execution_inputs'][0]['state']
    controls = state['probe_controls']['sqli_union']
    candidate = controls['candidates'][0]
    if mutation == 'payload': candidate['payload_or_logic'] = 'http://external.invalid/'
    if mutation == 'stage': candidate['stage'] = 'exploit'
    if mutation == 'source': candidate['source'] = 'llm_generated'
    if mutation == 'seed': candidate['source_seed_id'] = 'unknown'
    if mutation == 'method': candidate['method'] = 'sqli_error'
    if mutation == 'visit': controls['visit_id'] = 'other-visit'
    if mutation == 'order': controls['candidates'].reverse()
    if mutation == 'missing': controls['candidates'] = []
    if mutation == 'legacy': state.pop('probe_controls')
    if mutation == 'malformed': state['probe_controls']['sqli_union'] = ['invalid']
    # Hash integrity alone cannot validate an altered canonical probe set.
    from evaluation.scoring_evidence import evidence_hash
    controls['sha256'] = evidence_hash(controls['candidates'])
    source = save(artifact, f'rejected-{mutation}')
    before = deepcopy(state)
    requests, providers = len(fixture.requests), fixture.provider_calls
    replay = replay_method_inputs(source, output_path=source.parent / 'replay.json')
    assert replay['validation_rejections'] and replay['response_evidence'] == []
    assert len(fixture.requests) == requests and fixture.provider_calls == providers
    assert replay['fresh_provider_calls'] == 0 and state == before
    assert replay['manual_scoring_evidence'] == []
    write_json_report(source.parent / 'control.json', {
        'validation_scope': 'offline_synthetic_fixture', 'mutation': mutation,
        'validation_rejections': replay['validation_rejections'],
        'fresh_http_transactions': 0, 'fresh_provider_calls': 0,
        'source_sha256': sha256(source.read_bytes()).hexdigest(),
    })
