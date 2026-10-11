"""Saved-source review E2E controls declared before the evidence auditor.

Failures: stale sidecars supersede newer receipts, cross-source joins pass,
missing receipts become zero, probes inflate denominators, source bytes change,
human scores enter AI coverage, pending candidates become final numbers.
All graph/transport/model inputs are offline fixtures.
"""
from copy import deepcopy
import json
from pathlib import Path
from uuid import uuid4

import pytest

from evaluation.reporter import write_json_report
from evaluation.thesis_scoring import finalize_reviews, review_queue
from tests.test_scoring_evidence_v4_e2e import artifact_v4
from tests.test_thesis_scoring_e2e import grades


def saved_reviews(monkeypatch, tmp_path):
    rows, initial, later = [], [], []
    for case in ('final', 'pending', 'no_eligible', 'not_assessable'):
        artifact = artifact_v4(monkeypatch)
        artifact['config']['scoring_mode'] = 'ai'
        artifact['execution_id'] = case
        artifact['run_id'] = case
        if case == 'no_eligible':
            artifact['final_state']['payload_candidates'] = {}
            artifact['final_state']['response_evidence'] = []
            artifact['final_state']['scoring_decisions'] = [
                d for d in artifact['final_state']['scoring_decisions']
                if d.get('dimension') != 'Spayload']
            artifact['response_evidence'] = []
            artifact['manual_scoring_evidence'] = []
        if case == 'not_assessable':
            artifact['final_state']['payload_provenance'] = {}
        source = tmp_path / case / 'execution.json'
        write_json_report(source, artifact)
        queue = review_queue(source)
        result = finalize_reviews(source, [], output_dir=source.parent / 'initial')
        status_path = source.parent / 'initial' / f'{case}.review-status.json'
        initial.append({'execution_id': case, 'source_sha256': queue['source_sha256'],
            'status_path': str(status_path)})
        if case == 'final':
            decisions = grades(queue, 'ai')
            for decision in decisions:
                decision['rubric_version'] = queue['rubric_version']
            result = finalize_reviews(source, decisions, output_dir=source.parent / 'later')
            status_path = source.parent / 'later' / f'{case}.review-status.json'
            later.append({'execution_id': case, 'source_sha256': queue['source_sha256'],
                'status_path': str(status_path)})
        rows.append({'path': str(source), 'sha256': queue['source_sha256'],
            'execution_id': case, 'coordinate': {'case': case}})
    manifest = tmp_path / 'manifest.json'
    write_json_report(manifest, {'sources': rows})
    paths = []
    for name, records in [('initial', initial), ('later', later)]:
        path = tmp_path / f'{name}.jsonl'
        path.write_text(''.join(json.dumps(r) + '\n' for r in records))
        paths.append((path, None))
    return manifest, paths


def test_saved_review_coverage_preserves_nulls_and_latest_receipt(monkeypatch, tmp_path):
    from evaluation.remaining_evidence import EvidenceReader, audit_score_coverage
    manifest, rounds = saved_reviews(monkeypatch, tmp_path)
    reader = EvidenceReader()
    rows = audit_score_coverage(reader, manifest, rounds)
    indexed = {r['execution_id']: r for r in rows}
    assert indexed['final']['classification'] == 'numeric_ai_receipt'
    assert indexed['pending']['classification'] == 'pending_candidate_review'
    assert indexed['no_eligible']['classification'] == 'no_eligible_candidate'
    assert indexed['not_assessable']['classification'] == 'not_assessable'
    assert indexed['final']['denominator'] > 0
    assert indexed['no_eligible']['denominator'] == 0
    for case in ('pending', 'no_eligible', 'not_assessable'):
        assert indexed[case]['Srun_final'] is None
        assert indexed[case]['Spayload_final'] is None
    assert all(r['human_receipt'] is None for r in rows)
    reader.verify_unchanged()
    write_json_report(Path('results/validation/remaining-evidence-audit-offline') /
        uuid4().hex / 'coverage.json', {'validation_scope': 'offline_synthetic_fixture',
            'rows': rows, 'source_hashes': reader.sources, 'fresh_provider_calls': 0,
            'fresh_http_calls': 0})


@pytest.mark.parametrize('failure', ['source_hash', 'receipt_hash', 'missing_receipt',
    'denominator', 'candidate_ref', 'receipt_execution', 'duplicate_source'])
def test_bad_saved_review_join_stops(monkeypatch, tmp_path, failure):
    from evaluation.remaining_evidence import EvidenceReader, audit_score_coverage
    manifest, rounds = saved_reviews(monkeypatch, tmp_path)
    data = json.loads(manifest.read_text())
    source = Path(data['sources'][0]['path'])
    status_path = source.parent / 'later/final.review-status.json'
    status = json.loads(status_path.read_text())
    receipt_path = Path(status['receipts']['ai'])
    receipt = json.loads(receipt_path.read_text())
    if failure == 'source_hash':
        source.write_text(source.read_text() + '\n')
    elif failure == 'receipt_hash':
        receipt['source_sha256'] = '0' * 64
    elif failure == 'missing_receipt':
        receipt_path.unlink()
    elif failure == 'denominator':
        receipt['denominator'] += 1
    elif failure == 'candidate_ref':
        receipt['candidate_grades'][0]['evidence_refs'] = ['#/missing/evidence']
    elif failure == 'receipt_execution':
        receipt['execution_id'] = 'different-execution'
    elif failure == 'duplicate_source':
        data['sources'].append(deepcopy(data['sources'][0]))
        write_json_report(manifest, data)
    if failure not in {'source_hash', 'missing_receipt', 'duplicate_source'}:
        write_json_report(receipt_path, receipt)
    source_bytes = source.read_bytes()
    with pytest.raises((ValueError, FileNotFoundError)):
        audit_score_coverage(EvidenceReader(), manifest, rounds)
    # The audit never finalizes reviews or rewrites the execution artifact.
    assert source.read_bytes() == source_bytes


@pytest.mark.parametrize('method', [
    'sqli_union', 'sqli_error', 'sqli_boolean_blind', 'sqli_time_blind',
    'ac_idor', 'ac_vertical_escalation', 'ac_force_browse', 'bf_dictionary', 'bf_spray'])
def test_new_complete_input_epoch_has_saved_shapes_and_zero_provider_replay(monkeypatch, method):
    from hashlib import sha256
    from evaluation.payload_replay import replay_method_inputs
    from tests.test_method_agents_e2e import run_control
    from tesis.runtime_events import redact_secrets
    root = Path('results/validation/scoring-v4-remaining-evidence-2026-10-11/forward-offline') / uuid4().hex
    artifact, fixture = run_control(monkeypatch, method, 'low', 'generated_valid',
        payload_mode='llm_mutation_only')
    artifact['validation_scope'] = 'offline_synthetic_fixture'
    source = root / 'execution.json'
    write_json_report(source, artifact)
    source_bytes = source.read_bytes()
    original_shapes = deepcopy(fixture.requests)
    before_requests, before_calls = len(fixture.requests), fixture.provider_calls
    replay_path = root / 'replay.json'
    replay = replay_method_inputs(source, output_path=replay_path)
    shapes = fixture.requests[before_requests:]
    assert shapes and all(set(r) >= {'session', 'verb', 'url', 'data', 'cookie_id'} for r in shapes)
    assert fixture.provider_calls == before_calls and replay['fresh_provider_calls'] == 0
    assert not replay['validation_rejections']
    assert source.read_bytes() == source_bytes
    assert [(r['candidate_id'], r['stage'], r['payload']) for r in replay['response_evidence']] == [
        (r['candidate_id'], r['stage'], r['payload']) for r in artifact['response_evidence']]
    frozen = artifact['method_execution_inputs'][0]['state']
    assert frozen['probe_controls'][method]['candidates']
    assert frozen['payload_candidates'][method]
    # These are fixture session identifiers and synthetic credentials. Redaction
    # preserves request structure, while credential values stay in the fixture.
    write_json_report(root / 'request-shapes.json', redact_secrets({
        'validation_scope': 'offline_synthetic_fixture', 'source_sha256': sha256(source_bytes).hexdigest(),
        'original': original_shapes, 'replay': shapes}))
    write_json_report(root / 'control.json', {
        'validation_scope': 'offline_synthetic_fixture', 'method': method,
        'source_path': str(source), 'source_sha256': sha256(source_bytes).hexdigest(),
        'replay_path': str(replay_path), 'replay_sha256': sha256(replay_path.read_bytes()).hexdigest(),
        'request_shapes_path': str(root / 'request-shapes.json'),
        'request_shapes_sha256': sha256((root / 'request-shapes.json').read_bytes()).hexdigest(),
        'saved_probe_count': len(frozen['probe_controls'][method]['candidates']),
        'saved_exploit_count': len(frozen['payload_candidates'][method]),
        'fresh_provider_calls': 0, 'mock_http_transactions': len(shapes),
        'source_unchanged': True, 'candidate_values_and_execution_order_preserved': True,
        'limitations': 'Synthetic HTTP only; redacted credential/session values cannot recover historical live requests.',
    })
