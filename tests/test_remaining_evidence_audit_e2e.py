"""Saved-source review E2E controls declared before the evidence auditor.

Failures: stale sidecars supersede newer receipts, cross-source joins pass,
missing receipts become zero, probes inflate denominators, source bytes change,
human scores enter AI coverage, pending candidates become final numbers.
All graph/transport/model inputs are offline fixtures.
"""
import json
from pathlib import Path
from uuid import uuid4


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
    write_json_report(Path('results/validation/scoring-v4-remediation-2026-10-12-capture-epoch1/review-round-controls') /
        uuid4().hex / 'coverage.json', {'validation_scope': 'offline_synthetic_fixture',
            'rows': rows, 'source_hashes': reader.sources, 'fresh_provider_calls': 0,
            'fresh_http_calls': 0})
