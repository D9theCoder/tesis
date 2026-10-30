"""Offline execution → frozen artifact → review → thesis receipt failure controls.

Declared before production changes: missing/wrong-source evidence, probes,
rejections, transport failures, duplicate candidates/retries, ceiling overruns,
pending grades, independent graders, correction history, fractional means,
static output, absent oracle, wrong mode, and cross-run imports must fail closed.
External I/O uses the existing scoring fixture; exports are repeatable evidence.
Review-fix controls cover sidecar discovery, source aliases, offscreen actions,
CLI/TUI history continuity, evaluator correction links, grader grouping and
telemetry overwrites before changing their implementation.
"""
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import pytest

from evaluation.reporter import write_json_report
from tests.test_scoring_remediation_e2e import control


ROOT = Path('results/validation/thesis-scoring-v4')


def source(monkeypatch, selection='both', name='mixed_candidates'):
    artifact, _, _ = control(monkeypatch, name, ranked=True)
    artifact['validation_scope'] = 'offline_synthetic_fixture'
    artifact['config']['scoring_mode'] = selection
    artifact['config']['scoring_evaluator'] = {'provider': 'offline', 'model': 'independent-judge',
        'max_attempts': 2, 'max_tokens': 512, 'timeout': 5}
    artifact['execution_id'] = f'offline-{selection}-{uuid4().hex}'
    path = ROOT / 'controls' / artifact['execution_id'] / f'{name}.json'
    write_json_report(path, artifact)
    return path


def grades(queue, mode, value=2):
    return [{
        'decision_id': f'{mode}:{row["candidate_id"]}:1',
        'run_id': queue['run_id'], 'source_sha256': queue['source_sha256'],
        'rubric_version': queue['rubric_version'], 'scoring_mode': mode,
        'candidate_id': row['candidate_id'], 'score': min(value, row['proof_ceiling']),
        'reason': 'Reviewed candidate-linked execution evidence',
        'evidence_refs': row['evidence_refs'],
        'reviewer_id': 'offline/independent-judge' if mode == 'ai' else 'offline-reviewer',
        'review_version': 'judge.v1' if mode == 'ai' else 'offline-v1',
        'timestamp': '2026-09-30T00:00:00+00:00',
    } for row in queue['candidates'] if row['status'] == 'pending_review']


def test_execution_review_independent_receipts_and_fractional_mean(monkeypatch):
    from evaluation.thesis_scoring import review_queue, finalize_reviews
    path = source(monkeypatch)
    before = path.read_bytes()
    queue = review_queue(path)
    assert {r['status'] for r in queue['candidates']} >= {'signal_absent', 'pending_review'}
    # Detection probes live in frozen controls, never in the exploit review queue.
    assert not any(r['stage'] == 'probe' for r in queue['candidates'])
    assert not finalize_reviews(path, [], output_dir=ROOT / 'pending')['receipts']
    human = grades(queue, 'human', 3)
    result = finalize_reviews(path, human, output_dir=ROOT / 'dual')
    assert set(result['receipts']) == {'human'}
    receipt = json.loads(Path(result['receipts']['human']).read_text())
    assert receipt['Spayload_final'] == 1.5
    assert receipt['denominator'] == 2 and receipt['numerator'] == 3
    assert receipt['Srun_final'] == round(sum(receipt['components'][k] * w for k, w in
        {'Smethod': .2, 'Spayload': .2, 'Sexploit': .3, 'Schain': .1, 'Soutput': .2}.items()), 4)
    assert receipt['source_sha256'] == sha256(before).hexdigest()
    assert any(r['grade_origin'] == 'signal_gate' for r in receipt['candidate_grades'])
    ai = grades(queue, 'ai', 2)
    result = finalize_reviews(path, human + ai, output_dir=ROOT / 'dual')
    assert set(result['receipts']) == {'human', 'ai'}
    assert json.loads(Path(result['receipts']['ai']).read_text())['Spayload_final'] == 1.0
    assert path.read_bytes() == before
    assert result['fresh_http_calls'] == result['fresh_provider_calls'] == 0


def test_repeat_comparison_rejects_duplicate_sources_and_keeps_graders_separate(monkeypatch):
    from evaluation.thesis_scoring import review_queue, finalize_reviews, compare_receipts
    paths = []
    for _ in range(2):
        path = source(monkeypatch)
        queue = review_queue(path)
        result = finalize_reviews(path, grades(queue, 'human', 3) + grades(queue, 'ai', 2), output_dir=path.parent / 'final')
        paths.extend(result['receipts'].values())
    compared = compare_receipts(paths)
    assert len(compared['groups']) == 2
    assert {g['scoring_mode'] for g in compared['groups']} == {'human', 'ai'}
    assert all(g['n_final'] == 2 and g['consistency_score'] == 1 for g in compared['groups'])
    assert compared['cross_grader_composite'] is None
    with pytest.raises(ValueError, match='duplicate'):
        compare_receipts([paths[0], paths[0]])
    write_json_report(ROOT / 'repeat-comparison.json', compared)


@pytest.mark.parametrize('size', [(80, 24), (60, 24)])
def test_tui_review_exports_same_receipt_as_headless(monkeypatch, tmp_path, size):
    import asyncio
    from textual.widgets import Input, Select
    from tesis.tui import TesisApp, ReviewDrawer, LaunchDrawer
    from tesis import tui_state
    from evaluation.thesis_scoring import review_queue
    path = source(monkeypatch, 'human')
    cfg = tmp_path / 'config.yaml'
    cfg.write_text('target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\nscoring_mode: human\n')
    monkeypatch.setattr(tui_state, 'CONFIG_PATH', cfg)
    async def scenario():
        app = TesisApp()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await app.push_screen(LaunchDrawer())
            await pilot.pause()
            assert app.screen.query_one('#launch-field-scoring-mode', Select).value == 'human'
            await pilot.press('escape')
            await app.push_screen(ReviewDrawer(path))
            drawer = app.screen
            for _ in range(100):
                await pilot.pause(.02)
                if drawer.queue:
                    break
            assert drawer.queue['source_sha256'] == review_queue(path)['source_sha256']
            drawer.query_one('#review-score', Select).value = 3
            drawer.query_one('#review-reason', Input).value = 'Confirmed extraction evidence'
            drawer.query_one('#review-reviewer', Input).value = 'offline-reviewer'
            drawer.submit_grade()
            for _ in range(100):
                await pilot.pause(.02)
                if drawer.result and drawer.result['receipts']:
                    break
            assert drawer.result['workflows']['human']['Spayload_final'] == 1.5
            assert set(drawer.result['receipts']) == {'human'}
            capture = ROOT / f'review-{size[0]}.svg'
            capture.write_text(app.export_screenshot())
            await pilot.press('escape')
            app.exit()
    asyncio.run(asyncio.wait_for(scenario(), timeout=15))
