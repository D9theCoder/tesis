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
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import pytest

from evaluation.reporter import write_json_report
from tests.test_scoring_remediation_e2e import control


ROOT = Path('results/validation/thesis-scoring-v3')


def source(monkeypatch, selection='both', name='mixed_candidates'):
    artifact, _, _ = control(monkeypatch, name)
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
        'rubric_version': 'scoring.v3', 'scoring_mode': mode,
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
    assert {r['status'] for r in queue['candidates']} >= {'signal_absent', 'pending_review', 'probe_only'}
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


@pytest.mark.parametrize('mutation', ['ceiling', 'source', 'candidate', 'refs', 'boolean', 'mode', 'correction'])
def test_review_import_trust_boundary(monkeypatch, mutation):
    from evaluation.thesis_scoring import review_queue, finalize_reviews
    path = source(monkeypatch, 'human')
    queue = review_queue(path)
    decisions = grades(queue, 'human')
    bad = decisions[0]
    if mutation == 'ceiling': bad['score'] = 4
    if mutation == 'source': bad['source_sha256'] = '0' * 64
    if mutation == 'candidate': bad['candidate_id'] = 'other-run-candidate'
    if mutation == 'refs': bad['evidence_refs'] = ['#/config/provider']
    if mutation == 'boolean': bad['score'] = True
    if mutation == 'mode': bad['scoring_mode'] = 'ai'
    if mutation == 'correction': decisions.append({**bad, 'decision_id': 'orphan', 'supersedes': 'missing'})
    with pytest.raises(ValueError):
        finalize_reviews(path, decisions, output_dir=ROOT / 'rejected')


def test_correction_preserves_audit_and_other_grader(monkeypatch):
    from evaluation.thesis_scoring import review_queue, finalize_reviews
    path = source(monkeypatch)
    queue = review_queue(path)
    human, ai = grades(queue, 'human', 3), grades(queue, 'ai', 2)
    corrected = {**human[0], 'decision_id': 'human:correction',
        'supersedes': human[0]['decision_id'], 'score': 1, 'reason': 'Conservative correction'}
    result = finalize_reviews(path, human + ai + [corrected], output_dir=ROOT / 'correction')
    h = json.loads(Path(result['receipts']['human']).read_text())
    a = json.loads(Path(result['receipts']['ai']).read_text())
    assert h['Spayload_final'] == .5 and a['Spayload_final'] == 1
    assert len(h['review_history']) == 2
    assert h['review_history'][-1]['supersedes'] == human[0]['decision_id']


def test_static_control_and_missing_evidence_remain_unassessable(monkeypatch):
    from evaluation.thesis_scoring import review_queue, finalize_reviews
    path = source(monkeypatch, 'human', 'navigation')
    queue = review_queue(path)
    result = finalize_reviews(path, grades(queue, 'human'), output_dir=ROOT / 'static')
    assert not result['receipts'] and result['workflows']['human']['reason'] == 'output_not_applicable'
    artifact = json.loads(path.read_text())
    for field in ('response_evidence', 'timing_evidence'):
        for container in (artifact, artifact['final_state']):
            for row in container.get(field, []):
                row.pop('verification_reason', None)
    broken = ROOT / 'missing-evidence.json'
    write_json_report(broken, artifact)
    queue = review_queue(broken)
    assert all(r['proof_ceiling'] is None for r in queue['candidates'] if r['eligible'])
    assert not finalize_reviews(broken, [])['receipts']


@pytest.mark.parametrize('failure', ['transport', 'provenance', 'all_invalid', 'unexecuted'])
def test_incomplete_artifact_controls_preserve_denominator(monkeypatch, failure):
    from evaluation.thesis_scoring import review_queue, finalize_reviews
    path = source(monkeypatch, 'human')
    artifact = json.loads(path.read_bytes())
    state = artifact['final_state']
    positive = next(r['candidate_id'] for r in review_queue(path)['candidates'] if r['status'] == 'pending_review')
    if failure == 'transport':
        for container in (state, artifact):
            for field in ('response_evidence', 'timing_evidence'):
                for row in container.get(field, []):
                    if row.get('candidate_id') == positive:
                        row['status_code'] = None
    elif failure == 'provenance':
        state['payload_provenance'].pop(positive)
    elif failure == 'all_invalid':
        for row in state['payload_validation_results']['sqli_union']:
            row.update(valid=False, reason='offline_negative_validation_control')
    else:
        candidate = deepcopy(next(c for c in state['payload_candidates']['sqli_union'] if c['candidate_id'] == positive))
        candidate['candidate_id'] = 'offline-unexecuted'
        candidate['payload_or_logic'] = 'offline non-executed fixture value'
        state['payload_candidates']['sqli_union'].append(candidate)
        state['payload_provenance'][candidate['candidate_id']] = deepcopy(state['payload_provenance'][positive])
        state['payload_validation_results']['sqli_union'].append({'candidate_id': candidate['candidate_id'], 'valid': True, 'reason': 'offline_valid_nonexecuted_control'})
    artifact['kind'] = f'offline_artifact_failure_control:{failure}'
    write_json_report(path, artifact)
    queue = review_queue(path)
    result = finalize_reviews(path, grades(queue, 'human'), output_dir=path.parent / 'failure-review')
    if failure == 'unexecuted':
        receipt = json.loads(Path(result['receipts']['human']).read_bytes())
        assert receipt['denominator'] == 2
        assert 'offline-unexecuted' in receipt['excluded_candidates']
    else:
        assert not result['receipts']
        assert result['workflows']['human']['Srun_final'] is None


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


def test_review_uses_method_scoped_output_and_actual_execution_order(monkeypatch):
    from evaluation.thesis_scoring import review_queue
    path = source(monkeypatch, 'human')
    artifact = json.loads(path.read_bytes())
    state = artifact['final_state']
    state['invalid_json_events'].append({'scope': 'method', 'method': 'bf_dictionary',
        'reason': 'offline_other_method_output_control'})
    state['payload_candidates']['sqli_union'].reverse()
    artifact['kind'] = 'offline_method_scope_and_execution_order_control'
    write_json_report(path, artifact)
    queue = review_queue(path)
    assert queue['components']['Soutput'] == 3
    assert queue['metrics']['values']['attempts_to_success'] == 2
    write_json_report(path.parent / 'review-queue.json', queue)


@pytest.mark.parametrize('selection', ['human', 'ai', 'both'])
def test_exact_scored_output_count_for_frozen_selection(monkeypatch, selection):
    from evaluation.thesis_scoring import review_queue, finalize_reviews
    path = source(monkeypatch, selection)
    queue = review_queue(path)
    decisions = []
    if selection != 'ai': decisions += grades(queue, 'human')
    if selection != 'human': decisions += grades(queue, 'ai')
    directory = path.parent / 'outputs'
    result = finalize_reviews(path, decisions, output_dir=directory)
    expected = {'human', 'ai'} if selection == 'both' else {selection}
    assert set(result['receipts']) == expected
    assert len(list(directory.glob('*-verified.json'))) == len(expected)


@pytest.mark.parametrize('selection', ['human', 'ai', 'both'])
def test_selection_config_and_launch_parity(tmp_path, selection):
    from tesis.config_loader import load_and_resolve_config
    from tesis.tui_forms import _LAUNCH_CLI_KEYS
    from tesis.headless import _common_kwargs
    path = tmp_path / 'config.yaml'
    path.write_text(f'target_url: http://localhost/dvwa\nprovider: openai_compatible\nlevel: low\nscoring_mode: {selection}\n')
    cfg = load_and_resolve_config(config_path=str(path), cli_args={})
    assert _LAUNCH_CLI_KEYS['scoring_mode'] == 'scoring_mode'
    assert _common_kwargs(cfg, output_dir=tmp_path)['scoring_mode'] == selection
    assert cfg.scoring_evaluator == {}


def test_frozen_ai_evaluator_does_not_rate_negatives_or_escape_ceiling(monkeypatch):
    from evaluation.thesis_scoring import review_queue, evaluate_queue
    path = source(monkeypatch, 'ai')
    queue = review_queue(path)
    assert not evaluate_queue(queue, {})['decisions']
    responses = iter(['{', json.dumps({'score': 2, 'reason': 'Partial supported',
        'evidence_refs': next(r['evidence_refs'] for r in queue['candidates'] if r['status'] == 'pending_review')})])
    calls = []
    def judge(messages):
        calls.append(messages)
        return next(responses)
    result = evaluate_queue(queue, {'provider': 'offline', 'model': 'independent-judge',
        'max_attempts': 2, 'max_tokens': 512, 'timeout': 5}, invoke=judge)
    assert len(calls) == 2 and len(result['decisions']) == 1
    assert result['decisions'][0]['score'] == 2
    write_json_report(ROOT / 'evaluator-control.json', result)


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


def test_review_fix_discovery_excludes_multiple_decisions_and_telemetry(monkeypatch):
    from evaluation.thesis_scoring import review_queue, finalize_reviews
    from tesis.artifact_repository import ArtifactRepository
    path = source(monkeypatch, 'human')
    original = grades(review_queue(path), 'human')
    correction = {**original[0], 'decision_id': 'human:corrected',
        'supersedes': original[0]['decision_id'], 'score': 1}
    decisions = original + [correction]
    result = finalize_reviews(path, decisions)
    write_json_report(path.parent / 'reviews' / f'{path.stem}.decisions.json', decisions)
    write_json_report(path.parent / 'reviews' / 'offline.evaluator.json', {'decisions': decisions})
    found = ArtifactRepository(path.parent).scan()
    assert {r.path for r in found} == {path, Path(result['receipts']['human'])}
    assert len(found) == 2
    write_json_report(path.parent / 'discovery-check.json', {'paths': [str(r.path) for r in found]})


@pytest.mark.parametrize('alias', ['same', 'symlink', 'hardlink'])
def test_review_fix_template_preserves_source_before_rejecting_alias(monkeypatch, alias):
    from evaluation.thesis_scoring import main
    path = source(monkeypatch, 'human')
    before = path.read_bytes()
    template = path if alias == 'same' else path.parent / f'{alias}.json'
    if alias == 'symlink': template.symlink_to(path.resolve())
    if alias == 'hardlink': template.hardlink_to(path)
    with pytest.raises(SystemExit) as failed:
        main([str(path), '--template', str(template)])
    assert failed.value.code == 1
    assert path.read_bytes() == before
    write_json_report(path.parent / 'source-preservation-check.json',
        {'alias': alias, 'source_sha256': sha256(before).hexdigest(), 'unchanged': True})


@pytest.mark.parametrize('input_kind', ['import', 'ledger'])
def test_review_fix_template_preserves_decision_inputs(monkeypatch, input_kind):
    from evaluation.thesis_scoring import main, review_queue, finalize_reviews, review_ledger_path
    path = source(monkeypatch, 'human')
    decisions = grades(review_queue(path), 'human')
    if input_kind == 'ledger':
        finalize_reviews(path, decisions)
        protected = review_ledger_path(path)
        args = []
    else:
        protected = path.parent / 'import.decisions.json'
        write_json_report(protected, decisions)
        args = ['--decisions', str(protected)]
    before = protected.read_bytes()
    with pytest.raises(SystemExit) as failed:
        main([str(path), '--template', str(protected), *args])
    assert failed.value.code == 1
    assert protected.read_bytes() == before
    write_json_report(path.parent / 'decision-preservation-check.json',
        {'input_kind': input_kind, 'decisions_sha256': sha256(before).hexdigest(), 'unchanged': True})


def test_review_fix_cli_evaluator_corrections_preserve_namespaced_telemetry(monkeypatch):
    from types import SimpleNamespace
    from evaluation.thesis_scoring import main, review_queue
    calls = []
    def get_judge(*args, **kwargs):
        def invoke(messages):
            calls.append(messages)
            evidence = json.loads(messages[-1].content)
            return SimpleNamespace(content=json.dumps({'score': 2, 'reason': 'Offline evidence review',
                'evidence_refs': evidence['evidence_refs']}), usage_metadata={'output_tokens': 20})
        return SimpleNamespace(invoke=invoke)
    monkeypatch.setattr('llm.provider.get_llm', get_judge)
    paths = [source(monkeypatch, 'ai') for _ in range(2)]
    monkeypatch.setattr('tesis.config_loader.load_and_resolve_config',
        lambda **kwargs: SimpleNamespace(scoring_evaluator=review_queue(paths[0])['evaluator']))
    out = paths[0].parent / 'shared-reviews'
    for path in paths:
        assert main([str(path), '--evaluate', '--output-dir', str(out)]) == 0
    identifier = json.loads(paths[0].read_bytes())['execution_id']
    receipt = out / f'{identifier}.ai-verified.json'
    initial = json.loads(receipt.read_bytes())
    imported = paths[0].parent / 'imported-decisions.json'
    write_json_report(imported, initial['review_history'])
    telemetry = out / f'{identifier}.evaluator.json'
    assert telemetry.exists()
    previous = telemetry.read_bytes()
    assert main([str(paths[0]), '--evaluate', '--decisions', str(imported), '--output-dir', str(out)]) == 0
    corrected = json.loads(receipt.read_bytes())
    assert len(corrected['review_history']) == 2
    assert corrected['review_history'][-1]['supersedes'] == initial['review_history'][0]['decision_id']
    assert len(calls) == 3
    assert len(list(out.glob('*.evaluator.json'))) == 2
    assert any(p.read_bytes() == previous for p in (out / 'history').glob('*.json'))
    write_json_report(paths[0].parent / 'cli-evaluator-check.json',
        {'mocked_calls': len(calls), 'executions': [str(p) for p in paths], 'telemetry': str(telemetry)})


@pytest.mark.parametrize('identity_field', ['reviewer_id', 'review_version'])
def test_review_fix_comparison_separates_reviewer_and_version(monkeypatch, identity_field):
    from evaluation.thesis_scoring import review_queue, finalize_reviews, compare_receipts
    receipts = []
    identities = []
    for i in range(2):
        path = source(monkeypatch, 'human')
        decisions = grades(review_queue(path), 'human')
        decisions[0][identity_field] = f'offline-{identity_field}-{i}'
        identities.append(decisions[0][identity_field])
        receipts.append(finalize_reviews(path, decisions)['receipts']['human'])
    result = compare_receipts(receipts)
    assert len(result['groups']) == 2
    assert all(g['n_final'] == 1 and g['consistency_score'] is None for g in result['groups'])
    assert {g[identity_field] for g in result['groups']} == set(identities)
    write_json_report(path.parent / 'grader-comparison-check.json', result)


@pytest.mark.parametrize('layout', ['default', 'custom', 'legacy_receipt', 'legacy_custom_receipt', 'legacy_custom_both'])
def test_review_fix_cli_history_survives_tui_reopening(monkeypatch, layout):
    import asyncio
    from evaluation.thesis_scoring import main, review_queue
    from tesis.tui import TesisApp, ReviewDrawer, ResultsDrawer
    from tesis import tui_state
    from textual.widgets import DataTable
    selection = 'both' if layout == 'legacy_custom_both' else 'human'
    path = source(monkeypatch, selection)
    decisions = grades(review_queue(path), 'human', 3)
    if selection == 'both': decisions += grades(review_queue(path), 'ai', 2)
    imported = path.parent / 'import.json'
    write_json_report(imported, decisions)
    args = [str(path), '--decisions', str(imported)]
    custom = layout == 'custom' or layout.startswith('legacy_custom')
    out = path.parent / ('custom-reviews' if custom else 'reviews')
    if custom: args += ['--output-dir', str(out)]
    assert main(args) == 0
    if layout.startswith('legacy_'):
        for ledger in (path.parent / 'reviews').glob('*.decisions.json'):
            ledger.unlink()
    cfg = path.parent / 'tui-config.yaml'
    cfg.write_text(f'target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\noutput_dir: {out.resolve()}\n')
    monkeypatch.setattr(tui_state, 'CONFIG_PATH', cfg)
    identifier = json.loads(path.read_bytes())['execution_id']
    status_path = out / f'{identifier}.review-status.json'
    assert json.loads(status_path.read_bytes())['workflows']['human']['status'] == 'final'
    before = path.read_bytes()
    async def scenario():
        app = TesisApp()
        async with app.run_test(size=(80, 24)) as pilot:
            if layout.startswith('legacy_custom'):
                await app.push_screen(ResultsDrawer())
                results = app.screen
                table = results.query_one('#results-table', DataTable)
                for _ in range(100):
                    await pilot.pause(.02)
                    if table.row_count: break
                assert table.row_count == (2 if selection == 'both' else 1)
                table.focus()
                await pilot.press('enter')
                assert await pilot.click('#results-review')
                await pilot.pause()
                assert isinstance(app.screen, ReviewDrawer)
            else:
                await app.push_screen(ReviewDrawer(path))
            drawer = app.screen
            for _ in range(100):
                await pilot.pause(.02)
                if drawer.result: break
            assert drawer.result['workflows']['human']['status'] == 'final'
            assert all(info['status'] == 'final' for info in drawer.result['workflows'].values())
            assert drawer.decisions == decisions
            if layout.startswith('legacy_custom'):
                assert Path(drawer.result['receipts']['human']).parent.resolve() == out.resolve()
            assert json.loads(status_path.read_bytes())['workflows']['human']['status'] == 'final'
            (path.parent / f'reopened-{layout}.svg').write_text(app.export_screenshot())
            app.exit()
    asyncio.run(asyncio.wait_for(scenario(), timeout=15))
    assert path.read_bytes() == before


@pytest.mark.parametrize('size', [(80, 24), (60, 24)])
def test_review_fix_results_discovery_and_visible_review_action(monkeypatch, size):
    import asyncio
    from textual.widgets import DataTable
    from tesis.tui import TesisApp, ResultsDrawer, ReviewDrawer
    from tesis import tui_state
    from evaluation.thesis_scoring import finalize_reviews, review_queue
    path = source(monkeypatch, 'human')
    decisions = grades(review_queue(path), 'human')
    correction = {**decisions[0], 'decision_id': 'human:results-correction',
        'supersedes': decisions[0]['decision_id'], 'score': 1}
    result = finalize_reviews(path, decisions + [correction])
    write_json_report(path.parent / 'reviews' / f'{path.stem}.decisions.json', decisions + [correction])
    cfg = path.parent / 'tui-config.yaml'
    cfg.write_text(f'target_url: http://localhost/dvwa\nprovider: gemini\nlevel: low\noutput_dir: {path.parent.resolve()}\n')
    monkeypatch.setattr(tui_state, 'CONFIG_PATH', cfg)
    async def scenario():
        app = TesisApp()
        async with app.run_test(size=size) as pilot:
            await app.push_screen(ResultsDrawer())
            drawer = app.screen
            table = drawer.query_one('#results-table', DataTable)
            for _ in range(100):
                await pilot.pause(.02)
                if table.row_count: break
            assert table.row_count == 2
            assert table.region.height >= 3, 'Results must show selectable rows as well as actions'
            index = next(i for i, item in enumerate(drawer._items) if item.path.resolve() == path.resolve())
            table.move_cursor(row=index)
            table.focus()
            await pilot.press('enter')
            await pilot.pause()
            (path.parent / f'results-{size[0]}.svg').write_text(app.export_screenshot())
            assert await pilot.click('#results-review')
            await pilot.pause()
            assert isinstance(app.screen, ReviewDrawer)
            for _ in range(100):
                await pilot.pause(.02)
                if app.screen.result: break
            assert app.screen.result['workflows']['human']['status'] == 'final'
            assert Path(result['receipts']['human']).exists()
            app.exit()
    asyncio.run(asyncio.wait_for(scenario(), timeout=15))
