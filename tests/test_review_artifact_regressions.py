"""Focused saved-artifact and mocked runtime controls for the range review."""
import asyncio
from copy import deepcopy
import json
import os
import stat
from types import SimpleNamespace

import pytest

from core.run_status import matrix_terminal_status, terminal_status
from evaluation.reporter import write_json_report


@pytest.mark.parametrize("mode", [0o600, 0o640])
def test_replacement_is_private_before_any_content_is_written(tmp_path, monkeypatch, mode):
    path = tmp_path / "private.json"
    path.write_text('{}')
    path.chmod(mode)
    original_fdopen = os.fdopen
    observed = []

    def inspect_descriptor(descriptor, *args, **kwargs):
        observed.append((stat.S_IMODE(os.fstat(descriptor).st_mode), os.fstat(descriptor).st_size))
        return original_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(os, 'fdopen', inspect_descriptor)
    previous_umask = os.umask(0o022)
    try:
        write_json_report(path, {'private': 'contents'})
    finally:
        os.umask(previous_umask)
    assert observed == [(mode, 0)]
    assert stat.S_IMODE(path.stat().st_mode) == mode
    assert json.loads(path.read_text()) == {'private': 'contents'}
    assert list(tmp_path.iterdir()) == [path]


def test_unknown_child_prevents_matrix_completion_without_reclassifying_child():
    child = {'status': 'error', 'final_state': {}}
    before = deepcopy(child)
    fields = matrix_terminal_status([{'status': 'success'}, child, {'status': 'skipped'}])
    assert fields['execution_status'] == 'failed'
    assert fields['execution_reason']['code'] == 'CHILD_EXECUTION_UNKNOWN'
    assert terminal_status(child)['execution_status'] is None
    assert child == before
    assert matrix_terminal_status([child], interrupted=True)['execution_status'] == 'interrupted'


@pytest.mark.parametrize('status,expected', [('success', 0), ('cancelled', 0), ('error', 1), ('unknown', 1)])
def test_matrix_cli_exit_code_matches_result(monkeypatch, capsys, status, expected):
    import evaluation.scoring_v4_matrix as matrix
    monkeypatch.setattr(matrix, 'run_plan', lambda path: {
        'status': status, 'matrix_execution_id': 'mock-matrix',
        'completed_artifacts': 1, 'plan_sha256': 'mock-plan',
    })
    assert matrix.main(['run', '--manifest', 'unused.json']) == expected
    assert json.loads(capsys.readouterr().out)['status'] == status


@pytest.mark.parametrize('kind', ['permission', 'session', 'dependency'])
def test_comparison_ignores_collected_sources_but_keeps_frozen_protocol(kind):
    from evaluation.scoring_evidence import evidence_hash
    from evaluation.thesis_scoring import _comparison_fingerprint
    document = {'fixture_id': 'fixture', 'protocol_version': 'v1',
        'oracle_protocol': {'kind': kind, 'enabled': True}}
    protocol = {'source_id': 'protocol', 'origin': 'operator_fixture',
        'document': document, 'sha256': evidence_hash(document)}
    record = {'config': {'scoring_oracles': [protocol]},
        'method': 'ac_idor', 'scoring_rule_sha256': 'rule'}
    fingerprint = _comparison_fingerprint(record)
    for index in range(2):
        collected = {'protocol_source_sha256': protocol['sha256'],
            **document, 'candidate_replay': {'session_fingerprint': f'session-{index}'},
            'requests': [{'response_sha256': f'response-{index}'}]}
        enriched = deepcopy(record)
        enriched['config']['scoring_oracles'].append({'source_id': f'protocol:evidence-{index}',
            'origin': protocol['origin'], 'document': collected, 'sha256': evidence_hash(collected)})
        snapshot = deepcopy(enriched)
        assert _comparison_fingerprint(enriched) == fingerprint
        assert enriched == snapshot
    changed = deepcopy(record)
    changed['config']['scoring_oracles'][0]['document']['oracle_protocol']['enabled'] = False
    assert _comparison_fingerprint(changed) != fingerprint
    changed = deepcopy(record)
    changed['config']['scoring_oracles'][0]['origin'] = 'offline_control'
    assert _comparison_fingerprint(changed) != fingerprint


def test_results_select_and_export_each_embedded_child(tmp_path, monkeypatch):
    from textual.app import App
    from textual.widgets import DataTable, Static
    from tesis.tui_drawers import ResultsDrawer

    path = tmp_path / 'aggregate.matrix.json'
    children = [{
        'run_id': 'same-compatibility-id', 'execution_id': f'child-{index}', 'status': 'success',
        'config': {'provider': f'provider-{index}', 'surface': 'sqli', 'security_level': 'low'},
        'selected_method': 'sqli_union', 'final_state': {},
    } for index in range(2)]
    write_json_report(path, {'status': 'success', 'runs': children})
    monkeypatch.setattr(ResultsDrawer, '_output_dir', lambda self: tmp_path)

    async def scenario():
        app = App()
        async with app.run_test(size=(100, 36)) as pilot:
            drawer = ResultsDrawer()
            await app.push_screen(drawer)
            for _ in range(100):
                await pilot.pause()
                if drawer.query_one('#results-table', DataTable).row_count == 2:
                    break
                await asyncio.sleep(0.01)
            table = drawer.query_one('#results-table', DataTable)
            assert table.row_count == 2
            assert '2 artifacts' in str(drawer.query_one('#results-summary', Static).render())
            for key in table.rows:
                drawer.inspect_row(SimpleNamespace(row_key=key))
                selected = drawer._selected_item
                raw = drawer._load_artifact(selected)
                assert raw['execution_id'] == selected.execution_id
                assert raw['config']['provider'] == selected.provider
                assert selected.provider in str(drawer.query_one('#results-detail', Static).render())
            drawer.export_triage()
            exported = json.loads((tmp_path / 'tui-results-export.json').read_text())
            assert {row['provider / model'] for row in exported} == {'provider-0 / —', 'provider-1 / —'}

    asyncio.run(asyncio.wait_for(scenario(), timeout=15))
