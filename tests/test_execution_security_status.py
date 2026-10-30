"""Unit controls for terminal metadata; no graph, HTTP, or provider execution."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from core.run_status import (terminal_status)
from core.state import new_default_state
from evaluation.thesis_scoring import review_queue, finalize_reviews


def evidence_artifact(method='sqli_union', decision='not_confirmed', signal='no_verified_exploit_signal'):
    row = dict(candidate_id='candidate', agent_id=method, stage='exploit', visit_id='visit',
        evidence_id='response', response_sha256='a' * 64, status_code=200,
        verification_reason=signal, signal_detected=decision == 'confirmed')
    state = new_default_state()
    state.update(selected_method=method, target_method=method,
        payload_candidates={method: [dict(candidate_id='candidate', method=method,
            stage='exploit', payload_or_logic='offline-example', source='static_seed')]},
        payload_validation_results={method: [dict(candidate_id='candidate', valid=True)]},
        payload_provenance={'candidate': dict(method=method, source='static_seed')},
        response_evidence=[row], verifier_history=[dict(agent_id=method, visit_id='visit',
            decision=decision, source='method_agent_evidence',
            evidence_refs=['#/final_state/response_evidence/0'])])
    return dict(status='success', run_id='unit', execution_id='unit-execution',
        selected_method=method, target_method=method, final_state=state, response_evidence=[row],
        config=dict(provider='offline', surface='sqli', security_level='low', payload_mode='static_only',
            scoring_rubric_version='scoring.v4', scoring_profile={}, scoring_oracles=[],
            scoring_mode='human', scoring_evaluator={}))


def test_confirmed_requires_method_proof_and_legacy_marker_alone_is_insufficient():
    artifact = evidence_artifact(decision='confirmed', signal='verified_account_extraction')
    assert terminal_status(artifact, classify=True)['security_outcome'] == 'confirmed'
    assert terminal_status({'status': 'success', 'task_result': 'SUCCESS', 'confirmed_vulns': ['old-label']})['security_outcome'] == 'unconfirmed'


@pytest.mark.parametrize('missing_component', [False, True])
def test_final_score_requires_all_components_and_zero_does_not_zero_the_sum(monkeypatch, tmp_path, missing_component):
    # Isolate finalization: ranking/output proofs are supplied by its queue contract.
    artifact = evidence_artifact()
    path = tmp_path / 'source.json'
    path.write_text(json.dumps(artifact))
    before = path.read_bytes()
    queue = review_queue(path)
    queue['components'].update(Smethod=3, Sexploit=0, Schain=0, Soutput=None if missing_component else 3)
    queue['component_pending_reasons'] = {'Soutput': 'missing_required_evidence'} if missing_component else {}
    monkeypatch.setattr('evaluation.thesis_scoring.review_queue', lambda source: deepcopy(queue))
    result = finalize_reviews(path, [])
    if missing_component:
        assert not result['receipts'] and result['workflows']['human']['Srun_final'] is None
    else:
        receipt = json.loads(Path(result['receipts']['human']).read_text())
        assert receipt['components']['Sexploit'] == receipt['Spayload_final'] == 0
        assert receipt['Srun_final'] == 1.2
        assert receipt['security_outcome'] == 'no_finding'
    assert path.read_bytes() == before
