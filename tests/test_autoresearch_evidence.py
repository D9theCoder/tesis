"""Deterministic G18/G21 controls for scoring.v4 evidence classification.

No graph, runner, provider, or DVWA imports: these fixtures exercise only the
pure evidence reads in ``evaluation.scoring_evidence``.
"""
from __future__ import annotations

from typing import Any

import pytest

from core.run_status import terminal_status
from evaluation.scoring_evidence import candidate_base, output_grade


def _call(**overrides: Any) -> dict[str, Any]:
    record = {
        'role': 'orchestrator',
        'method': 'ac_idor',
        'visit_id': 'ac_idor:visit:1',
        'parse_status': 'ok',
        'validation_status': 'valid',
        'attempt': 1,
    }
    record.update(overrides)
    return record


def _artifact(*calls: dict[str, Any], state: dict[str, Any] | None = None) -> dict[str, Any]:
    return {'final_state': dict(state or {}), 'llm_performance': list(calls)}


def _grade(*calls: dict[str, Any], state: dict[str, Any] | None = None) -> tuple[Any, Any]:
    grade, reason = output_grade(_artifact(*calls, state=state), 'ac_idor')
    return grade, reason


def test_rate_limit_retry_is_not_a_structural_output_repair():
    call = _call(
        attempts=2,
        provider_dispatches=2,
        attempt_records=[
            {
                'attempt_id': 'call:attempt-1',
                'status': 'provider_error',
                'retry_reason': 'rate_limit',
                'diagnostic': {'failure_class': 'http_rejected', 'status_code': 429},
            },
            {'attempt_id': 'call:attempt-2', 'status': 'responded'},
        ],
    )
    assert _grade(call) == (3, 'context_call_evidence')


def test_rate_limit_exclusion_wins_over_conflicting_schema_tag():
    call = _call(
        attempts=2,
        provider_dispatches=2,
        attempt_records=[
            {
                'status': 'provider_error',
                'retry_reason': 'rate_limit',
                'diagnostic': {'failure_class': 'schema_rejected', 'status_code': 429},
            },
            {'status': 'responded'},
        ],
    )
    assert _grade(call) == (3, 'context_call_evidence')


def test_generic_attempt_and_dispatch_counts_alone_are_not_repair():
    call = _call(attempts=5, provider_dispatches=9, attempt_records=[])
    assert _grade(call) == (3, 'context_call_evidence')


def test_generic_attempt_ordinal_alone_is_not_repair():
    call = _call(attempt=2, attempts=2, attempt_records=[])
    assert _grade(call) == (3, 'context_call_evidence')


@pytest.mark.parametrize('prior', [
    {'status': 'invalid'},
    {'status': 'schema_rejected'},
    {'status': 'incomplete'},
    {'status': 'provider_error', 'diagnostic': {'failure_class': 'schema_rejected'}},
])
def test_recorded_structural_attempt_is_level_two(prior: dict[str, Any]):
    call = _call(attempts=2, provider_dispatches=2,
                 attempt_records=[prior, {'status': 'responded'}])
    assert _grade(call) == (2, 'context_call_evidence')


def test_structured_output_fallback_remains_level_two():
    call = _call(structured_output_fallback={
        'fallback': 'native_text',
        'reason': 'validated raw text without an extra provider call',
    })
    assert _grade(call) == (2, 'context_call_evidence')


def test_collapsed_structural_receipt_in_same_logical_call_is_level_two():
    failed = _call(parse_status='invalid', validation_status='invalid',
                   failure_class='schema_rejected')
    recovered = _call()
    assert _grade(failed, recovered) == (2, 'context_call_evidence')


def test_collapsed_transport_receipt_in_same_logical_call_is_not_repair():
    failed = _call(parse_status='provider_error', validation_status='invalid',
                   failure_class='http_rejected', status_code=429)
    recovered = _call()
    assert _grade(failed, recovered) == (3, 'context_call_evidence')


def test_legacy_http_retry_without_parse_status_is_not_repair():
    failed = _call(parse_status='', validation_status='invalid', status_code=429)
    recovered = _call()
    assert _grade(failed, recovered) == (3, 'context_call_evidence')


def test_collapsed_incomplete_receipt_in_same_logical_call_is_level_two():
    failed = _call(parse_status='incomplete', validation_status='invalid')
    recovered = _call()
    assert _grade(failed, recovered) == (2, 'context_call_evidence')


def _candidate_fixture(method: str, *, verification_reason: str | None,
                       signal_detected: bool = True) -> tuple[dict[str, Any], str, str, list[str]]:
    candidate_id = 'candidate-1'
    visit_id = f'{method}:visit:1'
    ref = '#/final_state/response_evidence/0'
    row = {
        'candidate_id': candidate_id,
        'agent_id': method,
        'visit_id': visit_id,
        'stage': 'exploit',
        'status_code': 200,
        'response_sha256': 'a' * 64,
        'evidence_id': 'evidence-1',
        'signal_detected': signal_detected,
    }
    if verification_reason is not None:
        row['verification_reason'] = verification_reason
    artifact = {
        'final_state': {
            'payload_provenance': {candidate_id: {'origin': 'model'}},
            'payload_validation_results': {method: [{'candidate_id': candidate_id, 'valid': True}]},
            'payload_candidates': {method: [{'candidate_id': candidate_id, 'stage': 'exploit'}]},
            'verifier_history': [{
                'visit_id': visit_id,
                'agent_id': method,
                'source': 'method_agent_evidence',
                'decision': 'unverified',
                'evidence_refs': [ref],
            }],
            'response_evidence': [row],
        },
    }
    return artifact, candidate_id, method, [ref]


@pytest.mark.parametrize('method', ['ac_idor', 'bf_spray'])
def test_signal_boolean_without_a_proof_class_grants_no_tier(method: str):
    artifact, candidate_id, method, refs = _candidate_fixture(
        method, verification_reason=None, signal_detected=True,
    )
    assert candidate_base(artifact, candidate_id, method, refs) is None


@pytest.mark.parametrize(('method', 'verification_reason'), [
    ('ac_idor', 'visibility_without_permission_oracle'),
    ('bf_spray', 'verified_login'),
])
def test_recognized_partial_proof_class_keeps_its_tier(method: str, verification_reason: str):
    artifact, candidate_id, method, refs = _candidate_fixture(
        method, verification_reason=verification_reason, signal_detected=False,
    )
    assert candidate_base(artifact, candidate_id, method, refs) == 2


def test_signal_only_permission_row_stays_unconfirmed():
    """G21 blast radius: a bare boolean cannot become permission proof."""
    artifact, _candidate_id, _method, _refs = _candidate_fixture(
        'ac_idor', verification_reason=None, signal_detected=True,
    )
    status = terminal_status(artifact, execution_status='completed', classify=True)
    assert status['security_outcome'] == 'unconfirmed'
    assert status['security_outcome_reason']['code'] == 'NO_CANDIDATE_CONFIRMATION'


def test_recognized_partial_proof_still_reports_the_oracle_limitation():
    artifact, _candidate_id, _method, _refs = _candidate_fixture(
        'ac_idor', verification_reason='visibility_without_permission_oracle', signal_detected=False,
    )
    status = terminal_status(artifact, execution_status='completed', classify=True)
    assert status['security_outcome'] == 'fixture_limited'
    assert status['security_outcome_reason']['code'] == 'PERMISSION_ORACLE_UNAVAILABLE'


def test_oracle_path_still_grants_a_base_without_a_proof_class(monkeypatch):
    artifact, candidate_id, method, refs = _candidate_fixture(
        'ac_idor', verification_reason=None, signal_detected=False,
    )
    monkeypatch.setattr('evaluation.scoring_evidence.oracle_confirmed', lambda *_: True)
    assert candidate_base(artifact, candidate_id, method, refs) == 3


@pytest.mark.parametrize(('verification_reason', 'signal_detected', 'expected'), [
    ('no_verified_exploit_signal', False, 0),
    ('no_verified_exploit_signal', True, None),
    ('timing_not_verified', False, 0),
    ('timing_not_verified', True, None),
])
def test_measured_negative_requires_a_consistent_negative_signal(
        verification_reason: str, signal_detected: bool, expected: int | None):
    artifact, candidate_id, method, refs = _candidate_fixture(
        'sqli_time_blind', verification_reason=verification_reason,
        signal_detected=signal_detected,
    )
    assert candidate_base(artifact, candidate_id, method, refs) == expected
