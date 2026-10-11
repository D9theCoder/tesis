"""Read-only audit of frozen scoring sources, review joins and diagnostic evidence.

This module never creates target sessions, invokes providers, finalizes reviews,
or executes saved payloads. Evidence gaps remain gaps in the derived ledgers.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from urllib.parse import urlsplit

from evaluation.thesis_scoring import WEIGHTS, _validated_reviews, review_ledger_path, review_queue


COORDINATE_KEYS = ('experiment_condition', 'target_method', 'security_level',
                   'payload_mode', 'repeat_index')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def resolve(document, ref):
    require(isinstance(ref, str) and ref.startswith('#/'), 'Invalid evidence reference')
    value = document
    try:
        for part in ref[2:].split('/'):
            part = part.replace('~1', '/').replace('~0', '~')
            value = value[int(part)] if isinstance(value, list) else value[part]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise ValueError(f'Unresolved evidence reference: {ref}') from exc
    return value


class EvidenceReader:
    """Hash every input and check that it remains unchanged before publication."""

    def __init__(self):
        self.sources: dict[str, str] = {}

    def raw(self, path, expected=None):
        path = Path(path).resolve()
        raw = path.read_bytes()
        digest = sha256(raw).hexdigest()
        require(expected is None or digest == expected, f'Source hash mismatch: {path}')
        require(str(path) not in self.sources or self.sources[str(path)] == digest,
                f'Source changed during audit: {path}')
        self.sources[str(path)] = digest
        return raw

    def read(self, path, expected=None):
        return json.loads(self.raw(path, expected))

    def lines(self, path):
        return [json.loads(line) for line in self.raw(path).decode().splitlines() if line.strip()]

    def binding(self, path):
        self.raw(path)
        path = Path(path).resolve()
        return {'path': str(path), 'sha256': self.sources[str(path)]}

    def verify_unchanged(self):
        for path, digest in list(self.sources.items()):
            self.raw(path, digest)


def _check_grades(queue, document, grades):
    eligible = {r['candidate_id']: r for r in queue['candidates'] if r['eligible']}
    ids = [g['candidate_id'] for g in grades]
    require(len(ids) == len(set(ids)) and set(ids) == set(eligible),
            'Grades do not cover distinct eligible candidates exactly')
    for grade in grades:
        row = eligible[grade['candidate_id']]
        require(grade['proof_ceiling'] == row['proof_ceiling'], 'Candidate proof ceiling mismatch')
        refs = grade['evidence_refs']
        require(isinstance(refs, list) and set(refs) <= set(row['evidence_refs'])
                and (refs or (grade['score'] is None and row['status'] == 'not_assessable')),
                'Grade cites unrelated candidate evidence')
        for ref in refs:
            resolve(document, ref)
        score = grade['score']
        if score is not None:
            require(type(score) is int and row['proof_ceiling'] is not None
                    and 0 <= score <= row['proof_ceiling'], 'Grade exceeds evidence ceiling')
    return eligible


def audit_score_coverage(reader, manifest_path, rounds):
    """Join the latest recorded review round to each immutable execution source."""
    manifest = reader.read(manifest_path)
    sources = manifest['sources']
    by_id = {r['execution_id']: r for r in sources}
    require(len(by_id) == len(sources), 'Duplicate source execution')
    require(len({r['sha256'] for r in sources}) == len(sources), 'Duplicate source hash')
    latest, history = {}, {}
    for progress_path, receipt_dir in rounds:
        for record in reader.lines(progress_path):
            eid = record['execution_id']
            require(eid in by_id and record['source_sha256'] == by_id[eid]['sha256'],
                    'Review round joins a different execution/source')
            source = Path(by_id[eid]['path'])
            status_path = Path(record.get('status_path') or (
                (Path(receipt_dir) if receipt_dir else source.parent / 'reviews') /
                f'{eid}.review-status.json'))
            latest[eid] = status_path
            history.setdefault(eid, []).append({'progress': reader.binding(progress_path),
                'status_path': str(status_path)})
    require(set(latest) == set(by_id), 'Review coverage is incomplete')
    rows = []
    for item in sources:
        path = Path(item['path'])
        artifact = reader.read(path, item['sha256'])
        require(all(artifact.get(k) == v for k, v in item['coordinate'].items() if k in COORDINATE_KEYS),
                'Source coordinate does not match manifest')
        queue = review_queue(path)
        require(queue['source_sha256'] == item['sha256'] and queue['execution_id'] == item['execution_id'],
                'Queue execution/source mismatch')
        require(queue['selection'] == 'ai', 'Source is not from the AI-only cohort')
        status_path = latest[item['execution_id']]
        status = reader.read(status_path)
        require(status['source_sha256'] == item['sha256'] and status['method'] == queue['method']
                and status['rubric_version'] == queue['rubric_version']
                and status['scoring_rule_sha256'] == queue['scoring_rule_sha256'],
                'Review status source/method/rubric/rules mismatch')
        workflow = status['workflows']['ai']
        grades = workflow['candidate_grades']
        eligible = _check_grades(queue, artifact, grades)
        receipt_path = status['receipts'].get('ai')
        receipt_binding, vector = None, None
        if receipt_path:
            receipt = reader.read(receipt_path)
            require(receipt['source_sha256'] == item['sha256']
                    and receipt['execution_id'] == queue['execution_id']
                    and receipt['run_id'] == queue['run_id']
                    and receipt['method'] == queue['method']
                    and receipt['rubric_version'] == queue['rubric_version']
                    and receipt['scoring_rule_sha256'] == queue['scoring_rule_sha256']
                    and receipt['scoring_mode'] == 'ai'
                    and receipt['artifact_type'] == 'thesis_score_receipt'
                    and receipt['status'] == workflow['status'] == 'final',
                    'Receipt joins a different source/execution/workflow')
            _check_grades(queue, artifact, receipt['candidate_grades'])
            require(receipt['candidate_grades'] == grades, 'Receipt/status candidate mismatch')
            require(grades and all(g['score'] is not None for g in grades), 'Incomplete numeric receipt')
            decisions = _validated_reviews(queue, receipt['review_history'])
            for grade in grades:
                decision = decisions.get(('ai', grade['candidate_id']))
                if grade['grade_origin'] == 'signal_gate':
                    require(eligible[grade['candidate_id']]['status'] == 'signal_absent'
                            and grade['score'] == 0, 'Invalid automatic negative gate')
                else:
                    require(decision and decision['score'] == grade['score']
                            and decision['decision_id'] == grade['decision_id'], 'Grade has no bound AI decision')
            numerator, denominator = sum(g['score'] for g in grades), len(grades)
            require(receipt['denominator'] == denominator and receipt['numerator'] == numerator,
                    'Receipt numerator/denominator mismatch')
            vector = {**queue['components'], 'Spayload': numerator / denominator}
            require(receipt['components'] == vector and receipt['formula'] == WEIGHTS,
                    'Receipt vector/formula mismatch')
            score = round(sum(vector[k] * w for k, w in WEIGHTS.items()), 4)
            require(receipt['Srun_final'] == workflow['Srun_final'] == score
                    and receipt['Spayload_final'] == workflow['Spayload_final'] == round(numerator / denominator, 4),
                    'Receipt arithmetic mismatch')
            classification = 'numeric_ai_receipt'
            receipt_binding = reader.binding(receipt_path)
        else:
            require(workflow['status'] == 'pending' and workflow['Srun_final'] is None
                    and workflow['Spayload_final'] is None, 'Missing receipt was treated as final')
            classification = ('no_eligible_candidate' if not eligible else 'not_assessable'
                if any(r['status'] == 'not_assessable' for r in eligible.values())
                else 'pending_candidate_review')
        ledger_path = review_ledger_path(path)
        ledger = reader.read(ledger_path)
        _validated_reviews(queue, ledger)
        rows.append({'execution_id': item['execution_id'], 'source': reader.binding(path),
            'coordinate': item['coordinate'], 'original_status': artifact['status'],
            'classification': classification, 'workflow_reason': workflow['reason'],
            'component_pending_reasons': workflow['component_pending_reasons'],
            'eligible_candidate_ids': list(eligible), 'denominator': len(eligible),
            'assessed_denominator': sum(g['score'] is not None for g in grades),
            'assessed_numerator': sum(g['score'] for g in grades if g['score'] is not None),
            'candidate_grades': grades, 'Spayload_final': workflow['Spayload_final'],
            'candidates_missing_execution_evidence': [r['candidate_id'] for r in eligible.values() if not r['evidence_refs']],
            'Srun_final': workflow['Srun_final'], 'components': vector,
            'ai_receipt': receipt_binding, 'human_receipt': status['receipts'].get('human'),
            'review_status': reader.binding(status_path), 'decision_ledger': reader.binding(ledger_path),
            'review_rounds': history[item['execution_id']]})
    return rows


def audit_retry_outcomes(reader, root):
    retry = root / 'matrix/retry-failed-coordinates-epoch1'
    plan = reader.read(retry / 'retry-plan.json')
    end = reader.read(retry / 'matrix-end.json')
    require(len(plan['coordinates']) == end['completed_artifacts'] == 49, 'Retry cohort is incomplete')
    planned = {r['source_execution_id']: r for r in plan['coordinates']}
    controls_path = retry / 'ac-security-php-policy-controls-20261011T060228Z-5bfd23d4/summary.json'
    controls = reader.read(controls_path)
    for binding in controls['candidate_bindings']:
        reader.raw(binding['source_artifact'], binding['source_sha256'])
    repair_path = retry / 'code-fix-replay-sqli-error-high/session-recovery-replay-20261011T055922Z-02287ae8/summary.json'
    repair = reader.read(repair_path)
    require(repair['provider_calls'] == 0, 'Historical diagnostic replay called a provider')
    repairs = {r['source_sha256']: r for r in repair['replays']}
    rows = []
    for outcome in end['retry_outcomes']:
        selected = planned[outcome['source_execution_id']]
        reader.raw(selected['source_artifact_path'], selected['source_artifact_sha256'])
        path = retry / 'runs' / f'{outcome["execution_id"]}.json'
        artifact = reader.read(path, outcome['artifact_sha256'])
        require({k: artifact[k] for k in COORDINATE_KEYS} == selected['coordinate'] == outcome['coordinate'],
                'Retry coordinate mismatch')
        require(artifact['execution_id'] == outcome['execution_id'] and artifact['status'] == outcome['status'],
                'Retry identity/status mismatch')
        transport_path = retry / 'transport' / f'{outcome["execution_id"]}.transport.json'
        transport = reader.read(transport_path, outcome['transport_receipt_sha256'])
        require(transport['execution_id'] == artifact['execution_id']
                and transport['source_execution_id'] == outcome['source_execution_id']
                and transport['coordinate'] == selected['coordinate']
                and transport['scope_valid'] is True
                and len(transport['requests']) == transport['request_count'], 'Retry transport mismatch')
        if artifact['status'] != 'error':
            continue
        state = artifact['final_state']
        method = artifact['target_method']
        validations = list(artifact['payload_validation_results'].get(method, []))
        provenance = state.get('payload_provenance', {})
        candidates = {c['candidate_id']: c for c in artifact['payload_candidates'].get(method, [])}
        for frozen in artifact['method_execution_inputs']:
            for candidate in frozen['state'].get('payload_candidates', {}).get(method, []):
                candidates.setdefault(candidate['candidate_id'], candidate)
            probe_controls = frozen['state'].get('probe_controls', {}).get(method, {})
            for candidate in probe_controls.get('candidates', []):
                candidates.setdefault(candidate['candidate_id'], candidate)
            for validation in probe_controls.get('validation_results', []):
                if validation not in validations:
                    validations.append(validation)
        responses = []
        for index, response in enumerate(artifact['response_evidence']):
            matches = [i for i, request in enumerate(transport['requests'])
                if request.get('classification') == 'dvwa'
                and request.get('response_sha256') == response.get('response_sha256')
                and request.get('status_code') == response.get('status_code')
                and request.get('path') == urlsplit(response.get('endpoint', '')).path]
            responses.append({'ref': f'#/response_evidence/{index}',
                **{k: response.get(k) for k in ('evidence_id', 'candidate_id', 'stage', 'visit_id',
                    'status_code', 'response_sha256', 'verification_reason', 'verified_grade', 'oracle_ref')},
                'possible_transport_indices': matches,
                'wire_join': 'unique' if len(matches) == 1 else 'ambiguous' if matches else 'unavailable'})
        candidate_rows = []
        for cid in dict.fromkeys([*candidates, *[v['candidate_id'] for v in validations]]):
            candidate = candidates.get(cid, {})
            source = candidate.get('source') or provenance.get(cid, {}).get('source')
            own_responses = [r for r in responses if r['candidate_id'] == cid]
            candidate_rows.append({'candidate_id': cid, 'origin': source,
                'provenance': provenance.get(cid) or {k: candidate.get(k) for k in
                    ('source', 'source_seed_id', 'mutation_type', 'method', 'target_param', 'expected_signal')},
                'stage': candidate.get('stage'),
                'candidate_sha256': sha256(json.dumps(candidate, sort_keys=True).encode()).hexdigest() if candidate else None,
                'validation': [v for v in validations if v['candidate_id'] == cid],
                'executed_evidence_refs': [r['ref'] for r in own_responses],
                'observed_reasons': sorted({r['verification_reason'] for r in own_responses if r['verification_reason']}),
                'result': 'executed_negative_or_partial' if own_responses and any(r['stage'] in {'exploit', 'bypass'}
                    for r in own_responses) else 'probe_only' if own_responses else 'not_executed'})
        require({r['candidate_id'] for r in responses if r['candidate_id'] is not None} <=
                {c['candidate_id'] for c in candidate_rows},
                'Response candidate has no recorded identity')
        verifier = artifact['verifier_decision']
        for ref in verifier.get('evidence_refs', []):
            resolve(artifact, ref)
        matched = [b for b in controls['candidate_bindings'] if b['source_sha256'] == outcome['artifact_sha256']]
        diagnostic = repairs.get(outcome['artifact_sha256'])
        contextual = []
        if matched:
            contextual.append({'kind': 'candidate_bound_declared_policy', 'source': reader.binding(controls_path),
                'bindings': matched, 'limitation': 'Deployed version unpinned; authenticated allow is not unauthorized role access.'})
        if diagnostic:
            replay = reader.read(diagnostic['output'])
            require(replay['source_sha256'] == outcome['artifact_sha256'] and replay['fresh_provider_calls'] == 0,
                    'Historical replay source/provider mismatch')
            fields = ('candidate_id', 'payload_or_logic', 'method', 'stage', 'source', 'source_seed_id', 'mutation_type')
            saved = artifact['method_execution_inputs'][replay['input_index']]['state']['payload_candidates'][method]
            replayed = replay['final_state']['payload_candidates'][method]
            signature = lambda candidates: [{k: c.get(k) for k in fields} for c in candidates]
            require(signature(saved) == signature(replayed), 'Historical replay changed saved candidate values/order')
            contextual.append({'kind': 'historical_saved_input_replay', 'summary': reader.binding(repair_path),
                'replay': reader.binding(diagnostic['output']), 'verifier': diagnostic['verifier_decision'],
                'same_saved_queue': True, 'baseline_exploit_response_count': sum(r['stage'] in {'exploit', 'bypass'} for r in responses),
                'after_exploit_response_count': diagnostic['exploit_response_count'],
                'new_repair_in_this_audit': False})
        reasons = Counter(r['verification_reason'] for r in responses)
        mechanism = ('historical_probe_gate_prevented_exploit_execution' if diagnostic else
            'permission_oracle_missing' if reasons['visibility_without_permission_oracle'] else
            'only_probe_evidence_recorded' if not any(r['stage'] in {'exploit', 'bypass'} for r in responses) else
            'executed_candidates_did_not_meet_confirmation_policy')
        axes = {axis: 'insufficient_evidence' for axis in (
            'code', 'fixture', 'provider_parser', 'transport', 'verifier_scorer', 'evidence', 'executed_payload')}
        axes['transport'] = 'responses_received_in_scope' if all(r.get('response_received') for r in
            transport['requests'] if r.get('classification') == 'dvwa') else 'response_missing'
        axes['provider_parser'] = 'recorded_calls_completed' if artifact['llm_activity'].get('failed') == 0 else 'recorded_failure'
        axes['executed_payload'] = 'negative_or_partial_observed' if any(r['stage'] in {'exploit', 'bypass'}
            for r in responses) else 'not_executed'
        if diagnostic:
            axes['code'] = 'previously_repaired_probe_gate_defect'
        if reasons['visibility_without_permission_oracle']:
            axes['evidence'] = 'permission_oracle_missing'
        unattributed = [r['ref'] for r in responses if r['candidate_id'] is None]
        if unattributed:
            axes['evidence'] = 'response_candidate_identifier_missing'
        rows.append({'execution_id': artifact['execution_id'], 'source': reader.binding(path),
            'primary_source': {'path': selected['source_artifact_path'], 'sha256': selected['source_artifact_sha256']},
            'primary_execution_id': selected['source_execution_id'], 'coordinate': outcome['coordinate'],
            'original_status': artifact['status'], 'incomplete_reason': artifact['incomplete_reason'],
            'candidates': candidate_rows, 'responses': responses,
            'unattributed_response_evidence_refs': unattributed,
            'actual_transport': reader.binding(transport_path),
            'request_response_refs': [f'#/requests/{i}' for i, r in enumerate(transport['requests']) if r['classification'] == 'dvwa'],
            'verifier_decision': verifier, 'observed_mechanism': mechanism, 'cause_axes': axes,
            'primary_cause': 'code' if diagnostic else 'insufficient_evidence',
            'confidence': 'supported_contributor' if diagnostic else 'unresolved',
            'controls': contextual,
            'unavailable_controls_reason': 'No independent matched positive/negative control for this exact candidate, action and session epoch.'
                if not contextual else 'Attached diagnostics do not resolve every alternative cause.',
            'next_discriminating_control': 'Independent candidate-bound positive/negative fixture references with complete request/session evidence.',
            'model_attribution': 'not_established'})
    require(len(rows) == 46 and len({r['execution_id'] for r in rows}) == 46, 'Retry ledger does not cover 46/46')
    return rows, controls


def _snapshots(value, prefix='#'):
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            ref = f'{prefix}/{key}'
            if key == 'probe_controls' and child:
                found.append(ref)
            found.extend(_snapshots(child, ref))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            found.extend(_snapshots(child, f'{prefix}/{i}'))
    return found


def _probe_definitions(value, prefix='#'):
    """Find recoverable definitions without treating prompt seeds as validation."""
    found = []
    if isinstance(value, dict):
        if value.get('stage') == 'probe' and 'payload_or_logic' in value:
            found.append((prefix, value))
        for key, child in value.items():
            found.extend(_probe_definitions(child, f'{prefix}/{key}'))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            found.extend(_probe_definitions(child, f'{prefix}/{i}'))
    return found


def audit_original_nine(reader, root):
    manifest = reader.read(root / 'replay/original-nine-manifest.json')
    require(len(manifest['records']) == 9, 'Original-nine catalog is incomplete')
    rows = []
    for record in manifest['records']:
        source = Path(record['original_source_path'])
        artifact = reader.read(source, record['original_source_sha256'])
        traces = [source, *sorted(source.parent.glob(f'{source.stem}.rich.json')),
                  *sorted(source.parent.glob(f'{source.stem}.events.jsonl')),
                  *sorted(source.parent.glob(f'{source.stem}.failure.json'))]
        probes, definitions = [], []
        for trace in traces:
            document = reader.lines(trace) if trace.suffix == '.jsonl' else reader.read(trace)
            probes.extend({'path': str(trace), 'ref': ref} for ref in _snapshots(document))
            definitions.extend({'path': str(trace), 'ref': ref, 'candidate_id': candidate['candidate_id'],
                'definition_sha256': sha256(json.dumps(candidate, sort_keys=True).encode()).hexdigest(),
                'evidence_scope': 'seed_definition_not_validated_execution_snapshot'}
                for ref, candidate in _probe_definitions(document))
        transport_path = source.parent.parent / 'transport' / f'{source.stem}.transport.json'
        request_shapes = False
        if transport_path.exists():
            transport = reader.read(transport_path)
            traces.append(transport_path)
            requests = transport.get('requests', [])
            request_shapes = bool(requests) and all(set(r) >= {'method', 'path', 'query', 'body', 'session_context'} for r in requests)
        frozen = artifact['method_execution_inputs'][record['input_index']]['state']
        saved_probe_candidates = [c['candidate_id'] for c in frozen['payload_candidates'].get(record['method'], [])
                                  if c.get('stage') == 'probe']
        recovered = bool(probes or saved_probe_candidates) and request_shapes
        reconstructed = reader.read(record['replay_path'])
        recorded_seeds = {c['candidate_id']: c for call in artifact.get('llm_performance', [])
            for c in call.get('input', {}).get('seeds', []) if c.get('stage') == 'probe'}
        reconstructed_probes = {c['candidate_id']: c for c in reconstructed.get('probe_controls', {}).get(
            record['method'], {}).get('candidates', [])}
        fields = ('candidate_id', 'payload_or_logic', 'method', 'stage', 'source', 'source_seed_id', 'mutation_type')
        matching = bool(recorded_seeds) and set(recorded_seeds) == set(reconstructed_probes) and all(
            all(recorded_seeds[cid].get(k) == reconstructed_probes[cid].get(k) for k in fields) for cid in recorded_seeds)
        rows.append({'execution_id': record['original_execution_id'], 'source': reader.binding(source),
            'searched_traces': [reader.binding(p) for p in traces],
            'saved_probe_snapshot_refs': probes, 'saved_probe_candidate_ids': saved_probe_candidates,
            'recoverable_seed_definitions': definitions,
            'catalog_matches_recorded_seed_values_and_provenance': matching,
            'independent_transport_trace_present': transport_path.exists(),
            'complete_request_and_session_shapes': request_shapes,
            'disposition': 'exact_inputs_recovered' if recovered else 'irrecoverable_from_retained_source_traces',
            'missing': ([] if probes or saved_probe_candidates else ['validated_probe_snapshots']) +
                ([] if request_shapes else ['full_request_method_path_query_body_and_session_context']),
            'catalog_replay': reader.binding(record['replay_path']),
            'catalog_replay_scope': 'diagnostic_reconstruction_not_exact_historical_replay'})
    return rows


def audit_forward_controls(reader, control_paths):
    rows = []
    for path in control_paths:
        control = reader.read(path)
        source = reader.read(control['source_path'], control['source_sha256'])
        replay = reader.read(control['replay_path'], control['replay_sha256'])
        shapes = reader.read(control['request_shapes_path'], control['request_shapes_sha256'])
        require(source['validation_scope'] == control['validation_scope'] == shapes['validation_scope'] == 'offline_synthetic_fixture',
                'Forward control is not a labeled offline fixture')
        require(control['fresh_provider_calls'] == replay['fresh_provider_calls'] == 0
                and replay['source_sha256'] == control['source_sha256'] and not replay['validation_rejections'],
                'Forward replay binding/validation mismatch')
        frozen = source['method_execution_inputs'][0]['state']
        method = control['method']
        require(frozen['probe_controls'][method]['candidates'] and frozen['payload_candidates'][method],
                'Forward input stages are incomplete')
        require([(r['candidate_id'], r['stage'], r['payload']) for r in source['response_evidence']] ==
                [(r['candidate_id'], r['stage'], r['payload']) for r in replay['response_evidence']],
                'Forward candidate values/order changed')
        require(shapes['original'] and shapes['replay'] and all(set(r) >= {'session', 'verb', 'url', 'data', 'cookie_id'}
            for r in shapes['replay']), 'Forward request/session structures are missing')
        rows.append({'method': method, 'control': reader.binding(path), 'source': reader.binding(control['source_path']),
            'replay': reader.binding(control['replay_path']), 'request_shapes': reader.binding(control['request_shapes_path']),
            'fresh_provider_calls': 0, 'validation_scope': 'offline_synthetic_fixture',
            'mock_http_transactions': len(shapes['replay']), 'candidate_values_and_order_preserved': True})
    require(len(rows) == 9 and len({r['method'] for r in rows}) == 9, 'Forward controls must cover all nine methods once')
    return rows


def build_audit(root, forward_manifest):
    root = Path(root).resolve()
    reader = EvidenceReader()
    closure = reader.read(root / 'handoff-closure.json')
    completion = reader.read(root / 'completion-status.json', closure['source_completion_status_sha256'])
    review = root / 'matrix/reviews/v2-scoring-rules'
    rounds = [(review / 'ai-review-progress.jsonl', None)] + [
        (review / f'retry-0{i}/retry-progress.jsonl', review / f'retry-0{i}/receipts') for i in (1, 2, 3)]
    coverage = audit_score_coverage(reader, review / 'review-input-manifest.json', rounds)
    require(len(coverage) == 108 and len({tuple(r['coordinate'][k] for k in COORDINATE_KEYS) for r in coverage}) == 108,
            'Scoring coverage does not cover 108 distinct coordinates')
    counts = Counter(r['classification'] for r in coverage)
    require(counts == {'numeric_ai_receipt': 90, 'no_eligible_candidate': 8,
                       'not_assessable': 7, 'pending_candidate_review': 3}, 'Coverage differs from frozen closure counts')
    pending = completion['matrix_ai_review']['pending_candidates']
    actual_pending = {r['execution_id']: r for r in coverage if r['classification'] == 'pending_candidate_review'}
    for entry in pending:
        row = actual_pending[entry['execution_id']]
        require(row['source']['sha256'] == entry['source_sha256'] and set(entry['candidate_ids']) ==
                {g['candidate_id'] for g in row['candidate_grades'] if g['score'] is None}, 'Deferred candidate mismatch')
        row['deferred_decisions'] = entry
        telemetry_bindings, abstentions = [], Counter()
        for progress_path, _ in rounds:
            records = [r for r in reader.lines(progress_path) if r['execution_id'] == entry['execution_id']]
            for record in records:
                telemetry = reader.read(record['telemetry_path'])
                for attempt in telemetry['telemetry']:
                    if attempt.get('candidate_id') in entry['candidate_ids'] and attempt.get('status') == 'abstained':
                        abstentions[attempt['error_type']] += 1
                telemetry_bindings.append(reader.binding(record['telemetry_path']))
        require(abstentions['JSONDecodeError'] == sum(r['json_decode_abstentions'] for r in entry['candidate_failures']),
                'Deferred review telemetry count mismatch')
        row['deferred_review_telemetry'] = {'sources': telemetry_bindings, 'abstentions': dict(abstentions),
            'disposition': 'deferred_without_numeric_substitution',
            'limitation': 'Historical failed attempts retain prompt hashes/error types but no raw response; parser/provider cause cannot be resolved.'}
    retries, controls = audit_retry_outcomes(reader, root)
    originals = audit_original_nine(reader, root)
    forward_paths = reader.read(forward_manifest)['control_paths']
    forward = audit_forward_controls(reader, forward_paths)
    for code_path in (__file__, 'tests/test_remaining_evidence_audit_e2e.py',
                      'evaluation/thesis_scoring.py', 'evaluation/scoring_evidence.py'):
        reader.raw(code_path)
    # Recheck matrix and retry hash commitments rather than trust their summaries.
    retry_plan = reader.read(root / 'matrix/retry-failed-coordinates-epoch1/retry-plan.json')
    for filename, key in [('matrix-start.json', 'matrix_start_sha256'), ('matrix-end.json', 'matrix_end_sha256'),
                          ('matrix-aggregate.json', 'matrix_aggregate_sha256')]:
        reader.raw(root / 'matrix' / filename, retry_plan['source_matrix'][key])
    reader.verify_unchanged()
    summary = {'kind': 'scoring_v4_remaining_evidence_audit', 'validation_scope': 'offline_saved_artifact_audit',
        'fresh_provider_calls': 0, 'fresh_live_http_calls': 0, 'retry_rows': len(retries), 'scoring_rows': len(coverage),
        'scoring_classifications': dict(counts), 'original_nine_dispositions': dict(Counter(r['disposition'] for r in originals)),
        'retry_mechanisms': dict(Counter(r['observed_mechanism'] for r in retries)),
        'retry_primary_causes': dict(Counter(r['primary_cause'] for r in retries)),
        'original_nine_partial_seed_recovery': sum(bool(r['recoverable_seed_definitions']) for r in originals),
        'deferred_ai_decisions': pending, 'numeric_coverage': {'numerator': 90, 'denominator': 108},
        'new_code_repairs': [], 'historical_probe_gate_repairs': 4,
        'access_control': {'control_source': reader.binding(root / 'matrix/retry-failed-coordinates-epoch1/'
            'ac-security-php-policy-controls-20261011T060228Z-5bfd23d4/summary.json'),
            'deployed_source_version_pinned': controls['policy']['deployed_source_version_pinned'],
            'disposition': 'retain_declared_policy_limitation', 'role_restriction_proved': False,
            'scores_rewritten': False},
        'forward_capture': {'methods': len(forward), 'validation_scope': 'offline_synthetic_fixture',
            'historical_proof_replaced': False, 'live_acceptance': False},
        'originals_and_receipts_unchanged': True, 'cohorts_merged': False,
        'sources': reader.sources}
    return {'summary.json': summary, 'retry-attribution.json': retries,
            'scoring-coverage.json': coverage, 'original-nine-disposition.json': originals,
            'forward-capture.json': forward}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--forward-manifest', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args(argv)
    output = Path(args.output_dir).resolve()
    require(not output.exists(), 'Audit output must be a new evidence epoch')
    output.parent.mkdir(parents=True, exist_ok=True)
    require(not output.is_relative_to(Path(args.source_root).resolve()), 'Audit output must be outside frozen source root')
    evidence = build_audit(args.source_root, args.forward_manifest)
    output.mkdir()
    for name, data in evidence.items():
        with (output / name).open('x', encoding='utf-8') as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.write('\n')
    print(json.dumps({'output_dir': str(output), 'retry_rows': 46, 'scoring_rows': 108,
                      'fresh_provider_calls': 0, 'fresh_live_http_calls': 0}))


if __name__ == '__main__':
    main()
