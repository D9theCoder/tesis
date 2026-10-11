"""Opt-in independent DVWA session controls before immutable artifact export.

Only a frozen operator protocol enables HTTP. Credentials remain in memory;
the collector neither changes graph decisions nor claims chain consumption.
"""
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import re

from bs4 import BeautifulSoup

from evaluation.scoring_evidence import evidence_hash, validate_sources
from foundation.session_manager import DVWASession, session_fingerprint
from foundation.verifier import fixture_attestation_valid


def _identity(response):
    text = BeautifulSoup(response.text, 'html.parser').get_text(' ', strip=True)
    found = re.search(r'Username:\s*([^\s]+)', text)
    return found.group(1) if found else None


def _controls(target, username, password, initial_fingerprint):
    sessions, requests = [], []
    def new_session():
        session = DVWASession(target)
        sessions.append(session)
        session.http._client.event_hooks['response'].append(lambda response: requests.append({
            'method': response.request.method, 'path': response.request.url.path,
            'status_code': response.status_code, 'response_sha256': sha256(response.read()).hexdigest()}))
        return session
    try:
        positive = new_session()
        preauth = positive.get('index.php')
        before = session_fingerprint(positive)
        preauth_identity = _identity(preauth)
        accepted = positive.login(username, password)
        identity = _identity(positive.get('index.php'))
        fingerprint = session_fingerprint(positive)
        result = {'principal_id': identity, 'expected_principal_id': username,
            'session_fingerprint': fingerprint, 'initial_session_fingerprint': initial_fingerprint,
            'credentials_valid': accepted, 'new_session': bool(fingerprint and fingerprint != initial_fingerprint),
            'initial_authenticated': preauth_identity is not None}
        controls = [{**result, 'control': 'unauthenticated', 'principal_id': preauth_identity,
            'session_fingerprint': before, 'initial_session_fingerprint': before,
            'credentials_valid': False, 'new_session': False, 'expected_confirmed': False},
            {**result, 'control': 'reuse_authenticated_session', 'initial_session_fingerprint': fingerprint,
                'new_session': False, 'initial_authenticated': True, 'expected_confirmed': False}]
        negative = new_session()
        negative.get('index.php')
        rejected_before = session_fingerprint(negative)
        rejected = negative.login(username, 'tesis-oracle-invalid-credential')
        rejected_identity = _identity(negative.get('index.php'))
        controls.append({**result, 'control': 'wrong_credential', 'principal_id': rejected_identity,
            'credentials_valid': rejected, 'new_session': False,
            'session_fingerprint': session_fingerprint(negative),
            'initial_session_fingerprint': rejected_before, 'expected_confirmed': False})
        # Use a different existing fixture identity as a binding control. The
        # documented non-admin account may be the candidate itself, in which
        # case DVWA's existing admin account is the distinct-identity control.
        policy_reader = new_session()
        if not policy_reader.login():
            # A successful candidate session can read the documented policy
            # when that candidate is already the fixture's admin principal.
            # Keep the independent identity check below; do not infer policy
            # from the candidate's login marker alone.
            if not result['credentials_valid'] or result['principal_id'] != username:
                return None, controls, requests
            policy_reader = positive
        page = policy_reader.get('/vulnerabilities/authbypass/')
        policy = BeautifulSoup(page.text, 'html.parser').get_text(' ', strip=True)
        example = re.search(r'for example\s+(\w+)\s*/\s*([^\s<]+)', policy, re.I)
        if not example or 'This page should only be accessible by the admin user' not in policy:
            return None, controls, requests
        other_user, other_secret = example.groups()
        if other_user == username:
            other_user, other_secret = 'admin', 'password'
        other = new_session()
        other.get('index.php')
        other_before = session_fingerprint(other)
        other_accepted = other.login(other_user, other_secret)
        other_identity = _identity(other.get('index.php'))
        if not other_accepted or other_identity != other_user or rejected or rejected_identity is not None:
            return None, controls, requests
        controls.append({**result, 'control': 'different_identity', 'principal_id': other_identity,
            'credentials_valid': other_accepted, 'new_session': True,
            'session_fingerprint': session_fingerprint(other), 'initial_session_fingerprint': other_before,
            'expected_confirmed': False})
        return result, controls, requests
    finally:
        for session in sessions:
            session.close()


def collect_session_oracles(artifact, raw_state):
    """Enrich a copy using only validated, executed, candidate-owned receipts.

    The frozen source opts in with oracle_protocol.kind=dvwa_candidate_session.v1
    and enabled=true. Failed controls remain visible without an attestation.
    """
    sources = artifact['config'].get('scoring_oracles', [])
    validate_sources(sources)
    protocols = [s for s in sources if s['document'].get('oracle_protocol', {}).get('kind') == 'dvwa_candidate_session.v1'
        and s['document']['oracle_protocol'].get('enabled') is True]
    if not protocols:
        return artifact
    if len(protocols) != 1:
        raise ValueError('Session collection requires exactly one frozen protocol')
    protocol = protocols[0]
    config = artifact['config']
    if any(not config.get(k) or protocol['document'].get(k) != config[k] for k in ('fixture_id', 'protocol_version')):
        raise ValueError('Session collection protocol coordinate mismatch')
    if protocol['origin'] != 'operator_fixture' and artifact.get('validation_scope') != 'offline_synthetic_fixture':
        raise ValueError('Live session collection requires an operator fixture protocol')
    result = deepcopy(artifact)
    for row in result['final_state'].get('response_evidence', []):
        method, cid = row.get('agent_id', ''), row.get('candidate_id')
        if not method.startswith('bf_') or row.get('stage') not in {'exploit', 'bypass'} or row.get('success') is not True:
            continue
        source_id = f"{protocol['source_id']}:{row['evidence_id']}"
        if any(s['source_id'] == source_id for s in sources):
            continue
        candidate = next((c for c in raw_state.get('payload_candidates', {}).get(method, []) if c.get('candidate_id') == cid), None)
        valid = any(v.get('candidate_id') == cid and v.get('valid') is True
            for v in raw_state.get('payload_validation_results', {}).get(method, []))
        original = next((r for r in raw_state.get('response_evidence', []) if r.get('evidence_id') == row.get('evidence_id')), {})
        initial = row.get('initial_session_fingerprint')
        if not candidate or not valid or not initial or not row.get('response_sha256') or any(
            original.get(k) != row.get(k) for k in ('agent_id', 'candidate_id', 'visit_id', 'response_sha256')):
            continue
        material = candidate.get('payload_or_logic', '')
        if ':' not in material:
            continue
        username, password = material.split(':', 1)
        if row.get('principal_id') and row['principal_id'] != username:
            continue
        document = {'fixture_id': config['fixture_id'], 'protocol_version': config['protocol_version'],
            'oracle_protocol': protocol['document']['oracle_protocol'], 'protocol_source_sha256': protocol['sha256'],
            'attestations': [], 'controls': [], 'requests': [], 'status': 'pending'}
        try:
            observed, controls, requests = _controls(config['target_url'], username, password, initial)
            document.update(controls=[{**c, 'fixture_id': config['fixture_id'], 'protocol_version': config['protocol_version']}
                for c in controls], requests=requests)
            if observed:
                attestation = {**observed, 'kind': 'session', 'run_id': artifact['run_id'],
                    'execution_id': artifact['execution_id'], 'method': method,
                    'fixture_id': config['fixture_id'], 'protocol_version': config['protocol_version'],
                    **{k: row[k] for k in ('visit_id', 'candidate_id', 'evidence_id', 'response_sha256')},
                    'timestamp': datetime.now(timezone.utc).isoformat()}
                enriched = {**row, 'principal_id': observed['principal_id'], 'session_fingerprint': observed['session_fingerprint']}
                if fixture_attestation_valid(attestation, enriched, document, artifact):
                    document.update(attestations=[attestation], status='confirmed')
                    row.update(principal_id=observed['principal_id'], session_fingerprint=observed['session_fingerprint'])
        except Exception as exc:
            # No exception text: transports can contain query/auth material.
            document['failure'] = type(exc).__name__
        source = {'source_id': source_id, 'origin': protocol['origin'],
            'document': document, 'sha256': evidence_hash(document)}
        validate_sources([source])
        result['config']['scoring_oracles'].append(source)
    return result
