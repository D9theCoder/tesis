"""Evidence verification for contained DVWA experiments."""

from core.historical_contracts import read_contract

from dataclasses import dataclass, field
import logging
import os
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

PERMISSION_CONTROL_SEMANTICS = "permission-outcome-bound"
PERMISSION_CONTROL_OUTCOMES = (
    "allowed", "denied", "authentication_redirect", "authorization_redirect",
    "http_error", "transport_error", "ambiguous",
)
PERMISSION_INTERPRETABLE_OUTCOMES = frozenset(
    {"allowed", "denied", "authentication_redirect"}
)
PERMISSION_CURRENT_OUTCOME_FIELDS = frozenset({
    "control_outcome", "denial_kind", "interpretable", "final_url",
    "security_level", "observed_at", "request_path",
})
PERMISSION_EVIDENCE_CURRENT = "current-outcome-bound"
PERMISSION_EVIDENCE_HISTORICAL = "historical-source-bound"
PERMISSION_EVIDENCE_INVALID = "invalid"
PERMISSION_HTTP_STATUSES = frozenset({200, 301, 302, 303, 307, 308, 403})


def _hex_digest(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdefABCDEF" for character in value
    )


def permission_url_is_login(final_url) -> bool:
    """Whether a recorded final URL is the fixture login page."""
    path = urlparse(str(final_url or "")).path.lower()
    return path == "/login.php" or path.endswith("/login.php")


def permission_same_origin(final_url, target: str) -> bool:
    """Whether a recorded final URL stays on the configured target origin."""
    expected, observed = urlparse(str(target or "")), urlparse(str(final_url or ""))
    return bool(
        expected.scheme and expected.hostname and observed.scheme and observed.hostname
        and (observed.scheme, observed.hostname, observed.port)
        == (expected.scheme, expected.hostname, expected.port)
    )


def permission_control_outcome(
    *,
    status_code,
    final_url,
    target: str,
    resource_visible: bool,
    denial_observed: bool,
) -> dict:
    """Classify one permission control response for producer and consumer.

    The order is deliberate: transport failure, HTTP error and an out-of-origin
    response cannot become a login redirect or an authorization denial merely
    because a URL or label says so.  A login redirect is only recognised when
    the recorded status is a successful page or redirect.
    """
    status = status_code if isinstance(status_code, int) and not isinstance(status_code, bool) else None
    final = str(final_url or "")
    same_origin = permission_same_origin(final, target)
    login = permission_url_is_login(final)
    if not same_origin:
        outcome, denial_kind = "ambiguous", None
    elif status is None:
        outcome, denial_kind = "transport_error", None
    elif 500 <= status <= 599:
        outcome, denial_kind = "http_error", None
    elif login:
        if status in {200, 301, 302, 303, 307, 308}:
            outcome, denial_kind = "authentication_redirect", "authentication_redirect"
        else:
            outcome, denial_kind = "ambiguous", None
    elif status == 200 and resource_visible:
        outcome, denial_kind = "allowed", None
    elif denial_observed and status in {200, 403}:
        outcome, denial_kind = "denied", "endpoint_denied"
    elif 300 <= status < 400:
        outcome, denial_kind = "authorization_redirect", "authorization_redirect"
    else:
        outcome, denial_kind = "ambiguous", None
    return {
        "control_outcome": outcome,
        "denial_kind": denial_kind,
        "status_code": status,
        "final_url": final,
        "interpretable": outcome in PERMISSION_INTERPRETABLE_OUTCOMES,
        "resource_visible": bool(resource_visible),
    }


def permission_control_outcome_problem(record, *, target: str) -> str | None:
    """Return why one recorded control outcome is not internally consistent."""
    if not isinstance(record, dict):
        return "control_record_not_object"
    outcome = record.get("control_outcome")
    if outcome not in PERMISSION_CONTROL_OUTCOMES:
        return "control_outcome_unknown"
    denial_kind = record.get("denial_kind")
    status = record.get("status_code")
    status = status if isinstance(status, int) and not isinstance(status, bool) else None
    interpretable = record.get("interpretable")
    final_url = record.get("final_url")
    if outcome in {"http_error", "transport_error", "ambiguous"}:
        if interpretable is not False:
            return "error_control_marked_interpretable"
        if denial_kind is not None:
            return "error_control_has_denial_kind"
        if outcome == "http_error" and not (status is not None and 500 <= status <= 599):
            return "http_error_status_invalid"
        if outcome == "transport_error" and status is not None:
            return "transport_error_has_status"
        return None
    if interpretable is not True:
        return "interpretable_control_not_marked"
    if not permission_same_origin(final_url, target):
        return "control_final_url_outside_target"
    login = permission_url_is_login(final_url)
    if outcome == "allowed":
        if denial_kind is not None or status != 200 or login:
            return "allowed_outcome_inconsistent"
    elif outcome == "denied":
        if denial_kind != "endpoint_denied" or status not in {200, 403} or login:
            return "denied_outcome_inconsistent"
    elif outcome == "authentication_redirect":
        if denial_kind != "authentication_redirect" or status not in {200, 301, 302, 303, 307, 308} or not login:
            return "authentication_redirect_inconsistent"
    elif outcome == "authorization_redirect":
        if denial_kind != "authorization_redirect" or status not in {301, 302, 303, 307, 308} or login:
            return "authorization_redirect_inconsistent"
    return None


def permission_candidate_outcome_problem(record, *, target: str) -> str | None:
    """Validate a candidate replay/attestation outcome without inventing a status."""
    if not isinstance(record, dict):
        return "candidate_outcome_not_object"
    outcome = record.get("control_outcome")
    denial_kind = record.get("denial_kind")
    final_url = record.get("final_url")
    if outcome not in {"allowed", "denied"}:
        return "candidate_outcome_not_interpretable"
    if not permission_same_origin(final_url, target):
        return "candidate_final_url_outside_target"
    login = permission_url_is_login(final_url)
    if outcome == "allowed" and (denial_kind is not None or login):
        return "candidate_allowed_outcome_inconsistent"
    if outcome == "denied" and (denial_kind != "endpoint_denied" or login):
        return "candidate_denied_outcome_inconsistent"
    return None


def _permission_has_current_metadata(document: dict) -> bool:
    records = [document]
    for key in ("controls", "attestations", "negative_attestations"):
        value = document.get(key)
        if isinstance(value, list):
            records.extend(value)
    for key in ("candidate_replay", "policy_evidence"):
        value = document.get(key)
        if isinstance(value, dict):
            records.append(value)
    return any(
        isinstance(record, dict)
        and any(field in record for field in PERMISSION_CURRENT_OUTCOME_FIELDS)
        for record in records
    )


def _permission_legacy_status_problem(document: dict) -> str | None:
    def status_problem(record, *, require_visible_200: bool, require_status: bool) -> str | None:
        if not isinstance(record, dict):
            return "legacy_record_not_object"
        status = record.get("status_code")
        if status is None:
            return "legacy_status_code_missing" if require_status else None
        if not isinstance(status, int) or isinstance(status, bool) \
                or status not in PERMISSION_HTTP_STATUSES:
            return "legacy_status_code_invalid"
        if require_visible_200 and record.get("observed_allowed") is True and status != 200:
            return "legacy_allowed_status_not_200"
        return None

    for control in document.get("controls") or []:
        problem = status_problem(control, require_visible_200=True, require_status=True)
        if problem:
            return problem
    problem = status_problem(
        document.get("candidate_replay"), require_visible_200=True, require_status=True,
    )
    if problem:
        return problem
    for attestation in (document.get("attestations") or []) + (
            document.get("negative_attestations") or []):
        problem = status_problem(attestation, require_visible_200=True, require_status=False)
        if problem:
            return problem
    policy = document.get("policy_evidence")
    if isinstance(policy, dict) and policy.get("status_code") not in (None, 200):
        return "legacy_policy_status_not_200"
    return None


def _permission_parent_source_bound(artifact: dict, document: dict) -> bool:
    parent_hash = document.get("protocol_source_sha256")
    if not isinstance(parent_hash, str) or not parent_hash:
        return False
    parents = [
        parent for parent in (artifact.get("config") or {}).get("scoring_oracles", [])
        if isinstance(parent, dict) and parent.get("sha256") == parent_hash
        and "status" not in (parent.get("document") or {})
        and (parent.get("document") or {}).get("oracle_protocol") == document.get("oracle_protocol")
        and ((parent.get("document") or {}).get("oracle_protocol") or {}).get("enabled") is True
    ]
    return len(parents) == 1


def _permission_historical_source_bound(artifact: dict, document: dict) -> bool:
    epoch = artifact.get("policy_epoch")
    if not isinstance(epoch, dict) or not isinstance(epoch.get("epoch_id"), str) \
            or not epoch["epoch_id"].strip():
        return False
    recorded = artifact.get("source_hashes_sha256")
    identity = artifact.get("source_identity")
    if not _hex_digest(recorded) and isinstance(identity, dict):
        recorded = identity.get("source_hashes_sha256")
    if not _hex_digest(recorded):
        return False
    if isinstance(identity, dict) and _hex_digest(identity.get("source_hashes_sha256")) \
            and _hex_digest(artifact.get("source_hashes_sha256")) \
            and identity["source_hashes_sha256"] != artifact["source_hashes_sha256"]:
        return False
    config = artifact.get("config")
    if not isinstance(config, dict) or not config.get("fixture_id") or not config.get("protocol_version"):
        return False
    if document.get("fixture_id") != config["fixture_id"] \
            or document.get("protocol_version") != config["protocol_version"]:
        return False
    if document.get("status") not in {"confirmed", "not_confirmed"}:
        return False
    if document.get("scope_outcome") not in {"candidate_specific", "broad_exposure"}:
        return False
    if not _permission_parent_source_bound(artifact, document):
        return False
    return _permission_legacy_status_problem(document) is None


def permission_evidence_mode(artifact: dict, document: dict) -> str:
    """Classify permission evidence from independent context, not a self-label.

    A document marker can confirm current semantics, but its absence must not
    downgrade a current write to a weaker legacy path.  Current/prospective
    writes are identified by an independently recorded plan identity, and any
    current-only outcome metadata without the canonical marker is refused.
    Historical evidence decodes read-only only when its legacy schema, frozen
    epoch/source identity and protocol parent binding are all present.
    """
    if not isinstance(artifact, dict) or not isinstance(document, dict):
        return PERMISSION_EVIDENCE_INVALID
    marker = document.get("control_semantics")
    if marker is not None:
        return (
            PERMISSION_EVIDENCE_CURRENT
            if marker == PERMISSION_CONTROL_SEMANTICS
            else PERMISSION_EVIDENCE_INVALID
        )
    if "research_plan_identity" in artifact or "plan_identity" in artifact:
        return PERMISSION_EVIDENCE_INVALID
    if _permission_has_current_metadata(document):
        return PERMISSION_EVIDENCE_INVALID
    if _permission_historical_source_bound(artifact, document):
        return PERMISSION_EVIDENCE_HISTORICAL
    return PERMISSION_EVIDENCE_INVALID


def credential_rejection_observed(body: str) -> bool:
    """Recognize an evaluated DVWA credential rejection, excluding form errors."""
    text = BeautifulSoup(str(body), "html.parser").get_text(" ", strip=True).lower()
    return ("username and/or password incorrect" in text
        and "csrf token is incorrect" not in text and "captcha" not in text)


def fixture_attestation_valid(attestation, row, document, artifact, *, outcome="confirmed"):
    """Check operator evidence offline; response text cannot create an oracle."""
    if any(not isinstance(record, dict) for record in (attestation, row, document, artifact)):
        return False
    if outcome not in {"confirmed", "not_confirmed"} or not isinstance(row.get('agent_id'), str):
        return False
    negative = outcome == "not_confirmed"
    if negative and (attestation.get('outcome') != outcome or row.get('signal_detected') is not False
                     or row.get('status_code') not in (200, 403)):
        return False
    from evaluation.scoring_evidence import timestamp
    config = artifact.get('config', {})
    for key in ('run_id', 'execution_id'):
        if not artifact.get(key) or attestation.get(key) != artifact[key]:
            return False
    for key in ('fixture_id', 'protocol_version'):
        if not config.get(key) or document.get(key) != config[key] or attestation.get(key) != config[key]:
            return False
    for key, row_key in (('method', 'agent_id'), ('visit_id', 'visit_id'), ('candidate_id', 'candidate_id'),
                         ('evidence_id', 'evidence_id'), ('response_sha256', 'response_sha256')):
        if not row.get(row_key) or attestation.get(key) != row[row_key]:
            return False
    try:
        when = timestamp(attestation['timestamp'])
        if row.get('timestamp') and when < timestamp(row['timestamp']):
            return False
    except (ValueError, KeyError, TypeError):
        return False
    kind = 'permission' if row['agent_id'].startswith('ac_') else 'session' if row['agent_id'].startswith('bf_') else None
    if attestation.get('kind') != kind or kind is None:
        return False
    for key in ('principal_id', 'session_fingerprint', 'initial_session_fingerprint'):
        if not row.get(key) or row[key] != attestation.get(key):
            return False
    if kind == 'permission' and any(not row.get(k) or row[k] != attestation.get(k) for k in ('object_id', 'action')):
        return False

    def confirmed(record):
        if not record.get('principal_id') or not record.get('session_fingerprint'):
            return False
        if record.get('principal_id') != record.get('expected_principal_id'):
            return False
        if kind == 'permission':
            return bool(record.get('object_id') and record.get('action')) and record.get('expected_allowed') is False and record.get('observed_allowed') is True
        return (record.get('session_fingerprint') != record.get('initial_session_fingerprint')
            and record.get('credentials_valid') is True and record.get('new_session') is True
            and record.get('initial_authenticated') is False)

    controls = document.get('controls')
    if not isinstance(controls, list) or not controls or any(not isinstance(c, dict)
        or c.get('fixture_id') != config['fixture_id'] or c.get('protocol_version') != config['protocol_version']
        or type(c.get('expected_confirmed')) is not bool or confirmed(c) != c['expected_confirmed'] for c in controls):
        return False
    if kind == 'permission':
        covered = all(any(c.get('expected_allowed') is allowed and c.get('observed_allowed') is allowed
            and c.get('principal_id') and c.get('principal_id') == c.get('expected_principal_id')
            and c.get('object_id') == attestation['object_id'] and c.get('action') == attestation['action']
            for c in controls) for allowed in (True, False))
        protocol = (document.get('oracle_protocol') or {}).get('kind')
        if not read_contract(protocol, 'dvwa_candidate_permission'):
            return False
        if read_contract(protocol, 'dvwa_candidate_permission'):
            mode = permission_evidence_mode(artifact, document)
            if mode == PERMISSION_EVIDENCE_INVALID:
                return False
            strict = mode == PERMISSION_EVIDENCE_CURRENT
            replay = document.get('candidate_replay')
            policy = document.get('policy_evidence')
            if not isinstance(replay, dict) or not isinstance(policy, dict):
                return False
            if (not policy.get('admin_only_marker_observed') or policy.get('status_code') != 200
                    or not isinstance(policy.get('response_sha256'), str)
                    or len(policy['response_sha256']) != 64):
                return False
            target = str((artifact.get('config') or {}).get('target_url') or '')

            def same_origin(url):
                expected, observed = urlparse(target), urlparse(str(url or ''))
                return bool(observed.scheme and observed.hostname and (
                    observed.scheme, observed.hostname, observed.port)
                    == (expected.scheme, expected.hostname, expected.port))

            def observed_at(value):
                try:
                    return timestamp(value)
                except (ValueError, KeyError, TypeError):
                    return None

            row_time = observed_at(row.get('timestamp'))
            if strict:
                if any(replay.get(key) != expected for key, expected in {
                    'security_level': config.get('security_level'),
                    'request_path': attestation.get('request_path'),
                    'control_outcome': attestation.get('control_outcome'),
                    'denial_kind': attestation.get('denial_kind'),
                    'final_url': attestation.get('final_url'),
                }.items()):
                    return False
                if (replay.get('control_outcome') not in {
                        'allowed', 'denied', 'authentication_redirect',
                        'authorization_redirect', 'http_error', 'transport_error', 'ambiguous'}
                        or not same_origin(replay.get('final_url'))
                        or not replay.get('interpretable')
                        or replay.get('security_level') != config.get('security_level')
                        or attestation.get('security_level') != config.get('security_level')
                        or not same_origin(attestation.get('final_url'))
                        or attestation.get('control_semantics') != 'permission-outcome-bound'):
                    return False
                policy_time = observed_at(policy.get('observed_at'))
                if (policy.get('security_level') != config.get('security_level')
                        or not same_origin(policy.get('final_url'))
                        or permission_url_is_login(policy.get('final_url'))
                        or policy_time is None or row_time is None or policy_time < row_time):
                    return False
                if (permission_control_outcome_problem(replay, target=target)
                        or permission_candidate_outcome_problem(attestation, target=target)
                        or attestation.get('control_semantics') != PERMISSION_CONTROL_SEMANTICS):
                    return False
                if negative and not (
                        replay.get('control_outcome') == 'denied'
                        and replay.get('denial_kind') == 'endpoint_denied'
                        and attestation.get('control_outcome') == 'denied'
                        and attestation.get('denial_kind') == 'endpoint_denied'):
                    return False
                if not negative and not (
                        replay.get('control_outcome') == 'allowed'
                        and attestation.get('control_outcome') == 'allowed'):
                    return False
                replay_time = observed_at(replay.get('observed_at'))
                attestation_time = observed_at(attestation.get('timestamp'))
                if None in (row_time, replay_time, attestation_time) or not (
                        row_time <= replay_time <= attestation_time):
                    return False
                parent_hash = document.get('protocol_source_sha256')
                parents = [
                    parent for parent in (artifact.get('config') or {}).get('scoring_oracles', [])
                    if isinstance(parent, dict) and parent.get('sha256') == parent_hash
                    and 'status' not in (parent.get('document') or {})
                    and (parent.get('document') or {}).get('oracle_protocol') == document.get('oracle_protocol')
                    and ((parent.get('document') or {}).get('oracle_protocol') or {}).get('enabled') is True
                ]
                if not parent_hash or len(parents) != 1:
                    return False
            if any(replay.get(k) != expected for k, expected in {
                'run_id': artifact.get('run_id'), 'execution_id': artifact.get('execution_id'),
                'fixture_id': config.get('fixture_id'), 'protocol_version': config.get('protocol_version'),
                'method': row.get('agent_id'), 'visit_id': row.get('visit_id'),
                'candidate_id': row.get('candidate_id'), 'evidence_id': row.get('evidence_id'),
                'original_response_sha256': row.get('response_sha256'), 'principal_id': row.get('principal_id'),
                'object_id': row.get('object_id'), 'action': row.get('action'), 'payload': row.get('payload'),
                'endpoint': row.get('endpoint'),
            }.items()):
                return False
            if replay.get('denial_observed') is not negative \
                    or attestation.get('denial_observed') is not negative:
                return False
            if (replay.get('expected_allowed') is not False or replay.get('observed_allowed') is not (not negative)
                    or replay.get('status_code') not in ((200, 403) if negative else (200,)) or not replay.get('response_sha256')
                    or not replay.get('session_fingerprint') or not replay.get('initial_session_fingerprint')
                    or replay['session_fingerprint'] == replay['initial_session_fingerprint']
                    or replay.get('principal_id') == (document.get('admin_principal_id') or 'admin')):
                return False
            named = {c.get('control'): c for c in controls}
            if set(named) != {'admin_allowed', 'anonymous_denied'}:
                return False
            admin_control, denied_control = named['admin_allowed'], named['anonymous_denied']
            if strict:
                for control in (admin_control, denied_control):
                    control_time = observed_at(control.get('observed_at'))
                    if (permission_control_outcome_problem(control, target=target)
                            or control.get('security_level') != config.get('security_level')
                            or not same_origin(control.get('final_url'))
                            or not control.get('control_outcome')
                            or control.get('interpretable') is not True
                            or control_time is None or row_time is None or control_time < row_time
                            or control_time > attestation_time):
                        return False
                if not (
                        admin_control.get('control_outcome') == 'allowed'
                        and admin_control.get('observed_allowed') is True
                        and admin_control.get('status_code') == 200):
                    return False
                if document.get('scope_outcome') == 'broad_exposure':
                    if not (denied_control.get('control_outcome') == 'allowed'
                            and denied_control.get('observed_allowed') is True
                            and denied_control.get('status_code') == 200):
                        return False
                elif not (
                        denied_control.get('control_outcome') in {'denied', 'authentication_redirect'}
                        and denied_control.get('denial_kind') in {'endpoint_denied', 'authentication_redirect'}
                        and denied_control.get('observed_allowed') is False):
                    return False
            broad_exposure = document.get('scope_outcome') == 'broad_exposure'
            if broad_exposure:
                covered = bool(
                    (document.get('oracle_protocol') or {}).get('allow_broad_exposure') is True
                    and denied_control.get('expected_allowed') is False
                    and denied_control.get('observed_allowed') is True
                    and denied_control.get('expected_confirmed') is True
                    and denied_control.get('object_id') == attestation.get('object_id')
                    and denied_control.get('action') == attestation.get('action')
                )
            else:
                covered = covered and document.get('scope_outcome') == 'candidate_specific'
            if (admin_control.get('principal_id') != (document.get('admin_principal_id') or 'admin')
                    or admin_control.get('expected_allowed') is not True
                    or admin_control.get('observed_allowed') is not True
                    or denied_control.get('principal_id') != 'anonymous'
                    or denied_control.get('expected_allowed') is not False
                    or (denied_control.get('observed_allowed') is True) != broad_exposure
                    or attestation.get('expected_allowed') is not False
                    or attestation.get('observed_allowed') is not (not negative)
                    or attestation.get('scope_outcome') != document.get('scope_outcome')
                    or replay.get('scope_outcome') != document.get('scope_outcome')
                    or attestation.get('principal_id') == (document.get('admin_principal_id') or 'admin')):
                return False
            if negative:
                return (covered and not broad_exposure and replay.get('denial_observed') is True
                    and attestation.get('denial_observed') is True
                    and attestation.get('principal_id') == attestation.get('expected_principal_id'))
        elif negative:
            return False
    else:
        covered = (any(c.get('new_session') is False for c in controls)
            and any(c.get('credentials_valid') is False for c in controls)
            and any(c.get('session_fingerprint') == c.get('initial_session_fingerprint') for c in controls)
            and any(c.get('principal_id') != c.get('expected_principal_id') for c in controls))
        if read_contract((document.get('oracle_protocol') or {}).get('kind'), 'dvwa_candidate_session'):
            replay = document.get('candidate_replay')
            if not isinstance(replay, dict) or any(replay.get(key) != attestation.get(key) for key in (
                    'run_id', 'execution_id', 'fixture_id', 'protocol_version', 'method',
                    'visit_id', 'candidate_id', 'evidence_id', 'response_sha256',
                    'initial_session_fingerprint')):
                return False
            if negative:
                return (covered and credential_rejection_observed(row.get('response_excerpt', ''))
                    and replay.get('credentials_valid') is False
                    and replay.get('initial_authenticated') is False and not replay.get('principal_id')
                    and replay.get('expected_principal_id') == attestation.get('principal_id')
                    and any(c.get('control') == 'known_valid_identity' and confirmed(c) for c in controls))
            if replay.get('principal_id') != attestation.get('principal_id'):
                return False
            return covered and confirmed(replay)
        elif negative:
            return False
    return covered and confirmed(attestation)


def usable_blind_response(response, *, allow_missing: bool = False) -> bool:
    """Accept DVWA's documented missing-ID 404, excluding generic HTTP errors."""
    return response.status_code == 200 or (
        allow_missing and response.status_code == 404
        and "user id is missing from the database" in response.text.lower()
    )


def complementary_boolean_payload(payload: str) -> str | None:
    """Negate a bounded DVWA AND predicate, preserving its ID and SQL suffix.

    Unrecognized syntax cannot establish that a missing-ID response is a
    successfully evaluated false predicate, so callers must leave it unverified.
    """
    match = re.fullmatch(
        r"(\s*\d+\s*'?(?:\s|/\*.*?\*/)*AND(?:\s|/\*.*?\*/)*)"
        r"(.+?)(\s*(?:--\s.*|#.*))?",
        payload, re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return None
    prefix, predicate, suffix = match.groups()
    return f"{prefix}NOT ({predicate}){suffix or ''}"


@dataclass
class VerificationResult:
    """Structured result from a verification check.

    Attributes:
        ok: Whether the verification passed.
        confidence: Confidence score between 0.0 and 1.0.
        evidence: List of human-readable evidence strings supporting the result.
    """

    ok: bool = False
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to a plain dict for LangGraph state compatibility."""
        return {
            "ok": self.ok,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


class Verifier:
    """Evidence-oriented verification for exploitation results."""

    def contains_any(self, body: str, signals: list[str]) -> VerificationResult:
        """Check whether ``body`` contains any text signal case-insensitively.

        Responses are bounded before matching, so truncated medium-level
        error envelopes can still be audited without retaining oversized
        bodies.
        """
        # Truncate large responses to prevent memory issues.
        max_body_size = 1_048_576  # 1 MB
        if len(body) > max_body_size:
            body = body[:max_body_size]

        if not body or not signals:
            return VerificationResult(ok=False, confidence=0.0, evidence=[])

        lowered = body.lower()
        matches: list[str] = []
        for signal in signals:
            normalized = str(signal)
            if normalized.lower() in lowered and normalized not in matches:
                matches.append(normalized)

        ok = bool(matches)
        confidence = 1.0 if ok else 0.0
        return VerificationResult(ok=ok, confidence=confidence, evidence=matches)

    def regex_match(self, body: str, patterns: list[str]) -> VerificationResult:
        """Check whether ``body`` matches any regex pattern."""
        # Truncate large responses to prevent memory issues
        max_body_size = 1_048_576  # 1 MB
        if len(body) > max_body_size:
            body = body[:max_body_size]

        if not body or not patterns:
            return VerificationResult(ok=False, confidence=0.0, evidence=[])

        evidence: list[str] = []
        for pattern in patterns:
            try:
                if re.search(pattern, body, flags=re.IGNORECASE | re.MULTILINE):
                    evidence.append(pattern)
            except re.error as exc:
                logger.warning("Invalid regex pattern encountered during verification: %s", pattern, exc_info=exc)
                # Do NOT include invalid regex in evidence — evidence should only contain matches
                continue

        matched = [item for item in evidence if not item.startswith("invalid_regex:")]
        ok = bool(matched)
        confidence = min(1.0, 0.6 + 0.1 * len(matched)) if ok else 0.0
        return VerificationResult(ok=ok, confidence=confidence, evidence=evidence)


def has_captcha_challenge(body: str) -> bool:
    """Return whether an HTML response contains an actual CAPTCHA control.

    DVWA renders an ``Insecure CAPTCHA`` navigation link on many pages. A
    plain substring check therefore misclassifies ordinary brute-force
    responses as an out-of-scope CAPTCHA boundary. Restrict detection to
    form controls/widgets associated with a challenge.
    """
    if not body:
        return False
    soup = BeautifulSoup(body[:1_048_576], "html.parser")
    selectors = (
        "input[name*='captcha' i]",
        "input[id*='captcha' i]",
        "textarea[name*='captcha' i]",
        ".g-recaptcha",
        "[data-sitekey]",
        "iframe[src*='recaptcha' i]",
    )
    if any(soup.select(selector) for selector in selectors):
        return True

    # Some implementations use a generic input name but put the challenge
    # text inside the same form. Do not inspect global navigation text.
    for form in soup.find_all("form"):
        form_text = form.get_text(" ", strip=True).lower()
        if "captcha" in form_text and form.find(["input", "textarea", "select"]):
            return True
    return False

def verify_method_response(agent_id: str, response_text: str, expected_signal: str) -> bool:
    """Verify if a method's expected signal is present in the response.

    .. deprecated::
        Use ``Verifier.contains_any()`` instead for consistent API.
    """
    return expected_signal.lower() in response_text.lower()
