"""Evidence verification for contained DVWA experiments."""

from dataclasses import dataclass, field
import logging
import os
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


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
        if protocol == 'dvwa_candidate_permission.v1':
            replay = document.get('candidate_replay')
            policy = document.get('policy_evidence')
            if not isinstance(replay, dict) or not isinstance(policy, dict):
                return False
            if (not policy.get('admin_only_marker_observed') or policy.get('status_code') != 200
                    or not isinstance(policy.get('response_sha256'), str)
                    or len(policy['response_sha256']) != 64):
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
        if (document.get('oracle_protocol') or {}).get('kind') == 'dvwa_candidate_session.v1':
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
