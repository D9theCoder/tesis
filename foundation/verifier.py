"""Evidence verification for contained DVWA experiments."""

from dataclasses import dataclass, field
import logging
import os
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def fixture_attestation_valid(attestation, row, document, artifact):
    """Check operator evidence offline; response text cannot create an oracle."""
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
            and c.get('principal_id') and c.get('object_id') and c.get('action') for c in controls) for allowed in (True, False))
    else:
        covered = (any(c.get('new_session') is False for c in controls)
            and any(c.get('credentials_valid') is False for c in controls)
            and any(c.get('session_fingerprint') == c.get('initial_session_fingerprint') for c in controls)
            and any(c.get('principal_id') != c.get('expected_principal_id') for c in controls))
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
