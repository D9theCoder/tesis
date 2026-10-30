"""Bounded, offline derivation of plaintext credentials from recovered hashes.

A SQL-injection dump of DVWA's ``users`` table yields ``md5`` password hashes, so
the only plaintext that can exist for a chain to consume has to be *derived*.
This module performs that derivation explicitly, offline, against the harness's
own declared credential corpus, and attaches evidence to every derived value so
the derivation is auditable instead of implicit.

Deliberate properties:

- no network, no fixture state: derivation is pure computation over a hash that
  the run already recovered;
- bounded: the candidate corpus is the static credential corpus the brute-force
  payload library already declares, sorted and capped, and every row records how
  many candidates were considered;
- explicit: the derived credential keeps ``representation="plaintext"`` (so the
  existing chain gate can consume it) and carries a ``derivation`` block naming
  the algorithm, the hash digest, the candidate index, and the corpus digest.

A failure to derive is not an error: the credential simply stays a hash, and the
chain gate keeps rejecting it with ``plaintext_source_credentials_unavailable``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import md5, sha256
import re
from typing import Any, Iterable, Mapping

DERIVATION_POLICY_VERSION = "credential-derivation.v1"
DERIVATION_METHOD = "md5_declared_corpus_v1"
DERIVATION_ALGORITHM = "md5"
MAX_CANDIDATES = 64

_MD5_HEX = re.compile(r"^[a-f0-9]{32}$")


def _corpus_digest(candidates: list[str]) -> str:
    return sha256("\n".join(candidates).encode("utf-8")).hexdigest()


def declared_password_corpus(library: Any = None) -> list[str]:
    """Return the password corpus the brute-force payload library declares.

    The corpus is read from the same static seeds the brute-force methods use, so
    derivation never invents a password the harness was not already allowed to
    try.  Order is the declared order, deduplicated and capped deterministically.
    """
    if library is None:
        from foundation.payload_library import PayloadLibrary

        library = PayloadLibrary()
    passwords: list[str] = []
    for method in ("bf_dictionary", "bf_spray"):
        try:
            seed_sets = library.get(method, "low")
        except Exception:  # a missing corpus degrades to "cannot derive"
            continue
        payloads: list[str] = list(getattr(seed_sets, "exploit", []) or [])
        for payload in payloads:
            if ":" not in str(payload):
                continue
            _username, password = str(payload).split(":", 1)
            if password and password not in passwords:
                passwords.append(password)
    return passwords[:MAX_CANDIDATES]


def derive_plaintext_password(
    password_hash: Any,
    candidates: Iterable[str],
) -> dict[str, Any] | None:
    """Return the derivation record for one hash, or ``None`` when it is unknown."""
    value = str(password_hash or "").strip().lower()
    if not _MD5_HEX.match(value):
        return None
    considered = [str(candidate) for candidate in candidates][:MAX_CANDIDATES]
    for index, candidate in enumerate(considered):
        if md5(candidate.encode("utf-8")).hexdigest() == value:
            return {
                "policy_version": DERIVATION_POLICY_VERSION,
                "method": DERIVATION_METHOD,
                "algorithm": DERIVATION_ALGORITHM,
                "hash_sha256": sha256(value.encode("utf-8")).hexdigest(),
                "password_sha256": sha256(candidate.encode("utf-8")).hexdigest(),
                "password": candidate,
                "candidate_index": index,
                "candidates_considered": len(considered),
                "candidate_set_sha256": _corpus_digest(considered),
                "derived_at": datetime.now(timezone.utc).isoformat(),
            }
    return None


def derive_credentials(
    credentials: Iterable[Mapping[str, Any]],
    *,
    candidates: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Return derived plaintext credentials for every derivable hash credential.

    Each returned record keeps the source binding of the hash it came from
    (``source_evidence_id``, ``source_candidate_id``, ``source_visit_id``) so the
    chain gate can still require evidence bound to this run, and adds a
    ``derivation`` block plus a deterministic ``derivation_evidence_id``.
    """
    corpus = list(candidates if candidates is not None else declared_password_corpus())
    derived: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for credential in credentials or ():
        if not isinstance(credential, Mapping):
            continue
        if str(credential.get("representation") or "") != "password_hash":
            continue
        username = str(credential.get("username") or "")
        if not username:
            continue
        record = derive_plaintext_password(credential.get("password"), corpus)
        if record is None:
            continue
        key = (username, record["password"])
        if key in seen:
            continue
        seen.add(key)
        source_id = str(credential.get("source_evidence_id") or "")
        derived.append({
            "username": username,
            "password": record["password"],
            "representation": "plaintext",
            "derived_from_representation": "password_hash",
            "derivation_evidence_id": (f"derivation:{source_id or 'unbound'}:{record['hash_sha256'][:12]}"),
            "source_evidence_id": credential.get("source_evidence_id"),
            "source_candidate_id": credential.get("source_candidate_id"),
            "source_visit_id": credential.get("source_visit_id"),
            "derivation": record,
        })
    return derived
