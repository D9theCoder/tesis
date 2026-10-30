"""Bounded plaintext derivation from recovered password hashes (D5)."""

from hashlib import md5

from foundation.credential_derivation import (
    MAX_CANDIDATES,
    declared_password_corpus,
    derive_credentials,
    derive_plaintext_password,
)


def _hash(password: str) -> str:
    return md5(password.encode()).hexdigest()


def test_declared_corpus_comes_from_the_brute_force_seeds():
    corpus = declared_password_corpus()
    assert corpus and len(corpus) <= MAX_CANDIDATES
    assert "password" in corpus and "abc123" in corpus
    assert len(corpus) == len(set(corpus))


def test_derivation_records_its_own_evidence():
    record = derive_plaintext_password(_hash("abc123"), ["password", "abc123"])
    assert record is not None
    assert record["password"] == "abc123"
    assert record["algorithm"] == "md5"
    assert record["candidate_index"] == 1
    assert record["candidates_considered"] == 2
    assert len(record["candidate_set_sha256"]) == 64
    assert record["hash_sha256"] == __import__("hashlib").sha256(
        _hash("abc123").encode()).hexdigest()


def test_underivable_and_non_hash_values_are_not_invented():
    assert derive_plaintext_password(_hash("not-in-corpus"), ["password"]) is None
    assert derive_plaintext_password("not-a-hash", ["password"]) is None
    assert derive_plaintext_password(None, ["password"]) is None


def test_derived_credentials_keep_the_source_binding():
    hash_credential = {
        "username": "gordonb", "password": _hash("abc123"), "representation": "password_hash",
        "source_evidence_id": "response:2", "source_candidate_id": "cand-1",
        "source_visit_id": "sqli_union:visit:1",
    }
    derived = derive_credentials([hash_credential], candidates=["password", "abc123"])
    assert len(derived) == 1
    row = derived[0]
    assert row["representation"] == "plaintext"
    assert row["password"] == "abc123"
    assert row["source_evidence_id"] == "response:2"
    assert row["source_candidate_id"] == "cand-1"
    assert row["source_visit_id"] == "sqli_union:visit:1"
    assert row["derivation"]["method"] == "md5_declared_corpus_v1"
    assert row["derivation_evidence_id"].startswith("derivation:response:2:")


def test_already_plaintext_and_duplicate_rows_are_left_alone():
    derived = derive_credentials(
        [{"username": "admin", "password": "password", "representation": "plaintext"}],
        candidates=["password"])
    assert derived == []
    duplicate = [
        {"username": "gordonb", "password": _hash("abc123"), "representation": "password_hash",
         "source_evidence_id": "response:2", "source_candidate_id": "c", "source_visit_id": "v"},
        {"username": "gordonb", "password": _hash("abc123"), "representation": "password_hash",
         "source_evidence_id": "response:3", "source_candidate_id": "c", "source_visit_id": "v"},
    ]
    assert len(derive_credentials(duplicate, candidates=["abc123"])) == 1
