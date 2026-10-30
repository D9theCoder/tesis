"""Bounded plaintext derivation from recovered password hashes (D5)."""

from hashlib import md5

from foundation.credential_derivation import (
    derive_plaintext_password,
)


def _hash(password: str) -> str:
    return md5(password.encode()).hexdigest()


def test_underivable_and_non_hash_values_are_not_invented():
    assert derive_plaintext_password(_hash("not-in-corpus"), ["password"]) is None
    assert derive_plaintext_password("not-a-hash", ["password"]) is None
    assert derive_plaintext_password(None, ["password"]) is None
