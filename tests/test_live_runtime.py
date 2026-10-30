"""Tests for the live-run descriptor lifecycle and AKG snapshot export."""

from __future__ import annotations



from tesis.live_runtime import (
    safe_target_scope,
)


def test_safe_target_scope_removes_url_credentials_and_query_secrets() -> None:
    assert (
        safe_target_scope(
            "http://dvwa-user:dvwa-pass@127.0.0.1:8080/dvwa/login.php?token=secret#step"
        )
        == "http://127.0.0.1:8080/dvwa/login.php"
    )
