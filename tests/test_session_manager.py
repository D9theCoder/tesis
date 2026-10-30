"""Tests for foundation/session_manager.py — DVWA session manager.

Validates:
1. Login flow (CSRF token extraction, credential submission)
2. Security level management (set, detect, validate)
3. Edge cases (missing token, login failure, invalid level)
4. Context manager protocol
"""

import pytest
from unittest.mock import patch

from foundation.session_manager import DVWASession, dvwa_credentials


def test_scoped_credentials_are_used_and_explicit_principals_still_win():
    with patch("foundation.session_manager.HTTPClient") as factory:
        client = factory.return_value
        client.get.return_value.text = "<form></form>"
        client.post.return_value.text = '<a href="logout.php">Logout</a>'
        client.post.return_value.url = "http://localhost/dvwa/index.php"
        with DVWASession("http://localhost/dvwa") as session:
            with dvwa_credentials("custom-admin", "custom-password"):
                assert session.login()
                assert client.post.call_args.kwargs["data"]["username"] == "custom-admin"
                assert client.post.call_args.kwargs["data"]["password"] == "custom-password"
                assert session.login("fixture-user", "fixture-password")
                assert client.post.call_args.kwargs["data"]["username"] == "fixture-user"
            assert session.login()
            assert client.post.call_args.kwargs["data"]["username"] == "admin"


class TestDVWASessionSecurityLevel:
    """Validate security level management."""


    @patch("foundation.session_manager.HTTPClient")
    def test_set_security_level_rejects_unverified_server_state(self, mock_http_cls):
        mock_http_cls.return_value.get.return_value.text = (
            '<input type="hidden" name="user_token" value="tok">DVWA Security Level: low'
        )
        session = DVWASession("http://localhost/dvwa")
        with pytest.raises(RuntimeError, match="not verified server-side"):
            session.set_security_level("medium")
        assert session.observed_security_level() == "low"
