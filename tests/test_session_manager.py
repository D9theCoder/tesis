"""Tests for foundation/session_manager.py — DVWA session manager.

Validates:
1. Login flow (CSRF token extraction, credential submission)
2. Security level management (set, detect, validate)
3. Convenience HTTP method delegation
4. Edge cases (missing token, login failure, invalid level)
5. Context manager protocol
"""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock

from foundation.session_manager import DVWASession, VALID_LEVELS, TransportError


class TestExtractUserToken:
    """Validate CSRF token extraction from HTML."""

    def test_extract_token_from_valid_html(self):
        """Should extract user_token from a standard DVWA login form."""
        html = '''
        <form action="" method="post">
            <input type="hidden" name="user_token" value="abc123def456">
            <input type="text" name="username">
            <input type="password" name="password">
        </form>
        '''
        token = DVWASession._extract_user_token(html)
        assert token == "abc123def456"

    def test_extract_token_missing(self):
        """Should return None when user_token field is absent."""
        html = '<form><input type="text" name="username"></form>'
        token = DVWASession._extract_user_token(html)
        assert token is None

    def test_extract_token_empty_value(self):
        """Should return None when user_token exists but has no value."""
        html = '<input type="hidden" name="user_token" value="">'
        token = DVWASession._extract_user_token(html)
        assert token is None

    def test_extract_token_from_malformed_html(self):
        """Should handle malformed HTML gracefully."""
        html = "<not valid html at all"
        token = DVWASession._extract_user_token(html)
        assert token is None

    def test_extract_token_multiple_forms(self):
        """Should extract token from the first matching element."""
        html = '''
        <form>
            <input type="hidden" name="user_token" value="first_token">
        </form>
        <form>
            <input type="hidden" name="user_token" value="second_token">
        </form>
        '''
        token = DVWASession._extract_user_token(html)
        assert token == "first_token"


class TestDVWASessionLogin:
    """Validate login flow."""

    @patch("foundation.session_manager.HTTPClient")
    def test_login_success_with_logout_indicator(self, mock_http_cls):
        """Successful login should be detected by 'logout' in response."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http

        # Mock the GET to return login page with token
        login_response = MagicMock()
        login_response.text = '<input type="hidden" name="user_token" value="tok123">'
        mock_http.get.return_value = login_response

        # Mock the POST to return success page
        post_response = MagicMock()
        post_response.text = '<a href="logout.php">Logout</a>'
        post_response.url = "http://localhost/dvwa/index.php"
        mock_http.post.return_value = post_response

        session = DVWASession("http://localhost/dvwa")
        result = session.login("admin", "password")

        assert result is True
        assert session.is_logged_in is True
        # Verify POST was called with correct payload including token
        call_kwargs = mock_http.post.call_args
        assert call_kwargs[0][0] == "login.php"
        data = call_kwargs[1]["data"]
        assert data["username"] == "admin"
        assert data["password"] == "password"
        assert data["user_token"] == "tok123"

    @patch("foundation.session_manager.HTTPClient")
    def test_login_success_with_redirect(self, mock_http_cls):
        """Successful login should be detected by redirect to index.php."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http

        login_response = MagicMock()
        login_response.text = '<input type="hidden" name="user_token" value="tok456">'
        mock_http.get.return_value = login_response

        post_response = MagicMock()
        post_response.text = "Welcome"
        post_response.url = "http://localhost/dvwa/index.php"
        mock_http.post.return_value = post_response

        session = DVWASession("http://localhost/dvwa")
        result = session.login("admin", "password")

        assert result is True

    @patch("foundation.session_manager.HTTPClient")
    def test_login_failure_with_error_message(self, mock_http_cls):
        """Failed login should be detected by error message."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http

        login_response = MagicMock()
        login_response.text = '<input type="hidden" name="user_token" value="tok789">'
        mock_http.get.return_value = login_response

        post_response = MagicMock()
        post_response.text = "Username and/or password incorrect."
        post_response.url = "http://localhost/dvwa/login.php"
        mock_http.post.return_value = post_response

        session = DVWASession("http://localhost/dvwa")
        result = session.login("admin", "wrong_password")

        assert result is False
        assert session.is_logged_in is False

    @patch("foundation.session_manager.HTTPClient")
    def test_login_without_token(self, mock_http_cls):
        """Login should proceed even when no CSRF token is found."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http

        login_response = MagicMock()
        login_response.text = "<form><input name='username'></form>"
        mock_http.get.return_value = login_response

        post_response = MagicMock()
        post_response.text = '<a href="logout.php">Logout</a>'
        post_response.url = "http://localhost/dvwa/index.php"
        mock_http.post.return_value = post_response

        session = DVWASession("http://localhost/dvwa")
        result = session.login()

        assert result is True
        # Verify POST was called without token
        call_kwargs = mock_http.post.call_args
        data = call_kwargs[1]["data"]
        assert "user_token" not in data


class TestDVWASessionSecurityLevel:
    """Validate security level management."""

    @patch("foundation.session_manager.HTTPClient")
    def test_set_valid_security_levels(self, mock_http_cls):
        """All valid levels should be accepted."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http

        # Mock the GET and POST for security form
        sec_response = MagicMock()
        sec_response.text = '<input type="hidden" name="user_token" value="sec_tok">'
        mock_http.get.return_value = sec_response

        for level in VALID_LEVELS:
            session = DVWASession("http://localhost/dvwa")
            session.set_security_level(level)
            assert session.security_level == level

    @patch("foundation.session_manager.HTTPClient")
    def test_set_invalid_security_level_raises(self, mock_http_cls):
        """Invalid security levels should raise ValueError."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http

        session = DVWASession("http://localhost/dvwa")
        with pytest.raises(ValueError, match="Invalid security level"):
            session.set_security_level("ultra")

    @patch("foundation.session_manager.HTTPClient")
    def test_set_impossible_security_level_raises(self, mock_http_cls):
        """'impossible' should be rejected to match canonical low/medium/high contract."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http

        session = DVWASession("http://localhost/dvwa")
        with pytest.raises(ValueError, match="Invalid security level"):
            session.set_security_level("impossible")

    @patch("foundation.session_manager.HTTPClient")
    def test_set_security_level_sets_cookie(self, mock_http_cls):
        """set_security_level should set the security cookie."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http

        sec_response = MagicMock()
        sec_response.text = '<input type="hidden" name="user_token" value="tok">'
        mock_http.get.return_value = sec_response

        session = DVWASession("http://localhost/dvwa")
        session.set_security_level("medium")

        mock_http.set_cookie.assert_called_once_with("security", "medium")

    @patch("foundation.session_manager.HTTPClient")
    def test_detect_security_level_prefers_server_page_over_cookie(self, mock_http_cls):
        """detect_security_level should prefer server-side page state over cookie value."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http

        mock_cookies = MagicMock()
        mock_cookies.get.return_value = "high"  # conflicting cookie value
        mock_http.cookies = mock_cookies

        sec_response = MagicMock()
        sec_response.text = '''
        <form>
            <select name="security">
                <option value="low">Low</option>
                <option value="medium" selected>Medium</option>
                <option value="high">High</option>
            </select>
        </form>
        '''
        mock_http.get.return_value = sec_response

        session = DVWASession("http://localhost/dvwa")
        level = session.detect_security_level()

        assert level == "medium"
        mock_http.get.assert_called_once_with("security.php")

    @patch("foundation.session_manager.HTTPClient")
    def test_detect_security_level_falls_back_to_cookie_on_request_error(self, mock_http_cls):
        """detect_security_level should fall back to cookie only when page fetch fails."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http

        mock_http.get.side_effect = TransportError("network down")
        mock_cookies = MagicMock()
        mock_cookies.get.return_value = "medium"
        mock_http.cookies = mock_cookies

        session = DVWASession("http://localhost/dvwa")
        level = session.detect_security_level()

        assert level == "medium"


class TestDVWASessionContextManager:
    """Validate context manager protocol."""

    @patch("foundation.session_manager.HTTPClient")
    def test_context_manager_closes_http(self, mock_http_cls):
        """Exiting context should close the underlying HTTP client."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http

        with DVWASession("http://localhost/dvwa") as session:
            pass
        mock_http.close.assert_called_once()


class TestDVWASessionHTTPMethods:
    """Validate convenience HTTP methods."""

    @patch("foundation.session_manager.HTTPClient")
    def test_get_delegates_to_http_client(self, mock_http_cls):
        """get() should delegate to HTTPClient.get with params."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http
        expected_result = MagicMock()
        mock_http.get.return_value = expected_result

        session = DVWASession("http://localhost/dvwa")
        result = session.get("vulnerabilities/sqli/", params={"id": "1"})

        mock_http.get.assert_called_once_with("vulnerabilities/sqli/", params={"id": "1"})
        assert result is expected_result

    @patch("foundation.session_manager.HTTPClient")
    def test_post_delegates_to_http_client(self, mock_http_cls):
        """post() should delegate to HTTPClient.post with data."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http
        expected_result = MagicMock()
        mock_http.post.return_value = expected_result

        session = DVWASession("http://localhost/dvwa")
        result = session.post("login.php", data={"username": "admin"})

        mock_http.post.assert_called_once_with("login.php", data={"username": "admin"})
        assert result is expected_result

    @patch("foundation.session_manager.HTTPClient")
    def test_post_with_files(self, mock_http_cls):
        """post() should pass files kwarg through to HTTPClient."""
        mock_http = MagicMock()
        mock_http_cls.return_value = mock_http
        expected_result = MagicMock()
        mock_http.post.return_value = expected_result

        session = DVWASession("http://localhost/dvwa")
        files = {"uploaded": ("shell.php", b"<?php system($_GET['cmd']); ?>", "image/jpeg")}
        result = session.post("vulnerabilities/upload/", files=files)

        mock_http.post.assert_called_once_with("vulnerabilities/upload/", files=files)
