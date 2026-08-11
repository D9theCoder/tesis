"""Tests for foundation/http_client.py — HTTP client wrapper.

Validates:
1. HTTPClient initialization and URL normalization
2. RequestResult dataclass properties
3. GET and POST request methods
4. Cookie management
5. Error mapping (TransportError, RequestTimeoutError)
6. Context manager protocol
"""

import pytest
from unittest.mock import patch, MagicMock

from foundation.http_client import (
    HTTPClient,
    RequestResult,
    TransportError,
    RequestTimeoutError,
    ContainmentError,
)


class TestRequestResult:
    """Validate the RequestResult dataclass."""

    def test_properties_delegate_to_response(self):
        """RequestResult properties should delegate to the underlying httpx.Response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>hello</html>"
        mock_resp.url = "http://localhost/dvwa/test"
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.elapsed = MagicMock()

        result = RequestResult(response=mock_resp, elapsed_ms=123.4)

        assert result.status_code == 200
        assert result.text == "<html>hello</html>"
        assert result.url == "http://localhost/dvwa/test"
        assert result.headers["Content-Type"] == "text/html"
        assert result.elapsed_ms == 123.4


class TestHTTPClientInit:
    """Validate HTTPClient initialization and URL normalization."""

    def test_base_url_trailing_slash_normalization(self):
        """Base URL should have exactly one trailing slash."""
        client = HTTPClient("http://localhost/dvwa")
        assert client.base_url == "http://localhost/dvwa/"

        client2 = HTTPClient("http://localhost/dvva/")
        assert client2.base_url == "http://localhost/dvva/"

        client3 = HTTPClient("http://localhost/dvwa///")
        assert client3.base_url == "http://localhost/dvwa/"

    def test_client_creates_httpx_client(self):
        """HTTPClient should create an httpx.Client with proper settings."""
        client = HTTPClient("http://localhost/dvwa")
        assert client._client is not None
        client.close()

    def test_context_manager(self):
        """HTTPClient should work as a context manager."""
        with HTTPClient("http://localhost/dvwa") as client:
            assert client.base_url == "http://localhost/dvwa/"


class TestHTTPClientRequests:
    """Validate GET and POST request methods."""

    @patch("foundation.http_client.httpx.Client")
    def test_get_request_builds_url(self, mock_client_cls):
        """GET should combine base_url with the path."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        mock_response = MagicMock()
        mock_response.elapsed = MagicMock()
        mock_response.elapsed.total_seconds.return_value = 0.1
        mock_instance.request.return_value = mock_response

        client = HTTPClient("http://localhost/dvwa")
        result = client.get("vulnerabilities/sqli/")

        # Verify the URL was constructed using urljoin
        call_args = mock_instance.request.call_args
        assert call_args[0][0] == "GET"
        assert "localhost" in call_args[0][1]
        assert "sqli" in call_args[0][1]

    @patch("foundation.http_client.httpx.Client")
    def test_post_request_builds_url(self, mock_client_cls):
        """POST should combine base_url with the path."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        mock_response = MagicMock()
        mock_response.elapsed = MagicMock()
        mock_response.elapsed.total_seconds.return_value = 0.2
        mock_instance.request.return_value = mock_response

        client = HTTPClient("http://localhost/dvwa")
        result = client.post("login.php", data={"username": "admin"})

        call_args = mock_instance.request.call_args
        assert call_args[0][0] == "POST"
        assert "login.php" in call_args[0][1]

    @patch("foundation.http_client.httpx.Client")
    def test_get_strips_leading_slash(self, mock_client_cls):
        """Leading slashes in path should be stripped before urljoin."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        mock_response = MagicMock()
        mock_response.elapsed = MagicMock()
        mock_response.elapsed.total_seconds.return_value = 0.05
        mock_instance.request.return_value = mock_response

        client = HTTPClient("http://localhost/dvwa")
        client.get("/login.php")

        call_args = mock_instance.request.call_args
        # Should NOT be http://localhost/login.php (lost /dvwa/)
        assert call_args[0][1] == "http://localhost/dvwa/login.php"

    def test_rejects_external_absolute_target_before_request(self):
        """External absolute URLs must never reach the underlying transport."""
        client = HTTPClient("http://localhost/dvwa")
        with pytest.raises(ContainmentError, match="Blocked out-of-scope"):
            client.get("https://example.invalid/escape")
        client.close()

    def test_rejects_protocol_relative_external_target_before_request(self):
        """Protocol-relative URLs are external targets too."""
        client = HTTPClient("http://localhost/dvwa")
        with pytest.raises(ContainmentError, match="Blocked out-of-scope"):
            client.get("//example.invalid/escape")
        client.close()

    @patch("foundation.http_client.httpx.Client")
    def test_rejects_external_redirect(self, mock_client_cls):
        """Every redirect hop must remain on the configured DVWA host."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        redirect = MagicMock()
        redirect.status_code = 302
        redirect.headers = {"location": "https://example.invalid/escape"}
        mock_instance.request.return_value = redirect

        client = HTTPClient("http://localhost/dvwa")
        with pytest.raises(ContainmentError, match="Blocked out-of-scope"):
            client.get("login.php")
        mock_instance.request.assert_called_once()

    @patch("foundation.http_client.httpx.Client")
    def test_post_302_redirect_switches_to_get_without_resubmitting_form(self, mock_client_cls):
        """DVWA form redirects must not resend the original POST body."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        redirect = MagicMock()
        redirect.status_code = 302
        redirect.headers = {"location": "security.php"}
        complete = MagicMock()
        complete.status_code = 200
        complete.headers = {}
        complete.elapsed.total_seconds.return_value = 0.1
        mock_instance.request.side_effect = [redirect, complete]

        client = HTTPClient("http://localhost/dvwa")
        client.post("security.php", data={"security": "medium"})

        first_call, second_call = mock_instance.request.call_args_list
        assert first_call.args[0] == "POST"
        assert first_call.kwargs["data"] == {"security": "medium"}
        assert second_call.args[0] == "GET"
        assert "data" not in second_call.kwargs

    @patch("foundation.http_client.httpx.Client")
    def test_post_307_redirect_preserves_method_and_body(self, mock_client_cls):
        """Only 307/308 redirects retain a POST request body."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        redirect = MagicMock()
        redirect.status_code = 307
        redirect.headers = {"location": "retry.php"}
        complete = MagicMock()
        complete.status_code = 200
        complete.headers = {}
        complete.elapsed.total_seconds.return_value = 0.1
        mock_instance.request.side_effect = [redirect, complete]

        client = HTTPClient("http://localhost/dvwa")
        client.post("security.php", data={"security": "medium"})

        first_call, second_call = mock_instance.request.call_args_list
        assert first_call.args[0] == "POST"
        assert second_call.args[0] == "POST"
        assert second_call.kwargs["data"] == {"security": "medium"}

    @patch("foundation.http_client.httpx.Client")
    def test_redirect_drops_original_query_params(self, mock_client_cls):
        """A redirect target must not inherit params from the original URL."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        redirect = MagicMock()
        redirect.status_code = 302
        redirect.headers = {"location": "index.php"}
        complete = MagicMock()
        complete.status_code = 200
        complete.headers = {}
        complete.elapsed.total_seconds.return_value = 0.1
        mock_instance.request.side_effect = [redirect, complete]

        client = HTTPClient("http://localhost/dvwa")
        client.get(
            "vulnerabilities/brute/",
            params={"username": "admin", "password": "password", "Login": "Login"},
        )

        first_call, second_call = mock_instance.request.call_args_list
        assert first_call.kwargs["params"]["username"] == "admin"
        assert second_call.args[0] == "GET"
        assert "params" not in second_call.kwargs


class TestHTTPClientErrorMapping:
    """Validate error mapping from httpx exceptions."""

    @patch("foundation.http_client.httpx.Client")
    def test_timeout_error_maps_to_request_timeout(self, mock_client_cls):
        """httpx.TimeoutException should be mapped to RequestTimeoutError."""
        import httpx
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        mock_instance.request.side_effect = httpx.TimeoutException("timeout")

        client = HTTPClient("http://localhost/dvwa")
        with pytest.raises(RequestTimeoutError, match="Request timed out"):
            client.get("test.php")

    @patch("foundation.http_client.httpx.Client")
    def test_network_error_maps_to_transport_error(self, mock_client_cls):
        """httpx.NetworkError should be mapped to TransportError."""
        import httpx
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        mock_instance.request.side_effect = httpx.ConnectError("connection refused")

        client = HTTPClient("http://localhost/dvwa")
        with pytest.raises(TransportError, match="Network error"):
            client.get("test.php")

    @patch("foundation.http_client.httpx.Client")
    def test_invalid_url_maps_to_value_error(self, mock_client_cls):
        """httpx.InvalidURL should be mapped to ValueError."""
        import httpx
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        mock_instance.request.side_effect = httpx.InvalidURL("bad url")

        client = HTTPClient("http://localhost/dvwa")
        with pytest.raises(ValueError, match="Invalid URL"):
            client.get("test.php")


class TestHTTPClientCookies:
    """Validate cookie management."""

    @patch("foundation.http_client.httpx.Client")
    def test_set_cookie(self, mock_client_cls):
        """set_cookie should add a cookie to the underlying client."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        mock_instance.cookies = MagicMock()

        client = HTTPClient("http://localhost/dvwa")
        client.set_cookie("security", "low")

        mock_instance.cookies.set.assert_called_once_with(
            "security", "low", domain="", path="/"
        )

    @patch("foundation.http_client.httpx.Client")
    def test_cookies_property(self, mock_client_cls):
        """cookies property should return the underlying httpx.Cookies."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        mock_cookies = MagicMock()
        mock_instance.cookies = mock_cookies

        client = HTTPClient("http://localhost/dvwa")
        assert client.cookies is mock_cookies


class TestHTTPClientClose:
    """Validate lifecycle methods."""

    @patch("foundation.http_client.httpx.Client")
    def test_close_calls_underlying_client(self, mock_client_cls):
        """close() should call the underlying httpx client close."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance

        client = HTTPClient("http://localhost/dvwa")
        client.close()
        mock_instance.close.assert_called_once()

    @patch("foundation.http_client.httpx.Client")
    def test_context_manager_closes_on_exit(self, mock_client_cls):
        """Context manager should close the underlying client on exit."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance

        with HTTPClient("http://localhost/dvwa") as client:
            pass
        mock_instance.close.assert_called_once()
