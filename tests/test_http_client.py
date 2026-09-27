"""HTTP URL handling, containment, redirect, error and cleanup regressions."""

import pytest
from unittest.mock import patch, MagicMock

from foundation.http_client import (
    HTTPClient,
    TransportError,
    RequestTimeoutError,
    ContainmentError,
)


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


class TestHTTPClientRequests:
    """Validate GET and POST request methods."""

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


class TestHTTPClientClose:
    """Validate lifecycle methods."""

    @patch("foundation.http_client.httpx.Client")
    def test_context_manager_closes_on_exit(self, mock_client_cls):
        """Context manager should close the underlying client on exit."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance

        with HTTPClient("http://localhost/dvwa") as client:
            pass
        mock_instance.close.assert_called_once()
