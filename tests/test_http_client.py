"""HTTP URL handling, containment, redirect, error and cleanup regressions."""

import pytest
from unittest.mock import patch, MagicMock

from foundation.http_client import (
    HTTPClient,
    ContainmentError,
)


class TestHTTPClientRequests:
    """Validate GET and POST request methods."""


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
