"""Tests for HTTP-layer containment in foundation/http_client.py."""

import pytest

from foundation.http_client import HTTPClient, ContainmentError


def test_allowed_host_derived_from_base_url():
    """The allowed host should be derived from the configured base URL."""
    client = HTTPClient("http://localhost/dvwa")
    assert client.allowed_host == "localhost"
    client.close()


def test_relative_and_same_host_in_scope():
    """Relative paths and same-host absolute URLs are in scope."""
    client = HTTPClient("http://localhost/dvwa")
    assert client._is_in_scope("/dvwa/vulnerabilities/sqli/") is True
    assert client._is_in_scope("http://localhost/dvwa/login.php") is True
    client.close()


def test_external_host_out_of_scope():
    """An external host must be flagged out of scope."""
    client = HTTPClient("http://localhost/dvwa")
    assert client._is_in_scope("http://evil.example.com/x") is False
    client.close()


def test_external_request_raises_and_logs_event():
    """A request to an external host raises ContainmentError and logs an event."""
    client = HTTPClient("http://localhost/dvwa")
    with pytest.raises(ContainmentError) as exc_info:
        client.get("http://evil.example.com/steal")
    assert exc_info.value.kind == "request"
    assert len(client.containment_events) == 1
    assert client.containment_events[0]["blocked_url"] == "http://evil.example.com/steal"
    client.close()


def test_external_redirect_blocked():
    """An external redirect target must be blocked before it is followed."""
    client = HTTPClient("http://localhost/dvwa")
    with pytest.raises(ContainmentError) as exc_info:
        client._assert_in_scope("http://evil.example.com/landing", kind="redirect")
    assert exc_info.value.kind == "redirect"
    assert client.containment_events[0]["kind"] == "redirect"
    client.close()
