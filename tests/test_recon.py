"""Tests for foundation/recon.py — DVWA reconnaissance module.

Validates:
1. Module name inference from URL patterns
2. Form parsing into normalized endpoints and vectors
3. Navigation link extraction
4. Security level detection from HTML
5. Endpoint and vector deduplication
6. Recon node integration with ExploitationState
"""

import pytest
from unittest.mock import patch, MagicMock

from foundation.recon import (
    infer_module_name,
    parse_forms,
    extract_nav_links,
    detect_security_level_from_html,
    fingerprint_server,
    _deduplicate_endpoints,
    _deduplicate_vectors,
    recon,
)

class TestInferModuleName:
    """Validate DVWA module name inference from URLs."""

    @pytest.mark.parametrize(
        "url,expected",
        [
            ("http://localhost/dvwa/vulnerabilities/sqli/", "sqli"),
            ("http://localhost/dvwa/vulnerabilities/sqli_blind/", "sqli_blind"),
        ],
    )
    def test_known_modules(self, url, expected):
        """Known DVWA module paths should map to correct module names."""
        assert infer_module_name(url) == expected

    def test_unknown_path(self):
        """Unknown paths should return 'unknown'."""
        assert infer_module_name("http://localhost/dvwa/setup.php") == "unknown"

    def test_case_insensitive(self):
        """Module inference should be case-insensitive."""
        assert infer_module_name("http://localhost/DVWA/vulnerabilities/SQLI/") == "sqli"

class TestParseForms:
    """Validate HTML form parsing into endpoints and vectors."""

    def test_parse_form_with_csrf_token(self):
        """Should extract CSRF token from user_token hidden field."""
        html = '''
        <form action="" method="post">
            <input type="hidden" name="user_token" value="tok_abc123">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit" name="Login" value="Login">
        </form>
        '''
        endpoints, vectors = parse_forms(html, "http://localhost/dvwa/login.php")

        assert endpoints[0]["csrf_token"] == "tok_abc123"

    def test_parse_form_discards_external_action(self):
        """Recon must not place external form actions into shared state."""
        html = '<form action="https://example.invalid/escape"><input name="id"></form>'
        endpoints, vectors = parse_forms(html, "http://localhost/dvwa/vulnerabilities/sqli/")
        assert endpoints == []
        assert vectors == []

    def test_parse_multiple_forms(self):
        """Should parse multiple forms on a page."""
        html = '''
        <form action="/form1" method="post">
            <input type="text" name="field1">
        </form>
        <form action="/form2" method="get">
            <input type="text" name="field2">
        </form>
        '''
        endpoints, vectors = parse_forms(html, "http://localhost/page")
        assert len(endpoints) == 2
        assert len(vectors) == 2
    def test_parse_skips_inputs_without_name(self):
        """Inputs without name attribute should be skipped."""
        html = '''
        <form action="/test" method="post">
            <input type="text" name="named_field">
            <input type="submit" value="Go">
        </form>
        '''
        endpoints, vectors = parse_forms(html, "http://localhost/test")
        assert len(vectors) == 1
        assert vectors[0]["param_name"] == "named_field"
class TestExtractNavLinks:
    """Validate navigation link extraction from DVWA pages."""

    def test_extracts_relative_vulnerability_link(self):
        """DVWA-style relative module links should resolve under the base path."""
        html = '<a href="vulnerabilities/sqli/">SQL Injection</a>'

        links = extract_nav_links(html, "http://localhost/dvwa/")

        assert links == ["http://localhost/dvwa/vulnerabilities/sqli/"]


    def test_extract_links_ignores_vulnerability_text_outside_path(self):
        """A query string mentioning a module must not be treated as a module link."""
        html = '<a href="/dvwa/index.php?next=/vulnerabilities/sqli/">Home</a>'

        assert extract_nav_links(html, "http://localhost/dvwa/") == []

    def test_extract_links_strips_fragments(self):
        """Should strip fragment identifiers from URLs."""
        html = '<a href="/dvwa/vulnerabilities/sqli/#top">SQLi</a>'
        links = extract_nav_links(html, "http://localhost/dvwa/")
        assert len(links) == 1
        assert "#top" not in links[0]
    def test_extract_links_discards_external_host(self):
        """Recon navigation must remain on the configured DVWA host."""
        html = '<a href="https://example.invalid/vulnerabilities/sqli/">external</a>'
        assert extract_nav_links(html, "http://localhost/dvwa/") == []

class TestDetectSecurityLevelFromHtml:
    """Validate security level detection from HTML content."""

    @pytest.mark.parametrize(
        "html,expected",
        [
            ("DVWA Security Level: low", "low"),
            ("DVWA Security Level: medium", "medium"),
            ("DVWA Security Level: high", "high"),
            ("DVWA Security Level: impossible", "impossible"),
            ("security level is low", "low"),
            ("the security level is high for this", "high"),
        ],
    )
    def test_detected_levels(self, html, expected):
        """Should correctly detect security level indicators in HTML."""
        result = detect_security_level_from_html(html)
        assert result == expected

class TestDeduplication:
    """Validate endpoint and vector deduplication."""

    def test_deduplicate_endpoints(self):
        """Should deduplicate endpoints by (url, method) and sort by url."""
        endpoints = [
            {"url": "http://localhost/b", "method": "post", "params": ["x"], "csrf_token": None, "module_name": "test"},
            {"url": "http://localhost/a", "method": "get", "params": ["y"], "csrf_token": None, "module_name": "test"},
            {"url": "http://localhost/b", "method": "post", "params": ["z"], "csrf_token": None, "module_name": "test2"},
        ]
        result = _deduplicate_endpoints(endpoints)
        assert len(result) == 2
        assert result[0]["url"] == "http://localhost/a"
        assert result[1]["url"] == "http://localhost/b"
        # First occurrence wins for deduplication
        assert result[1]["params"] == ["x"]
    def test_deduplicate_vectors(self):
        """Should deduplicate vectors by (param_name, endpoint_url)."""
        vectors = [
            {"param_name": "id", "param_type": "text", "endpoint_url": "http://localhost/a"},
            {"param_name": "id", "param_type": "text", "endpoint_url": "http://localhost/a"},  # duplicate
            {"param_name": "name", "param_type": "text", "endpoint_url": "http://localhost/b"},
        ]
        result = _deduplicate_vectors(vectors)
        assert len(result) == 2

class TestReconNodeIntegration:
    """Validate the recon function as a LangGraph node."""

    def test_recon_finishes_all_requests_before_closing_session(self):
        """Regression: recon must not reuse the HTTP client after cleanup."""
        with patch("foundation.recon.DVWASession") as MockSession:
            mock_session = MagicMock()
            client_closed = False

            mock_session.login.return_value = True
            mock_session.is_logged_in = True
            mock_session.detect_security_level.return_value = "low"
            mock_session.http.base_url = "http://localhost/dvwa/"

            index_result = MagicMock()
            index_result.text = '<a href="/dvwa/vulnerabilities/sqli/">SQLi</a>'
            sqli_result = MagicMock()
            sqli_result.text = '<form action="" method="get"><input name="id"></form>'
            setup_result = MagicMock(status_code=200, text="Database Setup")

            def mock_http_get(path, *args, **kwargs):
                if client_closed:
                    raise RuntimeError("Cannot send a request, as the client has been closed.")
                path_str = str(path)
                if path_str.endswith("index.php"):
                    return index_result
                if "setup.php" in path_str:
                    return setup_result
                return sqli_result

            def mock_close():
                nonlocal client_closed
                client_closed = True

            mock_session.http.get.side_effect = mock_http_get
            mock_session.close.side_effect = mock_close
            MockSession.return_value = mock_session

            update = recon({
                "target_url": "http://localhost/dvwa",
                "security_level": "low",
            })

            assert client_closed is True
            assert update["observations"]["force_browse_endpoints_visible"] is True
            assert update["input_vectors"][0]["param_name"] == "id"

    def test_force_browse_endpoints_visible_from_probe(self):
        """When setup.php is accessible, the force-browse observation should be true."""
        with patch("foundation.recon.DVWASession") as MockSession:
            mock_session = MagicMock()
            mock_session.login.return_value = True
            mock_session.detect_security_level.return_value = "low"
            mock_session.close.return_value = None

            index_result = MagicMock()
            index_result.text = '<a href="/dvwa/vulnerabilities/sqli/">SQLi</a>'
            sqli_result = MagicMock()
            sqli_result.text = '<form action="" method="get"><input name="id"></form>'
            setup_result = MagicMock()
            setup_result.status_code = 200
            setup_result.text = "Database Setup"

            def mock_http_get(path, *args, **kwargs):
                """Supports regression tests for test recon."""
                path_str = str(path)
                if path_str.endswith("index.php"):
                    return index_result
                if "setup.php" in path_str:
                    return setup_result
                return sqli_result

            mock_session.http.get.side_effect = mock_http_get
            mock_session.http.base_url = "http://localhost/dvwa/"
            MockSession.return_value = mock_session

            state = {"target_url": "http://localhost/dvwa", "security_level": "low"}
            update = recon(state)

            assert update["observations"].get("force_browse_endpoints_visible") is True

    def test_force_browse_endpoints_visible_false_on_403(self):
        """When setup.php is forbidden, the force-browse observation should be false."""
        with patch("foundation.recon.DVWASession") as MockSession:
            mock_session = MagicMock()
            mock_session.login.return_value = True
            mock_session.detect_security_level.return_value = "low"
            mock_session.close.return_value = None

            index_result = MagicMock()
            index_result.text = '<a href="/dvwa/vulnerabilities/sqli/">SQLi</a>'
            sqli_result = MagicMock()
            sqli_result.text = '<form action="" method="get"><input name="id"></form>'
            setup_result = MagicMock()
            setup_result.status_code = 403
            setup_result.text = "Forbidden"

            def mock_http_get(path, *args, **kwargs):
                """Supports regression tests for test recon."""
                path_str = str(path)
                if path_str.endswith("index.php"):
                    return index_result
                if "setup.php" in path_str:
                    return setup_result
                return sqli_result

            mock_session.http.get.side_effect = mock_http_get
            mock_session.http.base_url = "http://localhost/dvwa/"
            MockSession.return_value = mock_session

            state = {"target_url": "http://localhost/dvwa", "security_level": "low"}
            update = recon(state)

            assert update["observations"].get("force_browse_endpoints_visible") is False

class TestFormParsingNoDuplicates:
    """Validate that parse_forms does not produce duplicate vectors for textarea/select."""

    def test_textarea_not_duplicated(self):
        """Textarea elements should appear exactly once in vectors."""
        html = '''
        <form action="/test" method="post">
            <input type="text" name="username">
            <textarea name="message">Default text</textarea>
            <input type="submit" name="submit">
        </form>
        '''
        endpoints, vectors = parse_forms(html, "http://localhost/test")
        message_vectors = [v for v in vectors if v["param_name"] == "message"]
        assert len(message_vectors) == 1
        assert message_vectors[0]["param_type"] == "textarea"

    def test_select_not_duplicated(self):
        """Select elements should appear exactly once in vectors with type 'select'."""
        html = '''
        <form action="/test" method="post">
            <select name="color">
                <option value="red">Red</option>
                <option value="blue">Blue</option>
            </select>
            <input type="submit" name="submit">
        </form>
        '''
        endpoints, vectors = parse_forms(html, "http://localhost/test")
        color_vectors = [v for v in vectors if v["param_name"] == "color"]
        assert len(color_vectors) == 1
        assert color_vectors[0]["param_type"] == "select"

    def test_textarea_and_select_in_same_form(self):
        """Both textarea and select should be captured with correct types in a single form."""
        html = '''
        <form action="/test" method="post">
            <input type="text" name="title">
            <textarea name="body"></textarea>
            <select name="category">
                <option value="a">A</option>
            </select>
            <input type="submit" name="submit">
        </form>
        '''
        endpoints, vectors = parse_forms(html, "http://localhost/test")
        param_types = {v["param_name"]: v["param_type"] for v in vectors}
        assert param_types["title"] == "text"
        assert param_types["body"] == "textarea"
        assert param_types["category"] == "select"

        # Also ensure correct params in endpoint
        assert "title" in endpoints[0]["params"]
        assert "body" in endpoints[0]["params"]
        assert "category" in endpoints[0]["params"]

class TestFingerprintServer:
    """Keep header lookup case insensitive for server fingerprints."""

    def test_case_insensitive_headers(self):
        """Should match headers case-insensitively."""
        fingerprint = fingerprint_server({"server": "nginx"})
        assert fingerprint["server"] == "nginx"

def test_authbypass_maps_to_idor():
    """authbypass endpoint should map to idor module."""
    assert infer_module_name("http://localhost/dvwa/vulnerabilities/authbypass/") == "idor"
