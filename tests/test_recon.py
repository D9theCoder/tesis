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
    EndpointRecord,
    InputVectorRecord,
    _deduplicate_endpoints,
    _deduplicate_vectors,
    recon,
)
from core.state import SECURITY_LEVELS


class TestInferModuleName:
    """Validate DVWA module name inference from URLs."""

    @pytest.mark.parametrize(
        "url,expected",
        [
            ("http://localhost/dvwa/vulnerabilities/sqli/", "sqli"),
            ("http://localhost/dvwa/vulnerabilities/sqli_blind/", "sqli_blind"),
            ("http://localhost/dvwa/vulnerabilities/xss_r/", "xss_r"),
            ("http://localhost/dvwa/vulnerabilities/xss_s/", "xss_s"),
            ("http://localhost/dvwa/vulnerabilities/xss_d/", "xss_d"),
            ("http://localhost/dvwa/vulnerabilities/exec/", "cmdi"),
            ("http://localhost/dvwa/vulnerabilities/fi/", "lfi"),
            ("http://localhost/dvwa/vulnerabilities/upload/", "upload"),
            ("http://localhost/dvwa/vulnerabilities/csrf/", "csrf"),
            ("http://localhost/dvwa/vulnerabilities/brute/", "brute"),
            ("http://localhost/dvwa/vulnerabilities/weak_id/", "weak_session"),
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

    def test_ordering_independence(self):
        """More specific patterns should match regardless of dict insertion order.

        This test verifies that 'sqli_blind' matches before 'sqli' even if
        the dict were constructed with 'sqli' first.
        """
        assert infer_module_name("http://localhost/dvwa/vulnerabilities/sqli_blind/") == "sqli_blind"
        assert infer_module_name("http://localhost/dvwa/vulnerabilities/sqli/") == "sqli"

    def test_xss_prefix_disambiguation(self):
        """xss_r, xss_s, xss_d should not all match as 'xss'."""
        assert infer_module_name("http://localhost/dvwa/vulnerabilities/xss_r/") == "xss_r"
        assert infer_module_name("http://localhost/dvwa/vulnerabilities/xss_s/") == "xss_s"
        assert infer_module_name("http://localhost/dvwa/vulnerabilities/xss_d/") == "xss_d"


class TestEndpointRecord:
    """Validate EndpointRecord construction and normalization."""

    def test_basic_construction(self):
        """EndpointRecord should create a dict with expected fields."""
        ep = EndpointRecord(
            url="http://localhost/dvwa/vulnerabilities/sqli/",
            method="GET",
            params=["id", "Submit"],
            csrf_token="abc123",
            module_name="sqli",
        )
        assert ep["url"] == "http://localhost/dvwa/vulnerabilities/sqli/"
        assert ep["method"] == "get"  # Normalized to lowercase
        assert ep["params"] == ["Submit", "id"]  # Sorted and deduplicated
        assert ep["csrf_token"] == "abc123"
        assert ep["module_name"] == "sqli"

    def test_default_values(self):
        """EndpointRecord should have sensible defaults."""
        ep = EndpointRecord(url="http://example.com/test")
        assert ep["method"] == "get"
        assert ep["params"] == []
        assert ep["csrf_token"] is None
        assert ep["module_name"] == "unknown"


class TestInputVectorRecord:
    """Validate InputVectorRecord construction."""

    def test_basic_construction(self):
        """InputVectorRecord should create a dict with expected fields."""
        vec = InputVectorRecord(
            param_name="id",
            param_type="text",
            endpoint_url="http://localhost/dvwa/vulnerabilities/sqli/",
        )
        assert vec["param_name"] == "id"
        assert vec["param_type"] == "text"
        assert vec["endpoint_url"] == "http://localhost/dvwa/vulnerabilities/sqli/"

    def test_type_normalization(self):
        """Param type should be normalized to lowercase."""
        vec = InputVectorRecord(param_name="test", param_type="HIDDEN")
        assert vec["param_type"] == "hidden"


class TestParseForms:
    """Validate HTML form parsing into endpoints and vectors."""

    def test_parse_simple_form(self):
        """Should parse a simple form with one input."""
        html = '''
        <form action="/dvwa/vulnerabilities/sqli/" method="get">
            <input type="text" name="id" value="">
            <input type="submit" name="Submit" value="Submit">
        </form>
        '''
        endpoints, vectors = parse_forms(html, "http://localhost/dvwa/vulnerabilities/sqli/")

        assert len(endpoints) == 1
        assert endpoints[0]["url"] == "http://localhost/dvwa/vulnerabilities/sqli/"
        assert endpoints[0]["method"] == "get"
        assert "id" in endpoints[0]["params"]
        assert "Submit" in endpoints[0]["params"]
        assert endpoints[0]["module_name"] == "sqli"

        assert len(vectors) >= 1
        id_vectors = [v for v in vectors if v["param_name"] == "id"]
        assert len(id_vectors) == 1
        assert id_vectors[0]["param_type"] == "text"

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

    def test_parse_form_with_relative_action(self):
        """Should resolve relative action URLs using page_url."""
        html = '''
        <form action="?page=../../../etc/passwd" method="get">
            <input type="text" name="page" value="">
        </form>
        '''
        endpoints, vectors = parse_forms(html, "http://localhost/dvwa/vulnerabilities/fi/")

        assert endpoints[0]["url"].startswith("http://localhost")

    def test_parse_form_default_method(self):
        """Forms without method attribute should default to 'get'."""
        html = '''
        <form action="/test">
            <input type="text" name="q">
        </form>
        '''
        endpoints, _ = parse_forms(html, "http://localhost/test")
        assert endpoints[0]["method"] == "get"

    def test_parse_no_forms(self):
        """Should return empty lists when no forms are present."""
        html = "<html><body><p>No forms here</p></body></html>"
        endpoints, vectors = parse_forms(html, "http://localhost/test")
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

    def test_extract_vulnerability_links(self):
        """Should extract links under /vulnerabilities/."""
        html = '''
        <html>
        <body>
            <a href="/dvwa/vulnerabilities/sqli/">SQL Injection</a>
            <a href="/dvwa/vulnerabilities/xss_r/">XSS Reflected</a>
            <a href="/dvwa/vulnerabilities/exec/">Command Injection</a>
            <a href="/dvwa/index.php">Home</a>
        </body>
        </html>
        '''
        links = extract_nav_links(html, "http://localhost/dvwa/")
        assert len(links) == 3
        assert any("sqli" in l for l in links)
        assert any("xss_r" in l for l in links)
        assert any("exec" in l for l in links)

    def test_extract_links_deduplicates(self):
        """Should deduplicate and sort links."""
        html = '''
        <a href="/dvwa/vulnerabilities/sqli/">Link 1</a>
        <a href="/dvwa/vulnerabilities/sqli/">Link 2</a>
        '''
        links = extract_nav_links(html, "http://localhost/dvwa/")
        assert len(links) == 1

    def test_extract_links_strips_fragments(self):
        """Should strip fragment identifiers from URLs."""
        html = '<a href="/dvwa/vulnerabilities/sqli/#top">SQLi</a>'
        links = extract_nav_links(html, "http://localhost/dvwa/")
        assert len(links) == 1
        assert "#top" not in links[0]

    def test_extract_no_vulnerability_links(self):
        """Should return empty list when no module links are present."""
        html = '<html><body><a href="/dvwa/index.php">Home</a></body></html>'
        links = extract_nav_links(html, "http://localhost/dvwa/")
        assert links == []


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

    def test_no_level_detected(self):
        """Should return None when no security level is found."""
        result = detect_security_level_from_html("<html><body>No level info</body></html>")
        assert result is None

    def test_case_insensitive_detection(self):
        """Detection should be case-insensitive."""
        result = detect_security_level_from_html("dvwa SECURITY level: MEDIUM")
        assert result == "medium"


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

    def test_recon_returns_state_compatible_update(self):
        """recon() should return a dict with all required ExploitationState keys."""
        # This test validates the return shape without requiring a running DVWA instance.
        # We mock the HTTP interactions.
        with patch("foundation.recon.DVWASession") as MockSession:
            mock_session = MagicMock()

            # Mock login to succeed
            mock_session.login.return_value = True
            mock_session.is_logged_in = True

            # Mock security level detection
            mock_session.detect_security_level.return_value = "low"

            # Mock index page crawl to return navigation links
            index_result = MagicMock()
            index_result.text = '''
            <a href="/dvwa/vulnerabilities/sqli/">SQLi</a>
            <a href="/dvwa/vulnerabilities/xss_r/">XSS</a>
            '''
            mock_session.http.get.return_value = index_result
            mock_session.http.base_url = "http://localhost/dvwa/"

            # Mock the closing to not fail
            mock_session.close.return_value = None

            MockSession.return_value = mock_session

            state = {
                "target_url": "http://localhost/dvwa",
                "security_level": "low",
            }
            update = recon(state)

            # Validate all required output keys
            assert "endpoints" in update
            assert "security_level" in update
            assert "next_agent" in update
            assert update["next_agent"] == "orchestrator"
            assert update["security_level"] in SECURITY_LEVELS
            assert isinstance(update["endpoints"], list)

    def test_recon_with_empty_target_url(self):
        """recon() should handle empty target_url gracefully."""
        state = {"target_url": "", "security_level": "low"}
        update = recon(state)

        assert update["endpoints"] == []
        assert update["next_agent"] == "orchestrator"

    def test_recon_deduplicates_and_sorts_endpoints(self):
        """recon() should produce deterministic, deduplicated output."""
        with patch("foundation.recon.DVWASession") as MockSession:
            mock_session = MagicMock()
            mock_session.login.return_value = True
            mock_session.detect_security_level.return_value = "low"
            mock_session.close.return_value = None

            # Create deterministic HTML responses
            index_html = '''
            <a href="/dvwa/vulnerabilities/sqli/">SQLi</a>
            <a href="/dvwa/vulnerabilities/sqli/">SQLi Again</a>
            '''
            sqli_html = '''
            <form action="" method="get">
                <input type="text" name="id">
                <input type="submit" name="Submit" value="Submit">
            </form>
            '''

            index_result = MagicMock()
            index_result.text = index_html
            sqli_result = MagicMock()
            sqli_result.text = sqli_html
            setup_result = MagicMock()
            setup_result.text = "Forbidden"

            def mock_http_get(path, *args, **kwargs):
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

            # Should have only one endpoint (deduplicated)
            if update["endpoints"]:
                urls = [ep["url"] for ep in update["endpoints"]]
                # No duplicate URLs
                assert len(urls) == len(set(urls))

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
    """Validate server fingerprinting from HTTP headers."""

    def test_apache_server_detected(self):
        """Should detect Apache server from Server header."""
        fingerprint = fingerprint_server({"Server": "Apache/2.4.41"})
        assert fingerprint["server"] == "Apache/2.4.41"

    def test_php_version_detected(self):
        """Should detect PHP version from X-Powered-By header."""
        fingerprint = fingerprint_server({"X-Powered-By": "PHP/7.4.3"})
        assert fingerprint["php_version"] == "PHP/7.4.3"

    def test_multiple_fingerprints(self):
        """Should detect multiple technologies from headers."""
        fingerprint = fingerprint_server({
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/7.4.3",
        })
        assert fingerprint["server"] == "Apache/2.4.41"
        assert fingerprint["php_version"] == "PHP/7.4.3"

    def test_no_relevant_headers(self):
        """Should return empty dict when no fingerprint headers are present."""
        fingerprint = fingerprint_server({"Content-Type": "text/html"})
        assert fingerprint == {}

    def test_case_insensitive_headers(self):
        """Should match headers case-insensitively."""
        fingerprint = fingerprint_server({"server": "nginx"})
        assert fingerprint["server"] == "nginx"


def test_authbypass_maps_to_idor():
    """authbypass endpoint should map to idor module."""
    assert infer_module_name("http://localhost/dvwa/vulnerabilities/authbypass/") == "idor"


def test_object_ids_enumerable_after_authbypass_fix():
    """DVWA_MODULE_HINTS must include authbypass->idor mapping."""
    from foundation.recon import DVWA_MODULE_HINTS
    assert "authbypass" in DVWA_MODULE_HINTS
    assert DVWA_MODULE_HINTS["authbypass"] == "idor"
