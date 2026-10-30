"""Tests for foundation/recon.py — DVWA reconnaissance module.

Validates:
1. Module name inference from URL patterns
2. Form parsing into normalized endpoints and vectors
3. Navigation link extraction
4. Security level detection from HTML
5. Endpoint and vector deduplication
6. Recon node integration with ExploitationState
"""


from foundation.recon import (
    infer_module_name,
    parse_forms,
    extract_nav_links,
)


class TestParseForms:
    """Validate HTML form parsing into endpoints and vectors."""


    def test_parse_form_discards_external_action(self):
        """Recon must not place external form actions into shared state."""
        html = '<form action="https://example.invalid/escape"><input name="id"></form>'
        endpoints, vectors = parse_forms(html, "http://localhost/dvwa/vulnerabilities/sqli/")
        assert endpoints == []
        assert vectors == []

class TestExtractNavLinks:
    """Validate navigation link extraction from DVWA pages."""


    def test_extract_links_discards_external_host(self):
        """Recon navigation must remain on the configured DVWA host."""
        html = '<a href="https://example.invalid/vulnerabilities/sqli/">external</a>'
        assert extract_nav_links(html, "http://localhost/dvwa/") == []


def test_authbypass_maps_to_idor():
    """authbypass endpoint should map to idor module."""
    assert infer_module_name("http://localhost/dvwa/vulnerabilities/authbypass/") == "idor"
