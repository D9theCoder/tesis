"""Focused tests for high-security SQLi session-input discovery."""

from unittest.mock import MagicMock, patch

import pytest

from foundation.recon import recon


BASE_URL = "http://localhost/dvwa/"
SQLI_URL = f"{BASE_URL}vulnerabilities/sqli/"
SESSION_INPUT_URL = f"{SQLI_URL}session-input.php"


def _response(text: str, *, status_code: int = 200, headers: dict | None = None) -> MagicMock:
    response = MagicMock()
    response.text = text
    response.status_code = status_code
    response.headers = headers or {}
    return response


def _mock_session(sqli_body: str, security_level: str) -> MagicMock:
    session = MagicMock()
    session.login.return_value = True
    session.detect_security_level.return_value = security_level
    session.is_logged_in = True
    session.close.return_value = None
    session.http.base_url = BASE_URL

    index_result = _response('<a href="/dvwa/vulnerabilities/sqli/">SQLi</a>')
    sqli_result = _response(sqli_body)
    session_input_result = _response("session input endpoint")
    setup_result = _response("Forbidden", status_code=403)

    def get(path: str, *args, **kwargs):
        path_text = str(path).split("?", 1)[0].split("#", 1)[0]
        if path_text.endswith("index.php"):
            return index_result
        if path_text.endswith("session-input.php"):
            return session_input_result
        if path_text.endswith("setup.php"):
            return setup_result
        if path_text.rstrip("/").endswith("vulnerabilities/sqli"):
            return sqli_result
        raise AssertionError(f"unexpected recon request: {path!r}")

    session.http.get.side_effect = get
    return session


def _run_recon(sqli_body: str, security_level: str) -> tuple[dict, MagicMock]:
    session = _mock_session(sqli_body, security_level)
    with patch("foundation.recon.DVWASession", return_value=session):
        update = recon(
            {
                "target_url": "http://localhost/dvwa",
                "security_level": security_level,
            }
        )
    return update, session


def test_high_sqli_popup_markup_registers_contained_post_endpoint():
    """A popup/JS reference should add the high-SQLi POST endpoint."""
    sqli_body = """
    <form action="" method="get"><input name="id"></form>
    <script>function openInput() { popUp('session-input.php'); }</script>
    """

    update, session = _run_recon(sqli_body, "high")

    discovered = [endpoint for endpoint in update["endpoints"] if endpoint["url"] == SESSION_INPUT_URL]
    assert discovered == [
        {
            "url": SESSION_INPUT_URL,
            "method": "post",
            "params": ["id"],
            "csrf_token": None,
            "module_name": "sqli",
        }
    ]
    session.http.get.assert_any_call(SESSION_INPUT_URL)


def test_high_sqli_without_session_input_marker_does_not_register_endpoint():
    """A high SQLi page without the marker must not invent the endpoint."""
    update, session = _run_recon(
        '<form action="" method="get"><input name="id"></form>',
        "high",
    )

    assert all(endpoint["url"] != SESSION_INPUT_URL for endpoint in update["endpoints"])
    requested_urls = [str(call.args[0]) for call in session.http.get.call_args_list]
    assert SESSION_INPUT_URL not in requested_urls


@pytest.mark.parametrize("security_level", ["low", "medium"])
def test_low_and_medium_sqli_do_not_probe_session_input(security_level: str):
    """The high-only discovery path must not alter lower-level recon."""
    update, session = _run_recon(
        "<form action='' method='get'><input name='id'></form>"
        "<script>popUp('session-input.php')</script>",
        security_level,
    )

    assert all(endpoint["url"] != SESSION_INPUT_URL for endpoint in update["endpoints"])
    requested_urls = [str(call.args[0]) for call in session.http.get.call_args_list]
    assert SESSION_INPUT_URL not in requested_urls
