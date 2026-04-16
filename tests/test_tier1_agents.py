from types import SimpleNamespace
import importlib

cmdi_module = importlib.import_module("agents.tier1.cmdi_agent")
sqli_module = importlib.import_module("agents.tier1.sqli_agent")
sqli_blind_module = importlib.import_module("agents.tier1.sqli_blind_agent")
xss_dom_module = importlib.import_module("agents.tier1.xss_dom_agent")
xss_reflected_module = importlib.import_module("agents.tier1.xss_reflected_agent")
xss_stored_module = importlib.import_module("agents.tier1.xss_stored_agent")
from foundation.verifier import VerificationResult


class FakeResult:
    def __init__(self, text: str = "", elapsed_ms: float = 0.0, headers: dict | None = None):
        self.text = text
        self.elapsed_ms = elapsed_ms
        self.headers = headers or {}


def test_sqli_agent_updates_score_and_confirmed_nodes(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={"PHPSESSID": "abc"})

        def get(self, _endpoint, params=None):
            return FakeResult(text="First name: admin Surname: user password")

        def close(self):
            return None

    monkeypatch.setattr(sqli_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "sqli", "url": "/vulnerabilities/sqli/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = sqli_module.sqli_agent(state)

    assert update["scores"]["sqli"] == 4
    assert "sqli_confirmed" in update["confirmed_vulns"]
    assert "credentials_extracted" in update["confirmed_vulns"]
    assert update["found_credentials"]


def test_sqli_blind_agent_budget_gates_full_extraction(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.calls = 0
            self.http = SimpleNamespace(cookies={})

        def get(self, _endpoint, params=None):
            self.calls += 1
            if self.calls == 1:
                return FakeResult(text="normal", elapsed_ms=50)
            if self.calls == 2:
                return FakeResult(text="different", elapsed_ms=50)
            return FakeResult(text="normal", elapsed_ms=3001)

        def close(self):
            return None

    monkeypatch.setattr(sqli_blind_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "sqli_blind", "url": "/vulnerabilities/sqli_blind/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 29,
        "max_iterations": 30,
    }
    update = sqli_blind_module.sqli_blind_agent(state)

    assert update["scores"]["sqli_blind"] <= 2
    assert "blind_sqli_confirmed" in update["confirmed_vulns"]
    assert "data_exfiltrated" not in update.get("confirmed_vulns", [])


def test_xss_reflected_agent_uses_browser_verifier(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={"PHPSESSID": "abc"})

        def get(self, _endpoint, params=None):
            payload = params["name"] if params else ""
            return FakeResult(text=f"echo {payload}")

        def close(self):
            return None

    monkeypatch.setattr(xss_reflected_module, "DVWASession", FakeSession)
    monkeypatch.setattr(
        xss_reflected_module._AGENT.verifier,
        "verify_xss_dialog",
        lambda *args, **kwargs: VerificationResult(ok=True, confidence=1.0, evidence=["dialog"]),
    )

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "xss_r", "url": "/vulnerabilities/xss_r/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = xss_reflected_module.xss_reflected_agent(state)

    assert update["scores"]["xss_r"] >= 3
    assert "xss_reflected_confirmed" in update["confirmed_vulns"]


def test_xss_stored_agent_enables_csrf_chain(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={"PHPSESSID": "abc"})

        def post(self, _endpoint, data=None):
            return FakeResult(text="Successfully signed guestbook")

        def get(self, _endpoint, params=None):
            return FakeResult(text="<script>alert(1)</script>")

        def close(self):
            return None

    monkeypatch.setattr(xss_stored_module, "DVWASession", FakeSession)
    monkeypatch.setattr(
        xss_stored_module._AGENT.verifier,
        "verify_xss_dialog",
        lambda *args, **kwargs: VerificationResult(ok=True, confidence=1.0, evidence=["dialog"]),
    )

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [
            {"module_name": "xss_s", "url": "/vulnerabilities/xss_s/"},
            {"module_name": "csrf", "url": "/vulnerabilities/csrf/"},
        ],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = xss_stored_module.xss_stored_agent(state)

    assert update["scores"]["xss_s"] == 4
    assert "xss_stored_confirmed" in update["confirmed_vulns"]


def test_xss_stored_agent_does_not_mark_payload_if_session_prep_fails(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={"PHPSESSID": "abc"})

        def login(self, username="admin", password="password"):
            return False

        def close(self):
            return None

    monkeypatch.setattr(xss_stored_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [
            {"module_name": "xss_s", "url": "/vulnerabilities/xss_s/"},
            {"module_name": "csrf", "url": "/vulnerabilities/csrf/"},
        ],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = xss_stored_module.xss_stored_agent(state)

    module_tried = update["tried_payloads"]["xss_s"]
    assert "session_login_failed" in module_tried
    assert "<script>alert(1)</script>" not in module_tried


def test_xss_dom_agent_dom_signal_path(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={})

        def get(self, _endpoint, params=None):
            payload = params["default"] if params else ""
            return FakeResult(text=f"dom sink: {payload}")

        def close(self):
            return None

    monkeypatch.setattr(xss_dom_module, "DVWASession", FakeSession)
    monkeypatch.setattr(
        xss_dom_module._AGENT.verifier,
        "verify_xss_dialog",
        lambda *args, **kwargs: VerificationResult(ok=False, confidence=0.0, evidence=["no_dialog"]),
    )

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "xss_d", "url": "/vulnerabilities/xss_d/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = xss_dom_module.xss_dom_agent(state)

    assert update["scores"]["xss_d"] >= 2
    assert "xss_dom_confirmed" in update["confirmed_vulns"]


def test_cmdi_agent_sets_rce_achieved(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={})

        def post(self, _endpoint, data=None):
            return FakeResult(text="uid=33(www-data) gid=33(www-data)")

        def close(self):
            return None

    monkeypatch.setattr(cmdi_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "cmdi", "url": "/vulnerabilities/exec/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = cmdi_module.cmdi_agent(state)

    assert update["scores"]["cmdi"] == 4
    assert "cmd_injection_confirmed" in update["confirmed_vulns"]
    assert "rce_achieved" in update["confirmed_vulns"]
    assert "rce_achieved" in update["achieved_outcomes"]


def test_cmdi_agent_does_not_flag_benign_non_empty_output(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={})

        def post(self, _endpoint, data=None):
            return FakeResult(text="PING 127.0.0.1 (127.0.0.1): 56 data bytes")

        def close(self):
            return None

    monkeypatch.setattr(cmdi_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "cmdi", "url": "/vulnerabilities/exec/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = cmdi_module.cmdi_agent(state)

    assert update["scores"]["cmdi"] == 0
    assert "confirmed_vulns" not in update


def test_sqli_blind_agent_ignores_token_only_boolean_noise(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.calls = 0
            self.http = SimpleNamespace(cookies={})

        def get(self, _endpoint, params=None):
            self.calls += 1
            if self.calls == 1:
                return FakeResult(text='<input name="user_token" value="abc123">', elapsed_ms=50)
            if self.calls == 2:
                return FakeResult(text='<input name="user_token" value="def456">', elapsed_ms=50)
            return FakeResult(text="stable", elapsed_ms=100)

        def close(self):
            return None

    monkeypatch.setattr(sqli_blind_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "sqli_blind", "url": "/vulnerabilities/sqli_blind/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
        "max_iterations": 30,
    }
    update = sqli_blind_module.sqli_blind_agent(state)

    assert update["scores"]["sqli_blind"] == 0
    assert "confirmed_vulns" not in update
