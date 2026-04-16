from types import SimpleNamespace
import importlib

brute_module = importlib.import_module("agents.tier2.brute_agent")
csrf_module = importlib.import_module("agents.tier2.csrf_agent")
idor_module = importlib.import_module("agents.tier2.idor_agent")
lfi_module = importlib.import_module("agents.tier2.lfi_agent")
upload_module = importlib.import_module("agents.tier2.upload_agent")
weak_session_module = importlib.import_module("agents.tier2.weak_session_agent")


class FakeResult:
    def __init__(self, text: str = "", elapsed_ms: float = 0.0, headers: dict | None = None):
        self.text = text
        self.elapsed_ms = elapsed_ms
        self.headers = headers or {}


def test_brute_agent_persists_found_credentials(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={})

        def get(self, _endpoint, params=None):
            return FakeResult(text="Welcome to the password protected area")

        def close(self):
            return None

    monkeypatch.setattr(brute_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "brute", "url": "/vulnerabilities/brute/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = brute_module.brute_agent(state)

    assert update["scores"]["brute"] == 4
    assert update["found_credentials"]
    assert "credentials_extracted" in update["confirmed_vulns"]


def test_lfi_agent_sets_log_access_confirmed_when_log_readable(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.calls = 0
            self.http = SimpleNamespace(cookies={})

        def get(self, _endpoint, params=None):
            self.calls += 1
            if self.calls == 1:
                return FakeResult(text="root:x:0:0:root:/root:/bin/bash")
            return FakeResult(text='GET /dvwa HTTP/1.1\nPOST /login HTTP/1.1')

        def close(self):
            return None

    monkeypatch.setattr(lfi_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "lfi", "url": "/vulnerabilities/fi/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = lfi_module.lfi_agent(state)

    assert update["scores"]["lfi"] == 4
    assert "lfi_confirmed" in update["confirmed_vulns"]
    assert "log_access_confirmed" in update["confirmed_vulns"]


def test_upload_agent_requires_admin_on_high():
    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "high",
        "confirmed_vulns": [],
        "endpoints": [{"module_name": "upload", "url": "/vulnerabilities/upload/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = upload_module.upload_agent(state)

    assert update["scores"]["upload"] == 0
    assert "confirmed_vulns" not in update


def test_csrf_agent_direct_vs_chain_path(monkeypatch):
    class DirectSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={})
            self.calls = 0

        def get(self, _endpoint, params=None):
            self.calls += 1
            if self.calls == 1:
                return FakeResult(text="<form><input name='password_new'></form>")
            return FakeResult(text="Password Changed")

        def close(self):
            return None

    monkeypatch.setattr(csrf_module, "DVWASession", DirectSession)
    state_direct = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "confirmed_vulns": [],
        "endpoints": [{"module_name": "csrf", "url": "/vulnerabilities/csrf/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    direct = csrf_module.csrf_agent(state_direct)
    assert direct["scores"]["csrf"] == 3
    assert "user_compromised" in direct["confirmed_vulns"]

    class ChainSession:
        def __init__(self, _target):
            self.http = SimpleNamespace(cookies={})

        def get(self, _endpoint, params=None):
            return FakeResult(text="<input type='hidden' name='user_token' value='tok'>")

        def close(self):
            return None

    monkeypatch.setattr(csrf_module, "DVWASession", ChainSession)
    state_chain = {
        "target_url": "http://localhost/dvwa",
        "security_level": "high",
        "confirmed_vulns": ["xss_stored_confirmed"],
        "endpoints": [{"module_name": "csrf", "url": "/vulnerabilities/csrf/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    chained = csrf_module.csrf_agent(state_chain)
    assert chained["scores"]["csrf"] == 4
    assert "csrf_confirmed" in chained["confirmed_vulns"]


def test_weak_session_agent_prediction_signal(monkeypatch):
    class FakeHTTP:
        def __init__(self):
            self.cookies = {}

        def set_cookie(self, _name, _value):
            return None

    class FakeSession:
        def __init__(self, _target):
            self.http = FakeHTTP()
            self.calls = 0

        def get(self, _endpoint, params=None):
            self.calls += 1
            if self.calls <= 3:
                return FakeResult(text="sample", headers={"Set-Cookie": f"dvwaSession={self.calls}; path=/"})
            return FakeResult(text="welcome admin", headers={"Set-Cookie": "dvwaSession=4; path=/"})

        def close(self):
            return None

    monkeypatch.setattr(weak_session_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "weak_session", "url": "/vulnerabilities/weak_id/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = weak_session_module.weak_session_agent(state)

    assert update["scores"]["weak_session"] >= 3
    assert "weak_session_confirmed" in update["confirmed_vulns"]


def test_idor_agent_detects_unauthorized_resource_access(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.calls = 0
            self.http = SimpleNamespace(cookies={})

        def get(self, _endpoint, params=None):
            self.calls += 1
            if self.calls == 1:
                return FakeResult(text="Profile user_id=1")
            return FakeResult(text="Profile user_id=2 email=victim@example.com")

        def close(self):
            return None

    monkeypatch.setattr(idor_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "endpoints": [{"module_name": "idor", "url": "/vulnerabilities/idor/"}],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = idor_module.idor_agent(state)

    assert update["scores"]["idor"] == 3
    assert "idor_confirmed" in update["confirmed_vulns"]
    assert "data_exfiltrated" in update["confirmed_vulns"]
