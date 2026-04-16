import importlib

lfi_chain_module = importlib.import_module("agents.tier3.lfi_to_rce_chain")
sqli_chain_module = importlib.import_module("agents.tier3.sqli_to_creds_chain")
upload_chain_module = importlib.import_module("agents.tier3.upload_to_rce_chain")
xss_chain_module = importlib.import_module("agents.tier3.xss_to_csrf_chain")


def test_sqli_to_creds_chain_requires_preconditions():
    state = {
        "target_url": "",
        "confirmed_vulns": ["credentials_extracted"],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = sqli_chain_module.sqli_to_creds_chain(state)

    assert update["scores"]["sqli"] == 0
    assert "confirmed_vulns" not in update


def test_upload_to_rce_chain_sets_rce_achieved():
    def fake_upload_agent(_state):
        return {
            "scores": {"upload": 4},
            "tried_payloads": {"upload": []},
            "confirmed_vulns": ["rce_achieved"],
            "achieved_outcomes": ["rce_achieved"],
            "iteration_count": 1,
            "next_agent": "orchestrator",
        }

    upload_chain_module.upload_agent = fake_upload_agent

    state = {
        "target_url": "http://localhost/dvwa",
        "confirmed_vulns": ["admin_session_obtained"],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = upload_chain_module.upload_to_rce_chain(state)

    assert update["scores"]["upload"] == 4
    assert "rce_achieved" in update["confirmed_vulns"]
    assert "rce_achieved" in update["achieved_outcomes"]


def test_xss_to_csrf_chain_sets_user_compromised():
    class FakeSession:
        def __init__(self, _target):
            pass

        def get(self, _endpoint, params=None):
            if params is None:
                return type("R", (), {"text": "<input name='user_token' value='tok123'>"})()
            return type("R", (), {"text": "Password Changed"})()

        def close(self):
            return None

    xss_chain_module.DVWASession = FakeSession

    state = {
        "target_url": "http://localhost/dvwa",
        "confirmed_vulns": ["xss_stored_confirmed"],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = xss_chain_module.xss_to_csrf_chain(state)

    assert update["scores"]["xss_s"] == 4
    assert "csrf_confirmed" in update["confirmed_vulns"]
    assert "user_compromised" in update["confirmed_vulns"]


def test_lfi_to_rce_chain_sets_rce_achieved():
    class FakeHTTP:
        def get(self, _endpoint, headers=None):
            return None

    class FakeSession:
        def __init__(self, _target):
            self.http = FakeHTTP()

        def get(self, _endpoint, params=None):
            return type("R", (), {"text": "uid=33(www-data)"})()

        def close(self):
            return None

    lfi_chain_module.DVWASession = FakeSession

    state = {
        "target_url": "http://localhost/dvwa",
        "confirmed_vulns": ["lfi_confirmed", "log_access_confirmed"],
        "tried_payloads": {},
        "scores": {},
        "iteration_count": 0,
    }
    update = lfi_chain_module.lfi_to_rce_chain(state)

    assert update["scores"]["lfi"] == 4
    assert "rce_achieved" in update["confirmed_vulns"]
    assert "rce_achieved" in update["achieved_outcomes"]


def test_sqli_to_creds_chain_tries_multiple_passwords_for_same_user(monkeypatch):
    class FakeSession:
        def __init__(self, _target):
            self.http = type("H", (), {"cookies": {}})()

        def login(self, username="admin", password="password"):
            return username == "admin" and password == "correct"

        def close(self):
            return None

    monkeypatch.setattr(sqli_chain_module, "DVWASession", FakeSession)

    state = {
        "target_url": "http://localhost/dvwa",
        "security_level": "low",
        "confirmed_vulns": ["sqli_confirmed", "credentials_extracted"],
        "found_credentials": [
            {"username": "admin", "password": "wrong"},
            {"username": "admin", "password": "correct"},
        ],
        "tried_payloads": {"sqli": ["login:admin"]},
        "scores": {},
        "iteration_count": 0,
    }
    update = sqli_chain_module.sqli_to_creds_chain(state)

    assert update["scores"]["sqli"] == 4
    assert "admin_session_obtained" in update["confirmed_vulns"]
