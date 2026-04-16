from agents.state_utils import prepare_agent_session


def test_prepare_agent_session_skips_login_when_not_required():
    class FakeSession:
        def __init__(self):
            self.login_calls = 0
            self.level_calls = 0

        def login(self):
            self.login_calls += 1
            return True

        def set_security_level(self, _level):
            self.level_calls += 1

    session = FakeSession()
    ready, notes = prepare_agent_session(session, "low", require_login=False)

    assert ready is True
    assert notes == []
    assert session.login_calls == 0
    assert session.level_calls == 1


def test_prepare_agent_session_requires_login_when_requested():
    class FakeSession:
        def login(self):
            return False

    ready, notes = prepare_agent_session(FakeSession(), "low", require_login=True)

    assert ready is False
    assert "session_login_failed" in notes