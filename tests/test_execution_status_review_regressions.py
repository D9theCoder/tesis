"""Status review controls using metadata and setup-only session stubs.

No graph or request execution, provider calls, or framework E2E.
"""
import importlib

import pytest

from core.state import ALL_METHOD_AGENTS
from tests.support import ready_state


def method_module(method):
    surface = 'sqli' if method.startswith('sqli_') else 'access_control' if method.startswith('ac_') else 'brute_force'
    return importlib.import_module(f'agents.{surface}.{method}_agent')


@pytest.mark.parametrize('method', [m for m in ALL_METHOD_AGENTS if not m.startswith('ac_')])
def test_explicit_session_login_rejection_is_a_setup_failure(monkeypatch, method):
    from types import SimpleNamespace
    module = method_module(method)
    monkeypatch.setattr(module, 'DVWASession', lambda *args: SimpleNamespace(login=lambda: False, close=lambda: None))
    state = dict(ready_state(method), target_url='http://localhost/dvwa')
    update = getattr(module, method + '_agent')(state)
    assert update['execution_status'] == 'failed'
    assert update['execution_reason']['code'] == 'SESSION_LOGIN_FAILED'
