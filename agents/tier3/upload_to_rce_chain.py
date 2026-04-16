"""Tier 3 chain agent: admin session -> upload -> RCE."""

from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent
from agents.state_utils import make_update, merge_tried_payloads
from agents.tier2.upload_agent import upload_agent
from core.state import ExploitationState


class UploadToRCEChainAgent(BaseAgent):
    module_name = "upload"

    def check_prerequisites(self, state: ExploitationState) -> bool:
        return "admin_session_obtained" in set(state.get("confirmed_vulns", []))

    def run(self, state: ExploitationState) -> dict[str, Any]:
        tried_now = ["chain:upload_to_rce"]
        score = 0

        if not self.check_prerequisites(state):
            return make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
            )

        update = upload_agent(state)
        chained_tried = merge_tried_payloads(
            {"tried_payloads": update.get("tried_payloads", state.get("tried_payloads", {}))},
            self.module_name,
            tried_now,
        )
        update["tried_payloads"] = chained_tried
        return update


_AGENT = UploadToRCEChainAgent()


def upload_to_rce_chain(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
