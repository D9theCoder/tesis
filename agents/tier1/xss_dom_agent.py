"""Tier 1 DOM XSS agent."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from agents.base_agent import BaseAgent
from agents.state_utils import make_update, module_endpoint, normalize_security_level
from core.state import ExploitationState
from foundation.payload_library import PayloadLibrary
from foundation.session_manager import DVWASession
from foundation.verifier import Verifier


class XSSDOMAgent(BaseAgent):
    module_name = "xss_d"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()
        self.verifier = Verifier()

    @staticmethod
    def _with_payload(base_url: str, endpoint: str, payload: str) -> str:
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            root = endpoint
        else:
            root = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        query = urlencode({"default": payload})
        sep = "&" if "?" in root else "?"
        return f"{root}{sep}{query}"

    def run(self, state: ExploitationState) -> dict[str, Any]:
        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/xss_d/")
        payload_set = self.payloads.get(self.module_name, level)

        score = 0
        confirmed: list[str] = []
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

                response = session.get(endpoint, params={"default": payload})
                body = response.text or ""
                if payload in body or "alert(1)" in body.lower():
                    score = max(score, 2)
                    if "xss_dom_confirmed" not in confirmed:
                        confirmed.append("xss_dom_confirmed")

                verify_result = self.verifier.verify_xss_dialog(
                    self._with_payload(target_url, endpoint, payload),
                    {k: v for k, v in session.http.cookies.items()},
                )
                if verify_result.ok:
                    score = 3
                    confirmed = ["xss_dom_confirmed"]
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
        )


_AGENT = XSSDOMAgent()


def xss_dom_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
