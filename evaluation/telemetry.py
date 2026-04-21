"""Telemetry helpers for Stage 7.1 rich experiment sidecars."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
import json


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_sha256(text: str) -> str:
    return "sha256:" + sha256(text.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class TelemetryEvent:
    seq: int
    ts: str
    iteration: int
    node: str
    event_type: str
    status: str
    payload: dict[str, Any]


class RunTelemetry:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self._seq = 0
        self.events: list[TelemetryEvent] = []

    def emit(
        self,
        *,
        iteration: int,
        node: str,
        event_type: str,
        status: str,
        payload: dict[str, Any],
        ts: str | None = None,
    ) -> None:
        self._seq += 1
        self.events.append(
            TelemetryEvent(
                seq=self._seq,
                ts=ts or utc_now_iso(),
                iteration=int(iteration),
                node=str(node),
                event_type=str(event_type),
                status=str(status),
                payload=dict(payload),
            )
        )

    def extend_from_state_events(self, state_events: list[dict[str, Any]]) -> None:
        for item in state_events:
            if not isinstance(item, dict):
                continue
            iteration = int(item.get("iteration", 0) or 0)
            node = str(item.get("node", "runtime"))
            event_type = str(item.get("event") or item.get("event_type") or "runtime.event")
            status = str(item.get("status", "ok"))

            payload: dict[str, Any]
            explicit_payload = item.get("payload")
            if isinstance(explicit_payload, dict):
                payload = dict(explicit_payload)
                for key, value in item.items():
                    if key in {"iteration", "node", "event", "event_type", "status", "payload"}:
                        continue
                    payload[key] = value
            else:
                payload = {
                    k: v
                    for k, v in item.items()
                    if k not in {"iteration", "node", "event", "event_type", "status"}
                }

            self.emit(
                iteration=iteration,
                node=node,
                event_type=event_type,
                status=status,
                payload=payload,
            )

    def as_dict_list(self) -> list[dict[str, Any]]:
        return [asdict(event) for event in self.events]

    def write_jsonl(self, path: str | Path) -> Path:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as handle:
            for event in self.events:
                handle.write(json.dumps(asdict(event), sort_keys=True) + "\n")
        return out_path
