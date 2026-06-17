"""Telemetry helpers for Stage 7.1 rich experiment sidecars."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
import json


def utc_now_iso() -> str:
    """Handles utc now iso behavior for this module."""
    return datetime.now(timezone.utc).isoformat()


def stable_sha256(text: str) -> str:
    """Handles stable sha256 behavior for this module.

    Args:
        text: Value used by this function."""
    return "sha256:" + sha256(text.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class TelemetryEvent:
    """Single telemetry event recorded during framework execution."""
    seq: int
    ts: str
    iteration: int
    node: str
    event_type: str
    status: str
    payload: dict[str, Any]


class RunTelemetry:
    """Telemetry container for events collected during one run."""
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
        """Handles emit behavior for this module.

        Args:
            iteration: Value used by this function.
            node: Value used by this function.
            event_type: Value used by this function.
            status: Value used by this function.
            payload: Value used by this function.
            ts: Value used by this function."""
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
        """Handles extend from state events behavior for this module.

        Args:
            state_events: Value used by this function."""
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
        """Handles as dict list behavior for this module."""
        return [asdict(event) for event in self.events]

    def write_jsonl(self, path: str | Path) -> Path:
        """Handles write jsonl behavior for this module.

        Args:
            path: Value used by this function."""
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as handle:
            for event in self.events:
                handle.write(json.dumps(asdict(event), sort_keys=True) + "\n")
        return out_path
