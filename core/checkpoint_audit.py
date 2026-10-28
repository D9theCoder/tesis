"""Content-addressed audit storage for synchronous LangGraph checkpoints.

The serializer preserves the full checkpoint contract on read, including pending
writes. Large immutable audit entries are stored once beside the SQLite file.
Missing or corrupted entries refuse restoration rather than dropping evidence.
"""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from core.state import ARTIFACT_ONLY_STATE_FIELDS


_AUDIT_FIELDS = ARTIFACT_ONLY_STATE_FIELDS | {"llm_call_receipts"}
_REFERENCE = "tesis.checkpoint.audit.v1"


class AuditCheckpointSerializer:
    """Compact persisted audit channels while exposing original Python values."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.serde = JsonPlusSerializer()

    def _store(self, value: Any) -> str:
        kind, payload = self.serde.dumps_typed(value)
        data = kind.encode() + b"\n" + payload
        digest = sha256(data).hexdigest()
        destination = self.directory / digest
        if destination.exists():
            return digest
        descriptor, temporary = tempfile.mkstemp(prefix=".audit-", dir=self.directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError:
                pass
        finally:
            Path(temporary).unlink(missing_ok=True)
        return digest

    def _load(self, digest: str) -> Any:
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Invalid checkpoint audit reference")
        data = (self.directory / digest).read_bytes()
        if sha256(data).hexdigest() != digest:
            raise ValueError("Checkpoint audit evidence hash mismatch")
        kind, payload = data.split(b"\n", 1)
        return self.serde.loads_typed((kind.decode(), payload))

    def _reference(self, value: Any) -> dict:
        return {"format": _REFERENCE, "kind": "list" if isinstance(value, list) else "value",
            "entries": [self._store(entry) for entry in value] if isinstance(value, list) else [self._store(value)]}

    def _restore(self, value: Any) -> Any:
        if not isinstance(value, dict) or value.get("format") != _REFERENCE:
            return value
        if set(value) != {"format", "kind", "entries"} or not isinstance(value["entries"], list):
            raise ValueError("Invalid checkpoint audit manifest")
        entries = [self._load(digest) for digest in value["entries"]]
        if value["kind"] == "list":
            return entries
        if value["kind"] != "value" or len(entries) != 1:
            raise ValueError("Invalid checkpoint audit value")
        return entries[0]

    def dumps_typed(self, value: Any) -> tuple[str, bytes]:
        if isinstance(value, dict) and isinstance(value.get("channel_values"), dict):
            channels = dict(value["channel_values"])
            for field in _AUDIT_FIELDS & channels.keys():
                channels[field] = self._reference(channels[field])
            return self.serde.dumps_typed({**value, "channel_values": channels})
        kind, payload = self.serde.dumps_typed(value)
        if len(payload) >= 2048:
            manifest_kind, manifest = self.serde.dumps_typed(self._reference(value))
            return f"{_REFERENCE}:{manifest_kind}", manifest
        return kind, payload

    def loads_typed(self, data: tuple[str, bytes]) -> Any:
        kind, payload = data
        if kind.startswith(f"{_REFERENCE}:"):
            return self._restore(self.serde.loads_typed((kind[len(_REFERENCE) + 1:], payload)))
        value = self.serde.loads_typed(data)
        if isinstance(value, dict) and isinstance(value.get("channel_values"), dict):
            channels = dict(value["channel_values"])
            for field in _AUDIT_FIELDS & channels.keys():
                channels[field] = self._restore(channels[field])
            value = {**value, "channel_values": channels}
        return value
