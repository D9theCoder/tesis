"""Current checkpoint writes and strict, read-only historical audit decoding."""
from hashlib import sha256

import pytest

from core.checkpoint_audit import AuditCheckpointSerializer
from core.historical_contracts import HISTORICAL_LABELS


@pytest.mark.parametrize("value", ["retained proof" * 300, ["receipt" * 400]])
def test_checkpoint_writes_canonical_format_and_round_trips(tmp_path, value):
    serializer = AuditCheckpointSerializer(tmp_path)
    encoded = serializer.dumps_typed(value)
    assert encoded[0].startswith("tesis.checkpoint.audit:")
    assert serializer.loads_typed(encoded) == value


def test_checkpoint_audit_channels_write_canonical_manifests(tmp_path):
    serializer = AuditCheckpointSerializer(tmp_path)
    value = {"channel_values": {"response_evidence": [{"response_sha256": "a" * 64}]}}
    encoded = serializer.dumps_typed(value)
    raw = serializer.serde.loads_typed(encoded)
    assert raw["channel_values"]["response_evidence"]["format"] == "tesis.checkpoint.audit"
    assert serializer.loads_typed(encoded) == value


def test_historical_wrapped_audit_decodes_without_changing_source_bytes(tmp_path):
    serializer = AuditCheckpointSerializer(tmp_path)
    legacy = next(iter(HISTORICAL_LABELS["checkpoint_audit"]))
    value = {"proof": "historical evidence"}
    digest = serializer._store(value)
    original = (tmp_path / digest).read_bytes()
    manifest = {"format": legacy, "kind": "value", "entries": [digest]}
    kind, payload = serializer.serde.dumps_typed(manifest)
    encoded = (f"{legacy}:{kind}", payload)
    assert serializer.loads_typed(encoded) == value
    assert sha256((tmp_path / digest).read_bytes()).hexdigest() == digest
    assert (tmp_path / digest).read_bytes() == original
    assert serializer.dumps_typed("proof" * 1000)[0].startswith("tesis.checkpoint.audit:")


def test_historical_audit_channel_decodes_without_promoting_its_identity(tmp_path):
    serializer = AuditCheckpointSerializer(tmp_path)
    legacy = next(iter(HISTORICAL_LABELS["checkpoint_audit"]))
    value = {"proof": "retained"}
    digest = serializer._store(value)
    document = {"channel_values": {"response_evidence": {
        "format": legacy, "kind": "list", "entries": [digest],
    }}}
    encoded = serializer.serde.dumps_typed(document)
    assert serializer.loads_typed(encoded) == {"channel_values": {"response_evidence": [value]}}
    assert document["channel_values"]["response_evidence"]["format"] == legacy


def test_audit_hash_corruption_fails_for_historical_format(tmp_path):
    serializer = AuditCheckpointSerializer(tmp_path)
    legacy = next(iter(HISTORICAL_LABELS["checkpoint_audit"]))
    digest = serializer._store({"evidence": "original"})
    (tmp_path / digest).write_bytes(b"tampered")
    manifest = {"format": legacy, "kind": "value", "entries": [digest]}
    kind, payload = serializer.serde.dumps_typed(manifest)
    with pytest.raises(ValueError, match="hash mismatch"):
        serializer.loads_typed((f"{legacy}:{kind}", payload))


def test_audit_outer_and_inner_format_cannot_disagree(tmp_path):
    serializer = AuditCheckpointSerializer(tmp_path)
    legacy = next(iter(HISTORICAL_LABELS["checkpoint_audit"]))
    manifest = serializer._reference({"evidence": "current"})
    kind, payload = serializer.serde.dumps_typed(manifest)
    with pytest.raises(ValueError, match="format binding mismatch"):
        serializer.loads_typed((f"{legacy}:{kind}", payload))


def test_audit_unknown_format_and_missing_entries_fail_closed(tmp_path):
    serializer = AuditCheckpointSerializer(tmp_path)
    unknown = "tesis.checkpoint.audit.unsupported"
    manifest = {"format": unknown, "kind": "list", "entries": []}
    encoded = serializer.serde.dumps_typed({"channel_values": {"response_evidence": manifest}})
    with pytest.raises(ValueError, match="Unsupported checkpoint audit format"):
        serializer.loads_typed(encoded)
    legacy = next(iter(HISTORICAL_LABELS["checkpoint_audit"]))
    kind, payload = serializer.serde.dumps_typed({"format": legacy, "kind": "value", "entries": ["b" * 64]})
    with pytest.raises(FileNotFoundError):
        serializer.loads_typed((f"{legacy}:{kind}", payload))
