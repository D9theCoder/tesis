"""Focused contract tests for runtime events and artifact discovery."""

from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from tesis.artifact_repository import ArtifactRepository, config_fingerprint, new_execution_id
from tesis.runtime_events import (
    CancellationRequested,
    CancellationToken,
    CollectingRuntimeEventSink,
    RunEvent,
    normalize_stream_chunk,
    normalize_stream_chunks,
    redact_secrets,
)


def test_event_sink_preserves_order_and_collects_concurrent_events() -> None:
    """Events stay in emission order and concurrent producers lose nothing."""

    sink = CollectingRuntimeEventSink()
    for event_type in ("run.started", "graph.node.started", "run.completed"):
        sink.emit(RunEvent(event_type, data={"sequence": len(sink)}))

    assert [event.event_type for event in sink.snapshot()] == [
        "run.started",
        "graph.node.started",
        "run.completed",
    ]
    assert [event.data["sequence"] for event in sink.events] == [0, 1, 2]

    def emit_worker(worker: int) -> None:
        for index in range(25):
            sink.emit(RunEvent("llm.token", data={"worker": worker, "index": index}))

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(emit_worker, range(8)))

    concurrent_events = sink.snapshot()[3:]
    assert len(concurrent_events) == 8 * 25
    assert {(event.data["worker"], event.data["index"]) for event in concurrent_events} == {
        (worker, index) for worker in range(8) for index in range(25)
    }


def test_cancellation_token_is_cooperative_and_one_shot() -> None:
    token = CancellationToken()

    assert not token.is_cancelled
    assert token.cancel("user requested stop")
    assert not token.cancel("a later reason is ignored")
    assert token.cancelled
    assert token.reason == "user requested stop"
    assert token.wait(0)

    with pytest.raises(CancellationRequested, match="stop") as raised:
        token.check()
    assert raised.value.reason == "user requested stop"


@pytest.mark.parametrize(
    ("chunk", "expected"),
    [
        (
            {
                "candidates": [
                    {"content": {"parts": [{"text": "gemini "}, {"text": "chunk"}]}}
                ]
            },
            "gemini chunk",
        ),
        ({"choices": [{"delta": {"content": "openai"}}]}, "openai"),
        (
            {
                "type": "content_block_delta",
                "delta": {"type": "text_delta", "text": "claude"},
            },
            "claude",
        ),
        ({"content": [{"type": "text", "text": "anthropic"}]}, "anthropic"),
    ],
)
def test_normalize_stream_chunk_handles_provider_shapes(chunk: object, expected: str) -> None:
    assert normalize_stream_chunk(chunk) == expected


def test_normalize_stream_chunks_concatenates_openai_stream_and_ignores_tool_events() -> None:
    chunks = [
        {"choices": [{"delta": {"content": "hel"}}]},
        {"choices": [{"delta": {"content": "lo"}}]},
    ]

    assert normalize_stream_chunks(chunks) == "hello"
    assert normalize_stream_chunk({"type": "tool_use", "input": {"secret": "hidden"}}) == ""


def test_redact_secrets_masks_nested_keys_and_explicit_values_without_mutation() -> None:
    original = {
        "api_key": "key-from-config",
        "prompt": "Use key-from-trace only for this request",
        "nested": {"Authorization": "Bearer header-value", "visible": "safe"},
        "items": ["key-from-trace", {"response": "safe response"}],
    }

    redacted = redact_secrets(original, known_secrets=["key-from-trace", "header-value"])

    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["prompt"] == "Use [REDACTED] only for this request"
    assert redacted["nested"]["Authorization"] == "[REDACTED]"
    assert redacted["nested"]["visible"] == "safe"
    assert redacted["items"] == ["[REDACTED]", {"response": "safe response"}]
    assert original["api_key"] == "key-from-config"
    assert original["nested"]["Authorization"] == "Bearer header-value"


def test_config_fingerprint_excludes_secrets_and_execution_identity() -> None:
    config = {
        "provider": "openai",
        "model": "gpt-5",
        "surface": "sqli",
        "payload_mode": "hybrid",
        "candidate_budget": 4,
        "target_url": "http://dvwa.test/login.php?api_key=query-secret&mode=low",
        "api_key": "secret-a",
        "execution_id": "exec-a",
        "run_id": "logical-a",
        "repeat_index": 0,
        "output_path": "/tmp/first.json",
        "timing": {"started_at": "2026-01-01T00:00:00Z", "duration_ms": 10},
    }
    repeated = copy.deepcopy(config)
    repeated.update(
        {
            "api_key": "secret-b",
            "execution_id": "exec-b",
            "run_id": "logical-b",
            "repeat_index": 3,
            "output_path": "/tmp/second.json",
            "timing": {"started_at": "2027-01-01T00:00:00Z", "duration_ms": 99},
        }
    )

    first = config_fingerprint(config)
    second = config_fingerprint(repeated)

    assert first.startswith("sha256:")
    assert first == second
    assert "secret-a" not in first
    assert "secret-b" not in second

    changed_setup = copy.deepcopy(config)
    changed_setup["candidate_budget"] = 5
    assert config_fingerprint(changed_setup) != first


def test_new_execution_ids_are_unique_and_filename_safe() -> None:
    execution_ids = {new_execution_id() for _ in range(64)}

    assert len(execution_ids) == 64
    assert all(execution_id.startswith("exec-") for execution_id in execution_ids)
    assert all("/" not in execution_id and "\\" not in execution_id for execution_id in execution_ids)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_artifact_repository_loads_legacy_new_matrix_and_malformed_files(tmp_path: Path) -> None:
    common_config = {
        "provider": "openai",
        "model": "gpt-5",
        "surface": "sqli",
        "security_level": "low",
        "payload_mode": "hybrid",
        "candidate_budget": 4,
        "api_key": "legacy-secret",
    }
    _write_json(
        tmp_path / "legacy-run.json",
        {
            "run_id": "legacy-run",
            "status": "success",
            "timestamp": "2025-01-01T00:00:00Z",
            "config": common_config,
        },
    )
    repeated_config = {**common_config, "api_key": "new-secret", "repeat_index": 1}
    _write_json(
        tmp_path / "new-run.json",
        {
            "schema_version": "2",
            "execution_id": "exec-new",
            "run_id": "new-run",
            "status": "cancelled",
            "timestamp": "2025-01-02T00:00:00Z",
            "config": repeated_config,
        },
    )
    _write_json(
        tmp_path / "matrix.json",
        {
            "schema_version": "2",
            "execution_id": "exec-matrix",
            "timestamp": "2024-12-31T00:00:00Z",
            "config": {
                "provider": "anthropic",
                "model": "claude",
                "surface": "brute_force",
                "security_level": "high",
                "payload_mode": "static_only",
            },
            "runs": [
                {"run_id": "matrix-success", "status": "success", "timestamp": "2024-12-30T00:00:00Z"},
                {"run_id": "matrix-error", "status": "error", "timestamp": "2024-12-29T00:00:00Z"},
            ],
        },
    )
    (tmp_path / "malformed.json").write_text("{not valid json", encoding="utf-8")

    repository = ArtifactRepository(tmp_path)
    items = repository.scan()

    assert [item.run_id for item in items] == [
        "new-run",
        "legacy-run",
        "matrix-success",
        "matrix-error",
    ]
    assert repository.find_by_execution_id("exec-new").run_id == "new-run"
    assert repository.find_by_run_id("legacy-run").execution_id is None

    matrix_items = [item for item in items if item.is_matrix]
    assert {item.run_id for item in matrix_items} == {"matrix-success", "matrix-error"}
    assert {item.execution_id for item in matrix_items} == {"exec-matrix"}
    assert all(item.path.name != "malformed.json" for item in items)

    assert {item.run_id for item in repository.scan(provider="OPENAI")} == {"legacy-run", "new-run"}
    assert {item.run_id for item in repository.scan(filters={"security": "HIGH"})} == {
        "matrix-success",
        "matrix-error",
    }
    assert {item.run_id for item in repository.scan(status=["SUCCESS", "CANCELLED"])} == {
        "legacy-run",
        "new-run",
        "matrix-success",
    }

    duplicate_groups = repository.duplicate_config_fingerprints()
    assert sorted(
        {item.run_id for item in group} for group in duplicate_groups.values()
    ) == [
        {"legacy-run", "new-run"},
        {"matrix-error", "matrix-success"},
    ]
    assert repository.group_by_config_fingerprint(duplicates_only=True) == duplicate_groups
