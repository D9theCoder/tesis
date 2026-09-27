"""State inventory and checkpoint compatibility contract (arch handoff phase 1)."""

from core.graph_builder import GRAPH_BUILD_VERSION
from core.state import (
    ARTIFACT_ONLY_STATE_FIELDS,
    CHECKPOINT_SCHEMA_VERSION,
    STATE_SCHEMA_VERSION,
    checkpoint_safe_state,
    new_default_state,
)


def test_checkpoint_safe_state_drops_rendered_payloads():
    state = new_default_state()
    safe = checkpoint_safe_state(state)
    assert not (set(safe) & ARTIFACT_ONLY_STATE_FIELDS)
    assert set(safe) == set(state) - ARTIFACT_ONLY_STATE_FIELDS


def test_run_artifact_carries_version_stamps(monkeypatch):
    from evaluation.runner import run_single_engagement
    from tesis.artifact_repository import config_fingerprint

    class FakeApp:
        def stream(self, state, stream_mode=None, config=None):
            yield {**state, "iteration_count": 1, "task_result": "SUCCESS"}

    monkeypatch.setattr("evaluation.runner.build_framework", lambda **_kwargs: FakeApp())
    artifact = run_single_engagement(
        target_url="http://localhost/dvwa",
        security_level="low",
        llm_provider="gemini",
        max_iterations=5,
        repeat_index=0,
        target_method="sqli_union",
    )
    assert artifact["state_schema_version"] == STATE_SCHEMA_VERSION
    assert artifact["checkpoint_schema_version"] == CHECKPOINT_SCHEMA_VERSION
    assert artifact["graph_build_version"] == GRAPH_BUILD_VERSION
    assert artifact["config_fingerprint"] == config_fingerprint(artifact["config"])
