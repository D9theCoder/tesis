"""Opt-in offline Settings -> frozen execution -> evaluator HTTP -> AI receipt."""

import asyncio
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from textual.widgets import Button, Select

from evaluation.reporter import write_json_report
from evaluation.runner import run_single_engagement
from evaluation.thesis_scoring import evaluate_queue, finalize_reviews, review_queue
from llm.provider import get_llm
from tesis.config_loader import load_and_resolve_config, load_yaml_config
from tesis.provider_registry import model_profile_id
from tests.test_scoring_remediation_e2e import ScoringFixture, frozen_test_profile
from tests.test_tui_evaluator import EVIDENCE, SettingsApp, evaluator_config, wait_saved


def test_settings_evaluator_selection_reaches_frozen_review_and_ai_receipt(evaluator_config, monkeypatch):
    selected = model_profile_id("gateway", "second")

    async def select_and_save():
        app = SettingsApp()
        async with app.run_test(size=(80, 24)) as pilot:
            drawer = app.screen
            drawer.query_one("#settings-evaluator-provider", Select).value = selected
            await pilot.pause()
            drawer.apply_evaluator()
            drawer.query_one("#settings-save", Button).press()
            await wait_saved(pilot, drawer)
    asyncio.run(select_and_save())
    config = load_and_resolve_config(config_path=str(evaluator_config), cli_args={})
    execution_id = f"offline-evaluator-{uuid4().hex}"
    folder = EVIDENCE / execution_id
    folder.mkdir(parents=True)
    fixture = ScoringFixture("sqli_union", "mixed_candidates")
    with monkeypatch.context() as runtime:
        runtime.setattr(httpx.Client, "request", lambda client, *a, **k: fixture.request(client, *a, **k))
        runtime.setattr(httpx.Client, "send", lambda *_a, **_k: pytest.fail("External HTTP forbidden"))
        runtime.setattr("llm.runtime.get_llm", lambda *_a, **_k: fixture)
        artifact = run_single_engagement(
            target_url=config.target_url, security_level="low", llm_provider=config.provider,
            surface="sqli", payload_mode="hybrid",
            experiment_condition="linear_hybrid", max_iterations=12, candidate_budget=5,
            execution_id=execution_id, output_dir=str(folder / "run"),
            model_config=asdict(config.models[config.provider]),
            model_profiles={name: asdict(model) for name, model in config.models.items()},
            llm_role_configs={role: {"structured_output": "off"} for role in config.role_configs},
            scoring_mode=config.scoring_mode, scoring_evaluator=config.scoring_evaluator,
            scoring_rubric_version="scoring.v4", scoring_profile=frozen_test_profile(),
            fixture_id="synthetic-dvwa", protocol_version="offline.v1",
        )
    assert artifact.get("report"), artifact.get("error")
    assert artifact["config"]["scoring_evaluator"]["provider"] == selected
    assert all(httpx.URL(row["url"]).host == "localhost" for row in fixture.requests)
    artifact["validation_scope"] = "offline_synthetic_fixture"
    source = folder / "execution.json"
    write_json_report(source, artifact)
    before = source.read_bytes()
    queue = review_queue(source)
    assert any(row["status"] == "pending_review" for row in queue["candidates"])
    requests = []

    def respond(request):
        body = json.loads(request.content)
        assert request.url.host == "gateway.invalid"
        assert request.url.path == "/v1/chat/completions"
        assert body["model"] == "second"
        assert request.headers["authorization"] == "Bearer offline-evaluator-secret"
        evidence = json.loads(body["messages"][-1]["content"])
        requests.append({"url": str(request.url), "body": body})
        answer = {"score": min(2, evidence["proof_ceiling"]),
                  "reason": "Offline candidate-bound evaluator check", "evidence_refs": evidence["evidence_refs"]}
        return httpx.Response(200, json={"id": "offline-judge", "object": "chat.completion", "created": 1,
            "model": "second", "choices": [{"index": 0, "finish_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(answer)}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        monkeypatch.setattr("llm.provider.get_llm", lambda adapter, **options: get_llm(adapter, http_client=client, **options))
        result = evaluate_queue(queue, config.scoring_evaluator)
    assert requests and result["decisions"]
    assert all(row["status"] == "accepted" for row in result["telemetry"])
    finalized = finalize_reviews(source, result["decisions"], output_dir=folder / "review")
    assert set(finalized["receipts"]) == {"ai"}
    receipt = json.loads(Path(finalized["receipts"]["ai"]).read_text())
    assert receipt["source_sha256"] == sha256(before).hexdigest()
    assert receipt["Spayload_final"] is not None and source.read_bytes() == before
    changed = {**config.scoring_evaluator, "provider": model_profile_id("gateway", "first"), "model": "first"}
    with pytest.raises(ValueError, match="frozen experiment configuration"):
        evaluate_queue(queue, changed)
    write_json_report(folder / "evaluator.json", result)
    write_json_report(folder / "validation.json", {
        "status": "passed", "validation_scope": "offline_synthetic_fixture",
        "source_sha256": sha256(before).hexdigest(), "source_unchanged": True,
        "saved_config": load_yaml_config(evaluator_config),
        "experiment_provider": config.provider, "evaluator_provider": selected,
        "mocked_dvwa_requests": len(fixture.requests), "mocked_evaluator_requests": requests,
        "live_http_calls": 0, "live_provider_calls": 0, "receipt": finalized["receipts"]["ai"],
    })
