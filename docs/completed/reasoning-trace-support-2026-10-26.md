# Provider reasoning trace artifact support

Provider-exposed reasoning is now retained separately from final answer text.
River AI DeepSeek and GLM `reasoning_content` populate `reasoning_trace`.
Typed `reasoning_details` and standard thinking blocks are also recognized.
Returned provider summaries populate `reasoning_summary`; encrypted reasoning
is excluded. Neither field is inferred from answers, model names, or token counts.

## Implementation

`llm/openai_chat.py` preserves gateway fields through complete and streaming
ChatOpenAI conversion. `llm/reasoning_evidence.py` extracts trace/summary text
and source fields. `llm/runtime.py` saves the redacted evidence in
`llm_performance` and physical attempt records, including responses whose JSON
is invalid or whose output is marked incomplete. AI evaluator receipts use the
same fields. SIWC retains summaries supplied in valid terminal responses.

New records have these additive fields, using `null` when unavailable:

```json
{
  "reasoning_trace": "Provider-returned reasoning text",
  "reasoning_trace_source": "additional_kwargs.reasoning_content",
  "reasoning_summary": null,
  "reasoning_summary_source": null
}
```

Cache hits make no provider request and add no new reasoning evidence; the
original call retains its trace. Capture changes neither scoring dimensions,
verification, prompt instructions, decoding settings, nor streaming defaults.
Existing SIWC header/terminal-output compatibility findings in the
[earlier live check](../reference/provider-reasoning-live-check-2026-10-26.md)
remain outside this change.

## Validation

The authorized GLM check made one live request to the saved
`zai-org/GLM-5.3-Flash` profile at River AI, using `low` effort, streaming,
an 8192-token output cap, a 60-second timeout, and no retry/cache. It returned
the correct answer to the shared arithmetic task, 100 explicit reasoning
tokens, and 37 nonempty `reasoning_content` deltas totaling 150 characters.
This call established the provider format before capture implementation.

The updated code was then checked with zero additional live calls against
the saved GLM stream and the earlier DeepSeek V4.1 Flash 1017 stream. Both
traces were preserved exactly through the real SDK conversion/runtime and
existing artifact writer:

| Saved response | Trace characters preserved | Reported reasoning tokens |
| --- | ---: | ---: |
| GLM 5.3 Flash | 150 | 100 |
| DeepSeek V4.1 Flash 1017 | 749 | 309 |

Focused offline checks passed: **321 tests**. They cover complete and streamed
native/JSON responses, async SDK conversion, artifact writing and redaction,
invalid/incomplete answers, repeated-call isolation, cache semantics,
summary separation, evaluator receipts, and the preceding provider/settings
changes from this session. No E2E, DVWA, experiment matrix, or additional
GPT/DeepSeek live requests were run for this implementation.

Evidence is local and gitignored:

- [`results/validation/junit.xml`](../../results/validation/junit.xml)
- [`glm-manifest.json`](../../results/validation/reasoning-trace-2026-10-26/glm-manifest.json)
- [`glm-live.json`](../../results/validation/reasoning-trace-2026-10-26/glm-live.json)
- [`glm-capture.json`](../../results/validation/reasoning-trace-2026-10-26/glm-capture.json)
- [`deepseek-capture.json`](../../results/validation/reasoning-trace-2026-10-26/deepseek-capture.json)

The live command was:

```bash
PYTHONPATH=. .venv/bin/python results/validation/reasoning-trace-2026-10-26/glm_probe.py
```

The saved-response check was:

```bash
PYTHONPATH=. .venv/bin/python results/validation/reasoning-trace-2026-10-26/replay_capture.py
```

The offline suite command was:

```bash
.venv/bin/python -m pytest -q tests/test_provider.py tests/test_llm_runtime.py tests/test_reasoning_config.py tests/test_reasoning_artifacts.py tests/test_siwc.py tests/test_evaluator_profile_config.py tests/test_api_providers.py tests/test_config_fields.py tests/test_config_loader.py tests/test_doctor.py tests/test_llm_runtime_config_cli.py tests/test_tui_api_providers.py tests/test_siwc_tui.py tests/test_tui_evaluator.py tests/test_tui_reasoning.py --junitxml=results/validation/junit.xml
```
