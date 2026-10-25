# Live reasoning check: GPT-6 Luna and DeepSeek V4.1 Flash 1017

This is the baseline snapshot before
[reasoning trace capture was implemented](../completed/reasoning-trace-support-2026-10-26.md).
That later change adds trace/summary artifact fields. The streaming-default and
SIWC response compatibility findings below remain unresolved by that change.

Completed on 2026-10-26, Asia/Jakarta. This investigation made two declared
provider probes and one separate GPT diagnostic repeat. It did not run DVWA,
the experiment graph, E2E checks, or a model-quality comparison. Production
runtime code and the user's configuration were unchanged during this check.

## Observed results

| Model and route | Requested effort | Explicit reasoning tokens | Answer | Normal runtime |
| --- | --- | --- | --- | --- |
| `gpt-6-luna`, saved TESIS ChatGPT account `default`, `openai_codex_auth` | `low`, also echoed by provider | 128 in the separate diagnostic | Correct, 346 | Primary probe failed with `invalid_stream` |
| `deepseek-ai/DeepSeek-V4.1-Flash-1017`, saved River AI profile, Chat Completions | `low` | 309 | Correct, 346 | Completed |

Both received the same benign modular-arithmetic problem and JSON-only
instructions. The task asked for the smallest positive integer with remainders
3 modulo 7, 5 modulo 11, and 8 modulo 13. The reference answer was calculated
independently by exhaustive enumeration. Each primary coordinate disabled
SDK retries, runtime fallback, and cache. Both explicitly enabled streaming
and selected `json_prompt` output mode to isolate reasoning from native schema
or tool-call support. DeepSeek's output cap was 8192 tokens. The SIWC adapter
does not send an output-token cap, so this is not an equal-enforced-budget
comparison. The saved YAML contained DeepSeek; GPT was an explicitly selected
model using the existing signed-in TESIS account, without adding a YAML profile.

The positive token counts establish that these provider responses used
reasoning while the request selected `low`. They do not establish relative
model quality or how much effort changes behavior compared with other levels.

## GPT integration failure

The initial GPT request returned HTTP 200 without a `Content-Type` header.
The adapter rejects it before consuming the body because it requires
`text/event-stream` in [the response header](../../llm/siwc/provider.py).

A separate, single diagnostic request consumed the response without changing
the production adapter. Its body contained valid Responses SSE events, a
completed response for `gpt-6-luna`, an echoed `low` effort, 128 reported
reasoning tokens, and the correct answer. The final response's `output` array
was empty, while `response.output_text.done` and `response.output_item.done`
contained the answer.

Offline replay through the unchanged adapter reproduced `invalid_stream`
with the original missing header. Supplying only the expected content type
in the offline fixture allowed parsing but returned empty content: the adapter
constructs its final text only from the final response's `output` array. It
does not retain completed output items to handle this observed terminal shape.
Provider-side reasoning therefore worked; the current TESIS integration did
not complete successfully. No further live requests were made.

## Reasoning in artifacts

Normal [runtime performance records](../../llm/runtime.py) retain
`reasoning_effort_requested`, `provider_usage`, `reasoning_token_evidence`,
and validated final output. The [experiment writer](../../evaluation/runner.py)
exports these under `llm_performance`. There is no dedicated reasoning-text
artifact field or reasoning-stream event channel.

DeepSeek emitted 91 nonempty `reasoning_content` deltas totaling 749 characters.
The installed `ChatOpenAI` implementation explicitly does not preserve
nonstandard `reasoning_content` or `reasoning_details`. Saved-response offline
replay confirmed that its final message had empty `additional_kwargs`, while
the normal runtime still retained the 309-token reasoning count. This probe's
extra transport capture retains the provider-emitted text; ordinary TESIS
artifacts do not.

GPT's stream contained a reasoning item with encrypted content, with empty
summary and content arrays. TESIS does not request reasoning summaries and its
SIWC adapter extracts message output text only. OpenAI distinguishes exposed
summaries from raw internal reasoning, which is not available through the API.
See the [official reasoning guide](https://developers.openai.com/api/docs/guides/reasoning#reasoning-summaries).

## Streaming behavior

The code supports token callbacks and batched `llm.token` events. However,
the runner constructs the runtime coordinate from saved profiles before adding
`streaming: true` to graph state for a TUI event sink. Context-backed role calls
resolve those saved profiles rather than that later state override. An offline
resolution of the current configuration showed `streaming=False` for both API
roles. Thus the current DeepSeek role configuration waits for full output.
Explicit `extra.streaming: true` reaches the SDK; the controlled live probe
used this explicit setting and its HTTP response was SSE.

The Codex adapter always sends `stream: true`. In either mode, method selection
and payload processing wait until the completed answer is parsed and validated.
Streaming is an observation mechanism, not execution of partial LLM output.
The [stream normalizer](../../tesis/runtime_events.py) and callback path expose
visible answer text, not a separate reasoning feed.

The initial probe harness captured real HTTP streaming but placed callbacks in
a copied LangChain context without running the call inside that yielded context.
Its zero token-callback counts are a harness limitation. A corrected offline
replay of the saved DeepSeek stream produced two batched visible-token events,
without new provider calls. This distinction is retained in the interpretation.

## Evidence and reproduction

All generated evidence is local and gitignored:
[`results/validation/reasoning-live-2026-10-26/`](../../results/validation/reasoning-live-2026-10-26/).

- `manifest.json`: prompts, declared coordinates, retries/cache/output settings,
  Git identity, tracked diff digest, source/config/script hashes.
- `gpt-6-luna.json` and `deepseek-v4.1-flash-1017.json`: primary receipts,
  exact secret-redacted inference requests, captured responses, and performance.
- `gpt-6-luna-diagnostic.json`: the separate GPT diagnostic response.
- `gpt-6-luna-stream-replay.json` and `deepseek-stream-replay.json`: zero-network
  replay evidence for adapter behavior and callback/artifact retention.
- `code-audit.json` and `interpretation.json`: current role streaming flags,
  provider evidence, integration failures, and interpretation limits.

Executed commands, from the repository root:

```bash
PYTHONPATH=. .venv/bin/python results/validation/reasoning-live-2026-10-26/probe.py
PYTHONPATH=. .venv/bin/python results/validation/reasoning-live-2026-10-26/diagnostic_gpt.py
PYTHONPATH=. .venv/bin/python results/validation/reasoning-live-2026-10-26/replay.py
PYTHONPATH=. .venv/bin/python results/validation/reasoning-live-2026-10-26/replay_gpt.py
```

The first two commands make live provider requests and must not be rerun as
offline checks. The replay commands use saved responses and make no live calls.
